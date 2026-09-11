using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Case templates / playbooks (E-06): admin CRUD, and applying a template to seed action items on a case
/// with the case-owner default, due-offset, need-to-know scoping, and the tamper-evident chain intact.
/// </summary>
public sealed class CaseTemplateTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 14, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseTemplateTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.Manager]; // sees all cases unless a test overrides
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private CaseService NewCaseService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private CaseTemplateService NewTemplateService(AppDbContext db) => new(NewFactory(), _user, _clock);

    private sealed class NoOpCaseNotifications : IncidentManager.Application.Abstractions.ICaseNotifications
    {
        public System.Threading.Tasks.Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string assigneeUserId, string assigneeDisplayName, IncidentManager.Domain.Enums.CaseAssignmentRole role, string assignedByUserId, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsOverdueAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.OverdueActionItem> items, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
    }

    private static CreateCaseRequest Req(string name) => new()
    {
        DescriptiveName = name,
        Title = $"{name} case",
        Classification = Classification.Incident,
        Severity = Severity.Medium,
        Origin = CaseOrigin.InternalDetection
    };

    private static TemplateInput Phishing(bool active = true) => new(
        "Phishing wave", "Credential-harvest phishing.", active, 1,
        Classification.Incident, Severity.Medium, "Credentials", "Suspected phishing campaign.",
        [
            new TemplateStepInput("Identify recipients", "Pull from the mail gateway.", null, 4),
            new TemplateStepInput("Block sender / URL / hash", null, "Detection eng", 8),
            new TemplateStepInput("Reset credentials for clickers", null, null, 8),
        ]);

    [Fact]
    public async Task Create_stores_the_template_with_ordered_steps_and_defaults()
    {
        await using var db = NewContext();
        var svc = NewTemplateService(db);

        var id = await svc.CreateAsync(Phishing());

        var t = await svc.GetAsync(id);
        t.Should().NotBeNull();
        t!.Name.Should().Be("Phishing wave");
        t.DefaultClassification.Should().Be(Classification.Incident);
        t.DefaultSeverity.Should().Be(Severity.Medium);
        t.Steps.Should().HaveCount(3);
        t.Steps.Select(s => s.Order).Should().BeInAscendingOrder();
        t.Steps[0].Title.Should().Be("Identify recipients");
        t.Steps[0].DueOffsetHours.Should().Be(4);
    }

    [Fact]
    public async Task Duplicate_template_name_is_rejected()
    {
        await using var db = NewContext();
        var svc = NewTemplateService(db);
        await svc.CreateAsync(Phishing());

        var act = () => svc.CreateAsync(Phishing());
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Update_replaces_the_step_set_wholesale()
    {
        Guid id;
        await using (var db = NewContext())
        {
            id = await NewTemplateService(db).CreateAsync(Phishing());
        }

        await using (var db = NewContext())
        {
            var svc = NewTemplateService(db);
            await svc.UpdateAsync(id, new TemplateInput(
                "Phishing wave", "Updated.", true, 2, Classification.Breach, Severity.High, "Credentials; NPI", null,
                [new TemplateStepInput("Only step now", null, null, 12)]));
        }

        await using (var db = NewContext())
        {
            var t = await NewTemplateService(db).GetAsync(id);
            t!.DefaultClassification.Should().Be(Classification.Breach);
            t.Steps.Should().ContainSingle().Which.Title.Should().Be("Only step now");
        }
    }

    [Fact]
    public async Task ListActive_hides_inactive_templates()
    {
        await using var db = NewContext();
        var svc = NewTemplateService(db);
        await svc.CreateAsync(Phishing());
        await svc.CreateAsync(new TemplateInput("Archived playbook", null, IsActive: false, 3,
            null, null, null, null, []));

        (await svc.ListActiveAsync()).Should().ContainSingle().Which.Name.Should().Be("Phishing wave");
        (await svc.ListAllAsync()).Should().HaveCount(2);
    }

    [Fact]
    public async Task Applying_a_template_seeds_action_items_owned_by_the_case_owner_with_due_offsets_and_keeps_the_chain_valid()
    {
        Guid caseId, templateId;
        await using (var db = NewContext())
        {
            var cases = NewCaseService(db);
            caseId = (await cases.CreateAsync(Req("Alpha"))).Id;
            await cases.AssignAsync(caseId, "ivy", "Ivy Commander", CaseAssignmentRole.IncidentCommander);
            templateId = await NewTemplateService(db).CreateAsync(Phishing());

            var seeded = await cases.ApplyTemplateAsync(caseId, templateId);
            seeded.Should().Be(3);
        }

        await using (var db = NewContext())
        {
            var c = await NewCaseService(db).GetDetailAsync(caseId);
            c!.ActionItems.Should().HaveCount(3);

            // Owner defaults to the case owner (IC); a step's owner hint wins when set.
            var identify = c.ActionItems.Single(a => a.Title == "Identify recipients");
            identify.Owner.Should().Be("ivy");
            identify.DueAtUtc.Should().Be(_clock.UtcNow.AddHours(4));

            var block = c.ActionItems.Single(a => a.Title == "Block sender / URL / hash");
            block.Owner.Should().Be("Detection eng");
            block.DueAtUtc.Should().Be(_clock.UtcNow.AddHours(8));

            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
            chain.Should().Contain(a => a.EntityType == "CaseTemplate" && a.Action == AuditAction.Create);
            chain.Should().Contain(a => a.EntityType == "ActionItem" && a.Action == AuditAction.Create);
        }
    }

    [Fact]
    public async Task Applying_a_subset_seeds_only_the_selected_steps()
    {
        await using var db = NewContext();
        var cases = NewCaseService(db);
        var caseId = (await cases.CreateAsync(Req("Alpha"))).Id;
        var template = await NewTemplateService(db).GetAsync(await NewTemplateService(db).CreateAsync(Phishing()));

        var firstStep = template!.Steps[0].Id;
        var seeded = await cases.ApplyTemplateAsync(caseId, template.Id, [firstStep]);

        seeded.Should().Be(1);
        var c = await cases.GetDetailAsync(caseId);
        c!.ActionItems.Should().ContainSingle().Which.Title.Should().Be("Identify recipients");
    }

    [Fact]
    public async Task Applying_to_a_restricted_case_the_caller_cannot_see_is_refused()
    {
        Guid restricted, templateId;
        await using (var db = NewContext())
        {
            // Manager sets up a restricted case owned by someone else, plus a template.
            var cases = NewCaseService(db);
            var r = IncidentManager.Domain.Entities.Case.Open(2026, 99, "Restricted", "Restricted",
                Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
            r.IsRestricted = true;
            db.Cases.Add(r);
            await db.SaveChangesAsync();
            restricted = r.Id;
            templateId = await NewTemplateService(db).CreateAsync(Phishing());
        }

        // Act as an analyst who is neither IC nor assigned on the restricted case.
        _user.UserId = "analyst-not-assigned";
        _user.RoleSet = [AppRole.Analyst];

        await using (var db = NewContext())
        {
            var cases = NewCaseService(db);
            var act = () => cases.ApplyTemplateAsync(restricted, templateId);
            await act.Should().ThrowAsync<InvalidOperationException>();
        }
    }

    public void Dispose() => _connection.Dispose();
}
