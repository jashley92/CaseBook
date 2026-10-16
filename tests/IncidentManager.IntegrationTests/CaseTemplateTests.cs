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
        _user.RoleSet = [AppRole.SysAdmin]; // sees all + may edit (F-21); tests override to a lesser role for scoping
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
    public async Task A_step_s_kind_carries_to_the_task_it_seeds(/* INV-28 */)
    {
        await using var db = NewContext();
        var cases = NewCaseService(db);
        var caseId = (await cases.CreateAsync(Req("Alpha"))).Id;
        var templateId = await NewTemplateService(db).CreateAsync(new TemplateInput("Containment playbook", null, IsActive: true, 1,
            null, null, null, null,
            [new TemplateStepInput("Isolate the host", null, null, null, TaskKind.Contain), new TemplateStepInput("Write it up", null, null, null)]));

        (await NewTemplateService(db).GetAsync(templateId))!.Steps.Select(x => x.Kind).Should().Equal(TaskKind.Contain, TaskKind.General);
        await cases.ApplyTemplateAsync(caseId, templateId);

        var c = await cases.GetDetailAsync(caseId);
        c!.ActionItems.Single(a => a.Title == "Isolate the host").Kind.Should().Be(TaskKind.Contain);
        c.ActionItems.Single(a => a.Title == "Write it up").Kind.Should().Be(TaskKind.General);
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
    public async Task Applying_to_a_case_with_no_owner_falls_back_to_the_default_owner_for_hintless_steps(/* U-45 */)
    {
        await using var db = NewContext();
        var cases = NewCaseService(db);
        var caseId = (await cases.CreateAsync(Req("Alpha"))).Id;   // no Incident Commander assigned
        var templateId = await NewTemplateService(db).CreateAsync(Phishing());

        await cases.ApplyTemplateAsync(caseId, templateId, defaultOwner: "ivy");

        var c = await cases.GetDetailAsync(caseId);
        // A step with no owner hint falls back to the supplied default owner…
        c!.ActionItems.Single(a => a.Title == "Identify recipients").Owner.Should().Be("ivy");
        // …but a step's own owner hint still wins over the default.
        c.ActionItems.Single(a => a.Title == "Block sender / URL / hash").Owner.Should().Be("Detection eng");
    }

    [Fact]
    public async Task Applying_to_a_case_with_no_owner_and_no_default_leaves_hintless_steps_unassigned(/* U-45 */)
    {
        await using var db = NewContext();
        var cases = NewCaseService(db);
        var caseId = (await cases.CreateAsync(Req("Alpha"))).Id;   // no Incident Commander, no default owner
        var templateId = await NewTemplateService(db).CreateAsync(Phishing());

        await cases.ApplyTemplateAsync(caseId, templateId);

        var c = await cases.GetDetailAsync(caseId);
        c!.ActionItems.Single(a => a.Title == "Identify recipients").Owner.Should().BeNullOrEmpty();
        c.ActionItems.Single(a => a.Title == "Block sender / URL / hash").Owner.Should().Be("Detection eng");
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

    [Fact]
    public async Task Two_template_saves_onto_one_name_at_once_leave_one(/* BUG-557 */)
    {
        Guid other;
        await using (var db = NewContext()) other = await NewTemplateService(db).CreateAsync(Phishing() with { Name = "Ransomware" });

        // A create and a rename onto the same name while another writer (an import) holds GuardGate: each check runs with
        // its save, after the other's, so whichever goes second is refused, in either order.
        Task create, rename;
        using (await GuardGate.EnterAsync())
        {
            create = Task.Run(async () => { await using var db = NewContext(); await NewTemplateService(db).CreateAsync(Phishing()); });
            rename = Task.Run(async () => { await using var db = NewContext(); await NewTemplateService(db).UpdateAsync(other, Phishing() with { Name = "PHISHING wave" }); });
            await Task.Delay(200);
            create.IsCompleted.Should().BeFalse("the name check and the save wait for GuardGate");
            rename.IsCompleted.Should().BeFalse();
        }
        var failures = new List<Exception>();
        foreach (var t in new[] { create, rename })
            try { await t; }
            catch (InvalidOperationException ex) { failures.Add(ex); }

        failures.Should().ContainSingle().Which.Message.Should().Contain("already exists");
        await OneTemplatePerNameAsync();

        // C17: in each order, the first gets the name and the second is refused.
        await RaceOrders.ForEveryOrderAsync(2, async _ =>
        {
            await using var db = NewContext();
            var svc = NewTemplateService(db);
            foreach (var t in await svc.ListAllAsync()) await svc.DeleteAsync(t.Id);
            var renamed = await svc.CreateAsync(Phishing() with { Name = "Ransomware" });
            return [() => svc.CreateAsync(Phishing()), () => svc.UpdateAsync(renamed, Phishing() with { Name = "PHISHING wave" })];
        }, async run =>
        {
            run.Outcomes[run.First].Should().BeNull(run.ToString());
            run.Outcomes[run.Order[1]].Should().BeOfType<InvalidOperationException>(run.ToString())
                .Which.Message.Should().Contain("already exists");
            await OneTemplatePerNameAsync();
        });
    }

    private async Task OneTemplatePerNameAsync()
    {
        await using var check = NewContext();
        (await NewTemplateService(check).ListAllAsync()).GroupBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
            .Should().OnlyContain(g => g.Count() == 1);
    }

    [Fact]
    public async Task A_template_edit_that_waited_behind_another_save_sees_it_and_refuses(/* BUG-557 */)
    {
        await using var db = NewContext();
        var svc = NewTemplateService(db);
        var id = await svc.CreateAsync(Phishing());
        var opened = (await svc.GetAsync(id))!;

        Task edit;
        using (await GuardGate.EnterAsync())
        {
            edit = Task.Run(() => svc.UpdateAsync(id, Phishing() with { Description = "mine" }, opened.Stamp));
            await Task.Delay(200);
            edit.IsCompleted.Should().BeFalse();
            await using var other = NewContext();
            (await other.CaseTemplates.SingleAsync(t => t.Id == id)).Description = "theirs";
            await other.SaveChangesAsync();
        }

        await edit.Invoking(x => x).Should().ThrowAsync<InvalidOperationException>().WithMessage("*the template*since you opened it*");
        (await svc.GetAsync(id))!.Description.Should().Be("theirs");
    }

    [Fact]
    public async Task A_template_rename_onto_a_name_saved_meanwhile_is_reported_as_a_duplicate(/* BUG-557 */)
    {
        Guid id;
        await using (var db = NewContext()) id = await NewTemplateService(db).CreateAsync(Phishing());
        // A writer outside the gate saves the name after UpdateAsync's check, before its save reaches the unique index.
        var racer = new BeforeFirstSave(async () =>
        {
            await using var other = NewContext();
            other.CaseTemplates.Add(new IncidentManager.Domain.Entities.CaseTemplate
                { Name = "Ransomware", CreatedBy = "admin2", CreatedAtUtc = _clock.UtcNow });
            await other.SaveChangesAsync();
        });

        var rename = async () => await new CaseTemplateService(RacingFactory(racer), _user, _clock)
            .UpdateAsync(id, Phishing() with { Name = "Ransomware" });

        (await rename.Should().ThrowAsync<InvalidOperationException>()).WithMessage("*already exists*");
        await using var check = NewContext();
        (await NewTemplateService(check).GetAsync(id))!.Name.Should().Be("Phishing wave");
    }

    [Fact]
    public async Task A_template_changed_under_an_edit_by_a_writer_outside_the_gate_says_so_about_the_template(/* BUG-557 */)
    {
        Guid id;
        await using (var db = NewContext()) id = await NewTemplateService(db).CreateAsync(Phishing());
        // Its steps are replaced after the edit loaded them, so the edit's delete of the old steps finds nothing.
        var racer = new BeforeFirstSave(async () =>
        {
            await using var other = NewContext();
            await other.CaseTemplateSteps.Where(s => s.TemplateId == id).ExecuteDeleteAsync();
        });

        var edit = async () => await new CaseTemplateService(RacingFactory(racer), _user, _clock)
            .UpdateAsync(id, Phishing() with { Description = "mine" });

        (await edit.Should().ThrowAsync<InvalidOperationException>()).WithMessage("Someone changed the template \"Phishing wave\"*");
    }

    private TestDbContextFactory RacingFactory(BeforeFirstSave racer) =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(racer, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    /// <summary>Runs another save once, in the middle of the first save made through these options.</summary>

    public void Dispose() => _connection.Dispose();
}
