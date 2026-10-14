using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
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
/// BUG-413: a wrong timeline entry is retracted, never deleted: it leaves the record, keeps its text, and says who took
/// it off and why. BUG-414: when a verdict was actually reached can be given as it's recorded, and corrected later.
/// </summary>
public sealed class RetractAndVerdictTimeTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 14, 15, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };

    public RetractAndVerdictTimeTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    public void Dispose() => _connection.Dispose();

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
        return db;
    }

    private CaseService NewService(AppDbContext db) => new(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db),
        new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private async Task<Guid> NewCaseAsync(CaseService svc) => (await svc.CreateAsync(new CreateCaseRequest
    {
        DescriptiveName = "Retract", Title = "Retract case", Classification = Classification.Incident, Severity = Severity.High,
        Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-2)
    })).Id;

    private async Task<Case> LoadAsync(Guid id)
    {
        await using var db = NewContext();
        return (await NewService(db).GetDetailAsync(id))!;
    }

    private async Task RecordsVerifyAsync()
    {
        await using var db = NewContext();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        (await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain)).Should().BeNull();
    }

    // ---- BUG-413 ----

    [Fact]
    public async Task A_retracted_step_leaves_the_attack_chain_but_keeps_its_text_and_says_who_and_why()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var wrong = await svc.AddEventStepAsync(id, _clock.UtcNow.AddHours(-5), [MitreTactic.Execution], "T1059", null, null, "Ran a script", "EDR");
        var right = await svc.AddEventStepAsync(id, _clock.UtcNow.AddHours(-4), [MitreTactic.Persistence], "T1053", null, null, "Made a task", "EDR");
        var stamp = (await LoadAsync(id)).TimelineEntries.Single(e => e.Id == wrong).RowHash;

        _clock.UtcNow = _clock.UtcNow.AddMinutes(10);
        await svc.RetractTimelineEntryAsync(id, wrong, "Logged on the wrong case", stamp);

        var c = await LoadAsync(id);
        var step = c.TimelineEntries.Single(e => e.Id == wrong);
        step.IsCurrent.Should().BeFalse();
        step.IsRetracted.Should().BeTrue();
        step.Description.Should().Be("Ran a script");
        step.RetractedBy.Should().Be(_user.UserId);
        step.RetractedAtUtc.Should().Be(_clock.UtcNow);
        step.RetractReason.Should().Be("Logged on the wrong case");
        c.TimelineEntries.Where(e => EventSteps.IsAttack(c, e)).Select(e => e.Id).Should().Equal(right);
        IncidentManager.Application.Mitre.CaseTechniques.For(c).Select(t => t.TechniqueId).Should().NotContain("T1059");
        await RecordsVerifyAsync();
    }

    [Fact]
    public async Task A_retraction_needs_a_reason_happens_once_and_a_retracted_step_cant_be_edited()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var step = await svc.AddEventStepAsync(id, _clock.UtcNow.AddHours(-1), [MitreTactic.Execution], null, null, null, "Ran a script", null);

        await svc.Invoking(s => s.RetractTimelineEntryAsync(id, step, "  ")).Should().ThrowAsync<ArgumentException>();
        await svc.RetractTimelineEntryAsync(id, step, "Duplicate");
        await svc.Invoking(s => s.RetractTimelineEntryAsync(id, step, "Again")).Should().ThrowAsync<InvalidOperationException>();
        await svc.Invoking(s => s.EditEventStepAsync(id, step, _clock.UtcNow, [MitreTactic.Execution], null, null, null, "Changed", null))
            .Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task A_retraction_from_a_stale_page_is_refused()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var step = await svc.AddEventStepAsync(id, _clock.UtcNow.AddHours(-1), [MitreTactic.Execution], null, null, null, "Ran a script", null);
        var seen = (await LoadAsync(id)).TimelineEntries.Single(e => e.Id == step).RowHash;
        await svc.EditEventStepAsync(id, step, _clock.UtcNow.AddHours(-1), [MitreTactic.Execution], null, null, null, "Ran a PowerShell script", null);

        await svc.Invoking(s => s.RetractTimelineEntryAsync(id, step, "Wrong", seen)).Should().ThrowAsync<StaleEditException>();
        (await LoadAsync(id)).TimelineEntries.Single(e => e.Id == step).IsRetracted.Should().BeFalse();
    }

    [Fact]
    public async Task An_edited_finding_is_retracted_at_its_latest_version_and_keeps_its_history()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var first = await svc.AddTimelineEntryAsync(id, TimelineKind.Investigation, TimelineEntryType.Analysis, _clock.UtcNow.AddHours(-2), "Looked at logs", null);
        await svc.EditInvestigationEntryAsync(id, first, TimelineEntryType.Analysis, _clock.UtcNow.AddHours(-2), "Looked at the VPN logs", null);
        var latest = (await LoadAsync(id)).TimelineEntries.Single(e => e.IsCurrent && e.Kind == TimelineKind.Investigation).Id;

        await svc.Invoking(s => s.RetractTimelineEntryAsync(id, first, "Wrong")).Should().ThrowAsync<InvalidOperationException>(
            "an earlier version is already out of the record");
        await svc.RetractTimelineEntryAsync(id, latest, "Wrong case");

        var c = await LoadAsync(id);
        c.TimelineEntries.Where(e => e.Kind == TimelineKind.Investigation).Should().HaveCount(2).And.OnlyContain(e => !e.IsCurrent);
        c.TimelineEntries.Single(e => e.Id == latest).SupersedesEntryId.Should().Be(first);
        await RecordsVerifyAsync();
    }

    [Fact]
    public async Task An_entity_a_retracted_step_names_stays_on_the_case_with_a_reason_why()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var host = await svc.AddEntityAsync(id, EntityType.Host, "KIOSK-07", null, EntityDisposition.Unknown, null, null);
        var step = await svc.AddEventStepAsync(id, _clock.UtcNow.AddHours(-1), [MitreTactic.Execution], null, null, host, "Ran a script", null);
        await svc.RetractTimelineEntryAsync(id, step, "Wrong host");

        (await svc.Invoking(s => s.RemoveEntityAsync(id, host)).Should().ThrowAsync<InvalidOperationException>())
            .WithMessage("A retracted attack step names this entity*");
    }

    [Fact]
    public async Task Retracting_needs_edit_rights()
    {
        Guid id, step;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            id = await NewCaseAsync(svc);
            step = await svc.AddEventStepAsync(id, _clock.UtcNow.AddHours(-1), [MitreTactic.Execution], null, null, null, "Ran a script", null);
        }
        _user.PermissionSet = [Permission.ViewCases];
        await using var db2 = NewContext();
        await NewService(db2).Invoking(s => s.RetractTimelineEntryAsync(id, step, "Wrong")).Should().ThrowAsync<ForbiddenException>();
    }

    // ---- BUG-414 ----

    private async Task<(Guid Case, Guid Entity)> CaseWithAccountAsync(CaseService svc)
    {
        var id = await NewCaseAsync(svc);
        var entity = (await svc.AddOrMatchEntityAsync(id, EntityType.Account, "CONTOSO\\jdoe", null, EntityDisposition.Unknown, null, null)).Id;
        return (id, entity);
    }

    [Fact]
    public async Task A_verdict_reached_earlier_keeps_both_times_and_needs_a_reason_when_over_an_hour_back()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var (id, entity) = await CaseWithAccountAsync(svc);
        var reached = _clock.UtcNow.AddHours(-3);

        await svc.Invoking(s => s.SetEntityVerdictAsync(id, entity, EntityDisposition.Suspicious, null, EntityDisposition.Unknown, determinedAtUtc: reached))
            .Should().ThrowAsync<ArgumentException>();
        await svc.Invoking(s => s.SetEntityVerdictAsync(id, entity, EntityDisposition.Suspicious, "x", EntityDisposition.Unknown,
            determinedAtUtc: _clock.UtcNow.AddHours(1))).Should().ThrowAsync<ArgumentException>("not in the future");

        await svc.SetEntityVerdictAsync(id, entity, EntityDisposition.Suspicious, "Seen on the morning call", EntityDisposition.Unknown,
            determinedAtUtc: reached);

        var v = (await LoadAsync(id)).VerdictChanges.Should().ContainSingle().Subject;
        v.ChangedAtUtc.Should().Be(_clock.UtcNow);
        v.EffectiveAtUtc.Should().Be(reached);
        v.EffectiveAt.Should().Be(reached);
        await RecordsVerifyAsync();
    }

    [Fact]
    public async Task A_verdict_cant_be_dated_before_the_previous_verdict_on_the_same_entity()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var (id, entity) = await CaseWithAccountAsync(svc);
        await svc.EditEntityAsync(id, entity, EntityType.Account, "CONTOSO\\jdoe", null, EntityDisposition.Suspicious, null, null,
            "First look", determinedAtUtc: _clock.UtcNow.AddHours(-2));

        await svc.Invoking(s => s.EditEntityAsync(id, entity, EntityType.Account, "CONTOSO\\jdoe", null, EntityDisposition.Compromised,
                null, null, "Confirmed", determinedAtUtc: _clock.UtcNow.AddHours(-5)))
            .Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task A_verdicts_time_can_be_corrected_later_and_the_correction_is_kept()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var (id, entity) = await CaseWithAccountAsync(svc);
        await svc.SetEntityVerdictAsync(id, entity, EntityDisposition.Compromised, "Token theft confirmed", EntityDisposition.Unknown);
        var change = (await LoadAsync(id)).VerdictChanges.Single();

        _clock.UtcNow = _clock.UtcNow.AddHours(1);
        var actually = _clock.UtcNow.AddHours(-6);
        await svc.CorrectTransitionTimeAsync(id, TransitionKind.Verdict, change.Id, actually, "Confirmed on the 09:00 call; entered later");

        var c = await LoadAsync(id);
        c.VerdictChanges.Single().EffectiveAt.Should().Be(actually);
        var k = c.TimeCorrections.Should().ContainSingle().Subject;
        k.Kind.Should().Be(TransitionKind.Verdict);
        k.FromEffectiveUtc.Should().Be(change.ChangedAtUtc);
        k.ToEffectiveUtc.Should().Be(actually);
        await RecordsVerifyAsync();
    }
}
