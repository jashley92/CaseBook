using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
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
/// Event-timeline attack steps (U-08c) persist their tactics + actor/target attribution and round-trip,
/// and folding the event fields into the canonical hash leaves the audit chain valid.
/// </summary>
public sealed class EventTimelinePersistenceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 11, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public EventTimelinePersistenceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.IncidentCommander];
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

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());


    [Fact]
    public async Task Event_step_persists_tactics_and_attribution_and_chain_stays_valid()
    {
        Guid id, actorId, targetId;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var created = await svc.CreateAsync(new CreateCaseRequest
            {
                DescriptiveName = "VPN Abuse",
                Title = "Anomalous VPN logins",
                Classification = Classification.Incident,
                Severity = Severity.High,
                Origin = CaseOrigin.InternalDetection
            });
            id = created.Id;

            actorId = await svc.AddEntityAsync(id, EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, null);
            targetId = await svc.AddEntityAsync(id, EntityType.Account, "jdoe", "John Doe", EntityDisposition.Benign, null, null);

            await svc.AddEventStepAsync(id, _clock.UtcNow.AddMinutes(5),
                new[] { MitreTactic.InitialAccess, MitreTactic.CredentialAccess },
                "T1078", actorId, targetId, "Authenticated with valid credentials", "SIEM");
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var loaded = await svc.GetDetailAsync(id);

            loaded.Should().NotBeNull();
            var step = loaded!.TimelineEntries.Single(t => t.Kind == TimelineKind.Event);
            step.Tactics.Select(t => t.Tactic).Should().BeEquivalentTo(new[] { MitreTactic.InitialAccess, MitreTactic.CredentialAccess });
            step.TechniqueId.Should().Be("T1078");
            step.ActorEntityId.Should().Be(actorId);
            step.TargetEntityId.Should().Be(targetId);

            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task Stated_times_and_step_order_round_trip_and_rows_rehash_when_reordered()
    {
        Guid id, window, loose;
        var mar4 = new DateTimeOffset(2026, 3, 4, 0, 0, 0, TimeSpan.Zero);
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            id = (await svc.CreateAsync(new CreateCaseRequest
            {
                DescriptiveName = "Vendor breach", Title = "Payroll vendor intrusion",
                Classification = Classification.Incident, Severity = Severity.High, Origin = CaseOrigin.ThirdParty, VendorName = "Acme Payroll"
            })).Id;
            window = await svc.AddEventStepAsync(id, mar4, [MitreTactic.InitialAccess], null, null, null, "Phished a vendor admin", "Vendor letter",
                timing: new StepTiming(TimePrecision.Window, mar4.AddDays(2)));
            await svc.AddEventStepAsync(id, mar4.AddDays(5), [MitreTactic.Exfiltration], null, null, null, "Took the payroll export", "Vendor letter",
                timing: new StepTiming(TimePrecision.OnOrBefore));
            loose = await svc.AddEventStepAsync(id, _clock.UtcNow, [MitreTactic.LateralMovement], null, null, null, "Reached the file server", "Vendor letter",
                timing: new StepTiming(TimePrecision.NotStated, AfterStepId: window));
            await svc.MoveEventStepAsync(id, loose, earlier: true);
        }

        await using (var db = NewContext())
        {
            var loaded = (await NewService(db).GetDetailAsync(id))!;
            var steps = loaded.TimelineEntries.Where(t => t.Kind == TimelineKind.Event).InTimelineOrder().ToList();
            steps.Select(s => s.Description).Should().Equal("Reached the file server", "Phished a vendor admin", "Took the payroll export");
            var w = steps.Single(s => s.Id == window);
            w.OccurredPrecision.Should().Be(TimePrecision.Window);
            w.OccurredUntilUtc.Should().Be(new DateTimeOffset(2026, 3, 6, 12, 0, 0, TimeSpan.Zero));
            steps[0].OccurredPrecision.Should().Be(TimePrecision.NotStated);
            steps.Take(2).Select(s => s.StepOrder).Should().Equal(1, 2);

            foreach (var s in steps) s.RowHash.Should().Be(_hasher.ComputeRowHash(s));
            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task Third_party_disclosure_step_persists_its_milestone_type_without_attack_attribution()
    {
        // E-32: a third-party/vendor case records vendor-disclosure milestones on the Event timeline —
        // no ATT&CK tactics / technique / actor→target — carrying the stage in the entry Type.
        Guid id;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            id = (await svc.CreateAsync(new CreateCaseRequest
            {
                DescriptiveName = "Vendor Breach", Title = "Vendor disclosed a data breach",
                Classification = Classification.Breach, Severity = Severity.High, Origin = CaseOrigin.ThirdParty,
                VendorName = "Acme SaaS"
            })).Id;

            await svc.AddEventStepAsync(id, _clock.UtcNow.AddHours(1), Array.Empty<MitreTactic>(),
                null, null, null, "Vendor confirmed our policyholder records were in the exposed dataset",
                "Acme SaaS", type: TimelineEntryType.Analysis);
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var step = (await svc.GetDetailAsync(id))!.TimelineEntries.Single(t => t.Kind == TimelineKind.Event);
            step.Type.Should().Be(TimelineEntryType.Analysis);
            step.Tactics.Should().BeEmpty();
            step.TechniqueId.Should().BeNull();
            step.ActorEntityId.Should().BeNull();
            step.TargetEntityId.Should().BeNull();
            step.Source.Should().Be("Acme SaaS");

            // Editing to a later stage updates the milestone type in place.
            await svc.EditEventStepAsync(id, step.Id, step.OccurredAtUtc, Array.Empty<MitreTactic>(),
                null, null, null, "Vendor **restored** service\n  from backups", step.Source, type: TimelineEntryType.Recovery);
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var step = (await svc.GetDetailAsync(id))!.TimelineEntries.Single(t => t.Kind == TimelineKind.Event);
            step.Type.Should().Be(TimelineEntryType.Recovery);
            step.Description.Should().Be("Vendor **restored** service from backups", "a step is one line of inline Markdown");

            // The attacker pivots from the vendor into our network: a step in our environment, kept and editable.
            await svc.AddEventStepAsync(id, _clock.UtcNow.AddHours(2), [MitreTactic.LateralMovement], "T1021", null, null,
                "Came in over the vendor's VPN tunnel", "EDR", environment: StepEnvironment.Ours);
            var pivot = (await svc.GetDetailAsync(id))!.TimelineEntries.Single(t => t.Description.StartsWith("Came in", StringComparison.Ordinal));
            pivot.Environment.Should().Be(StepEnvironment.Ours);
            await svc.EditEventStepAsync(id, pivot.Id, pivot.OccurredAtUtc, [MitreTactic.LateralMovement], "T1021", null, null,
                pivot.Description, pivot.Source, environment: StepEnvironment.Vendor);
            (await svc.GetDetailAsync(id))!.TimelineEntries.Single(t => t.Id == pivot.Id).Environment.Should().Be(StepEnvironment.Vendor);

            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task A_timeline_entry_persists_its_linked_screenshot_and_the_chain_stays_valid()
    {
        // U-40: the entry stores an EvidenceId (the pasted screenshot, uploaded separately as evidence).
        var shotId = Guid.NewGuid();
        Guid id;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            id = (await svc.CreateAsync(new CreateCaseRequest
            {
                DescriptiveName = "Phish", Title = "Phishing wave",
                Classification = Classification.Incident, Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
            })).Id;

            await svc.AddTimelineEntryAsync(id, TimelineKind.Investigation, TimelineEntryType.Analysis,
                _clock.UtcNow, "Reviewed the mailbox rule", "analyst", evidenceId: shotId);
        }

        await using (var db = NewContext())
        {
            var entry = await db.TimelineEntries.SingleAsync(t => t.CaseId == id);
            entry.EvidenceId.Should().Be(shotId);

            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    public void Dispose() => _connection.Dispose();
}
