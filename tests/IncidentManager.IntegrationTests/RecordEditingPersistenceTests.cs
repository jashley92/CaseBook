using FluentAssertions;
using IncidentManager.Application.Abstractions;
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
/// Records change during an investigation. IOCs and Event steps are corrected in place; Investigation
/// entries are superseded (versioned). Every path must keep the tamper-evident audit chain valid, and an
/// optional analyst reason is recorded on the audit entry.
/// </summary>
public sealed class RecordEditingPersistenceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 14, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public RecordEditingPersistenceTests()
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

    private sealed class NoOpCaseNotifications : IncidentManager.Application.Abstractions.ICaseNotifications
    {
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
    }

    private async Task<Guid> NewCaseAsync(CaseService svc)
    {
        var created = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Editing",
            Title = "Records change during investigation",
            Classification = Classification.Incident,
            Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection
        });
        return created.Id;
    }

    [Fact]
    public async Task Editing_an_entity_in_place_reassesses_it_and_records_the_reason_with_a_valid_chain()
    {
        Guid id, entityId;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            id = await NewCaseAsync(svc);
            entityId = await svc.AddEntityAsync(id, EntityType.IpAddress, "203.0.113.66", null,
                EntityDisposition.Suspicious, null, "SIEM");

            await svc.EditEntityAsync(id, entityId, EntityType.IpAddress, "203.0.113.66", "C2 node",
                EntityDisposition.Malicious, "confirmed beaconing", "VirusTotal", reason: "re-assessed after VT review");
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var loaded = (await svc.GetDetailAsync(id))!;
            var entity = loaded.Entities.Single();
            entity.Disposition.Should().Be(EntityDisposition.Malicious);
            entity.Label.Should().Be("C2 node");
            entity.ModifiedBy.Should().NotBeNull();

            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();

            // The correction reason rides on the entity's Update audit entry.
            var update = chain.Single(a => a.EntityType == "CaseEntity" && a.Action == AuditAction.Update);
            update.Reason.Should().Be("re-assessed after VT review");
        }
    }

    [Fact]
    public async Task Editing_an_event_step_reconciles_tactics_in_place_and_chain_stays_valid()
    {
        Guid id, entryId, actorId, targetId;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            id = await NewCaseAsync(svc);
            actorId = await svc.AddEntityAsync(id, EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, null);
            targetId = await svc.AddEntityAsync(id, EntityType.Account, "jdoe", "John Doe", EntityDisposition.Benign, null, null);
            await svc.AddEventStepAsync(id, _clock.UtcNow.AddMinutes(5),
                new[] { MitreTactic.InitialAccess }, "T1078", actorId, targetId, "Logged in", "SIEM");

            var step = (await svc.GetDetailAsync(id))!.TimelineEntries.Single(t => t.Kind == TimelineKind.Event);
            entryId = step.Id;

            await svc.EditEventStepAsync(id, entryId, _clock.UtcNow.AddMinutes(5),
                new[] { MitreTactic.InitialAccess, MitreTactic.LateralMovement }, "T1021", actorId, targetId,
                "Logged in, then pivoted to finance", "SIEM", reason: "added lateral movement detail");
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var step = (await svc.GetDetailAsync(id))!.TimelineEntries.Single(t => t.Kind == TimelineKind.Event);
            step.Tactics.Select(t => t.Tactic).Should().BeEquivalentTo(new[] { MitreTactic.InitialAccess, MitreTactic.LateralMovement });
            step.TechniqueId.Should().Be("T1021");
            step.Description.Should().Contain("pivoted");
            // Still a single (in-place) event row — not versioned.
            step.Version.Should().Be(1);
            (await db.TimelineEntries.CountAsync(t => t.Kind == TimelineKind.Event)).Should().Be(1);

            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task Editing_an_investigation_entry_supersedes_it_with_a_new_version_and_chain_stays_valid()
    {
        Guid id, entryId;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            id = await NewCaseAsync(svc);
            await svc.AddTimelineEntryAsync(id, TimelineKind.Investigation, TimelineEntryType.Analysis,
                _clock.UtcNow, "Initial meeting notes.", "Analyst");

            entryId = (await svc.GetDetailAsync(id))!.TimelineEntries.Single(t => t.Kind == TimelineKind.Investigation).Id;

            await svc.EditInvestigationEntryAsync(id, entryId, TimelineEntryType.Analysis, _clock.UtcNow,
                "Initial meeting notes.\n\n- Clarified: exfil confirmed.", "Analyst", reason: "added clarification");
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var all = (await svc.GetDetailAsync(id))!.TimelineEntries.Where(t => t.Kind == TimelineKind.Investigation).ToList();
            all.Should().HaveCount(2);

            var current = all.Single(t => t.IsCurrent);
            current.Version.Should().Be(2);
            current.Description.Should().Contain("Clarified");

            var prior = all.Single(t => !t.IsCurrent);
            prior.Version.Should().Be(1);
            prior.IsCurrent.Should().BeFalse();
            current.SupersedesEntryId.Should().Be(prior.Id);

            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task An_original_investigation_entry_hashes_identically_whether_or_not_it_is_later_edited()
    {
        // The v1 canonical must not change when versioning fields exist, or existing rows would re-baseline.
        Guid id, entryId;
        string originalHash;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            id = await NewCaseAsync(svc);
            await svc.AddTimelineEntryAsync(id, TimelineKind.Investigation, TimelineEntryType.Containment,
                _clock.UtcNow, "Contained the host.", "Analyst");
            var entry = (await svc.GetDetailAsync(id))!.TimelineEntries.Single(t => t.Kind == TimelineKind.Investigation);
            entryId = entry.Id;
            originalHash = entry.RowHash!;
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            await svc.EditInvestigationEntryAsync(id, entryId, TimelineEntryType.Containment, _clock.UtcNow,
                "Contained the host, then reimaged.", "Analyst", reason: null);
        }

        await using (var db = NewContext())
        {
            // The original (now superseded) row is untouched — same stored hash, and it still recomputes.
            var prior = await db.TimelineEntries.AsNoTracking().SingleAsync(t => t.Id == entryId);
            prior.RowHash.Should().Be(originalHash);
            _hasher.ComputeRowHash(prior).Should().Be(originalHash);

            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    public void Dispose() => _connection.Dispose();
}
