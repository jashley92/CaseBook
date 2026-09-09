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

    private sealed class NoOpCaseNotifications : IncidentManager.Application.Abstractions.ICaseNotifications
    {
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
    }

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
