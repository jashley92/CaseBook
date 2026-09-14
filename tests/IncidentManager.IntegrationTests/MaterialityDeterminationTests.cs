using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.StageGates;
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

/// <summary>PROD-18: the materiality determination — persistence + audit, and close-gate enforcement.</summary>
public sealed class MaterialityDeterminationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 16, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public MaterialityDeterminationTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.Manager];
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(), new TestSlaTargets());

    private async Task<Guid> NewIncidentAsync(CaseService svc) =>
        (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Vendor Event",
            Title = "Vendor security event",
            Classification = Classification.Incident,
            Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection,
            Summary = "Confirmed vendor compromise."
        })).Id;

    private async Task SeedCloseGateAsync(AppDbContext db)
    {
        var gate = new StageGate
        {
            Trigger = StageGateTrigger.CloseCase, Name = "Closure readiness", IsActive = true,
            CreatedBy = "system", CreatedAtUtc = _clock.UtcNow
        };
        gate.Requirements.Add(new StageGateRequirement
        {
            GateId = gate.Id, Order = 0, Kind = GateRequirementKind.MachineCheck,
            CheckKey = GateCheckKeys.MaterialityDetermined, Label = "Materiality recorded", IsBlocking = true
        });
        db.StageGates.Add(gate);
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Recording_a_final_determination_persists_the_off_app_provenance_and_a_change_row()
    {
        Guid id;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            id = await NewIncidentAsync(svc);
        }

        var decidedOn = _clock.UtcNow.AddDays(-1);
        await using (var db = NewContext())
        {
            _user.UserId = "soc-analyst";
            await NewService(db).RecordMaterialityAsync(id, MaterialityStatus.Material,
                "Disclosure Committee", decidedOn, "Reasonable likelihood of harm to NY residents.");
        }

        await using (var verify = NewContext())
        {
            var c = await verify.Cases.Include(x => x.MaterialityChanges).FirstAsync(x => x.Id == id);
            c.Materiality.Status.Should().Be(MaterialityStatus.Material);
            c.Materiality.DecisionMaker.Should().Be("Disclosure Committee");
            c.Materiality.DecidedOnUtc.Should().Be(decidedOn);
            c.Materiality.RecordedBy.Should().Be("soc-analyst");
            c.MaterialityChanges.Should().ContainSingle().Which.To.Should().Be(MaterialityStatus.Material);

            // The determination is audited and the chain stays intact.
            (await verify.AuditLog.CountAsync(a => a.EntityType == "MaterialityChange")).Should().Be(1);
            _hasher.VerifyChain(await verify.AuditLog.OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task An_incident_cannot_close_until_a_materiality_determination_is_recorded()
    {
        Guid id;
        await using (var db = NewContext())
        {
            await SeedCloseGateAsync(db);
            var svc = NewService(db);
            id = await NewIncidentAsync(svc);
        }

        // Undetermined → the close gate blocks the transition.
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var act = () => svc.ChangePhaseAsync(id, CasePhase.Closed, "wrapping up");
            await act.Should().ThrowAsync<GateNotSatisfiedException>();
            (await db.Cases.FirstAsync(c => c.Id == id)).Phase.Should().NotBe(CasePhase.Closed);
        }

        // "Under review" is not enough — it is not a final call.
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            await svc.RecordMaterialityAsync(id, MaterialityStatus.UnderReview, null, null, null);
            var act = () => svc.ChangePhaseAsync(id, CasePhase.Closed, "wrapping up");
            await act.Should().ThrowAsync<GateNotSatisfiedException>();
        }

        // A final determination satisfies the gate and the case closes.
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            await svc.RecordMaterialityAsync(id, MaterialityStatus.NotMaterial,
                "General Counsel", _clock.UtcNow, "No sensitive data left our estate.");
            await svc.ChangePhaseAsync(id, CasePhase.Closed, "wrapping up");
        }

        await using (var verify = NewContext())
            (await verify.Cases.FirstAsync(c => c.Id == id)).Phase.Should().Be(CasePhase.Closed);
    }

    private sealed class NoOpCaseNotifications : ICaseNotifications
    {
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
    }

    public void Dispose() => _connection.Dispose();
}
