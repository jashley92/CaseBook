using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
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

public sealed class StageGateEnforcementTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 16, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    // Ids of the seeded Breach-gate requirements so the test can attest by id.
    private Guid _attestReqId;

    public StageGateEnforcementTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin]; // sees all + may edit/reclassify (F-21: reclassify asserts ChangeClassification)
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
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(), new TestSlaTargets());


    /// <summary>Seeds a Breach gate: two blocking machine checks plus one blocking attestation.</summary>
    private async Task SeedBreachGateAsync(AppDbContext db)
    {
        var gate = new StageGate
        {
            Trigger = StageGateTrigger.EscalateToBreach, Name = "Breach readiness", IsActive = true,
            CreatedBy = "system", CreatedAtUtc = _clock.UtcNow
        };
        gate.Requirements.Add(new StageGateRequirement
        {
            GateId = gate.Id, Order = 0, Kind = GateRequirementKind.MachineCheck,
            CheckKey = GateCheckKeys.SummaryPresent, Label = "Summary recorded", IsBlocking = true
        });
        gate.Requirements.Add(new StageGateRequirement
        {
            GateId = gate.Id, Order = 1, Kind = GateRequirementKind.MachineCheck,
            CheckKey = GateCheckKeys.AffectedIndividualsCountSet, Label = "Affected count recorded", IsBlocking = true
        });
        var attest = new StageGateRequirement
        {
            GateId = gate.Id, Order = 2, Kind = GateRequirementKind.Attestation,
            CheckKey = null, Label = "Impact reviewed with leadership", IsBlocking = true
        };
        gate.Requirements.Add(attest);
        _attestReqId = attest.Id;

        db.StageGates.Add(gate);
        await db.SaveChangesAsync();
    }

    private async Task<Guid> NewIncidentAsync(CaseService svc, string? summary)
    {
        var created = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Vendor Event",
            Title = "Vendor security event",
            Classification = Classification.Incident,
            Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection,
            Summary = summary
        });
        return created.Id;
    }

    [Fact]
    public async Task Escalating_to_Breach_with_unmet_requirements_and_no_override_is_blocked()
    {
        Guid id;
        await using (var db = NewContext())
        {
            await SeedBreachGateAsync(db);
            var svc = NewService(db);
            id = await NewIncidentAsync(svc, summary: "Confirmed vendor compromise.");
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            // Summary is set, but affected count and the attestation are not.
            var act = () => svc.ReclassifyAsync(id, Classification.Breach, "NPI confirmed");
            await act.Should().ThrowAsync<GateNotSatisfiedException>();
        }

        await using (var verify = NewContext())
        {
            var loaded = await verify.Cases.FirstAsync(c => c.Id == id);
            loaded.Classification.Should().Be(Classification.Incident, "the blocked escalation must not have taken effect");
        }
    }

    [Fact]
    public async Task Escalating_to_Breach_with_an_override_justification_succeeds_and_records_the_override()
    {
        Guid id;
        await using (var db = NewContext())
        {
            await SeedBreachGateAsync(db);
            var svc = NewService(db);
            id = await NewIncidentAsync(svc, summary: "Confirmed vendor compromise.");
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            await svc.ReclassifyAsync(id, Classification.Breach, "NPI confirmed",
                attestedRequirementIds: null, overrideJustification: "Board notified; assessment finalized offline.");
        }

        await using (var verify = NewContext())
        {
            var loaded = await verify.Cases.FirstAsync(c => c.Id == id);
            loaded.Classification.Should().Be(Classification.Breach);

            var passage = await verify.GatePassages.SingleAsync(p => p.CaseId == id);
            passage.Trigger.Should().Be(StageGateTrigger.EscalateToBreach);
            passage.WasOverridden.Should().BeTrue();
            passage.OverrideJustification.Should().Contain("Board notified");

            var chain = _hasher.VerifyChain(await verify.AuditLog.OrderBy(a => a.Sequence).ToListAsync());
            chain.IsValid.Should().BeTrue("recording a gate passage must keep the audit chain intact");
        }
    }

    [Fact]
    public async Task Escalating_to_Breach_when_every_requirement_is_met_passes_without_override()
    {
        Guid id;
        await using (var db = NewContext())
        {
            await SeedBreachGateAsync(db);
            var svc = NewService(db);
            id = await NewIncidentAsync(svc, summary: "Confirmed vendor compromise.");
            // Satisfy the second machine check.
            await svc.UpdateImpactAssessmentAsync(id, 1200, new[] { "Name" }, "NY");
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            // Tick the attestation by id; no override needed.
            await svc.ReclassifyAsync(id, Classification.Breach, "NPI confirmed",
                attestedRequirementIds: new HashSet<Guid> { _attestReqId });
        }

        await using (var verify = NewContext())
        {
            var loaded = await verify.Cases.FirstAsync(c => c.Id == id);
            loaded.Classification.Should().Be(Classification.Breach);

            var passage = await verify.GatePassages.SingleAsync(p => p.CaseId == id);
            passage.WasOverridden.Should().BeFalse("all blocking requirements were satisfied");
        }
    }

    [Fact]
    public async Task A_gate_min_length_applies_to_the_reason_and_records_it_on_the_passage()
    {
        Guid id;
        await using (var db = NewContext())
        {
            var gate = new StageGate
            {
                Trigger = StageGateTrigger.EscalateToBreach, Name = "Breach readiness", IsActive = true,
                CommentaryMinLength = 20, CreatedBy = "system", CreatedAtUtc = _clock.UtcNow
            };
            gate.Requirements.Add(new StageGateRequirement
            {
                GateId = gate.Id, Order = 0, Kind = GateRequirementKind.MachineCheck,
                CheckKey = GateCheckKeys.SummaryPresent, Label = "Summary recorded", IsBlocking = true
            });
            db.StageGates.Add(gate);
            await db.SaveChangesAsync();
            var svc = NewService(db);
            id = await NewIncidentAsync(svc, summary: "Confirmed vendor compromise.");
        }

        // Every check is met, but the reason is shorter than the gate's minimum → blocked.
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var act = () => svc.ReclassifyAsync(id, Classification.Breach, "NPI confirmed"); // 12 chars
            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*reason of at least 20*");
            (await db.Cases.FirstAsync(c => c.Id == id)).Classification.Should().Be(Classification.Incident);
        }

        // A sufficient reason passes and is recorded (trimmed) on the passage.
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            await svc.ReclassifyAsync(id, Classification.Breach,
                "  Confirmed NPI exposure for NY residents; escalating per IRP.  ");
        }

        await using (var verify = NewContext())
        {
            (await verify.Cases.FirstAsync(c => c.Id == id)).Classification.Should().Be(Classification.Breach);
            var passage = await verify.GatePassages.AsNoTracking().SingleAsync(p => p.CaseId == id);
            passage.Commentary.Should().Be("Confirmed NPI exposure for NY residents; escalating per IRP.");
        }
    }

    [Fact]
    public async Task When_overriding_the_min_length_also_applies_to_the_override_justification()
    {
        Guid id;
        await using (var db = NewContext())
        {
            var gate = new StageGate
            {
                Trigger = StageGateTrigger.EscalateToBreach, Name = "Breach readiness", IsActive = true,
                CommentaryMinLength = 20, CreatedBy = "system", CreatedAtUtc = _clock.UtcNow
            };
            // A blocking check that will NOT be met, forcing an override.
            gate.Requirements.Add(new StageGateRequirement
            {
                GateId = gate.Id, Order = 0, Kind = GateRequirementKind.MachineCheck,
                CheckKey = GateCheckKeys.AtLeastOneEntity, Label = "An entity is recorded", IsBlocking = true
            });
            db.StageGates.Add(gate);
            await db.SaveChangesAsync();
            var svc = NewService(db);
            id = await NewIncidentAsync(svc, summary: "Confirmed vendor compromise.");
        }

        var longReason = "Confirmed NPI exposure; escalating despite the open entity gap.";

        // The reason is long enough, but the override justification is too short → blocked.
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var act = () => svc.ReclassifyAsync(id, Classification.Breach, longReason,
                attestedRequirementIds: null, overrideJustification: "forced");
            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*override justification*at least 20*");
            (await db.Cases.FirstAsync(c => c.Id == id)).Classification.Should().Be(Classification.Incident);
        }

        // Both long enough → the override succeeds and is recorded.
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            await svc.ReclassifyAsync(id, Classification.Breach, longReason,
                attestedRequirementIds: null,
                overrideJustification: "IOC capture deferred to the vendor's forensics report.");
        }

        await using (var verify = NewContext())
        {
            var passage = await verify.GatePassages.AsNoTracking().SingleAsync(p => p.CaseId == id);
            passage.WasOverridden.Should().BeTrue();
            passage.Commentary.Should().Be(longReason);
        }
    }

    /// <summary>An Incident gate whose only (blocking) check is at least one entity on the case.</summary>
    private static async Task SeedIncidentGateAsync(AppDbContext db, DateTimeOffset now)
    {
        var gate = new StageGate
        {
            Trigger = StageGateTrigger.EscalateToIncident, Name = "Incident readiness", IsActive = true,
            CreatedBy = "system", CreatedAtUtc = now
        };
        gate.Requirements.Add(new StageGateRequirement
        {
            GateId = gate.Id, Order = 0, Kind = GateRequirementKind.MachineCheck,
            CheckKey = GateCheckKeys.AtLeastOneEntity, Label = "At least one entity", IsBlocking = true
        });
        db.StageGates.Add(gate);
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Jumping_rungs_passes_the_gate_of_each_rung_climbed()
    {
        // BUG-60: Adverse Event straight to Breach used to run only the Breach gate.
        Guid id;
        await using (var db = NewContext())
        {
            await SeedBreachGateAsync(db);
            await SeedIncidentGateAsync(db, _clock.UtcNow);
            id = (await NewService(db).CreateAsync(new CreateCaseRequest
            {
                DescriptiveName = "Jump", Title = "Jump", Classification = Classification.AdverseEvent,
                Severity = Severity.High, Origin = CaseOrigin.InternalDetection, Summary = "Seen."
            })).Id;
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var blocked = () => svc.ReclassifyAsync(id, Classification.Breach, "NPI confirmed", new HashSet<Guid> { _attestReqId });
            (await blocked.Should().ThrowAsync<GateNotSatisfiedException>()).Which.Trigger.Should().Be(StageGateTrigger.EscalateToIncident);

            var combined = await svc.EvaluateClimbAsync(id, Classification.Breach);
            combined.GateName.Should().Be("Incident readiness + Breach readiness");
            combined.Requirements.Should().Contain(r => r.CheckKey == GateCheckKeys.AtLeastOneEntity);

            await svc.ReclassifyAsync(id, Classification.Breach, "NPI confirmed", new HashSet<Guid> { _attestReqId },
                overrideJustification: "Vendor letter received before any indicators");
        }

        await using var verify = NewContext();
        (await verify.GatePassages.Where(p => p.CaseId == id).Select(p => p.Trigger).ToListAsync())
            .Should().BeEquivalentTo([StageGateTrigger.EscalateToIncident, StageGateTrigger.EscalateToBreach]);
    }

    [Fact]
    public async Task A_new_cases_gates_see_the_verdicts_its_indicators_are_filed_with(/* WF-16 */)
    {
        await using var db = NewContext();
        var gate = new StageGate { Trigger = StageGateTrigger.EscalateToIncident, IsActive = true, Name = "Malicious IOC", CreatedBy = "admin", CreatedAtUtc = _clock.UtcNow };
        gate.Requirements.Add(new StageGateRequirement { GateId = gate.Id, Order = 0, Kind = GateRequirementKind.MachineCheck,
            CheckKey = GateCheckKeys.AtLeastOneMaliciousEntity, CheckParam = 1, Label = "A confirmed malicious IOC", IsBlocking = true });
        db.StageGates.Add(gate);
        await db.SaveChangesAsync();
        var svc = new CaseService(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(), new TestSlaTargets());
        var req = new CreateCaseRequest
        {
            DescriptiveName = "Imported", Title = "Imported", Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, Summary = "From XSIAM.", PlannedEntityCount = 2,
            PlannedDispositions = [EntityDisposition.Unknown, EntityDisposition.Unknown],
        };

        (await svc.EvaluateNewCaseGatesAsync(req))!.IsSatisfiedBy(new HashSet<Guid>()).Should().BeFalse();
        req.PlannedDispositions = [EntityDisposition.Malicious, EntityDisposition.Unknown];
        (await svc.EvaluateNewCaseGatesAsync(req))!.IsSatisfiedBy(new HashSet<Guid>()).Should().BeTrue("the import says one is malicious");
    }

    [Fact]
    public async Task A_case_filed_straight_onto_a_rung_passes_its_gates()
    {
        // BUG-61: creating a case at Incident or Breach ran no gate and recorded no passage.
        var siem = new CapturingSecurityEventSink();
        await using var db = NewContext();
        await SeedIncidentGateAsync(db, _clock.UtcNow);
        await SeedBreachGateAsync(db);
        var svc = new CaseService(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(), new TestSlaTargets(), siem: siem);
        CreateCaseRequest Req(Classification c) => new()
        {
            DescriptiveName = $"Filed {c}", Title = $"Filed {c}", Classification = c, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, Summary = "Reported by the vendor."
        };

        var noIndicators = () => svc.CreateAsync(Req(Classification.Incident));
        await noIndicators.Should().ThrowAsync<GateNotSatisfiedException>();
        var withIndicators = Req(Classification.Incident);
        withIndicators.PlannedEntityCount = 1;
        (await svc.EvaluateNewCaseGatesAsync(withIndicators))!.IsSatisfiedBy(new HashSet<Guid>())
            .Should().BeTrue("the indicators filed with it count");

        var incident = await svc.CreateAsync(withIndicators);
        (await db.GatePassages.AsNoTracking().SingleAsync(p => p.CaseId == incident.Id)).WasOverridden.Should().BeFalse();

        var breachReq = Req(Classification.Breach);
        breachReq.PlannedEntityCount = 1;
        breachReq.AttestedRequirementIds = new HashSet<Guid> { _attestReqId };
        breachReq.OverrideJustification = "Filed as a Breach on the vendor's notice; counts to follow";
        var breach = await svc.CreateAsync(breachReq);
        var passages = await db.GatePassages.AsNoTracking().Where(p => p.CaseId == breach.Id).ToListAsync();
        passages.Select(p => p.Trigger).Should().BeEquivalentTo([StageGateTrigger.EscalateToIncident, StageGateTrigger.EscalateToBreach]);
        passages.Single(p => p.Trigger == StageGateTrigger.EscalateToBreach).WasOverridden.Should().BeTrue("the affected count isn't set yet");
        siem.Events.Should().Contain(e => e.Action == "BreachEscalated");

        // BUG-100: an exercise filed as a Breach is marked EXERCISE in the SIEM, or sends nothing when the org skips them.
        var policy = new FakeExercisePolicy();
        var exerciseSvc = new CaseService(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(), new TestSlaTargets(), siem: siem, exercise: policy);
        breachReq.IsExercise = true;
        breachReq.DescriptiveName = "Tabletop";
        var before = siem.Events.Count;
        await exerciseSvc.CreateAsync(breachReq);
        siem.Events.Skip(before).Should().ContainSingle(e => e.Action == "BreachEscalated")
            .Which.Detail.Should().StartWith("EXERCISE");
        policy.Mode = IncidentManager.Application.Abstractions.ExerciseEscalation.Skip;
        breachReq.DescriptiveName = "Tabletop two";
        before = siem.Events.Count;
        await exerciseSvc.CreateAsync(breachReq);
        siem.Events.Skip(before).Should().NotContain(e => e.Action == "BreachEscalated");
    }

    private sealed class FakeExercisePolicy : IncidentManager.Application.Abstractions.IExerciseEscalationPolicy
    {
        public IncidentManager.Application.Abstractions.ExerciseEscalation Mode { get; set; }
    }

    public void Dispose() => _connection.Dispose();
}
