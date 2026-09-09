using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>Stage-gate authoring (C-08): admin CRUD over gates + requirements, one-active-per-transition.</summary>
public sealed class StageGateServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 16, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public StageGateServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin];
        using var db = NewContext(); // create schema
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

    private StageGateService NewService() => new(NewFactory(), _user, _clock);

    private static StageGateInput BreachGate(bool active = true) => new(
        StageGateTrigger.EscalateToBreach, "Breach readiness", "desc", active,
        new[]
        {
            new GateRequirementInput(GateRequirementKind.MachineCheck, GateCheckKeys.SummaryPresent, null, "", true),
            new GateRequirementInput(GateRequirementKind.MachineCheck, GateCheckKeys.AffectedIndividualsCountSet, null, "", true),
            new GateRequirementInput(GateRequirementKind.Attestation, null, null, "Reviewed with leadership", true),
            // A blank machine check (no Check) and a blank attestation should be dropped.
            new GateRequirementInput(GateRequirementKind.MachineCheck, null, null, "", true),
            new GateRequirementInput(GateRequirementKind.Attestation, null, null, "   ", true),
        });

    [Fact]
    public async Task Create_persists_the_gate_and_drops_blank_requirement_rows()
    {
        var svc = NewService();
        var id = await svc.CreateAsync(BreachGate());

        var view = await svc.GetAsync(id);
        view.Should().NotBeNull();
        view!.Trigger.Should().Be(StageGateTrigger.EscalateToBreach);
        view.Requirements.Should().HaveCount(3, "the two blank rows are dropped");
        // A machine check with no explicit label inherits the check's default label.
        view.Requirements[0].Label.Should().Be("Case summary recorded");
        view.Requirements[2].Kind.Should().Be(GateRequirementKind.Attestation);
    }

    [Fact]
    public async Task A_custom_machine_check_wording_is_preserved(/* X-02 slice 3b: gate-check descriptions */)
    {
        var svc = NewService();
        var id = await svc.CreateAsync(new StageGateInput(
            StageGateTrigger.EscalateToBreach, "Breach readiness", "desc", true,
            new[]
            {
                new GateRequirementInput(GateRequirementKind.MachineCheck, GateCheckKeys.SummaryPresent, null, "Case summary documented per IRP §4.2", true),
            }));

        var view = await svc.GetAsync(id);
        // The reworded description sticks; the underlying check is unchanged.
        view!.Requirements[0].Label.Should().Be("Case summary documented per IRP §4.2");
        view.Requirements[0].CheckKey.Should().Be(GateCheckKeys.SummaryPresent);
    }

    [Fact]
    public async Task A_second_active_gate_for_the_same_transition_is_rejected()
    {
        var svc = NewService();
        await svc.CreateAsync(BreachGate(active: true));

        var act = () => svc.CreateAsync(BreachGate(active: true));

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*already governs*");
    }

    [Fact]
    public async Task An_inactive_second_gate_for_the_same_transition_is_allowed()
    {
        var svc = NewService();
        await svc.CreateAsync(BreachGate(active: true));

        var act = () => svc.CreateAsync(BreachGate(active: false) with { Name = "Old breach gate" });

        await act.Should().NotThrowAsync();
        (await svc.ListAllAsync()).Should().HaveCount(2);
    }

    [Fact]
    public async Task Update_replaces_the_requirement_set_wholesale()
    {
        var svc = NewService();
        var id = await svc.CreateAsync(BreachGate());

        await svc.UpdateAsync(id, new StageGateInput(
            StageGateTrigger.EscalateToBreach, "Breach readiness", "tighter", true,
            new[] { new GateRequirementInput(GateRequirementKind.MachineCheck, GateCheckKeys.AtLeastOneReport, null, "", false) }));

        var view = await svc.GetAsync(id);
        view!.Description.Should().Be("tighter");
        view.Requirements.Should().ContainSingle();
        view.Requirements[0].CheckKey.Should().Be(GateCheckKeys.AtLeastOneReport);
        view.Requirements[0].IsBlocking.Should().BeFalse();
    }

    [Fact]
    public async Task A_parameterized_check_persists_its_threshold_and_defaults_the_label(/* X-06(b) stage 2 */)
    {
        var svc = NewService();
        var id = await svc.CreateAsync(new StageGateInput(
            StageGateTrigger.EscalateToBreach, "Breach readiness", "desc", true,
            new[]
            {
                new GateRequirementInput(GateRequirementKind.MachineCheck, GateCheckKeys.AtLeastOneEntity, 3, "", true),
            }));

        var view = await svc.GetAsync(id);
        view!.Requirements[0].CheckKey.Should().Be(GateCheckKeys.AtLeastOneEntity);
        view.Requirements[0].CheckParam.Should().Be(3);
        view.Requirements[0].Label.Should().Be("At least 3 entities / IOCs added", "the default label reflects the threshold");
    }

    [Fact]
    public async Task A_below_floor_threshold_is_clamped_to_the_minimum()
    {
        var svc = NewService();
        var id = await svc.CreateAsync(new StageGateInput(
            StageGateTrigger.EscalateToBreach, "Breach readiness", "desc", true,
            new[]
            {
                // 0 is below the family's floor of 1 — the service clamps it.
                new GateRequirementInput(GateRequirementKind.MachineCheck, GateCheckKeys.AtLeastOneEvidence, 0, "", true),
            }));

        (await svc.GetAsync(id))!.Requirements[0].CheckParam.Should().Be(1);
    }

    [Fact]
    public async Task A_commentary_minimum_length_persists_and_clamps_negative_to_zero()
    {
        var svc = NewService();
        var id = await svc.CreateAsync(new StageGateInput(
            StageGateTrigger.EscalateToBreach, "Breach readiness", "desc", true,
            new[] { new GateRequirementInput(GateRequirementKind.MachineCheck, GateCheckKeys.SummaryPresent, null, "", true) },
            CommentaryMinLength: 40));
        (await svc.GetAsync(id))!.CommentaryMinLength.Should().Be(40);

        await svc.UpdateAsync(id, new StageGateInput(
            StageGateTrigger.EscalateToBreach, "Breach readiness", "desc", true,
            new[] { new GateRequirementInput(GateRequirementKind.MachineCheck, GateCheckKeys.SummaryPresent, null, "", true) },
            CommentaryMinLength: -5));
        (await svc.GetAsync(id))!.CommentaryMinLength.Should().Be(0, "a negative minimum is clamped");
    }

    public void Dispose() => _connection.Dispose();
}
