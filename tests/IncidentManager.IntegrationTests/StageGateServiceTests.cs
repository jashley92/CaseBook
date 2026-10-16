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

        var act = () => svc.CreateAsync(BreachGate(active: true) with { Name = "Second breach gate" });

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*already governs*");
    }

    [Fact]
    public async Task Two_gates_cant_share_a_name(/* BUG-265 */)
    {
        var svc = NewService();
        var first = await svc.CreateAsync(BreachGate(active: true));

        var same = () => svc.CreateAsync(BreachGate(active: false) with { Name = BreachGate(active: false).Name.ToUpperInvariant() });

        await same.Should().ThrowAsync<InvalidOperationException>().WithMessage("*already called*");
        (await svc.ListAllAsync()).Should().ContainSingle(g => g.Id == first);
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
    public async Task A_gate_someone_changed_since_the_editor_opened_is_not_written_back(/* REV-27 */)
    {
        var svc = NewService();
        var id = await svc.CreateAsync(BreachGate());
        var stamp = (await svc.GetAsync(id))!.Stamp;
        var tighter = new StageGateInput(StageGateTrigger.EscalateToBreach, "Breach readiness", "tighter", true,
            new[] { new GateRequirementInput(GateRequirementKind.MachineCheck, GateCheckKeys.AtLeastOneReport, null, "", true) });
        await svc.UpdateAsync(id, tighter, stamp);

        var stale = () => svc.UpdateAsync(id, BreachGate(), stamp);

        await stale.Should().ThrowAsync<InvalidOperationException>().WithMessage("*since you opened it*");
        (await svc.GetAsync(id))!.Description.Should().Be("tighter");
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

    [Fact]
    public async Task Two_gates_saved_at_once_leave_one_active_and_one_per_name(/* BUG-538 */)
    {
        var svc = NewService();
        var other = await svc.CreateAsync(BreachGate(active: false) with { Name = "Other" });

        // Two creates of an active gate for one transition, and a rename onto the same name, while another writer holds
        // GuardGate: each check runs with its save, after the one before, so only the first passes.
        Task a, b, rename;
        using (await GuardGate.EnterAsync())
        {
            a = Task.Run(() => svc.CreateAsync(BreachGate()));
            b = Task.Run(() => svc.CreateAsync(BreachGate() with { Name = "Breach readiness v2" }));
            rename = Task.Run(() => svc.UpdateAsync(other, BreachGate(active: false) with { Name = "breach READINESS" }));
            await Task.Delay(200);
            a.IsCompleted.Should().BeFalse("the checks and the save wait for GuardGate");
            b.IsCompleted.Should().BeFalse();
            rename.IsCompleted.Should().BeFalse();
        }
        var failures = new List<Exception>();
        foreach (var t in new[] { a, b, rename })
            try { await t; }
            catch (InvalidOperationException ex) { failures.Add(ex); }
        failures.Should().NotBeEmpty().And.HaveCountLessThan(3);
        await NoSaveSlippedPastAnotherAsync(svc);

        // C17: the three queue in no fixed order, so each order is run in turn: the first always lands, and which of the
        // others are refused follows (b first refuses a, and the rename then has no name to clash with).
        await RaceOrders.ForEveryOrderAsync(3, async _ =>
        {
            foreach (var g in await svc.ListAllAsync()) await svc.DeleteAsync(g.Id);
            var renamed = await svc.CreateAsync(BreachGate(active: false) with { Name = "Other" });
            return [() => svc.CreateAsync(BreachGate()),
                    () => svc.CreateAsync(BreachGate() with { Name = "Breach readiness v2" }),
                    () => svc.UpdateAsync(renamed, BreachGate(active: false) with { Name = "breach READINESS" })];
        }, async run =>
        {
            run.Outcomes[run.First].Should().BeNull($"the first to get the gate passes its checks ({run})");
            run.Outcomes.Should().OnlyContain(e => e == null || e is InvalidOperationException, run.ToString());
            var aLandedFirst = run.Outcomes[0] == null && run.Order.ToList().IndexOf(0) < run.Order.ToList().IndexOf(1);
            (run.Outcomes[1] != null).Should().Be(aLandedFirst, $"b is refused exactly when a landed before it ({run})");
            await NoSaveSlippedPastAnotherAsync(svc);
        });
    }

    private static async Task NoSaveSlippedPastAnotherAsync(StageGateService svc)
    {
        var gates = await svc.ListAllAsync();
        gates.Count(g => g.IsActive && g.Trigger == StageGateTrigger.EscalateToBreach).Should().Be(1);
        gates.GroupBy(g => g.Name, StringComparer.OrdinalIgnoreCase).Should().OnlyContain(g => g.Count() == 1);
    }

    [Fact]
    public async Task An_edit_that_waited_behind_another_save_sees_it_and_refuses(/* BUG-538 */)
    {
        var svc = NewService();
        var id = await svc.CreateAsync(BreachGate());
        var opened = (await svc.GetAsync(id))!;

        // The stamp is read under the gate too, so a change saved while the edit waited is seen, not overwritten.
        Task edit;
        using (await GuardGate.EnterAsync())
        {
            edit = Task.Run(() => svc.UpdateAsync(id, BreachGate() with { Description = "mine" }, opened.Stamp));
            await Task.Delay(200);
            edit.IsCompleted.Should().BeFalse();
            await using var db = NewContext();
            (await db.StageGates.SingleAsync(g => g.Id == id)).Description = "theirs";
            await db.SaveChangesAsync();
        }

        await edit.Invoking(x => x).Should().ThrowAsync<InvalidOperationException>().WithMessage("*since you opened it*");
        (await svc.GetAsync(id))!.Description.Should().Be("theirs");
    }

    public void Dispose() => _connection.Dispose();
}
