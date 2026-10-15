using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Components.Pages.CaseTabs;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-507: the Briefing's attack chain walks each step's tactics in ATT&amp;CK matrix order.</summary>
public class BriefingChainTests
{
    private static readonly DateTimeOffset T0 = new(2026, 5, 1, 9, 0, 0, TimeSpan.Zero);

    private static TimelineEntry Step(int minutes, params MitreTactic[] tactics)
    {
        var e = new TimelineEntry { Kind = TimelineKind.Event, OccurredAtUtc = T0.AddMinutes(minutes), Description = "step" };
        foreach (var t in tactics) e.Tactics.Add(new EventStepTactic { TimelineEntryId = e.Id, Tactic = t });
        return e;
    }

    [Fact]
    public void A_steps_tactics_are_in_matrix_order_whatever_order_they_were_stored_in()
    {
        // Stored Stealth (rank 7) first, Persistence (rank 5) second.
        var chain = Chain(Step(0, MitreTactic.Stealth, MitreTactic.Persistence));

        chain.Should().Equal(MitreTactic.Persistence, MitreTactic.Stealth);
    }

    [Fact]
    public void Repeats_collapse_the_same_way_whatever_the_stored_order()
    {
        // Step 1 ends on Execution in matrix order; step 2 starts with it, so it isn't repeated.
        var a = Chain(Step(0, MitreTactic.Execution, MitreTactic.InitialAccess), Step(5, MitreTactic.Persistence, MitreTactic.Execution));
        var b = Chain(Step(0, MitreTactic.InitialAccess, MitreTactic.Execution), Step(5, MitreTactic.Execution, MitreTactic.Persistence));

        a.Should().Equal(MitreTactic.InitialAccess, MitreTactic.Execution, MitreTactic.Persistence);
        b.Should().Equal(a);
    }

    [Fact]
    public void Unspecified_and_retired_versions_are_left_out()
    {
        var old = Step(0, MitreTactic.Impact);
        old.IsCurrent = false;
        Chain(old, Step(1, MitreTactic.Unspecified, MitreTactic.Discovery))
            .Should().Equal(MitreTactic.Discovery);
    }

    private static List<MitreTactic> Chain(params TimelineEntry[] steps) => CaseBriefing.ChainOf(steps);
}
