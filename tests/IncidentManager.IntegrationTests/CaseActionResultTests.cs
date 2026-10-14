using FluentAssertions;
using IncidentManager.Web.Components.Pages.Workspace;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-337: an action's result names the case it was for, so a save that finishes after a case switch doesn't
/// run its follow-up on the case now open.</summary>
public sealed class CaseActionResultTests
{
    private static readonly Guid A = Guid.NewGuid();
    private static readonly Guid B = Guid.NewGuid();

    [Fact]
    public void A_result_is_for_the_case_it_was_applied_to_and_not_the_one_opened_since()
    {
        var applied = new CaseActionApplied(A, "IR-2026-0001", "Superseded by IR-2026-0002. Close this case to finish.", "Duplicate of IR-2026-0002: same alert");

        applied.IsFor(A).Should().BeTrue();
        applied.IsFor(B).Should().BeFalse("the workspace has moved to B, so B isn't reloaded or sent to its close-out");
        new CaseActionFor(A, "IR-2026-0001").IsFor(B).Should().BeFalse("a refusal on A doesn't demote B");
    }

    [Fact]
    public void Elsewhere_it_only_says_what_was_done_and_on_which_case()
    {
        new CaseActionApplied(A, "IR-2026-0001", "Severity changed to High", null).ElsewhereMessage
            .Should().Be("IR-2026-0001: Severity changed to High.");
        new CaseActionApplied(A, "IR-2026-0001", "Superseded by IR-2026-0002. Close this case to finish.", "x").ElsewhereMessage
            .Should().Be("IR-2026-0001: Superseded by IR-2026-0002. Close this case to finish.");
        new CaseActionApplied(A, "IR-2026-0001", "", null).ElsewhereMessage.Should().Be("Saved on IR-2026-0001.");
    }
}
