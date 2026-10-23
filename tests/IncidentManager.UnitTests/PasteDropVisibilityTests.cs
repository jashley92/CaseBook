using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-701: the paste helper decides which drop zone is showing. offsetParent is null for a position:fixed element, and
/// the timeline's popped-out composer is fixed, so a screenshot pasted into it was dropped. Visibility is read from the
/// zone's boxes instead. (No JS test runner, so this checks the source.)
/// </summary>
public sealed class PasteDropVisibilityTests
{
    [Fact]
    public void The_paste_helper_doesnt_read_visibility_from_offsetParent()
    {
        var js = File.ReadAllText(Path.Combine(ComponentSourceScanner.RepoRoot(), "src", "IncidentManager.Web", "wwwroot", "js", "paste-drop.js"));
        var code = string.Join('\n', js.Split('\n').Where(l => !l.TrimStart().StartsWith("//", StringComparison.Ordinal)));
        code.Should().NotContain("offsetParent", "a fixed (popped-out) zone has no offsetParent but is showing");
        code.Should().Contain("getClientRects()");
    }
}
