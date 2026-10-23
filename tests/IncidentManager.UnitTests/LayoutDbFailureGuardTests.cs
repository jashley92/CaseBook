using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-702: the components hosted by the layout outside its ErrorBoundary (the top bar, the bell, the palette, the case
/// beside, the tab strip's state) read the database; an exception there ends the circuit. A failed read is a DbException
/// (or a timeout), not EF's DbUpdateException (which wraps SaveChanges only), so each must catch that.
/// </summary>
public sealed partial class LayoutDbFailureGuardTests
{
    private static readonly string[] LayoutHosted =
    [
        "src/IncidentManager.Web/Components/Layout/MainLayout.razor",
        "src/IncidentManager.Web/Components/Shared/NotificationBell.razor",
        "src/IncidentManager.Web/Components/Shared/CommandPalette.razor",
        "src/IncidentManager.Web/Components/Shared/CaseBeside.razor",
        "src/IncidentManager.Web/Components/Shared/ImportQueueBadge.razor",
        "src/IncidentManager.Web/Services/CaseTabsState.cs",
    ];

    public static TheoryData<string> Files() => new(LayoutHosted);

    [Theory, MemberData(nameof(Files))]
    public void A_layout_hosted_database_reader_catches_a_failed_read(string file)
    {
        var code = ComponentSourceScanner.StripComments(File.ReadAllText(Path.Combine(ComponentSourceScanner.RepoRoot(), file)));
        code.Should().Contain("DbException", "a failed read outside the ErrorBoundary would end the session");
        foreach (Match m in DbUpdateFilter().Matches(code))
            m.Value.Should().Contain("DbException", $"a filter in {file} names DbUpdateException, which a failed read never throws");
    }

    // A catch filter (up to its closing parenthesis, across a line break) that names DbUpdateException.
    [GeneratedRegex(@"catch \(Exception ex\) when \([^)]*DbUpdateException[^)]*\)")]
    private static partial Regex DbUpdateFilter();
}
