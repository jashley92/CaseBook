using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// v1.11.0: a navigation's <c>TargetLocation</c> is as the navigation gave it, and Administration search and the command
/// palette navigate to relative addresses ("admin/settings/…"). The settings page's leave check passed it straight to
/// <c>ToBaseRelativePath</c>, which throws for a relative address, so opening a search result from a settings page took the
/// circuit down. A target is made absolute (<c>ToAbsoluteUri</c>) before it's made base-relative.
/// </summary>
public class NavigationTargetGuardTests
{
    private static readonly Regex Raw = new(@"ToBaseRelativePath\(\s*\w+\.TargetLocation\s*\)", RegexOptions.None, TimeSpan.FromSeconds(1));

    [Fact]
    public void A_navigation_target_is_made_absolute_before_it_is_made_base_relative()
    {
        var root = ComponentSourceScanner.RepoRoot();
        Directory.EnumerateFiles(Path.Combine(root, "src"), "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
            .Select(f => (Path: Path.GetRelativePath(root, f).Replace('\\', '/'), File: f))
            .Where(s => !s.Path.Contains("/bin/", StringComparison.Ordinal) && !s.Path.Contains("/obj/", StringComparison.Ordinal))
            .SelectMany(s => File.ReadAllLines(s.File).Select((line, i) => (s.Path, Line: i + 1, Text: line)))
            .Where(l => Raw.IsMatch(l.Text))
            .Select(l => $"{l.Path}:{l.Line}")
            .Should().BeEmpty("ToBaseRelativePath throws for a relative target; pass Nav.ToAbsoluteUri(target).ToString()");
    }
}
