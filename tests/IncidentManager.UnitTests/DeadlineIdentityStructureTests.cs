using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C19: a regulatory deadline has one identity. BUG-619: every sent mark for a deadline is named by DeadlineIdentity
/// (case, jurisdiction, band, due), so no writer can drop the jurisdiction again.
/// </summary>
public class DeadlineIdentityStructureTests
{
    private static readonly Regex DeadlineKeyLiteral = new(@"\$?@?""deadline\|", RegexOptions.None, TimeSpan.FromSeconds(1));

    private const string Helper = "src/IncidentManager.Application/Notifications/DeadlineIdentity.cs";

    private static IEnumerable<(string Path, string Code)> Sources() =>
        Directory.EnumerateFiles(Path.Combine(ComponentSourceScanner.RepoRoot(), "src"), "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
            .Select(f => (Path: Path.GetRelativePath(ComponentSourceScanner.RepoRoot(), f).Replace('\\', '/'), File: f))
            .Where(s => !s.Path.Contains("/Migrations/", StringComparison.Ordinal)
                        && !s.Path.Contains("/bin/", StringComparison.Ordinal) && !s.Path.Contains("/obj/", StringComparison.Ordinal))
            .Select(s => (s.Path, ComponentSourceScanner.StripComments(File.ReadAllText(s.File))));

    [Fact]
    public void Only_DeadlineIdentity_spells_a_deadline_mark(/* BUG-619 */)
    {
        Sources().Where(s => s.Path != Helper && DeadlineKeyLiteral.IsMatch(s.Code)).Select(s => s.Path)
            .Should().BeEmpty("a deadline's mark names its jurisdiction: build it with DeadlineIdentity.Key");
        Sources().Should().Contain(s => s.Path == Helper && DeadlineKeyLiteral.IsMatch(s.Code), "the scan finds the helper's own key");
    }
}
