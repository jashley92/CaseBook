using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C19: a regulatory deadline has one identity and one in-play rule. BUG-619: every sent mark for a deadline is named by
/// DeadlineIdentity (case, jurisdiction, band, due), so no writer can drop the jurisdiction again. BUG-625: what a case
/// has in play is decided only through NotificationDeadlineService (Case.KeptInPlay); a data element's jurisdictions are
/// read elsewhere only to edit, move or show the mapping itself.
/// </summary>
public class DeadlineIdentityStructureTests
{
    private static readonly Regex DeadlineKeyLiteral = new(@"\$?@?""deadline\|", RegexOptions.None, TimeSpan.FromSeconds(1));
    private static readonly Regex JurisdictionsRead = new(@"\bNotificationJurisdictions\b", RegexOptions.None, TimeSpan.FromSeconds(1));

    private const string Helper = "src/IncidentManager.Application/Notifications/DeadlineIdentity.cs";

    // Reviewed: each reads the element mapping for what it is, not to decide what a case has in play.
    private static readonly HashSet<string> MappingReaders = new(StringComparer.Ordinal)
    {
        "src/IncidentManager.Application/Compliance/NotificationDeadlineService.cs",   // the in-play rule itself
        "src/IncidentManager.Application/Admin/DataElementService.cs",                 // edits the mapping
        "src/IncidentManager.Application/Config/ConfigBundle.cs",                      // exports and imports it
        "src/IncidentManager.Application/Config/ConfigBundleService.cs",
        "src/IncidentManager.Application/Config/ConfigBundleService.Import.cs",
        "src/IncidentManager.Application/Reporting/ReportService.cs",                  // groups by it, filtered through KeptInPlay
        "src/IncidentManager.Domain/Entities/DataElement.cs",                          // the property and its canonical
        "src/IncidentManager.Infrastructure/Persistence/Configurations/CoreConfigurations.cs",   // the column
        "src/IncidentManager.Infrastructure/Persistence/DevDataSeeder.cs",             // dev data
        "src/IncidentManager.Web/Components/Pages/AdminDataElements.razor",            // the admin page
    };

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

    [Fact]
    public void Only_the_deadline_service_decides_what_a_case_has_in_play(/* BUG-625 */)
    {
        Sources().Where(s => !MappingReaders.Contains(s.Path) && JurisdictionsRead.IsMatch(s.Code)).Select(s => s.Path)
            .Should().BeEmpty("read a case's jurisdictions in play through NotificationDeadlineService (Case.KeptInPlay), as every view does");
        MappingReaders.Should().OnlyContain(p => Sources().Any(s => s.Path == p && JurisdictionsRead.IsMatch(s.Code)),
            "a reviewed entry that no longer reads the mapping is taken off the list");
    }
}
