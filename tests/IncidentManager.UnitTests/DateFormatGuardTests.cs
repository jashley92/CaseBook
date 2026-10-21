using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// UX-57: one way to write a date on screen. Times go through TimeDisplay: Short or Long ("20 Oct 2026, 21:04 UTC"),
/// Stamp under a header that names the zone, Brief where recency matters, and TimeDisplay.Utc on the audit and system
/// pages. The 2026-10-21 audit found four formats (2026-10-20, Tue 9:04 PM, 2026-10-20 9:04 PM UTC-04:00, …Z) because
/// screens formatted their own. A component that writes ToString("u") or a "yyyy-MM-dd HH:mm" pattern fails here.
/// Machine values (query strings, a date input's min and max) keep yyyy-MM-dd and aren't matched; the report preview
/// mirrors the Word report (ADR-0013), which keeps its own fixed format.
/// </summary>
public sealed partial class DateFormatGuardTests
{
    private static readonly string[] Exempt = ["ReportPreview.razor"];

    [Fact]
    public void Components_format_times_through_TimeDisplay()
    {
        var offenders = Directory.EnumerateFiles(Path.Combine(WebRoot(), "Components"), "*.razor", SearchOption.AllDirectories)
            .Where(f => !Exempt.Contains(Path.GetFileName(f)))
            .SelectMany(f => File.ReadAllLines(f).Select((line, i) => (File: Path.GetFileName(f), Line: i + 1, Text: line)))
            .Where(l => RawStamp().IsMatch(l.Text))
            .Select(l => $"{l.File}:{l.Line}: {l.Text.Trim()}")
            .ToList();

        offenders.Should().BeEmpty("times on screen go through TimeDisplay (UX-57), not a format written in the component");
    }

    // ToString("u"), and a date written with a time ("yyyy-MM-dd HH:mm", "yyyy-MM-dd h:mm tt").
    [GeneratedRegex("""ToString\("u"\)|yyyy-MM-dd[ ,]+h""", RegexOptions.IgnoreCase)]
    private static partial Regex RawStamp();

    private static string WebRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var web = Path.Combine(dir.FullName, "src", "IncidentManager.Web");
            if (Directory.Exists(web)) return web;
        }
        throw new DirectoryNotFoundException("src/IncidentManager.Web not found above the test output.");
    }
}
