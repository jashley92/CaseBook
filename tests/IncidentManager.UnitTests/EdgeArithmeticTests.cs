using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Common;
using IncidentManager.Application.Work;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C12 (BUG-577): date arithmetic on a stored or typed instant is safe at the ends of the calendar. A due of
/// 9999-12-31 made the calendar feed throw for everyone who could see the task.
/// </summary>
public partial class EdgeArithmeticTests
{
    private static readonly TimeZoneInfo East = TimeZoneInfo.CreateCustomTimeZone("UTC+14", TimeSpan.FromHours(14), "UTC+14", "UTC+14");
    private static readonly TimeZoneInfo West = TimeZoneInfo.CreateCustomTimeZone("UTC-12", TimeSpan.FromHours(-12), "UTC-12", "UTC-12");

    [Fact]
    public void AddClamped_holds_at_the_ends_instead_of_throwing()
    {
        Instants.AddClamped(DateTimeOffset.MaxValue, TimeSpan.FromMinutes(30)).Should().Be(DateTimeOffset.MaxValue);
        Instants.AddClamped(DateTimeOffset.MaxValue.AddMinutes(-10), TimeSpan.FromMinutes(30)).Should().Be(DateTimeOffset.MaxValue);
        Instants.AddClamped(DateTimeOffset.MinValue, TimeSpan.FromDays(-1)).Should().Be(DateTimeOffset.MinValue);
        var t = new DateTimeOffset(2026, 10, 15, 9, 0, 0, TimeSpan.FromHours(-4));
        Instants.AddClamped(t, TimeSpan.FromMinutes(30)).Should().Be(t.AddMinutes(30));
        Instants.AddClamped(t, TimeSpan.FromMinutes(-30)).Should().Be(t.AddMinutes(-30));
    }

    [Theory]
    [InlineData(0)]          // the last instant
    [InlineData(10)]         // a due typed as 9999-12-31 23:50
    [InlineData(60 * 24)]    // 9999-12-31, any time
    public void The_calendar_feed_writes_an_event_due_at_the_end_of_time(int minutesBeforeMax)
    {
        var due = DateTimeOffset.MaxValue.AddMinutes(-minutesBeforeMax);
        var now = new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);

        var write = () => IcsWriter.Write("x", [new IcsEvent("i1", due, "far", null, null, false)], now);

        write.Should().NotThrow();
        write().Should().Contain("DTEND:9999123");
    }

    [Fact]
    public void A_calendar_day_at_either_end_has_a_start_in_any_zone()
    {
        ZonedDays.StartUtc(DateOnly.MinValue, East).Should().Be(DateTimeOffset.MinValue);
        ZonedDays.StartUtc(DateOnly.MinValue, West).Should().Be(new DateTimeOffset(1, 1, 1, 12, 0, 0, TimeSpan.Zero));
        ZonedDays.StartUtc(DateOnly.MaxValue, West).Should().Be(new DateTimeOffset(9999, 12, 31, 12, 0, 0, TimeSpan.Zero));
        ZonedDays.StartUtc(DateOnly.MaxValue, East).Should().Be(new DateTimeOffset(9999, 12, 30, 10, 0, 0, TimeSpan.Zero));
        ZonedMonths.StartUtc(1, 1, East).Should().Be(DateTimeOffset.MinValue);
        // Unchanged inside the range.
        ZonedDays.StartUtc(new DateOnly(2026, 10, 15), West).Should().Be(new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public void A_due_at_the_end_of_time_is_bucketed_as_later()
    {
        var now = new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
        AgendaService.Bucket(DateTimeOffset.MaxValue, now, East).Should().Be(AgendaBucketKind.Later);
        AgendaService.Bucket(DateTimeOffset.MinValue, now, West).Should().Be(AgendaBucketKind.Overdue);
    }

    // ── Structural: every Add<Unit>() on a value that isn't the clock's is reviewed ─────────────────────────────

    /// <summary>
    /// Calendar arithmetic on an instant that came from storage or input, reviewed: each is safe for the reason given,
    /// or is reported to its file's owner. A new call on such a value fails this test until it uses
    /// <see cref="Instants.AddClamped"/> or is added here with the reason it can't reach the ends of the range.
    /// Keyed by file name and the text of the call, not line numbers.
    /// </summary>
    private static readonly (string File, string Code, string Why)[] Reviewed =
    [
        ("IOrganizationTimeZone.cs", "local.AddHours(1)", "local midnight of a DateOnly; +1 h never passes 9999-12-31 23:59"),
        ("CaseService.cs", "new DateTime(oy, om, 1).AddMonths(1)", "BUG-475: guarded to years 2..9998"),
        ("StepTime.cs", "from.AddDays(from == DateOnly.MinValue ? 0 : -1)", "guarded at MinValue; to is an occurred time, never in the future"),
        ("NotificationDeadlinePolicy.cs", "start.AddHours(windowHours", "start is a detection/awareness time, refused in the future"),
        ("SlaPolicy.cs", "start.AddHours(hours", "start is a detection/creation time, refused in the future"),
        ("DashboardService.cs", "current.AddMonths(", "current is this month from the clock"),
        ("OverviewPeriod.cs", "to.AddDays(1)", "to is at most today"),
        // REPORTED (Dashboards owner): /program?from=0001-01-02&to=0001-01-03 passes ParseRange (from <= today, under five
        // years) and from.AddDays(-days) throws. ZonedDays.StartUtc itself now clamps (BUG-577).
        ("OverviewPeriod.cs", "from.AddDays(-days)", "REPORTED: a typed range in year 1 throws"),
        ("OverviewPeriod.cs", "thisMonth.AddMonths(", "thisMonth is from the clock"),
        ("ProgramReportService.cs", ".AddDays(-1)", "LastDay of a validated quarter"),
        ("CaseImportService.cs", "against.AddYears(-Case.MaxDwellYears)", "guarded by against.Year <= MaxDwellYears"),
        // REPORTED (Domain owner): a detected time typed in years 1..10 makes AddYears(-10) throw ArgumentOutOfRange (an
        // ArgumentException, so the page shows the runtime's wording rather than a crash).
        ("Case.cs", "detectedAtUtc.AddYears(-MaxDwellYears)", "REPORTED: detected in years 1..10 throws"),
        ("StepTiming.cs", ".Date.AddHours(12)", "midday of a date; never passes the range"),
        ("OverviewPeriod.cs", "MonthStart(m.AddMonths(1))", "m is one of the twelve months up to this one"),
        ("CaseService.cs", "recorded = recorded.AddTicks(1)", "recorded starts at the clock's now"),
        ("Case.cs", "ordered[i - 1].EffectiveAt.AddTicks(1)", "a recorded phase change, refused in the future"),
        ("Case.cs", "ordered[i + 1].EffectiveAt.AddTicks(-1)", "a later recorded phase change, so above MinValue"),
        ("Case.cs", "latest.AddTicks(1)", "a recorded change at or after a time refused in the future"),
    ];

    [GeneratedRegex(@"(?<recv>[\w\.\)\]\?]+)\.Add(?:Minutes|Hours|Days|Months|Years|Seconds|Milliseconds|Ticks)\(", RegexOptions.None, 1000)]
    private static partial Regex AddUnit();

    [GeneratedRegex(@"now|today|clock|Now|Today|Clock", RegexOptions.None, 1000)]
    private static partial Regex ClockDerived();

    [Fact]
    public void Calendar_arithmetic_on_stored_or_typed_instants_is_clamped_or_reviewed()
    {
        var root = Path.Combine(RepoRoot(), "src");
        var unreviewed = new List<string>();
        foreach (var project in new[] { "IncidentManager.Application", "IncidentManager.Domain", "IncidentManager.Infrastructure" })
            foreach (var file in Directory.EnumerateFiles(Path.Combine(root, project), "*.cs", SearchOption.AllDirectories))
            {
                var name = Path.GetFileName(file);
                if (name == "DevDataSeeder.cs" || file.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}")) continue;
                var lines = File.ReadAllLines(file);
                for (var i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    if (line.TrimStart().StartsWith("//", StringComparison.Ordinal)) continue;
                    foreach (Match m in AddUnit().Matches(line))
                    {
                        if (ClockDerived().IsMatch(m.Groups["recv"].Value)) continue;   // arithmetic on the clock's now/today
                        if (Reviewed.Any(r => r.File == name && line.Contains(r.Code, StringComparison.Ordinal))) continue;
                        unreviewed.Add($"{Path.GetRelativePath(root, file)}:{i + 1}: {line.Trim()}");
                    }
                }
            }

        unreviewed.Should().BeEmpty("calendar arithmetic on a stored or typed instant must use Instants.AddClamped or be reviewed");
    }

    internal static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }
}
