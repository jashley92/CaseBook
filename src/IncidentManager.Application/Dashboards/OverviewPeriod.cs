using IncidentManager.Application.Abstractions;

namespace IncidentManager.Application.Dashboards;

/// <summary>The stretch of time the Program overview's period figures cover.</summary>
public enum OverviewPeriod
{
    Last30Days,
    QuarterToDate,
    Last12Months
}

/// <summary>The windows behind the Program overview's period figures: the chosen period, the one before it to
/// compare with, and the last 12 calendar months for the trend lines. Months and quarters are cut in the
/// organization's reporting time zone.</summary>
public sealed record OverviewWindows(ProgramWindow Current, ProgramWindow Previous, IReadOnlyList<ProgramWindow> Months)
{
    /// <summary>The period a URL asks for; 12 months when it names none, since a new quarter has little in it.</summary>
    public static OverviewPeriod Parse(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "30d" => OverviewPeriod.Last30Days,
        "quarter" => OverviewPeriod.QuarterToDate,
        _ => OverviewPeriod.Last12Months
    };

    public static string Key(OverviewPeriod period) => period switch
    {
        OverviewPeriod.Last30Days => "30d",
        OverviewPeriod.QuarterToDate => "quarter",
        _ => "12m"
    };

    public static OverviewWindows For(OverviewPeriod period, DateTimeOffset now, TimeZoneInfo zone)
    {
        var (year, month) = ZonedMonths.Of(now, zone);
        var thisMonth = new DateTime(year, month, 1);
        DateTimeOffset MonthStart(DateTime m) => ZonedMonths.StartUtc(m.Year, m.Month, zone);

        var months = Enumerable.Range(0, 12).Select(i => thisMonth.AddMonths(i - 11))
            .Select(m => new ProgramWindow(MonthStart(m), m == thisMonth ? now : MonthStart(m.AddMonths(1)), m.ToString("MMM yyyy")))
            .ToList();

        switch (period)
        {
            case OverviewPeriod.Last30Days:
                return new(new(now.AddDays(-30), now, "the last 30 days"),
                    new(now.AddDays(-60), now.AddDays(-30), "the 30 days before"), months);
            case OverviewPeriod.Last12Months:
                var start = MonthStart(thisMonth.AddMonths(-11));
                return new(new(start, now, "the last 12 months"),
                    new(MonthStart(thisMonth.AddMonths(-23)), start, "the 12 months before"), months);
            default:
                var quarter = ProgramPeriod.Containing(now, zone);
                return new(new(quarter.StartUtc(zone), now, $"{quarter.Label} to date"),
                    new(quarter.Previous.StartUtc(zone), quarter.Previous.EndUtc(zone), quarter.Previous.Label), months);
        }
    }
}
