using System.Globalization;
using IncidentManager.Application.Abstractions;

namespace IncidentManager.Application.Dashboards;

/// <summary>The stretch of time the Program overview's period figures cover.</summary>
public enum OverviewPeriod
{
    Last30Days,
    QuarterToDate,
    Last12Months,
    /// <summary>From one date to another, both included, in the reporting time zone.</summary>
    Custom
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
        OverviewPeriod.Custom => "custom",
        _ => "12m"
    };

    /// <summary>The longest custom range: five years.</summary>
    public const int MaxCustomDays = 5 * 366;

    /// <summary>A custom range from two <c>yyyy-MM-dd</c> dates, or null with why not. A range that runs past
    /// <paramref name="today"/> stops there.</summary>
    public static (DateOnly From, DateOnly To)? TryRange(string? from, string? to, DateOnly today, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(from) && string.IsNullOrWhiteSpace(to)) return null;
        if (!DateOnly.TryParseExact(from, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var f)
            || !DateOnly.TryParseExact(to, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var t))
            error = "Give both dates.";
        else if (f > t) error = "The start date is after the end date.";
        else if (f > today) error = "The range starts after today.";
        else if (t > today ? today.DayNumber - f.DayNumber >= MaxCustomDays : t.DayNumber - f.DayNumber >= MaxCustomDays)
            error = "Pick a range of five years or less.";
        else return (f, t > today ? today : t);
        return null;
    }

    /// <summary>A custom range, both dates included, compared with the same number of days just before it.</summary>
    public static OverviewWindows ForRange(DateOnly from, DateOnly to, DateTimeOffset now, TimeZoneInfo zone)
    {
        var start = ZonedDays.StartUtc(from, zone);
        var end = ZonedDays.StartUtc(to.AddDays(1), zone);
        if (end > now) end = now;
        var days = to.DayNumber - from.DayNumber + 1;
        var months = For(OverviewPeriod.Last12Months, now, zone).Months;
        return new(new(start, end, RangeLabel(from, to)),
            new(ZonedDays.StartUtc(from.AddDays(-days), zone), start, days == 1 ? "the day before" : $"the {days} days before"),
            months);
    }

    /// <summary>"1 Jul – 30 Sep 2026", "3 Mar 2026", or "15 Dec 2025 – 10 Jan 2026".</summary>
    public static string RangeLabel(DateOnly from, DateOnly to)
    {
        var inv = CultureInfo.InvariantCulture;
        if (from == to) return to.ToString("d MMM yyyy", inv);
        return from.Year == to.Year
            ? $"{from.ToString("d MMM", inv)} – {to.ToString("d MMM yyyy", inv)}"
            : $"{from.ToString("d MMM yyyy", inv)} – {to.ToString("d MMM yyyy", inv)}";
    }

    public static OverviewWindows For(OverviewPeriod period, DateTimeOffset now, TimeZoneInfo zone)
    {
        var (year, month) = ZonedMonths.Of(now, zone);
        var thisMonth = new DateTime(year, month, 1);
        DateTimeOffset MonthStart(DateTime m) => ZonedMonths.StartUtc(m.Year, m.Month, zone);

        var months = Enumerable.Range(0, 12).Select(i => thisMonth.AddMonths(i - 11))
            .Select(m => new ProgramWindow(MonthStart(m), m == thisMonth ? now : MonthStart(m.AddMonths(1)), m.ToString("MMM yyyy", CultureInfo.InvariantCulture)))
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
