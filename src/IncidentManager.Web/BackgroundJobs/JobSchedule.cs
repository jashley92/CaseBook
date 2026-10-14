using IncidentManager.Application.Admin;

namespace IncidentManager.Web.BackgroundJobs;

/// <summary>
/// BUG-262: a scan interval from settings as a <see cref="TimeSpan"/>. The settings page caps it, but the server's settings
/// file isn't checked, and an hour count over about 256 million overflows a TimeSpan: that threw out of the job's loop and
/// stopped the app. Zero or less is the job's default; anything over a month is a month.
/// </summary>
public static class JobSchedule
{
    public static TimeSpan Hours(double hours, double fallback) =>
        TimeSpan.FromHours(hours > 0 && !double.IsNaN(hours) ? Math.Min(hours, SettingsCatalog.MaxIntervalHours) : fallback);
}
