namespace IncidentManager.Web.Security;

/// <summary>
/// Per-user token-bucket limits for the download/export endpoints (F-13), bound from the
/// <c>RateLimiting:Downloads</c> configuration section. A token bucket lets a legitimate analyst burst
/// through several artifacts, then caps the sustained rate so a compromised account can't bulk-scrape
/// evidence. Server-side security config (not the in-app admin catalog).
/// </summary>
public sealed class DownloadRateLimitOptions
{
    /// <summary>Bucket size = the largest burst allowed before throttling kicks in.</summary>
    public int TokenLimit { get; set; } = 40;

    /// <summary>Tokens replenished each <see cref="PeriodSeconds"/> — the sustained requests/period.</summary>
    public int TokensPerPeriod { get; set; } = 40;

    /// <summary>Length of the replenishment period, in seconds.</summary>
    public int PeriodSeconds { get; set; } = 60;
}
