using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Time;

/// <summary>
/// Reads <c>Organization:TimeZone</c> from the live configuration on each use, so an administered change applies
/// without a restart. An unknown id falls back to <see cref="Default"/>.
/// </summary>
public sealed class ConfigurationOrganizationTimeZone : IOrganizationTimeZone
{
    public const string Key = "Organization:TimeZone";
    public const string Default = "America/New_York";

    private readonly IConfiguration _config;

    public ConfigurationOrganizationTimeZone(IConfiguration config) => _config = config;

    public TimeZoneInfo Current => Resolve(_config[Key]) ?? Resolve(Default) ?? TimeZoneInfo.Utc;

    // IANA ids resolve natively on Linux and on Windows with ICU (Windows 10 1903 / Server 2019 and later);
    // the Windows-id conversion covers hosts without it.
    internal static TimeZoneInfo? Resolve(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return null;
        if (TimeZoneInfo.TryFindSystemTimeZoneById(id.Trim(), out var zone)) return zone;
        return TimeZoneInfo.TryConvertIanaIdToWindowsId(id.Trim(), out var windowsId)
               && TimeZoneInfo.TryFindSystemTimeZoneById(windowsId, out zone) ? zone : null;
    }
}
