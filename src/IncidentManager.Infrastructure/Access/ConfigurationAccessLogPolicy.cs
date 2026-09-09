using IncidentManager.Application.Access;
using IncidentManager.Domain.Enums;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Access;

/// <summary>
/// Reads the access-log scope and coalescing window from live configuration on each call, so an
/// administered change (flowing in via the DB settings provider) takes effect without a restart (C-05).
/// Keys: <c>Access:LogScope</c> (Off/RestrictedOnly/All, default All) and
/// <c>Access:CoalesceWindowMinutes</c> (default 30).
/// </summary>
public sealed class ConfigurationAccessLogPolicy : IAccessLogPolicy
{
    private const int DefaultWindowMinutes = 30;

    private readonly IConfiguration _config;

    public ConfigurationAccessLogPolicy(IConfiguration config) => _config = config;

    public AccessLogScope Scope =>
        Enum.TryParse<AccessLogScope>(_config["Access:LogScope"], ignoreCase: true, out var s)
            ? s
            : AccessLogScope.All;

    public TimeSpan CoalesceWindow
    {
        get
        {
            var minutes = _config.GetValue<int?>("Access:CoalesceWindowMinutes") ?? DefaultWindowMinutes;
            if (minutes <= 0) minutes = DefaultWindowMinutes;
            return TimeSpan.FromMinutes(minutes);
        }
    }

    public bool ShouldLog(AccessType type, bool wasRestricted) => AccessLogRules.ShouldLog(Scope, type, wasRestricted);
}
