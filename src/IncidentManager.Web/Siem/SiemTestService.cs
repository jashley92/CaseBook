using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure.Siem;

namespace IncidentManager.Web.Siem;

/// <summary>One transport's result for a test event.</summary>
public sealed record SiemTestResult(string Transport, bool Delivered, string Detail);

/// <summary>
/// Diagnostics "Send test event": sends one clearly labeled test event (id 5901) straight to each enabled SIEM
/// transport, bypassing the queue, and reports per transport whether it went out. Lets an admin confirm the
/// collector receives CaseBook's stream before relying on it. Doesn't touch case data.
/// </summary>
public sealed class SiemTestService
{
    private readonly IEnumerable<ISecurityEventTransport> _transports;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public SiemTestService(IEnumerable<ISecurityEventTransport> transports, ICurrentUser user, IClock clock)
    {
        _transports = transports;
        _user = user;
        _clock = clock;
    }

    public bool AnyEnabled => _transports.Any(t => t.Enabled);

    public async Task<IReadOnlyList<SiemTestResult>> SendTestAsync(CancellationToken ct = default)
    {
        var e = new SecurityEvent
        {
            EventId = SecurityEventIds.SiemTest,
            Category = "Diagnostics",
            Action = "SiemTest",
            Actor = string.IsNullOrEmpty(_user.UserId) ? "system" : _user.UserId,
            Detail = "Test event sent from CaseBook Diagnostics. No action needed.",
            AtUtc = _clock.UtcNow,
            Host = Environment.MachineName,
        };

        var results = new List<SiemTestResult>();
        foreach (var t in _transports.Where(t => t.Enabled))
        {
            var error = await t.SendTestAsync(e, ct);
            results.Add(error is null
                ? new SiemTestResult(Label(t.Name), true, t.Name == "syslog"
                    ? "Sent. Syslog doesn't confirm receipt, so check that event 5901 reached the collector."
                    : "Delivered.")
                : new SiemTestResult(Label(t.Name), false, error));
        }
        return results;
    }

    private static string Label(string name) => name switch
    {
        "webhook" => "Webhook",
        "syslog" => "Syslog (CEF)",
        "eventlog" => "Windows Event Log",
        _ => name
    };
}
