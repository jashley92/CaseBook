using System.Diagnostics;
using System.Runtime.Versioning;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure.Siem;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Siem;

/// <summary>Configuration for the Windows Event Log transport (F-18), bound from <c>Siem:EventLog</c>.</summary>
public sealed class SiemEventLogOptions
{
    /// <summary>When false (default), nothing is written to the Event Log.</summary>
    public bool Enabled { get; set; }

    /// <summary>Event source. Must be registered once by an administrator (see docs/OPERATIONS.md §5).</summary>
    public string Source { get; set; } = "CaseBook";

    /// <summary>Log the source is registered in (normally <c>Application</c>).</summary>
    public string LogName { get; set; } = "Application";
}

/// <summary>The Event Log entry type an event maps to (platform-neutral, so the mapping is testable anywhere).</summary>
public enum EventLogLevel { Information, Warning, Error }

/// <summary>
/// Windows Event Log transport for the security-event stream (F-18): one entry per event, with the stable
/// catalog id as the Event ID and the same JSON body as the webhook, so Windows Event Forwarding / an agent
/// (XSIAM, Splunk UF, …) can collect it without a network collector. Windows-only; a no-op elsewhere.
/// Registering an event source needs administrator rights, so the app never tries: if the source is missing
/// it logs one warning and stops until restart. Best-effort like the other transports.
/// </summary>
public sealed class EventLogTransport : ISecurityEventTransport
{
    private readonly IOptionsMonitor<SiemEventLogOptions> _options;
    private readonly ILogger<EventLogTransport> _logger;
    private volatile bool _sourceMissing;

    public EventLogTransport(IOptionsMonitor<SiemEventLogOptions> options, ILogger<EventLogTransport> logger)
    {
        _options = options;
        _logger = logger;
    }

    public string Name => "eventlog";

    public bool Enabled => OperatingSystem.IsWindows() && _options.CurrentValue.Enabled && !_sourceMissing
                           && !string.IsNullOrWhiteSpace(_options.CurrentValue.Source);

    public Task SendAsync(SecurityEvent e, CancellationToken ct)
    {
        if (!Enabled) return Task.CompletedTask;
        var o = _options.CurrentValue;
        try
        {
            if (OperatingSystem.IsWindows()) Write(o, e);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.Security.SecurityException
                                       or System.ComponentModel.Win32Exception)
        {
            // Most often: the source isn't registered and the app (rightly) lacks rights to create it.
            _sourceMissing = true;
            _logger.LogWarning(ex,
                "Windows Event Log delivery disabled: couldn't write event {EventId} as source '{Source}' in '{Log}'. " +
                "Register the source once as an administrator (New-EventLog -LogName {Log} -Source {Source}) and restart.",
                e.EventId, o.Source, o.LogName, o.LogName, o.Source);
        }
        return Task.CompletedTask;
    }

    [SupportedOSPlatform("windows")]
    private static void Write(SiemEventLogOptions o, SecurityEvent e)
    {
        var (level, id, message) = Map(e);
        var type = level switch
        {
            EventLogLevel.Error => EventLogEntryType.Error,
            EventLogLevel.Warning => EventLogEntryType.Warning,
            _ => EventLogEntryType.Information,
        };
        using var log = new EventLog(o.LogName) { Source = o.Source };
        log.WriteEntry(message, type, id);
    }

    /// <summary>Entry type, Event ID and message for an event. Pure, so it's testable on any OS.</summary>
    public static (EventLogLevel Level, int EventId, string Message) Map(SecurityEvent e)
    {
        var type = e.Severity switch
        {
            SecuritySeverity.High or SecuritySeverity.Critical => EventLogLevel.Error,
            SecuritySeverity.Warning => EventLogLevel.Warning,
            _ => e.Outcome is SecurityOutcome.Success or SecurityOutcome.Allow ? EventLogLevel.Information : EventLogLevel.Warning,
        };
        // Event IDs are 16-bit in the classic API; the catalog (5001–55xx) fits, but clamp defensively.
        var id = e.EventId is >= 0 and <= ushort.MaxValue ? e.EventId : 0;
        // A readable first line for the Event Viewer pane, then the webhook's JSON body for parsers.
        var message = $"{e.Category}/{e.Action} {e.Outcome} by {e.Actor}" +
                      (e.CaseNumber is { Length: > 0 } cn ? $" on {cn}" : "") +
                      Environment.NewLine + SecurityEventJson.Serialize(e);
        return (type, id, message);
    }
}
