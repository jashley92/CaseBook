using System.Diagnostics;
using System.Runtime.Versioning;
using IncidentManager.Application.Abstractions;
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
    private readonly Action<SiemEventLogOptions, SecurityEvent>? _write;
    private readonly Func<string, bool>? _sourceRegistered;
    private volatile bool _sourceMissing;
    private readonly IDeliveryHealth? _health;   // CAP-04

    public EventLogTransport(IOptionsMonitor<SiemEventLogOptions> options, ILogger<EventLogTransport> logger, IDeliveryHealth? health = null)
    {
        _options = options;
        _logger = logger;
        _health = health;
    }

    /// <summary>For tests: stands in for the Event Log write and the source lookup, so no real entry is written.</summary>
    public EventLogTransport(IOptionsMonitor<SiemEventLogOptions> options, ILogger<EventLogTransport> logger,
        Action<SiemEventLogOptions, SecurityEvent> write, Func<string, bool> sourceRegistered) : this(options, logger)
    {
        _write = write;
        _sourceRegistered = sourceRegistered;
    }

    public string Name => "eventlog";

    public bool Enabled => (_write is not null || OperatingSystem.IsWindows()) && _options.CurrentValue.Enabled && !_sourceMissing
                           && !string.IsNullOrWhiteSpace(_options.CurrentValue.Source);

    public Task SendAsync(SecurityEvent e, CancellationToken ct)
    {
        Deliver(e);
        return Task.CompletedTask;
    }

    // BUG-548: the Diagnostics test takes the same write, so a missing source or a refused entry is reported, not shown
    // as Delivered.
    public Task<string?> SendTestAsync(SecurityEvent e, CancellationToken ct) => Task.FromResult(Deliver(e));

    // Returns null when the entry was written (or the transport is off), else a short reason for the test button.
    private string? Deliver(SecurityEvent e)
    {
        if (!Enabled) return null;
        var o = _options.CurrentValue;
        try
        {
            if (_write is not null) _write(o, e);
            else if (OperatingSystem.IsWindows()) Write(o, e);
            _health?.RecordSuccess(DeliveryHealth.Siem(Name));
            return null;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.Security.SecurityException
                                       or System.ComponentModel.Win32Exception)
        {
            _health?.RecordFailure(DeliveryHealth.Siem(Name), ex.GetType().Name);
            // REV-69: one event the log refused (one that's somehow still too long, say) is that event, not the transport.
            // Only a missing source turns delivery off; otherwise a single bad event left every later one, integrity
            // alarms included, unforwarded until restart.
            if (_sourceRegistered?.Invoke(o.Source) ?? (OperatingSystem.IsWindows() && SourceRegistered(o.Source)))
            {
                _logger.LogWarning(ex, "Windows Event Log refused event {EventId}; later events are still sent.", e.EventId);
                return $"The Windows Event Log refused the entry: {ex.Message}";
            }
            // Most often: the source isn't registered and the app (rightly) lacks rights to create it.
            _sourceMissing = true;
            var register = $"New-EventLog -LogName {o.LogName} -Source {o.Source}";
            _logger.LogWarning(ex,
                "Windows Event Log delivery disabled: couldn't write event {EventId} as source '{Source}' in '{Log}'. " +
                "Register the source once as an administrator ({RegisterCommand}) and restart.",
                e.EventId, o.Source, o.LogName, register);
            return $"Couldn't write as source '{o.Source}' in the {o.LogName} log, so Event Log delivery is off until restart. " +
                   $"Register the source once as an administrator ({register}), then restart.";
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool SourceRegistered(string source)
    {
        try { return EventLog.SourceExists(source); }
        catch (System.Security.SecurityException) { return false; }   // can't tell: treat as missing, as before
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

    /// <summary>REV-69: under the Event Log's limit on an entry's message (31,839 characters).</summary>
    public const int MaxMessage = 31_000;

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
        var headline = $"{e.Category}/{e.Action} {e.Outcome} by {e.Actor}" + (e.CaseNumber is { Length: > 0 } cn ? $" on {cn}" : "");
        var message = headline + Environment.NewLine + SecurityEventJson.Serialize(e);
        // REV-69: an entry holds about 31,800 characters, and WriteEntry throws past that. A long detail (a long request
        // path, JSON-escaped) is shortened instead, so the body stays whole JSON and the event still goes.
        if (e.Detail is { Length: > 0 } detail)
        {
            // Escaping can lengthen what's kept, so it's cut again until it fits.
            var keep = detail.Length;
            while (message.Length > MaxMessage && keep > 0)
            {
                keep = Math.Max(0, keep - Math.Max(64, message.Length - MaxMessage));
                message = headline + Environment.NewLine + SecurityEventJson.Serialize(e with { Detail = detail[..keep] + "… (shortened)" });
            }
        }
        return (type, id, message);
    }
}
