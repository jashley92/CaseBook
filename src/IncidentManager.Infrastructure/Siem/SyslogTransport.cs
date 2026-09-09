using System.Net.Sockets;
using System.Text;
using IncidentManager.Application.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Siem;

/// <summary>
/// Delivers security events as CEF over syslog (F-18) — UDP (fire-and-forget) or TCP (LF-framed) to an
/// SIEM Broker VM / syslog collector. Best-effort and time-bounded; never throws (the dispatcher also
/// guards it). UDP is inherently non-blocking; the TCP path is capped by a connect/send timeout so a
/// stalled collector can't wedge the dispatcher loop.
/// </summary>
public sealed class SyslogTransport : ISecurityEventTransport
{
    private readonly IOptionsMonitor<SiemSyslogOptions> _options;
    private readonly ILogger<SyslogTransport> _logger;

    public SyslogTransport(IOptionsMonitor<SiemSyslogOptions> options, ILogger<SyslogTransport> logger)
    {
        _options = options;
        _logger = logger;
    }

    public string Name => "syslog";

    public bool Enabled
    {
        get
        {
            var o = _options.CurrentValue;
            return o.Enabled && !string.IsNullOrWhiteSpace(o.Host);
        }
    }

    public async Task SendAsync(SecurityEvent e, CancellationToken ct)
    {
        var o = _options.CurrentValue;
        if (!o.Enabled || string.IsNullOrWhiteSpace(o.Host)) return;

        var line = SecurityEventCef.ToSyslogLine(e, o.Facility, o.AppName);
        var bytes = Encoding.UTF8.GetBytes(line);

        try
        {
            if (o.Protocol.Equals("Tcp", StringComparison.OrdinalIgnoreCase))
                await SendTcpAsync(o, bytes, ct);
            else
                await SendUdpAsync(o, bytes, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // shutting down
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Syslog delivery failed for event {EventId} to {Host}:{Port}.", e.EventId, o.Host, o.Port);
        }
    }

    private static async Task SendUdpAsync(SiemSyslogOptions o, byte[] bytes, CancellationToken ct)
    {
        using var udp = new UdpClient();
        await udp.SendAsync(bytes, bytes.Length, o.Host, o.Port).WaitAsync(ct);
    }

    private static async Task SendTcpAsync(SiemSyslogOptions o, byte[] bytes, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(o.TimeoutSeconds > 0 ? o.TimeoutSeconds : 5));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(o.Host, o.Port, timeoutCts.Token);
        var stream = tcp.GetStream();
        // Non-transparent framing (RFC 6587 §3.4.2): message terminated by LF.
        await stream.WriteAsync(bytes, timeoutCts.Token);
        await stream.WriteAsync(new byte[] { (byte)'\n' }, timeoutCts.Token);
        await stream.FlushAsync(timeoutCts.Token);
    }
}
