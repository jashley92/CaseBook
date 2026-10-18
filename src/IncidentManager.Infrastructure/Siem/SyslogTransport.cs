using System.Globalization;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Common;
using IncidentManager.Infrastructure.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Siem;

/// <summary>
/// Delivers security events as CEF over syslog (F-18) — UDP (fire-and-forget), TCP (LF-framed) or, CAP-33, TLS
/// (RFC 5425: octet-counted over <see cref="SslStream"/>) to an SIEM Broker VM / syslog collector. Best-effort and
/// time-bounded; never throws (the dispatcher also guards it). UDP is inherently non-blocking; the TCP and TLS paths are
/// capped by one timeout over connect, handshake and send (C10), so a stalled collector can't wedge the dispatcher loop.
/// <para>
/// CAP-33: with TLS the collector's certificate must chain to a root this server trusts and carry <c>Host</c>'s name;
/// <c>ServerCertificateThumbprint</c>, when set, also refuses any other certificate. An optional client certificate comes
/// from <c>LocalMachine\My</c> by thumbprint, as CyberArk's does. A misconfiguration (a protocol that isn't a name, a pin
/// that isn't a thumbprint, a client certificate that can't be used) stops the transport, and Diagnostics says why
/// (<see cref="StoppedReason"/>). One connection per event, as TCP has always been; nothing is retried.
/// </para>
/// </summary>
public sealed class SyslogTransport : ISecurityEventTransport
{
    /// <summary>How long a client certificate found (or not) is kept before the store is read again.</summary>
    internal static readonly TimeSpan ClientCertificateRecheck = TimeSpan.FromMinutes(5);

    private readonly IOptionsMonitor<SiemSyslogOptions> _options;
    private readonly ILogger<SyslogTransport> _logger;
    private readonly IDeliveryHealth? _health;   // CAP-04
    private readonly Func<string, X509Certificate2> _findClientCertificate;
    private readonly object _clientGate = new();
    private (string Thumbprint, X509Certificate2? Certificate, string? Problem, DateTimeOffset At)? _client;

    public SyslogTransport(IOptionsMonitor<SiemSyslogOptions> options, ILogger<SyslogTransport> logger, IDeliveryHealth? health = null)
        : this(options, logger, health, null) { }

    /// <summary>For tests: the client certificate's lookup is swappable (the machine store needs an administrator).</summary>
    internal SyslogTransport(IOptionsMonitor<SiemSyslogOptions> options, ILogger<SyslogTransport> logger, IDeliveryHealth? health,
        Func<string, X509Certificate2>? findClientCertificate)
    {
        _options = options;
        _logger = logger;
        _health = health;
        _findClientCertificate = findClientCertificate
                                 ?? (t => CertificateLookup.FindClient(t, "Siem:Syslog:ClientCertificateThumbprint"));
    }

    /// <summary>For tests: roots trusted for the collector's chain on top of the machine's (a self-signed test collector).</summary>
    internal X509Certificate2Collection? ExtraTrustedRoots { get; init; }

    public string Name => "syslog";

    public bool Enabled
    {
        get
        {
            var o = _options.CurrentValue;
            return o.Enabled && !string.IsNullOrWhiteSpace(o.Host) && Misconfiguration(o) is null;
        }
    }

    // CAP-04 review: on in its options but with no host, it sends nothing; the delivery card says so instead of hiding it.
    public bool Configured => _options.CurrentValue.Enabled;

    public string? StoppedReason
    {
        get
        {
            var o = _options.CurrentValue;
            if (!o.Enabled) return null;
            if (string.IsNullOrWhiteSpace(o.Host)) return "not sending: no collector host is set (Siem:Syslog:Host)";
            return Misconfiguration(o) is { } why ? "not sending: " + why : null;
        }
    }

    /// <summary>CAP-33: the protocol named in <paramref name="text"/> (by name only, C16: "2" isn't TLS), or false.</summary>
    public static bool TryParseProtocol(string? text, out SyslogProtocol protocol) =>
        EnumNames.TryParse(text, out protocol, ignoreCase: true);

    // CAP-33: what stops the transport before it tries (StoppedReason applies), in words for an administrator.
    private string? Misconfiguration(SiemSyslogOptions o)
    {
        if (!TryParseProtocol(o.Protocol, out var protocol))
            return $"Siem:Syslog:Protocol '{Shown(o.Protocol)}' isn't Udp, Tcp or Tls";
        if (protocol != SyslogProtocol.Tls) return null;
        if (!string.IsNullOrWhiteSpace(o.ServerCertificateThumbprint) && PinKind(o.ServerCertificateThumbprint) is null)
            return "Siem:Syslog:ServerCertificateThumbprint isn't a SHA-1 or SHA-256 thumbprint (40 or 64 hex digits)";
        return ClientCertificate(o).Problem;
    }

    // A setting shown back is cut short and kept on one line (it's ours, but it's typed).
    private static string Shown(string? value)
    {
        var v = new string((value ?? "").Where(c => !char.IsControl(c)).Take(20).ToArray());
        return v.Length < (value?.Length ?? 0) ? v + "…" : v;
    }

    private static HashAlgorithmName? PinKind(string pin) => CertificateLookup.Normalize(pin).Length switch
    {
        40 when Hex(pin) => HashAlgorithmName.SHA1,
        64 when Hex(pin) => HashAlgorithmName.SHA256,
        _ => null,
    };

    // Only hex digits and the separators people paste (spaces, colons).
    private static bool Hex(string pin) => pin.All(c => char.IsAsciiHexDigit(c) || c is ' ' or ':');

    // The client certificate named in the options, read from the store at most every few minutes (a missing one is
    // looked for again then, so installing it needs no restart). Null certificate and problem: none is configured.
    private (X509Certificate2? Certificate, string? Problem) ClientCertificate(SiemSyslogOptions o)
    {
        var thumb = CertificateLookup.Normalize(o.ClientCertificateThumbprint ?? "");
        if (thumb.Length == 0) return (null, null);
        var now = DateTimeOffset.UtcNow;
        lock (_clientGate)
        {
            if (_client is { } c && c.Thumbprint == thumb && now - c.At < ClientCertificateRecheck) return (c.Certificate, c.Problem);
        }
        X509Certificate2? cert = null;
        string? problem = null;
        try { cert = _findClientCertificate(thumb); }
        catch (Exception ex) when (ex is InvalidOperationException or CryptographicException or PlatformNotSupportedException)
        {
            problem = ex is InvalidOperationException ? ex.Message.TrimEnd('.') : $"the client certificate can't be read ({ex.GetType().Name})";
        }
        lock (_clientGate) _client = (thumb, cert, problem, now);
        return (cert, problem);
    }

    public async Task<string?> SendTestAsync(SecurityEvent e, CancellationToken ct)
    {
        var o = _options.CurrentValue;
        if (!o.Enabled || string.IsNullOrWhiteSpace(o.Host)) return null;
        if (Misconfiguration(o) is { } why)
        {
            _health?.RecordFailure(DeliveryHealth.Siem(Name), "misconfigured");
            return $"Not sent: {why}.";
        }
        var bytes = Encoding.UTF8.GetBytes(SecurityEventCef.ToSyslogLine(e, o.Facility, o.AppName));
        var tls = new TlsOutcome();
        try
        {
            await SendWithAsync(o, bytes, tls, ct);
            _health?.RecordSuccess(DeliveryHealth.Siem(Name));
            return null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            _health?.RecordFailure(DeliveryHealth.Siem(Name), "timed out");
            return $"{o.Host}:{o.Port} didn't accept a connection and finish the handshake in time.";
        }
        catch (AuthenticationException ex)
        {
            _health?.RecordFailure(DeliveryHealth.Siem(Name), tls.Reason ?? ex.GetType().Name);
            return $"The TLS handshake with {o.Host}:{o.Port} failed: {tls.Reason ?? ex.GetBaseException().Message}.";
        }
        catch (Exception ex) when (ex is SocketException or IOException or ArgumentException)
        {
            _health?.RecordFailure(DeliveryHealth.Siem(Name), tls.Reason ?? ex.GetBaseException().GetType().Name);
            return tls.Reason ?? ex.GetBaseException().Message;
        }
    }

    public async Task SendAsync(SecurityEvent e, CancellationToken ct)
    {
        var o = _options.CurrentValue;
        if (!o.Enabled || string.IsNullOrWhiteSpace(o.Host)) return;
        if (Misconfiguration(o) is not null) return;   // CAP-33: stopped; Diagnostics says why

        var line = SecurityEventCef.ToSyslogLine(e, o.Facility, o.AppName);
        var bytes = Encoding.UTF8.GetBytes(line);
        var tls = new TlsOutcome();

        try
        {
            await SendWithAsync(o, bytes, tls, ct);
            _health?.RecordSuccess(DeliveryHealth.Siem(Name));   // CAP-04 (UDP: handed to the network, as far as can be known)
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // shutting down
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Syslog delivery failed for event {EventId} to {Host}:{Port}{Why}.", e.EventId, o.Host, o.Port,
                tls.Reason is { } r ? $" ({r})" : "");
            _health?.RecordFailure(DeliveryHealth.Siem(Name),
                ex is OperationCanceledException ? "timed out" : tls.Reason ?? ex.GetBaseException().GetType().Name);
        }
    }

    private Task SendWithAsync(SiemSyslogOptions o, byte[] bytes, TlsOutcome tls, CancellationToken ct)
    {
        if (!TryParseProtocol(o.Protocol, out var protocol))   // Misconfiguration refused it first; never sent as another
            throw new ArgumentException("Siem:Syslog:Protocol isn't Udp, Tcp or Tls.");
        return protocol switch
        {
            SyslogProtocol.Tls => SendTlsAsync(o, bytes, tls, ct),
            SyslogProtocol.Tcp => SendTcpAsync(o, bytes, ct),
            _ => SendUdpAsync(o, bytes, ct),
        };
    }

    private static async Task SendUdpAsync(SiemSyslogOptions o, byte[] bytes, CancellationToken ct)
    {
        using var udp = new UdpClient();
        await udp.SendAsync(bytes, bytes.Length, o.Host, o.Port).WaitAsync(ct);
    }

    private static TimeSpan Timeout(SiemSyslogOptions o) => TimeSpan.FromSeconds(o.TimeoutSeconds > 0 ? Math.Min(o.TimeoutSeconds, 300) : 5);

    private static async Task SendTcpAsync(SiemSyslogOptions o, byte[] bytes, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(Timeout(o));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(o.Host, o.Port, timeoutCts.Token);
        var stream = tcp.GetStream();
        // Non-transparent framing (RFC 6587 §3.4.2): message terminated by LF.
        await stream.WriteAsync(bytes, timeoutCts.Token);
        await stream.WriteAsync(new byte[] { (byte)'\n' }, timeoutCts.Token);
        await stream.FlushAsync(timeoutCts.Token);
    }

    /// <summary>Why the collector's certificate was refused, in words safe to show (no certificate contents).</summary>
    private sealed class TlsOutcome
    {
        public string? Reason { get; set; }
    }

    // CAP-33: RFC 5425. One limit over connect, handshake and send (C10); the certificate is checked in Validate.
    private async Task SendTlsAsync(SiemSyslogOptions o, byte[] bytes, TlsOutcome tls, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(Timeout(o));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(o.Host, o.Port, timeoutCts.Token);
        await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        var client = ClientCertificate(o).Certificate;
        var pin = o.ServerCertificateThumbprint;
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = o.Host.Trim(),
            ClientCertificates = client is null ? null : [client],
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = (_, cert, chain, errors) => Validate(cert, chain, errors, pin, tls),
        }, timeoutCts.Token);
        // Octet-counting framing (RFC 5425 §4.3): MSG-LEN SP SYSLOG-MSG, no terminator.
        var frame = Encoding.ASCII.GetBytes(bytes.Length.ToString(CultureInfo.InvariantCulture) + " ");
        await ssl.WriteAsync(frame, timeoutCts.Token);
        await ssl.WriteAsync(bytes, timeoutCts.Token);
        await ssl.FlushAsync(timeoutCts.Token);
        await ssl.ShutdownAsync().WaitAsync(timeoutCts.Token);   // close_notify, so the collector knows the message ended whole
        await DrainAsync(tcp, ssl, timeoutCts.Token);
    }

    // CAP-33: a socket closed with bytes unread (a TLS 1.3 session ticket the collector sent after the handshake) is reset,
    // and a reset can throw away the message the collector hasn't read yet. So the sending side is closed first, and what
    // the collector sends is read until it closes too, for a second at most (within the send's limit).
    private static async Task DrainAsync(TcpClient tcp, SslStream ssl, CancellationToken ct)
    {
        try
        {
            tcp.Client.Shutdown(SocketShutdown.Send);
            using var drain = CancellationTokenSource.CreateLinkedTokenSource(ct);
            drain.CancelAfter(TimeSpan.FromSeconds(1));
            var buffer = new byte[1024];
            while (await ssl.ReadAsync(buffer, drain.Token) > 0) { /* discard */ }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException or ObjectDisposedException)
        {
            // the message was written and flushed; how the collector closes doesn't change that
        }
    }

    // CAP-33: the name and the chain must hold (a root the machine trusts, or a test's own); a pin must also match.
    private bool Validate(X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors, string? pin, TlsOutcome tls)
    {
        if (cert is null)
        {
            tls.Reason = "the collector sent no certificate";
            return false;
        }
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            tls.Reason = "the collector's certificate isn't issued to Siem:Syslog:Host";
            return false;
        }
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors) && !TrustedByExtraRoots(cert))
        {
            tls.Reason = "the collector's certificate isn't trusted by this server (its chain doesn't reach a trusted root)";
            return false;
        }
        if ((errors & ~(SslPolicyErrors.RemoteCertificateChainErrors)) != SslPolicyErrors.None)
        {
            tls.Reason = $"the collector's certificate was refused ({errors})";
            return false;
        }
        if (!string.IsNullOrWhiteSpace(pin) && !Pinned(cert, pin))
        {
            tls.Reason = "the collector's certificate isn't the one pinned in Siem:Syslog:ServerCertificateThumbprint";
            return false;
        }
        return true;
    }

    private bool TrustedByExtraRoots(X509Certificate cert)
    {
        if (ExtraTrustedRoots is not { Count: > 0 } roots) return false;
        using var leaf = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
        using var custom = new X509Chain();
        custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        custom.ChainPolicy.CustomTrustStore.AddRange(roots);
        custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return custom.Build(leaf);
    }

    private static bool Pinned(X509Certificate cert, string pin)
    {
        var want = CertificateLookup.Normalize(pin);
        using var leaf = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
        var have = PinKind(pin) == HashAlgorithmName.SHA256 ? leaf.GetCertHashString(HashAlgorithmName.SHA256) : leaf.Thumbprint;
        return string.Equals(have, want, StringComparison.OrdinalIgnoreCase);
    }
}
