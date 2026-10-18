namespace IncidentManager.Infrastructure.Siem;

/// <summary>CAP-33: how syslog reaches the collector. Read from <see cref="SiemSyslogOptions.Protocol"/> by name only.</summary>
public enum SyslogProtocol
{
    /// <summary>Fire-and-forget datagrams.</summary>
    Udp,
    /// <summary>Plain TCP, each message LF-terminated (RFC 6587 non-transparent framing).</summary>
    Tcp,
    /// <summary>CAP-33: TLS (RFC 5425), each message octet-counted, with the collector's certificate checked.</summary>
    Tls,
}

/// <summary>
/// Outbound SIEM syslog configuration (config section <c>Siem:Syslog</c>, F-18). Sends each event as a
/// CEF message over syslog (UDP, TCP or TLS) to an SIEM Broker VM / syslog collector. No secret here (a client
/// certificate is named by thumbprint, its key stays in the store), but it is still an infrastructure endpoint, so it
/// lives in server-side config.
/// </summary>
public sealed class SiemSyslogOptions
{
    /// <summary>When false (default), syslog delivery is off.</summary>
    public bool Enabled { get; set; }

    /// <summary>Syslog collector host (SIEM Broker VM, rsyslog, …). With TLS, the name its certificate must carry.</summary>
    public string Host { get; set; } = "";

    /// <summary>514 by default; a TLS collector usually listens on 6514 (RFC 5425).</summary>
    public int Port { get; set; } = 514;

    /// <summary>"Udp" (default, fire-and-forget), "Tcp" or "Tls" (CAP-33), by name (<see cref="SyslogProtocol"/>).</summary>
    public string Protocol { get; set; } = "Udp";

    /// <summary>Syslog facility number (default 16 = local0).</summary>
    public int Facility { get; set; } = 16;

    /// <summary>APP-NAME in the syslog header (RFC 5424).</summary>
    public string AppName { get; set; } = "CaseBook";

    /// <summary>Connect/send timeout for TCP, and connect, handshake and send for TLS.</summary>
    public int TimeoutSeconds { get; set; } = 5;

    /// <summary>
    /// CAP-33, TLS only: the collector's certificate, pinned by its SHA-1 or SHA-256 thumbprint (hex; spaces and colons
    /// ignored). Optional. The chain and the name are checked either way; a pin also refuses any other certificate.
    /// </summary>
    public string ServerCertificateThumbprint { get; set; } = "";

    /// <summary>
    /// CAP-33, TLS only: a client certificate for a collector that asks for one (mutual TLS), by thumbprint in
    /// <c>LocalMachine\My</c>, as <c>Secrets:CyberArk:ClientCertificateThumbprint</c> is. The app pool's account needs
    /// read on its private key. Optional.
    /// </summary>
    public string ClientCertificateThumbprint { get; set; } = "";
}
