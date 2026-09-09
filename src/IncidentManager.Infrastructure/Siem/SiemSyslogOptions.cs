namespace IncidentManager.Infrastructure.Siem;

/// <summary>
/// Outbound SIEM syslog configuration (config section <c>Siem:Syslog</c>, F-18). Sends each event as a
/// CEF message over syslog (UDP or TCP) to an SIEM Broker VM / syslog collector. No secret here (syslog
/// is unauthenticated), but it is still an infrastructure endpoint, so it lives in server-side config.
/// </summary>
public sealed class SiemSyslogOptions
{
    /// <summary>When false (default), syslog delivery is off.</summary>
    public bool Enabled { get; set; }

    /// <summary>Syslog collector host (SIEM Broker VM, rsyslog, …).</summary>
    public string Host { get; set; } = "";

    public int Port { get; set; } = 514;

    /// <summary>"Udp" (default, fire-and-forget) or "Tcp".</summary>
    public string Protocol { get; set; } = "Udp";

    /// <summary>Syslog facility number (default 16 = local0).</summary>
    public int Facility { get; set; } = 16;

    /// <summary>APP-NAME in the syslog header (RFC 5424).</summary>
    public string AppName { get; set; } = "CaseBook";

    /// <summary>Connect/send timeout for the TCP protocol.</summary>
    public int TimeoutSeconds { get; set; } = 5;
}
