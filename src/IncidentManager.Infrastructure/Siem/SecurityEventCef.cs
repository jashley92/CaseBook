using System.Globalization;
using System.Text;
using IncidentManager.Application.Security;

namespace IncidentManager.Infrastructure.Siem;

/// <summary>
/// Formats a <see cref="SecurityEvent"/> as ArcSight <b>CEF</b> and wraps it in an RFC 5424 syslog line
/// for the SIEM syslog transport (F-18). CEF is the SIEM lingua franca (SIEM parses it natively). The
/// header and extension escaping follow the CEF spec. Like the JSON contract, the field set is stable.
/// </summary>
public static class SecurityEventCef
{
    private const string Vendor = "CaseBook";
    private const string Product = "CaseBook";
    private const string Version = "1.0";

    /// <summary>The bare <c>CEF:0|…</c> string (no syslog envelope).</summary>
    public static string ToCef(SecurityEvent e)
    {
        var sb = new StringBuilder();
        sb.Append("CEF:0|").Append(Vendor).Append('|').Append(Product).Append('|').Append(Version).Append('|')
          .Append(e.EventId.ToString(CultureInfo.InvariantCulture)).Append('|')
          .Append(Header(e.Action)).Append('|')
          .Append(CefSeverity(e.Severity)).Append('|');

        // Extension: space-separated key=value with escaped values.
        Ext(sb, "rt", e.AtUtc.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture));
        Ext(sb, "cat", e.Category);
        Ext(sb, "act", e.Action);
        Ext(sb, "outcome", e.Outcome.ToString());
        Ext(sb, "suser", e.Actor);
        if (!string.IsNullOrEmpty(e.ActorUpn)) Ext(sb, "suid", e.ActorUpn);
        if (!string.IsNullOrEmpty(e.CaseNumber)) { Ext(sb, "cs1Label", "caseNumber"); Ext(sb, "cs1", e.CaseNumber); }
        if (!string.IsNullOrEmpty(e.TargetType))
        {
            Ext(sb, "cs2Label", "target");
            Ext(sb, "cs2", string.IsNullOrEmpty(e.TargetId) ? e.TargetType : $"{e.TargetType}:{e.TargetId}");
        }
        if (!string.IsNullOrEmpty(e.Detail)) Ext(sb, "msg", e.Detail);
        Ext(sb, "dvchost", e.Host);
        Ext(sb, "deviceProcessName", e.App);

        return sb.ToString().TrimEnd();
    }

    /// <summary>The full syslog line: <c>&lt;PRI&gt;1 TIMESTAMP HOST APP - - - CEF:…</c> (RFC 5424).</summary>
    public static string ToSyslogLine(SecurityEvent e, int facility, string appName)
    {
        var pri = (facility * 8) + SyslogSeverity(e.Severity);
        var ts = e.AtUtc.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
        var host = string.IsNullOrWhiteSpace(e.Host) ? "-" : e.Host;
        var app = string.IsNullOrWhiteSpace(appName) ? "CaseBook" : appName;
        // VERSION=1, PROCID/MSGID/STRUCTURED-DATA omitted as "-".
        return $"<{pri}>1 {ts} {host} {app} - - - {ToCef(e)}";
    }

    // CEF severity is 0–10.
    private static int CefSeverity(SecuritySeverity s) => s switch
    {
        SecuritySeverity.Info => 3,
        SecuritySeverity.Warning => 6,
        SecuritySeverity.High => 8,
        SecuritySeverity.Critical => 10,
        _ => 3
    };

    // Syslog severity is 0 (emerg) – 7 (debug).
    private static int SyslogSeverity(SecuritySeverity s) => s switch
    {
        SecuritySeverity.Info => 6,      // informational
        SecuritySeverity.Warning => 4,   // warning
        SecuritySeverity.High => 3,      // error
        SecuritySeverity.Critical => 2,  // critical
        _ => 6
    };

    // Header fields escape backslash and pipe.
    private static string Header(string v) => v.Replace("\\", "\\\\").Replace("|", "\\|");

    // Extension values escape backslash, equals, and newlines.
    private static void Ext(StringBuilder sb, string key, string value)
    {
        var v = value.Replace("\\", "\\\\").Replace("=", "\\=").Replace("\r", " ").Replace("\n", "\\n");
        sb.Append(key).Append('=').Append(v).Append(' ');
    }
}
