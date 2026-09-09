using System.Globalization;
using System.Text;
using IncidentManager.Domain.Entities;
using static IncidentManager.Application.Common.Csv;

namespace IncidentManager.Application.Access;

/// <summary>
/// Formats the access log (<see cref="CaseAccessEvent"/>) as an RFC-4180 CSV for the admin console
/// export (C-05). One row per coalesced view-session; times are UTC (the stored truth — U-29). This is
/// out-of-chain telemetry, so no chain sequence/hash columns (unlike the audit CSV).
/// </summary>
public static class AccessLogCsv
{
    public static string Build(IReadOnlyList<CaseAccessEvent> rows, DateTimeOffset generatedAtUtc)
    {
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();

        sb.Append("# CaseBook access log — read/access telemetry (out of the tamper-evident chain), generated ")
          .Append(generatedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(" UTC\r\n");

        sb.Append("actor,access_type,case_number,target,restricted,count,first_seen_utc,last_seen_utc\r\n");

        foreach (var r in rows)
        {
            sb.Append(Escape(r.ActorUserId)).Append(',')
              .Append(r.AccessType).Append(',')
              .Append(Escape(r.CaseNumber ?? "")).Append(',')
              .Append(Escape(r.TargetLabel ?? "")).Append(',')
              .Append(r.WasRestricted ? "yes" : "no").Append(',')
              .Append(r.Count.ToString(inv)).Append(',')
              .Append(r.FirstSeenUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(',')
              .Append(r.LastSeenUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append("\r\n");
        }

        return sb.ToString();
    }
}
