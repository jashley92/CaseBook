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
    public static string Build(IReadOnlyList<CaseAccessEvent> rows, DateTimeOffset generatedAtUtc, int? truncatedAt = null)
    {
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();

        sb.Append("# CaseBook access log (read and access telemetry, kept outside the tamper-evident chain), generated ")
          .Append(generatedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(" UTC\r\n");
        // REV-65: an export cut at its row limit says so, so the missing oldest rows aren't mistaken for no activity.
        // BUG-543: no thousands separator; a spreadsheet would split "100,000" at the comma and show "100".
        if (truncatedAt is { } limit)
            sb.Append("# Truncated: only the newest ").Append(limit.ToString(inv))
              .Append(" rows are here. Narrow the date range to export the rest.\r\n");

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

    /// <summary>
    /// BUG-132: the access-log entry for an export of the access log itself: the file name and the filter it was run
    /// with, so a review can see who pulled which slice. Kept to the 500-character target label.
    /// </summary>
    public static string ExportLabel(string fileName, AccessLogFilter f)
    {
        var inv = CultureInfo.InvariantCulture;
        var parts = new List<string>
        {
            $"{f.FromUtc?.UtcDateTime.ToString("yyyy-MM-dd", inv) ?? "start"} to {f.ToUtc?.UtcDateTime.ToString("yyyy-MM-dd", inv) ?? "now"}"
        };
        if (!string.IsNullOrWhiteSpace(f.Actor)) parts.Add($"actor {f.Actor}");
        if (!string.IsNullOrWhiteSpace(f.CaseNumber)) parts.Add($"case {f.CaseNumber}");
        if (f.AccessType is { } t) parts.Add($"type {t}");
        if (f.RestrictedOnly) parts.Add("restricted only");
        var label = $"{fileName} ({string.Join(", ", parts)})";
        return label.Length <= 500 ? label : label[..499] + "…";
    }
}
