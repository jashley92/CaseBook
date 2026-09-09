using System.Globalization;
using System.Text;
using IncidentManager.Domain.Entities;
using static IncidentManager.Application.Common.Csv;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// Formats a slice of the hash-chained audit trail as an RFC-4180 CSV for examiners (E-24). One row
/// per <see cref="AuditLogEntry"/>; times are UTC (the stored, forensic truth — U-29). The chain
/// sequence and hashes are included so a reviewer can tie an exported row back to the live chain.
/// </summary>
public static class AuditCsv
{
    public static string Build(IReadOnlyList<AuditLogEntry> entries, DateTimeOffset generatedAtUtc, string? caseNumber = null)
    {
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();

        var scope = string.IsNullOrWhiteSpace(caseNumber) ? "all visible cases" : $"case {caseNumber}";
        sb.Append("# CaseBook audit trail — ").Append(scope).Append(", generated ")
          .Append(generatedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(" UTC\r\n");

        sb.Append("sequence,at_utc,actor,action,entity_type,entity_id,case_number,summary,reason,entry_hash\r\n");

        foreach (var a in entries)
        {
            sb.Append(a.Sequence.ToString(inv)).Append(',')
              .Append(a.AtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(',')
              .Append(Escape(a.Actor)).Append(',')
              .Append(a.Action).Append(',')
              .Append(Escape(a.EntityType)).Append(',')
              .Append(Escape(a.EntityId ?? "")).Append(',')
              .Append(Escape(a.CaseNumber ?? "")).Append(',')
              .Append(Escape(a.Summary ?? "")).Append(',')
              .Append(Escape(a.Reason ?? "")).Append(',')
              .Append(Escape(a.EntryHash)).Append("\r\n");
        }

        return sb.ToString();
    }
}
