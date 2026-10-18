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
    public static string Build(IReadOnlyList<AuditLogEntry> entries, DateTimeOffset generatedAtUtc, string? caseNumber = null,
        int? truncatedAt = null)
    {
        var sb = new StringBuilder();
        AppendHeader(sb, generatedAtUtc, caseNumber, truncatedAt);
        foreach (var a in entries) AppendRow(sb, a);
        AppendTail(sb, truncatedAt);
        return sb.ToString();
    }

    // CAP-32: the file in its three parts, so the streamed export (IntegrityService.WriteCsvAsync) writes exactly what
    // Build does, a row at a time.
    internal static void AppendHeader(StringBuilder sb, DateTimeOffset generatedAtUtc, string? caseNumber, int? truncatedAt)
    {
        var inv = CultureInfo.InvariantCulture;
        var scope = string.IsNullOrWhiteSpace(caseNumber) ? "all visible cases" : "case " + CommentText(caseNumber);
        sb.Append("# CaseBook audit trail: ").Append(scope).Append(", generated ")
          .Append(generatedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(" UTC\r\n");
        // REV-65: an export cut at its row limit says so, so the missing oldest rows aren't mistaken for no activity.
        // BUG-543: no thousands separator; a spreadsheet would split "100,000" at the comma and show "100".
        if (truncatedAt is { } limit)
            sb.Append("# Truncated: only the newest ").Append(limit.ToString(inv))
              .Append(" rows are here. Narrow the date range to export the rest.\r\n");

        // `changes` renders the captured before/after diff (e.g. "Legal hold: No → Yes") so an examiner sees
        // what moved without parsing raw JSON; it sits next to the (now field-naming) summary.
        sb.Append("sequence,at_utc,actor,action,entity_type,entity_label,entity_id,case_number,summary,changes,reason,entry_hash\r\n");
    }

    internal static void AppendRow(StringBuilder sb, AuditLogEntry a)
    {
        var inv = CultureInfo.InvariantCulture;
        sb.Append(a.Sequence.ToString(inv)).Append(',')
          .Append(a.AtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(',')
          .Append(Escape(a.Actor)).Append(',')
          .Append(a.Action).Append(',')
          .Append(Escape(a.EntityType)).Append(',')
          .Append(Escape(a.EntityLabel ?? "")).Append(',')
          .Append(Escape(a.EntityId ?? "")).Append(',')
          .Append(Escape(a.CaseNumber ?? "")).Append(',')
          .Append(Escape(a.Summary ?? "")).Append(',')
          .Append(Escape(AuditChangeDetail.ToLine(AuditChangeDetail.Changes(a)))).Append(',')
          .Append(Escape(a.Reason ?? "")).Append(',')
          .Append(Escape(a.EntryHash)).Append("\r\n");
    }

    internal static void AppendTail(StringBuilder sb, int? truncatedAt)
    {
        // CAP-03 (CAP-32): and again at the end, where someone reading to the bottom would take the last row for the oldest.
        // No comma or semicolon in it (BUG-516, BUG-543): it stays one cell.
        if (truncatedAt is { } cut)
            sb.Append("# Truncated at ").Append(cut.ToString(CultureInfo.InvariantCulture)).Append(" rows: narrow the range to export the rest.\r\n");
    }

    // BUG-516: the comment line is one spreadsheet cell that starts with "#". A case number is printed after "case ", so it
    // can't lead a cell unless it opens one itself: with a separator (comma, or the semicolon Excel uses in many locales),
    // a quote, a tab or a line break. Those become spaces, so the value stays inside the line and can't start a formula
    // cell or forge rows below it.
    private static string CommentText(string value)
    {
        var chars = value.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
            if (chars[i] is ',' or ';' or '"' || char.IsControl(chars[i]) || (char.IsSeparator(chars[i]) && chars[i] != ' '))
                chars[i] = ' ';
        return new string(chars).Trim();
    }
}
