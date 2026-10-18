using System.Globalization;
using System.Text;
using IncidentManager.Domain.Enums;
using static IncidentManager.Application.Common.Csv;

namespace IncidentManager.Application.Cases;

/// <summary>
/// CAP-17: the Cases list as a CSV, every case its filters match rather than one page: the list's columns plus the
/// detected, contained, resolved, closed and reported times. Read with <see cref="CaseService.ListAsync"/>'s own filter and
/// order, the ids at once and the rows a page at a time, so need-to-know (ForUser), the exercise rule and every filter are
/// the list's own; bounded at <see cref="Limit"/> cases, and a cut file says so at the top and the end (as REV-65 and
/// CAP-03). Times are UTC; every cell goes through <c>Csv.Escape</c> (C13).
/// </summary>
public static class CaseListCsv
{
    /// <summary>The most cases one export holds.</summary>
    public const int Limit = 10_000;

    /// <summary>How many cases' rows each read loads.</summary>
    public const int PageSize = 500;

    /// <summary>Every case the filter matches, in the list's order, up to <paramref name="limit"/>; whether more matched.</summary>
    public static Task<(IReadOnlyList<CaseListItem> Items, bool Truncated)> CollectAsync(
        CaseService cases, CaseFilter filter, int limit = Limit, int pageSize = PageSize, CancellationToken ct = default) =>
        CollectAsync(cases, filter, limit, pageSize, afterPage: null, ct);

    /// <summary>
    /// As above; <paramref name="afterPage"/> runs after each read (tests). CAP-17 review: offset pages could miss a case
    /// that moved, while the export read, from a page not yet read to one already read (sort=updated, a note added), and
    /// sort=sla ranked every matching case once a page. So the ordered ids are read once, up to the limit and one more, and
    /// the rows by id, <paramref name="pageSize"/> at a time (<see cref="CaseService.ListAllAsync"/>).
    /// </summary>
    internal static Task<(IReadOnlyList<CaseListItem> Items, bool Truncated)> CollectAsync(
        CaseService cases, CaseFilter filter, int limit, int pageSize, Func<int, Task>? afterPage, CancellationToken ct) =>
        cases.ListAllAsync(filter, limit, pageSize, afterPage, ct);

    /// <summary>The file. The label functions give the names the list shows (configured taxonomy and severity labels);
    /// <paramref name="sla"/> the SLA word the list shows for a row, or blank where it shows none. CAP-36: <paramref name="team"/>
    /// names a case's team (blank for none), in the last column.</summary>
    public static string Build(IReadOnlyList<CaseListItem> items, DateTimeOffset generatedAtUtc, bool truncated,
        Func<Classification?, string> classification, Func<CasePhase, string> phase, Func<Severity, string> severity,
        Func<CaseListItem, string> sla, Func<Guid?, string>? team = null)
    {
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.Append("# CaseBook cases, as filtered on the Cases page (cases you can see), generated ")
          .Append(generatedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(" UTC; times are UTC\r\n");
        // BUG-543: no thousands separator; a spreadsheet would split "10,000" at the comma.
        var cut = $"# Truncated: only the first {Limit.ToString(inv)} cases in the list's order are here. Narrow the filters to export the rest.\r\n";
        if (truncated) sb.Append(cut);

        sb.Append("case_number,title,classification,phase,severity,sla,owner,other_assignees,origin,restricted,legal_referral,")
          .Append("legal_hold,exercise,opened_utc,detected_utc,contained_utc,resolved_utc,closed_utc,reported_utc,team\r\n");
        foreach (var c in items)
        {
            sb.Append(Escape(c.CaseNumber)).Append(',')
              .Append(Escape(c.Title)).Append(',')
              .Append(Escape(classification(c.Classification))).Append(',')
              .Append(Escape(phase(c.Phase))).Append(',')
              .Append(Escape(severity(c.Severity))).Append(',')
              .Append(Escape(sla(c))).Append(',')
              .Append(Escape(c.OwnerName ?? "")).Append(',')
              .Append(c.OtherAssignees.ToString(inv)).Append(',')
              .Append(c.Origin == CaseOrigin.ThirdParty ? "Third-party" : "Internal").Append(',')
              .Append(YesNo(c.IsRestricted)).Append(',')
              .Append(YesNo(c.LegalReferred)).Append(',')
              .Append(YesNo(c.LegalHold)).Append(',')
              .Append(YesNo(c.IsExercise)).Append(',')
              .Append(Time(c.CreatedAtUtc)).Append(',')
              .Append(Time(c.DetectedAtUtc)).Append(',')
              .Append(Time(c.ContainedAtUtc)).Append(',')
              .Append(Time(c.ResolvedAtUtc)).Append(',')
              .Append(Time(c.ClosedAtUtc)).Append(',')
              .Append(Time(c.ReportedAtUtc)).Append(',')
              .Append(Escape(c.TeamId is null ? "" : team?.Invoke(c.TeamId) ?? "")).Append("\r\n");   // CAP-36
        }
        if (truncated) sb.Append(cut);   // CAP-03: at the end too, where a reader scrolling down meets it
        return sb.ToString();
    }

    private static string YesNo(bool b) => b ? "yes" : "no";

    private static string Time(DateTimeOffset? t) =>
        t is { } v ? v.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) : "";
}
