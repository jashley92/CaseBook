using System.Globalization;
using System.Text;
using IncidentManager.Application.Export;
using IncidentManager.Domain.Enums;
using static IncidentManager.Application.Common.Csv;

namespace IncidentManager.Application.Intel;

/// <summary>
/// CAP-27: the Indicators page as a CSV, every indicator its filters match rather than one page, whatever the verdict
/// (the IOC feed is the malicious-only blocklist). One row per indicator as the page dedupes it, with its worst verdict,
/// how many cases (and open cases) it's on, and each case's number with the verdict recorded there. Read through
/// <see cref="IndicatorService.ExportAsync"/>, so only cases the person can see are in it; bounded at
/// <see cref="IndicatorService.ExportLimit"/> indicators, and a cut file says so at the top and the end (as CAP-03).
/// Values are as recorded (not defanged), and every cell goes through <c>Csv.Escape</c> (C13). Times are UTC.
/// </summary>
public static class IndicatorCsv
{
    public static string Build(IReadOnlyList<IndicatorRow> rows, DateTimeOffset generatedAtUtc, bool truncated)
    {
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.Append("# CaseBook indicators, as filtered on the Indicators page (cases you can see), generated ")
          .Append(generatedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(" UTC; times are UTC\r\n");
        // BUG-543: no thousands separator; a spreadsheet would split "50,000" at the comma.
        var cut = $"# Truncated: only the first {IndicatorService.ExportLimit.ToString(inv)} indicators in the page's order are here. Narrow the filters to export the rest.\r\n";
        if (truncated) sb.Append(cut);

        sb.Append("type,indicator,worst_verdict,case_count,open_case_count,first_seen_utc,last_seen_utc,cases\r\n");
        foreach (var r in rows)
        {
            sb.Append(IocFeedCsv.FeedType(r.Type)).Append(',')
              .Append(Escape(r.Value)).Append(',')
              .Append(Verdict(r.WorstDisposition)).Append(',')
              .Append(r.CaseCount.ToString(inv)).Append(',')
              .Append(r.OpenCaseCount.ToString(inv)).Append(',')
              .Append(Time(r.FirstSeenUtc)).Append(',')
              .Append(Time(r.LastSeenUtc)).Append(',')
              .Append(Escape(string.Join("; ", r.Cases.Select(c =>
                  $"{c.CaseNumber} ({Verdict(c.Disposition)}{(c.IsExercise ? ", exercise" : "")})")))).Append("\r\n");
        }
        if (truncated) sb.Append(cut);   // CAP-03: at the end too, where a reader scrolling down meets it
        return sb.ToString();
    }

    private static string Verdict(EntityDisposition d) => d.ToString().ToLowerInvariant();

    private static string Time(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
