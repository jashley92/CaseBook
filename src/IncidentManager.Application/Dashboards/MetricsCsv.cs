using System.Globalization;
using System.Text;
using IncidentManager.Domain.Enums;
using static IncidentManager.Application.Common.Csv;

namespace IncidentManager.Application.Dashboards;

/// <summary>
/// Formats <see cref="DashboardMetrics"/> as a flat metric/value CSV suitable for a
/// board / regulatory reporting pack. Values are computed over the caller's visible set,
/// so the export honours the same need-to-know scoping as the dashboard. (E-11)
/// </summary>
public static class MetricsCsv
{
    /// <param name="generatedAtUtc">Stamped into the export so the pack is self-dating.</param>
    public static string Build(DashboardMetrics m, DateTimeOffset generatedAtUtc)
    {
        var sb = new StringBuilder();
        sb.Append("Metric,Value\r\n");

        void Row(string metric, string value) =>
            sb.Append(Escape(metric)).Append(',').Append(Escape(value)).Append("\r\n");

        Row("Generated (UTC)", generatedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
        Row("Open items", m.OpenCount.ToString(CultureInfo.InvariantCulture));
        Row("Breaches", m.Breaches.ToString(CultureInfo.InvariantCulture));
        Row("Incidents", m.Incidents.ToString(CultureInfo.InvariantCulture));
        Row("Adverse events", m.AdverseEvents.ToString(CultureInfo.InvariantCulture));
        Row("Internal-origin", m.InternalOrigin.ToString(CultureInfo.InvariantCulture));
        Row("Third-party-origin", m.ThirdPartyOrigin.ToString(CultureInfo.InvariantCulture));
        Row("Legal-referred", m.LegalReferred.ToString(CultureInfo.InvariantCulture));
        Row("Overdue action items", m.OverdueActionItems.ToString(CultureInfo.InvariantCulture));
        Row("SLA at risk", m.SlaAtRisk.ToString(CultureInfo.InvariantCulture));
        Row("SLA breached", m.SlaBreached.ToString(CultureInfo.InvariantCulture));
        Row("Mean hours to contain", m.MeanHoursToContain?.ToString(CultureInfo.InvariantCulture) ?? "");
        Row("Mean hours to resolve", m.MeanHoursToResolve?.ToString(CultureInfo.InvariantCulture) ?? "");

        foreach (var phase in Enum.GetValues<CasePhase>())
        {
            var count = m.ByPhase.FirstOrDefault(p => p.Phase == phase)?.Count ?? 0;
            Row($"Open in phase: {phase}", count.ToString(CultureInfo.InvariantCulture));
        }

        // Monthly trend (derived from open/close timestamps).
        sb.Append("\r\nMonth,Opened,Closed,Open at month end\r\n");
        foreach (var t in m.Trend)
        {
            sb.Append(Escape($"{t.Year:D4}-{t.Month:D2}")).Append(',')
              .Append(t.Opened.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(t.Closed.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(t.OpenAtEnd.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
        }

        // Quarterly rollup of the same trend.
        sb.Append("\r\nQuarter,Opened,Closed,Open at quarter end\r\n");
        foreach (var q in m.Trend.GroupBy(t => (t.Year, Quarter: (t.Month - 1) / 3 + 1)).OrderBy(g => g.Key))
        {
            var opened = q.Sum(t => t.Opened);
            var closed = q.Sum(t => t.Closed);
            var openAtEnd = q.OrderBy(t => t.Month).Last().OpenAtEnd; // state at the quarter's final month
            sb.Append(Escape($"{q.Key.Year:D4}-Q{q.Key.Quarter}")).Append(',')
              .Append(opened.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(closed.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(openAtEnd.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
        }

        return sb.ToString();
    }
}
