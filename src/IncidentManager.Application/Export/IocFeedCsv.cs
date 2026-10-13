using System.Globalization;
using System.Text;
using IncidentManager.Domain.Enums;
using static IncidentManager.Application.Common.Csv;

namespace IncidentManager.Application.Export;

/// <summary>
/// Formats the curated malicious-IOC feed (<see cref="IocFeedRow"/>) as a flat, RFC-4180 CSV
/// blocklist suitable for import into SIEM / a firewall / EDR (E-13). One row per deduped
/// indicator; the type column uses short feed terms (ip/domain/url/filehash) common to those tools.
/// </summary>
public static class IocFeedCsv
{
    /// <param name="generatedAtUtc">Stamped into the header row so the feed is self-dating.</param>
    public static string Build(IReadOnlyList<IocFeedRow> rows, DateTimeOffset generatedAtUtc)
    {
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();

        // A leading comment line documents provenance without breaking parsers (most treat a
        // leading '#'/blank column-count-mismatch line as skippable; the real header follows).
        sb.Append("# CaseBook malicious-IOC feed: confirmed indicators across your visible cases, generated ")
          .Append(generatedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(" UTC\r\n");

        // WF-37: each indicator's TLP marking (the most restrictive across its cases; blank when none is set), last so
        // existing column positions don't move. The feed includes everything; whoever consumes it decides what to share.
        sb.Append("type,indicator,disposition,first_seen_utc,last_seen_utc,case_count,cases,sources,tlp\r\n");

        foreach (var r in rows)
        {
            sb.Append(FeedType(r.Type)).Append(',')
              .Append(Escape(r.Value)).Append(',')
              .Append("malicious").Append(',')
              .Append(r.FirstSeenUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(',')
              .Append(r.LastSeenUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", inv)).Append(',')
              .Append(r.Cases.Count.ToString(inv)).Append(',')
              .Append(Escape(string.Join("; ", r.Cases))).Append(',')
              .Append(Escape(string.Join("; ", r.Sources))).Append(',')
              .Append(Tlp(r.Tlp)).Append("\r\n");
        }

        return sb.ToString();
    }

    private static string Tlp(TlpLevel? t) => t switch
    {
        TlpLevel.Clear => "TLP:CLEAR", TlpLevel.Green => "TLP:GREEN", TlpLevel.Amber => "TLP:AMBER",
        TlpLevel.AmberStrict => "TLP:AMBER+STRICT", TlpLevel.Red => "TLP:RED", _ => ""
    };

    /// <summary>Short indicator-type terms common to firewall / EDR / SIEM blocklist imports.</summary>
    private static string FeedType(EntityType t) => t switch
    {
        EntityType.IpAddress => "ip",
        EntityType.Domain => "domain",
        EntityType.Url => "url",
        EntityType.FileHash => "filehash",
        _ => t.ToString().ToLowerInvariant()
    };
}
