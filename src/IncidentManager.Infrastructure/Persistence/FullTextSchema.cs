using System.Globalization;
using System.Text;
using IncidentManager.Domain.Entities;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// CAP-22: CaseBook's SQL Server full-text catalog and the free-text columns Find and the case-list search read by word.
/// Indicators (entity values and labels), case numbers, phase reasons and the review stay substring matches: an indicator
/// is matched by its exact value, and the rest are small. Each table's full-text key is its primary key (a unique,
/// single, non-null column, as full-text needs). Indexed with the English word breaker (fixed, so it doesn't depend on the
/// server's default) and no stoplist, so no word is a noise word that finds nothing; change tracking is automatic, so a
/// write is searchable by word within seconds.
/// <para>
/// <see cref="Script"/> creates whatever of it is missing, and only when the server has Full-Text Search, so it can run on
/// any server at any time: the Diagnostics action runs it, deploy/sql/03-Enable-FullText.sql is a copy of it for a DBA
/// (a test keeps them the same), and the 20261018120000_FullTextSearch migration ran it as it stood then. Full-text DDL
/// can't run inside a transaction, so it runs on its own.
/// </para>
/// </summary>
public static class FullTextSchema
{
    public const string Catalog = "CaseBookText";

    /// <summary>The word breaker's language: 1033, English.</summary>
    public const int Language = 1033;

    /// <summary>One indexed table: its name, the entity mapped to it, its primary key (the full-text key), the columns.</summary>
    public sealed record Table(string Name, Type Entity, string KeyIndex, IReadOnlyList<string> Columns);

    public static readonly IReadOnlyList<Table> Tables =
    [
        new("Cases", typeof(Case), "PK_Cases", ["Title", "Summary"]),
        new("CaseBriefs", typeof(CaseBrief), "PK_CaseBriefs", ["Summary", "WorkingAssessment", "Known", "OpenQuestions"]),
        new("TimelineEntries", typeof(TimelineEntry), "PK_TimelineEntries", ["Description", "Rationale"]),
        new("AnalystNotes", typeof(AnalystNote), "PK_AnalystNotes", ["Body"]),
        new("ActionItems", typeof(ActionItem), "PK_ActionItems", ["Title", "Description"]),
        new("ActionItemComments", typeof(ActionItemComment), "PK_ActionItemComments", ["Body"]),
        new("Evidence", typeof(Evidence), "PK_Evidence", ["OriginalFileName", "Description"]),
    ];

    /// <summary>Every (table, column) indexed.</summary>
    public static IEnumerable<(Table Table, string Column)> Columns => Tables.SelectMany(t => t.Columns.Select(c => (t, c)));

    /// <summary>Creates the catalog, each table's index and each column in it that's missing; nothing without Full-Text.</summary>
    public static string Script { get; } = BuildScript();

    private static string BuildScript()
    {
        var sb = new StringBuilder();
        sb.Append("-- CAP-22: CaseBook's full-text catalog and indexes. Creates only what's missing, and nothing when the server\n");
        sb.Append("-- doesn't have Full-Text Search, so it can be run again at any time. Not inside a transaction.\n");
        sb.Append("IF CAST(ISNULL(SERVERPROPERTY('IsFullTextInstalled'), 0) AS int) = 1\n");
        sb.Append("BEGIN\n");
        sb.Append(CultureInfo.InvariantCulture, $"    IF NOT EXISTS (SELECT 1 FROM sys.fulltext_catalogs WHERE name = N'{Catalog}')\n");
        sb.Append(CultureInfo.InvariantCulture, $"        EXEC(N'CREATE FULLTEXT CATALOG [{Catalog}]');\n");
        foreach (var t in Tables)
        {
            var columns = string.Join(", ", t.Columns.Select(c => string.Create(CultureInfo.InvariantCulture, $"[{c}] LANGUAGE {Language}")));
            sb.Append(CultureInfo.InvariantCulture, $"    IF OBJECT_ID(N'[{t.Name}]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[{t.Name}]'))\n");
            sb.Append(CultureInfo.InvariantCulture, $"        EXEC(N'CREATE FULLTEXT INDEX ON [{t.Name}] ({columns}) KEY INDEX [{t.KeyIndex}] ON [{Catalog}] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');\n");
            foreach (var c in t.Columns)
            {
                sb.Append(CultureInfo.InvariantCulture, $"    IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[{t.Name}]'))\n");
                sb.Append(CultureInfo.InvariantCulture, $"       AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[{t.Name}]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[{t.Name}]'), N'{c}', 'ColumnId'))\n");
                sb.Append(CultureInfo.InvariantCulture, $"        EXEC(N'ALTER FULLTEXT INDEX ON [{t.Name}] ADD ([{c}] LANGUAGE {Language})');\n");
            }
        }
        sb.Append("END;\n");
        return sb.ToString();
    }

    /// <summary>Removes CaseBook's indexes and catalog (the migration's Down).</summary>
    public static string DropScript { get; } = BuildDropScript();

    private static string BuildDropScript()
    {
        var sb = new StringBuilder();
        foreach (var t in Tables)
        {
            sb.Append(CultureInfo.InvariantCulture, $"IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[{t.Name}]'))\n");
            sb.Append(CultureInfo.InvariantCulture, $"    EXEC(N'DROP FULLTEXT INDEX ON [{t.Name}]');\n");
        }
        sb.Append(CultureInfo.InvariantCulture, $"IF EXISTS (SELECT 1 FROM sys.fulltext_catalogs WHERE name = N'{Catalog}')\n");
        sb.Append(CultureInfo.InvariantCulture, $"    EXEC(N'DROP FULLTEXT CATALOG [{Catalog}]');\n");
        return sb.ToString();
    }
}
