using System.Linq.Expressions;

namespace IncidentManager.Application.Abstractions;

/// <summary>CAP-22: how Find and the case-list search match words now.</summary>
public enum FullTextMode
{
    /// <summary>Not SQL Server (SQLite in development): substring matching, always.</summary>
    NotSqlServer,
    /// <summary>The SQL Server instance doesn't have the Full-Text Search feature: substring matching.</summary>
    NotInstalled,
    /// <summary>Full-Text Search is installed, but CaseBook's catalog and indexes aren't there yet.</summary>
    NotCreated,
    /// <summary>Some of the indexes are there or populated, not all: those columns are searched by word, the rest by substring.</summary>
    Partial,
    /// <summary>The indexes are there but still being filled for the first time: substring matching until they're done.</summary>
    Populating,
    /// <summary>Every text column Find searches is full-text indexed and populated.</summary>
    Ready,
    /// <summary>The check couldn't be made (the database didn't answer, or refused the metadata read): substring matching.</summary>
    Unknown,
}

/// <summary>
/// CAP-22: what the last check found, for the queries and Diagnostics. <see cref="Columns"/> are the (entity type, property)
/// pairs that are full-text indexed and populated, so each is searched by word and anything else by substring.
/// </summary>
public sealed record FullTextStatus(
    FullTextMode Mode,
    IReadOnlySet<(Type Entity, string Property)> Columns,
    DateTimeOffset CheckedAtUtc,
    string? Detail = null,
    int Fallbacks = 0,
    string? LastFallback = null)
{
    public static FullTextStatus Substring(FullTextMode mode, DateTimeOffset at, string? detail = null) =>
        new(mode, new HashSet<(Type, string)>(), at, detail);

    /// <summary>Whether any column is searched by word.</summary>
    public bool Any => Columns.Count > 0;

    public bool Covers(Type entity, string property) => Columns.Contains((entity, property));

    /// <summary>Diagnostics' line for it.</summary>
    public string Label => Mode switch
    {
        FullTextMode.Ready => "Search: full-text (SQL Server)",
        FullTextMode.Partial => "Search: full-text on some columns, substring on the rest",
        FullTextMode.Populating => "Search: substring (full-text indexes still being filled)",
        FullTextMode.NotCreated => "Search: substring (full-text installed, CaseBook's indexes not created)",
        FullTextMode.NotInstalled => "Search: substring (full-text not installed)",
        FullTextMode.NotSqlServer => "Search: substring (SQLite)",
        _ => "Search: substring (full-text couldn't be checked)",
    };
}

/// <summary>
/// CAP-22: SQL Server full-text search for Find and the case-list search. The status is checked at start-up, cached, and
/// checked again every few minutes and whenever Diagnostics opens; reading it never throws. A full-text query that fails
/// (an odd search the server can't read, an index dropped since the check) is run again by substring, and
/// <see cref="FellBack"/> logs the first of each kind and marks the status for a fresh check.
/// </summary>
public interface IFullTextSearch
{
    /// <summary>The status as last checked, checked again when it's stale.</summary>
    Task<FullTextStatus> StatusAsync(CancellationToken ct = default);

    /// <summary>Checks now (Diagnostics, and after the indexes are created).</summary>
    Task<FullTextStatus> RefreshAsync(CancellationToken ct = default);

    /// <summary>The provider's full-text predicate: (column, search condition) => CONTAINS(column, condition).</summary>
    Expression<Func<string?, string, bool>> ContainsTemplate { get; }

    /// <summary>Whether <paramref name="ex"/> (or one inside it) is the database refusing a full-text query.</summary>
    bool IsFullTextFailure(Exception ex);

    /// <summary>A full-text query failed and was run again by substring: counted, logged once per kind, re-checked.</summary>
    void FellBack(Exception ex, string search);

    /// <summary>
    /// Creates whatever of CaseBook's full-text catalog and indexes is missing (idempotent). Refused, in words, when the
    /// server doesn't have Full-Text Search or the database account can't create them. Returns the status after.
    /// </summary>
    Task<FullTextStatus> CreateIndexesAsync(CancellationToken ct = default);
}
