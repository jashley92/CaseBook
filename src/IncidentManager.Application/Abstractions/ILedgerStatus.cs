namespace IncidentManager.Application.Abstractions;

/// <summary>One evidentiary table and whether SQL Server keeps it as an append-only ledger table (E-10).</summary>
public sealed record LedgerTableStatus(string Table, bool IsLedger);

/// <summary>
/// Whether the SQL Server 2022 ledger is on for the evidentiary tables. <see cref="Applicable"/> is false on
/// providers without a ledger (SQLite in development).
/// </summary>
public sealed record LedgerStatus(bool Applicable, IReadOnlyList<LedgerTableStatus> Tables)
{
    public static readonly LedgerStatus NotApplicable = new(false, Array.Empty<LedgerTableStatus>());

    /// <summary>The tables deploy/sql/02-Enable-Ledger.sql converts.</summary>
    public static readonly IReadOnlyList<string> EvidentiaryTables = ["AuditLog", "IntegritySeals", "ChainOfCustodyEvents"];

    public bool AllOn => Applicable && Tables.Count == EvidentiaryTables.Count && Tables.All(t => t.IsLedger);
    public int OnCount => Tables.Count(t => t.IsLedger);
}

/// <summary>Reads the ledger state of the evidentiary tables. Read-only; enabling it is a deploy step.</summary>
public interface ILedgerStatus
{
    Task<LedgerStatus> GetAsync(CancellationToken ct = default);
}
