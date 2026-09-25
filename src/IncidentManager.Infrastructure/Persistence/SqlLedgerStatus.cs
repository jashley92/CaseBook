using IncidentManager.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// Reads sys.tables.ledger_type for the evidentiary tables on SQL Server (E-10). SQLite has no ledger, so it
/// reports not applicable. A read failure (e.g. no VIEW DEFINITION) is reported as not applicable rather
/// than breaking the page that shows it.
/// </summary>
public sealed class SqlLedgerStatus : ILedgerStatus
{
    private readonly IAppDbContextFactory _factory;

    public SqlLedgerStatus(IAppDbContextFactory factory) => _factory = factory;

    public async Task<LedgerStatus> GetAsync(CancellationToken ct = default)
    {
        using var ctx = _factory.CreateDbContext();
        if (ctx is not DbContext db || !db.Database.IsSqlServer()) return LedgerStatus.NotApplicable;
        try
        {
            // ledger_type: 0 = not a ledger table, 1 = history table, 2 = updatable ledger, 3 = append-only ledger.
            var rows = await db.Database
                .SqlQueryRaw<LedgerRow>(
                    "SELECT name AS [Name], CAST(ledger_type AS int) AS [LedgerType] FROM sys.tables " +
                    "WHERE schema_id = SCHEMA_ID(N'dbo') AND name IN (N'AuditLog', N'IntegritySeals', N'ChainOfCustodyEvents')")
                .ToListAsync(ct);
            var tables = LedgerStatus.EvidentiaryTables
                .Select(t => new LedgerTableStatus(t, rows.Any(r => r.Name == t && r.LedgerType is 2 or 3)))
                .ToList();
            return new LedgerStatus(true, tables);
        }
        catch (Microsoft.Data.SqlClient.SqlException)
        {
            return LedgerStatus.NotApplicable;
        }
    }

    private sealed class LedgerRow
    {
        public string Name { get; set; } = "";
        public int LedgerType { get; set; }
    }
}
