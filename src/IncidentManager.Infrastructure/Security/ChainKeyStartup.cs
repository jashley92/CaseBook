using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// BUG-26: decides what a missing chain key file means, before anything is written to the audit log. A first start
/// (no keyed entries) or a rotation (the old file moved to the retired folder, so every keyed entry's key is still
/// held) saves the new key. Keyed entries under a key this server doesn't hold mean the key was lost (a restore without
/// the keys folder, a changed WrappedKeyPath), and startup stops: running on a new key would leave those entries
/// unverifiable, and the old key would be gone for good.
/// </summary>
public static class ChainKeyStartup
{
    public static async Task EnsureAsync(IChainKeyring keyring, AppDbContext db, CancellationToken ct = default)
    {
        if (keyring is not ChainKeyring { NewKeyFile: { } missing } ring) return;
        var unknown = (await KeyIdsInUseAsync(db, ct)).Except(keyring.KeyIds, StringComparer.OrdinalIgnoreCase).ToList();
        if (unknown.Count > 0)
            throw new InvalidOperationException(
                $"The audit chain key file '{missing}' is missing, and the audit log has entries keyed with chain key {string.Join(", ", unknown)}, which this server doesn't hold. " +
                "Restore the file (and the certificate it's encrypted to) from backup, or point Integrity:ChainKey:WrappedKeyPath " +
                "at it. CaseBook won't start with a new key, because the existing keyed entries could no longer be verified.");
        ring.SaveNewKey();
    }

    private static async Task<List<string>> KeyIdsInUseAsync(AppDbContext db, CancellationToken ct)
    {
        // A fresh install has no database or no audit table yet: nothing is keyed. BUG-68: anything else (the server
        // unreachable, the login refused) stops startup instead, since it can't show that nothing is keyed, and a new
        // key written now would stay after the database came back.
        try
        {
            // BUG-562: SQL Server's ExistsAsync answers false for error 4060 too (the database is there but can't be opened:
            // offline, restoring, access refused), so there the log is read directly and only a missing table (208) means
            // a first start. The database itself is made by deploy/sql/01-Create-Database.sql before the app first starts.
            if (!db.Database.IsSqlServer()
                && !await db.GetService<Microsoft.EntityFrameworkCore.Storage.IRelationalDatabaseCreator>().ExistsAsync(ct))
                return [];
            return await db.AuditLog.Where(a => a.HashKeyId != null).Select(a => a.HashKeyId!).Distinct().ToListAsync(ct);
        }
        catch (Microsoft.Data.SqlClient.SqlException ex) when (ex.Number == 208) { return []; }   // invalid object name
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.Message.Contains("no such table", StringComparison.OrdinalIgnoreCase)) { return []; }
        // BUG-317: this runs before the migrations, so a database from before the key column (AddAuditHashKeyId) has no
        // such column yet, and so no keyed entries. Turning the chain key on in the same upgrade refused to start.
        catch (Microsoft.Data.SqlClient.SqlException ex) when (ex.Number == 207) { return []; }   // invalid column name
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.Message.Contains("no such column", StringComparison.OrdinalIgnoreCase)) { return []; }
        catch (Exception ex) when (ex is Microsoft.Data.SqlClient.SqlException or Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                "The audit chain key file is missing and the database couldn't be read to check whether existing audit entries " +
                $"need it ({ex.Message}). CaseBook won't create a new chain key until it can check. Fix the database connection, " +
                "or restore the key file, and start again.", ex);
        }
    }
}
