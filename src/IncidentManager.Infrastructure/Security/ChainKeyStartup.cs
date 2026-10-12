using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

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
        // A fresh install has no database or no audit table yet: nothing is keyed.
        if (!await db.Database.CanConnectAsync(ct)) return [];
        try { return await db.AuditLog.Where(a => a.HashKeyId != null).Select(a => a.HashKeyId!).Distinct().ToListAsync(ct); }
        catch (Exception ex) when (ex is Microsoft.Data.SqlClient.SqlException or Microsoft.Data.Sqlite.SqliteException) { return []; }
    }
}
