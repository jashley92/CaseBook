using System.Security.Cryptography;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Storage;

/// <summary>PROD-57: how the conversion of plain files stands, for Diagnostics (in memory since start-up).</summary>
public sealed class EvidenceConversionStatus
{
    public DateTimeOffset? LastRunUtc { get; internal set; }
    public int Converted { get; internal set; }
    public int Remaining { get; internal set; }
    public int Busy { get; internal set; }
    public int Mismatched { get; internal set; }
    public bool Running { get; internal set; }
    public string? LastProblem { get; set; }

    /// <summary>Set by Diagnostics' "Convert now"; the job runs at its next tick rather than waiting.</summary>
    public bool NowRequested { get; set; }
}

/// <summary>
/// PROD-57: encrypts the evidence files and reports stored before encryption was on (or restored from an older backup),
/// once the key is ready. For each plain file:
/// <list type="number">
/// <item>its bytes must hash to what was recorded (a file that doesn't is left as it is, and the re-check reports it:
/// encryption never vouches for a changed or damaged file);</item>
/// <item>it's encrypted to a temporary file beside it, flushed to disk, and that copy decrypted and hashed again;</item>
/// <item>only then is it swapped in with a move that replaces (File.Replace isn't supported on many SMB shares).</item>
/// </list>
/// A file in use (a download, a re-check) is left for the next run, and the re-check never runs at the same time
/// (<see cref="EvidenceFileGate"/>). A file needs free space for one copy of itself. The records aren't touched: the
/// hash is the original file's either way. One audit entry per run says how many were converted.
/// </summary>
public sealed class EvidenceConversion(IServiceScopeFactory scopes, IEvidenceKeyring keys, IOptions<EvidenceStoreOptions> evidence,
    IOptions<ReportOutputOptions> reports, EvidenceFileGate gate, EvidenceConversionStatus status, ILogger<EvidenceConversion>? logger = null)
{
    private readonly string _evidenceRoot = Path.GetFullPath(evidence.Value.RootPath);
    private readonly string _reportRoot = Path.GetFullPath(reports.Value.RootPath);

    private sealed record Item(string Root, string StoragePath, string Sha256);

    /// <summary>Converts up to <paramref name="batch"/> plain files; returns how many it converted (0 when none are left
    /// or the key isn't ready).</summary>
    public async Task<int> RunAsync(int batch, CancellationToken ct = default)
    {
        if (EncryptedFiles.ForNewFile(keys) is not { } key) return 0;
        List<Item> items;
        using (var scope = scopes.CreateScope())
        await using (var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct))
        {
            var ev = await db.Evidence.AsNoTracking().IgnoreQueryFilters().Where(e => e.PurgedAtUtc == null)   // no bytes to convert
                .Select(e => new Item(_evidenceRoot, e.StoragePath, e.Sha256)).ToListAsync(ct);
            var rp = await db.Reports.AsNoTracking().IgnoreQueryFilters()
                .Select(r => new Item(_reportRoot, r.StoragePath, r.ContentSha256)).ToListAsync(ct);
            items = [.. ev, .. rp];
        }

        using var _ = await gate.EnterAsync(ct);
        status.Running = true;
        // A conversion cut off before its swap left only its temporary copy (ciphertext; the plain file is untouched).
        foreach (var root in new[] { _evidenceRoot, _reportRoot }.Where(Directory.Exists))
            foreach (var leftover in Directory.EnumerateFiles(root, "*.cbe1", SearchOption.AllDirectories)) TryDelete(leftover);
        int converted = 0, busy = 0, mismatched = 0, remaining = 0;
        try
        {
            foreach (var item in items)
            {
                ct.ThrowIfCancellationRequested();
                var path = Path.GetFullPath(Path.Combine(item.Root, item.StoragePath));
                if (!path.StartsWith(item.Root + Path.DirectorySeparatorChar, StringComparison.Ordinal) || !File.Exists(path)) continue;
                bool plain;
                try { plain = !EncryptedFiles.IsEncrypted(path); }
                catch (IOException) { busy++; remaining++; continue; }   // in use: the next run
                if (!plain) continue;
                if (converted >= batch) { remaining++; continue; }
                switch (await ConvertAsync(path, item.Sha256, key, ct))
                {
                    case Outcome.Converted: converted++; break;
                    case Outcome.Busy: busy++; remaining++; break;
                    case Outcome.Mismatch: mismatched++; break;
                    case Outcome.NoRoom:
                        remaining++;
                        status.LastProblem = "Not enough free space on the store to convert the next file (it needs room for one copy of itself).";
                        break;
                }
            }
        }
        finally
        {
            status.Running = false;
            status.LastRunUtc = DateTimeOffset.UtcNow;
            status.Converted += converted;
            status.Remaining = remaining;
            status.Busy = busy;
            status.Mismatched = mismatched;
        }

        if (converted > 0)
        {
            logger?.LogInformation("Encrypted {Converted} stored file(s) at rest; {Remaining} left, {Busy} in use, {Mismatched} not matching their record.",
                converted, remaining, busy, mismatched);
            using var scope = scopes.CreateScope();
            await scope.ServiceProvider.GetRequiredService<IAuditWriter>().RecordAsync(AuditAction.Update, "EvidenceKey", key.KeyId, null,
                $"CaseBook upkeep: {converted} stored evidence file(s) and report(s) encrypted at rest with key {key.KeyId}. Their records and hashes are unchanged.",
                ct);
        }
        if (mismatched > 0)
            logger?.LogWarning("{Mismatched} stored file(s) don't match their recorded hash and were left unencrypted; the evidence re-check reports them.",
                mismatched);
        return converted;
    }

    private enum Outcome { Converted, Busy, Mismatch, NoRoom }

    private async Task<Outcome> ConvertAsync(string path, string recorded, (string KeyId, byte[] Key) key, CancellationToken ct)
    {
        var temp = path + ".cbe1";
        try
        {
            long length;
            string before;
            await using (var plain = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                length = plain.Length;
                before = Convert.ToHexString(await SHA256.HashDataAsync(plain, ct)).ToLowerInvariant();
            }
            if (!string.Equals(before, recorded, StringComparison.OrdinalIgnoreCase)) return Outcome.Mismatch;
            if (await StoreVolume.FreeBytesAsync(Path.GetDirectoryName(path)!, ct) is { } free && free < length + (1L << 20)) return Outcome.NoRoom;

            await using (var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            await using (var target = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                var (sha, _) = await EncryptedFiles.WriteAsync(target, source, key, ct);
                if (!string.Equals(sha, recorded, StringComparison.OrdinalIgnoreCase)) { TryDelete(temp); return Outcome.Busy; }   // changed while read
            }
            await using (var check = EncryptedFiles.OpenContent(new FileStream(temp, FileMode.Open, FileAccess.Read, FileShare.Read), keys))
            {
                var after = Convert.ToHexString(await SHA256.HashDataAsync(check, ct)).ToLowerInvariant();
                if (!string.Equals(after, recorded, StringComparison.OrdinalIgnoreCase)) { TryDelete(temp); return Outcome.Busy; }
            }
            File.Move(temp, path, overwrite: true);
            return Outcome.Converted;
        }
        catch (IOException)
        {
            TryDelete(temp);   // in use, or the swap was refused: the plain file is untouched; the next run tries again
            return Outcome.Busy;
        }
        catch (UnauthorizedAccessException)
        {
            TryDelete(temp);
            return Outcome.Busy;
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
