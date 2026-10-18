using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Security;

/// <summary>PROD-57: one envelope copy's state at the last check, for Diagnostics.</summary>
public sealed record EnvelopeCopyStatus(string Copy, string Where, bool Good, string? Problem);

/// <summary>PROD-57: one recovery certificate's state at the last check.</summary>
public sealed record RecoveryCertificateStatus(string Thumbprint, string Subject, DateTimeOffset NotAfter, bool InEnvelope);

/// <summary>PROD-57: what the last check found, for Diagnostics (key ids and places only; never a key).</summary>
public sealed record EvidenceKeyHealth(
    DateTimeOffset CheckedUtc,
    EvidenceKeyState State,
    string? KeyId,
    string? Protection,
    IReadOnlyList<EnvelopeCopyStatus> Copies,
    IReadOnlyList<RecoveryCertificateStatus> Recovery,
    SharesIssued? Shares,
    DateTimeOffset? LastDrillUtc,
    IReadOnlyList<string> Warnings);

/// <summary>
/// PROD-57: the evidence key. Loaded at start-up and checked again every few minutes until it's available, then daily:
/// <list type="bullet">
/// <item>The key's server copy is protected by the integrity keys already configured (no new certificate or vault object):
/// <c>Storage:Encryption:CertificateThumbprint</c> if set, else the chain key's certificate, else the seal-signing
/// certificate, else (chain key from CyberArk) a key derived from the chain key.</item>
/// <item>The envelope is kept in three places: the keys folder (authoritative), the database and beside the evidence.
/// A missing or damaged copy is rewritten from a good one; a copy naming another key is reported, never used.</item>
/// <item>A renewed certificate (the old one still in the store) gets the key re-encrypted to it at the next check, and
/// configured recovery certificates are added to (or dropped from) the envelope the same way.</item>
/// <item>The one hard rule (as BUG-26 for the chain key): a new key is never made while an envelope or an encrypted file
/// names a key this server can't open, or while the database can't be read to tell. The key would be new, and the
/// files written under the old one unreadable.</item>
/// <item>A key that can't be opened makes the keyring <see cref="EvidenceKeyState.Unavailable"/>: evidence and reports
/// pause, the rest of CaseBook works, and the next check (every 5 minutes) clears it when the cause is fixed.</item>
/// <item>No file is encrypted until a backup exists (a recovery certificate, or shares issued), so one lost certificate
/// can't lose everything.</item>
/// </list>
/// The key is held in memory only and zeroed when replaced.
/// </summary>
public sealed class EvidenceKeyring : IEvidenceKeyring, IDisposable
{
    private readonly EvidenceEncryptionOptions _options;
    private readonly SealSigningOptions _integrity;
    private readonly string _evidenceRoot;
    private readonly string _reportRoot;
    private readonly IChainKeyring _chainKeys;
    private readonly IServiceScopeFactory? _scopes;
    private readonly ILogger<EvidenceKeyring>? _logger;
    private readonly IncidentManager.Application.Security.ISecurityEventSink? _siem;
    private readonly HashSet<Guid> _recorded = [];   // keytool records already written to the audit trail this run
    private readonly SemaphoreSlim _gate = new(1, 1);   // C21: one load at a time, so an older one can't land after a newer

    private sealed record Loaded(EvidenceKeyState State, string? KeyId, byte[]? Key, string? Problem);
    private bool _loadedOnce;
    private volatile Loaded _now;

    public EvidenceKeyring(IOptions<EvidenceEncryptionOptions> options, IOptions<SealSigningOptions> integrity,
        IOptions<EvidenceStoreOptions> evidence, IOptions<ReportOutputOptions> reports, IChainKeyring chainKeys,
        IServiceScopeFactory? scopes = null, ILogger<EvidenceKeyring>? logger = null,
        IncidentManager.Application.Security.ISecurityEventSink? siem = null)
    {
        _siem = siem;
        _options = options.Value;
        _integrity = integrity.Value;
        _evidenceRoot = Path.GetFullPath(evidence.Value.RootPath);
        _reportRoot = Path.GetFullPath(reports.Value.RootPath);
        _chainKeys = chainKeys;
        _scopes = scopes;
        _logger = logger;
        _now = new Loaded(_options.Enabled ? EvidenceKeyState.Unavailable : EvidenceKeyState.Off, null, null,
            _options.Enabled ? "The evidence key hasn't been loaded yet." : null);
    }

    public EvidenceKeyState State => _now.State;
    public string? CurrentKeyId => _now.State == EvidenceKeyState.Ready ? _now.KeyId : null;
    public string? Problem => _now.Problem;

    public byte[]? Key(string keyId) =>
        _now is { Key: { } k, KeyId: { } id } && string.Equals(id, keyId, StringComparison.Ordinal) ? k : null;

    public void Dispose()
    {
        Replace(new Loaded(EvidenceKeyState.Off, null, null, null));   // zeroes the key held
        _gate.Dispose();
    }

    /// <summary>What the last check found, for Diagnostics.</summary>
    public EvidenceKeyHealth? Health { get; private set; }

    public string EnvelopePath => string.IsNullOrWhiteSpace(_options.EnvelopePath)
        ? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(_integrity.SigningKeyPath)) ?? ".", "evidence-key.json")
        : Path.GetFullPath(_options.EnvelopePath);

    public string EvidenceRootEnvelopePath => Path.Combine(_evidenceRoot, ".key", "evidence-key.json");

    /// <summary>Loads (or checks) the key: see the class summary. Never throws for a missing or unreadable key; the state says.</summary>
    public async Task<EvidenceKeyState> LoadAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var before = _now.State;
            var (loaded, health) = await CheckAsync(ct);
            // Review finding 7: the daily check opens the same key again. Keep the array writers already hold (zeroing it
            // under a save in progress would wrap that file's key under zeros) and drop the new copy instead.
            if (_now.Key is { } held && loaded.Key is { } fresh && !ReferenceEquals(held, fresh)
                && CryptographicOperations.FixedTimeEquals(held, fresh))
            {
                CryptographicOperations.ZeroMemory(fresh);
                loaded = loaded with { Key = held };
            }
            Replace(loaded);
            Health = health;
            // Before the first load the state reads Unavailable ("not loaded yet"), so the first load always logs: a key
            // that can't be opened at start-up gets its Critical line too.
            if (!_loadedOnce || loaded.State != before) LogChange(loaded);
            // PROD-59: the SOC sees the key go and come back, once per change.
            if (loaded.State == EvidenceKeyState.Unavailable && (!_loadedOnce || before != EvidenceKeyState.Unavailable))
                Emit(IncidentManager.Application.Security.SecurityEvents.EvidenceKeyUnavailable(loaded.Problem ?? "The evidence key can't be opened."));
            else if (loaded.State == EvidenceKeyState.Ready && _loadedOnce && before == EvidenceKeyState.Unavailable)
                Emit(IncidentManager.Application.Security.SecurityEvents.EvidenceKeyChanged("KeyAvailable", loaded.KeyId!,
                    "The evidence key can be opened again; evidence and reports resume."));
            _loadedOnce = true;
            return loaded.State;
        }
        finally { _gate.Release(); }
    }

    private void Replace(Loaded next)
    {
        var old = _now;
        _now = next;
        if (old.Key is { } k && !ReferenceEquals(k, next.Key)) CryptographicOperations.ZeroMemory(k);
    }

    private void LogChange(Loaded now)
    {
        switch (now.State)
        {
            case EvidenceKeyState.Ready:
                _logger?.LogInformation("Evidence encryption is on: new evidence and reports are encrypted with key {KeyId}.", now.KeyId);
                break;
            case EvidenceKeyState.Unavailable:
                _logger?.LogCritical("The evidence key can't be opened: {Problem} Encrypted evidence and reports can't be read or written " +
                                     "until it's fixed; the rest of CaseBook works. OPERATIONS.md section 2 (Evidence key recovery).", now.Problem);
                break;
            case EvidenceKeyState.NeedsBackup:
                _logger?.LogWarning("Evidence encryption is set up but not on yet: {Problem}", now.Problem);
                break;
            case EvidenceKeyState.NotConfigured:
                _logger?.LogWarning("Evidence encryption is turned on but can't start: {Problem}", now.Problem);
                break;
        }
    }

    // ---- the check ----

    private sealed record Protection(string Describe, string Kind, string Ref, Func<byte[], string> Wrap, Func<WrappedKey, byte[]?> Unwrap,
        bool CanWrap = true);

    private async Task<(Loaded, EvidenceKeyHealth)> CheckAsync(CancellationToken ct)
    {
        var warnings = new List<string>();
        var copies = new List<EnvelopeCopyStatus>();
        if (!_options.Enabled)
            return (new Loaded(EvidenceKeyState.Off, null, null, null), Report(EvidenceKeyState.Off, null, null, copies, [], null, warnings));

        // The copies: the keys folder first (it's authoritative), then the database's (every row, newest first: review
        // finding 5, a row for another key mustn't hide this one's), then the one beside the evidence.
        var fileJson = ReadFile(EnvelopePath, "keys folder", copies, ct);
        var (dbRows, dbReadable) = await ReadDatabaseAsync(copies, ct);
        var rootJson = ReadFile(EvidenceRootEnvelopePath, "beside the evidence", copies, ct);
        var all = new[] { fileJson }.Concat(dbRows).Append(rootJson).ToList();
        var named = all.Select(KeyEnvelope.Parse).OfType<KeyEnvelope>().Select(e => e.KeyId).Distinct().ToList();

        var protection = ResolveProtection(warnings);
        if (protection is null)
        {
            // Review finding 10: with no envelope anywhere, encryption simply can't start yet (files are stored as before).
            // With one, encryption was on and its protection was taken away: the key is unavailable, and nothing new is
            // stored unencrypted beside files that are.
            if (named.Count > 0)
                return (new Loaded(EvidenceKeyState.Unavailable, null, null,
                        $"Evidence is encrypted (key {string.Join(", ", named)}), but no certificate or chain key is configured to open " +
                        "its key. Put back the setting that protected it (Storage:Encryption:CertificateThumbprint, Integrity:ChainKey or " +
                        "Integrity:SigningKey), or recover the key onto a new certificate with casebook-keytool recover."),
                    Report(EvidenceKeyState.Unavailable, null, null, copies, [], null, warnings));
            const string why = "There's no integrity certificate or chain key to protect the evidence key with. Set " +
                               "Integrity:ChainKey (Certificate) or Integrity:SigningKey (CertificateStore), or " +
                               "Storage:Encryption:CertificateThumbprint (OPERATIONS.md section 2).";
            return (new Loaded(EvidenceKeyState.NotConfigured, null, null, why), Report(EvidenceKeyState.NotConfigured, null, null, copies, [], null, warnings));
        }

        byte[]? key = null;
        KeyEnvelope? envelope = null;
        foreach (var json in all)
        {
            if (KeyEnvelope.Parse(json) is not { } e || Open(e, protection) is not { } k) continue;
            if (KeyWrap.KeyIdOf(k) != e.KeyId) { CryptographicOperations.ZeroMemory(k); continue; }
            (key, envelope) = (k, e);
            break;
        }
        // The database copy compared and rewritten is this key's row (null when there's none yet).
        var dbJson = envelope is null ? null : dbRows.FirstOrDefault(j => KeyEnvelope.Parse(j)?.KeyId == envelope.KeyId);

        if (key is null || envelope is null)
        {
            if (named.Count > 0)
                return Unavailable($"The evidence key envelope (key {string.Join(", ", named)}) can't be opened with {protection.Describe}. " +
                                   "Restore the certificate, or recover the key with casebook-keytool recover (a recovery certificate or the shares).");
            if (!dbReadable)
                return Unavailable("The database couldn't be read to check whether an evidence key already exists, so no new key was made.");
            // Review finding 6: a certificate that isn't in the store can't protect a new key; say so, don't throw.
            if (!protection.CanWrap)
                return Unavailable($"No evidence key exists yet, and {protection.Describe}, so none was made.");
            if (await EncryptedFileKeyIdAsync(ct) is { } inUse)
                return Unavailable($"Files are encrypted with evidence key {inUse}, but no envelope for it was found in the keys folder, " +
                                   "the database or beside the evidence. Restore evidence-key.json from a backup, or recover the key with " +
                                   "casebook-keytool recover. No new key was made.");
            (key, envelope) = await CreateAsync(protection, copies, warnings, ct);
            if (key is null || envelope is null)
                return Unavailable("A new evidence key couldn't be stored in every place it must be kept (see the log); it wasn't used.");
        }
        else
        {
            var keyId = envelope.KeyId;
            envelope = await UpkeepAsync(envelope, key, protection, fileJson, dbJson, rootJson,
                all.Select(KeyEnvelope.Parse).OfType<KeyEnvelope>().Where(e => e.KeyId == keyId).ToList(), copies, warnings, ct);
        }

        var recovery = RecoveryStatus(envelope, warnings);
        if (envelope.LastDrillUtc is not { } drill || DateTimeOffset.UtcNow - drill > TimeSpan.FromDays(365))
            warnings.Add("No recovery drill in the last 12 months: run casebook-keytool verify with a recovery certificate or the shares.");
        var state = envelope.HasBackup ? EvidenceKeyState.Ready : EvidenceKeyState.NeedsBackup;
        var problem = envelope.HasBackup ? null
            : "No backup of the evidence key exists yet, so files are still stored unencrypted. Add a recovery certificate " +
              "(Storage:Encryption:RecoveryCertificates) or issue shares (casebook-keytool split).";
        return (new Loaded(state, envelope.KeyId, key, problem),
            Report(state, envelope.KeyId, protection.Describe, copies, recovery, envelope, warnings));

        (Loaded, EvidenceKeyHealth) Unavailable(string why) =>
            (new Loaded(EvidenceKeyState.Unavailable, null, null, why), Report(EvidenceKeyState.Unavailable, null, protection.Describe, copies, [], null, warnings));
    }

    private static EvidenceKeyHealth Report(EvidenceKeyState state, string? keyId, string? protection, List<EnvelopeCopyStatus> copies,
        IReadOnlyList<RecoveryCertificateStatus> recovery, KeyEnvelope? envelope, List<string> warnings) =>
        new(DateTimeOffset.UtcNow, state, keyId, protection, copies, recovery, envelope?.Shares, envelope?.LastDrillUtc, warnings);

    // The server's protection, in the order the plan sets; null when there's none.
    private Protection? ResolveProtection(List<string> warnings)
    {
        string? thumbprint = null, store = null, whose = null;
        if (!string.IsNullOrWhiteSpace(_options.CertificateThumbprint))
            (thumbprint, store, whose) = (_options.CertificateThumbprint, _options.StoreLocation, "Storage:Encryption");
        else if (_integrity.ChainKey is { Enabled: true, Source: ChainKeySource.Certificate } ck && !string.IsNullOrWhiteSpace(ck.CertificateThumbprint))
            (thumbprint, store, whose) = (ck.CertificateThumbprint, ck.StoreLocation, "the audit chain key's");
        else if (_integrity.SigningKey is { Source: SigningKeySource.CertificateStore } sk && !string.IsNullOrWhiteSpace(sk.CertificateThumbprint))
            (thumbprint, store, whose) = (sk.CertificateThumbprint, sk.StoreLocation, "the seal-signing");

        if (thumbprint is not null)
        {
            X509Certificate2 cert;
            try { cert = CertificateLookup.FindRsa(thumbprint, store!, "Storage:Encryption"); }
            catch (InvalidOperationException ex)
            {
                warnings.Add(ex.Message);
                // Still a protection: an envelope made under it names it, and opening it fails with the reason.
                return new Protection($"certificate {CertificateLookup.Normalize(thumbprint)} ({whose}), which isn't in the store",
                    WrappedKey.Certificate, CertificateLookup.Normalize(thumbprint), _ => throw new InvalidOperationException(ex.Message), _ => null,
                    CanWrap: false);
            }
            var normalized = CertificateLookup.Normalize(cert.Thumbprint);
            var location = store!;
            return new Protection($"certificate {normalized} ({whose})", WrappedKey.Certificate, normalized,
                data => KeyWrap.ToCertificate(cert, data),
                w => UnwrapCertificate(w, location, cert));
        }

        if (_integrity.ChainKey is { Enabled: true, Source: ChainKeySource.CyberArk } && _chainKeys.CurrentKeyId is { } chainId)
            return new Protection($"the audit chain key from CyberArk ({chainId})", WrappedKey.ChainKey, chainId,
                data => KeyWrap.UnderChainKey(_chainKeys.Key(chainId)!, data),
                w => _chainKeys.Key(w.Ref) is { } k ? TryOpen(() => KeyWrap.FromChainKey(k, w.Data)) : null);
        return null;
    }

    // The envelope names the certificate it was encrypted to; after a renewal that's the old one, still in the store.
    private static byte[]? UnwrapCertificate(WrappedKey w, string store, X509Certificate2 current)
    {
        if (w.Kind != WrappedKey.Certificate) return null;
        if (string.Equals(CertificateLookup.Normalize(w.Ref), CertificateLookup.Normalize(current.Thumbprint), StringComparison.Ordinal))
            return TryOpen(() => KeyWrap.FromCertificate(current, w.Data));
        try
        {
            using var old = CertificateLookup.FindRsa(w.Ref, store, "the evidence key envelope");
            return TryOpen(() => KeyWrap.FromCertificate(old, w.Data));
        }
        catch (InvalidOperationException) { return null; }
    }

    private static byte[]? TryOpen(Func<byte[]> open)
    {
        try { return open(); }
        catch (Exception ex) when (ex is CryptographicException or FormatException) { return null; }
    }

    private static byte[]? Open(KeyEnvelope e, Protection p) => p.Unwrap(e.Server);

    // ---- copies ----

    private static string? ReadFile(string path, string copy, List<EnvelopeCopyStatus> copies, CancellationToken ct)
    {
        try
        {
            var read = Task.Run(() => File.Exists(path) ? File.ReadAllText(path) : null, ct);
            var json = read.Wait(StoreVolume.TimeLimit, ct) ? read.Result : throw new TimeoutException("no answer in time");
            copies.Add(new EnvelopeCopyStatus(copy, path, json is not null && KeyEnvelope.Parse(json) is not null,
                json is null ? "missing" : KeyEnvelope.Parse(json) is null ? "damaged" : null));
            return json;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TimeoutException or AggregateException)
        {
            copies.Add(new EnvelopeCopyStatus(copy, path, false, ex.GetBaseException().Message));
            return null;
        }
    }

    private async Task<(List<string> Rows, bool Readable)> ReadDatabaseAsync(List<EnvelopeCopyStatus> copies, CancellationToken ct)
    {
        if (_scopes is null) return ([], true);
        try
        {
            using var scope = _scopes.CreateScope();
            await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
            var rows = await db.KeyEnvelopes.AsNoTracking().OrderByDescending(r => r.UpdatedAtUtc).Select(r => r.EnvelopeJson).ToListAsync(ct);
            var good = rows.Any(r => KeyEnvelope.Parse(r) is not null);
            copies.Add(new EnvelopeCopyStatus("database", "KeyEnvelopes", good, rows.Count == 0 ? "missing" : good ? null : "damaged"));
            return (rows, true);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            copies.Add(new EnvelopeCopyStatus("database", "KeyEnvelopes", false, ex.GetBaseException().Message));
            return ([], false);
        }
    }

    // Writes every copy that isn't this envelope; false if the keys folder's or the evidence root's couldn't be written.
    private async Task<bool> WriteCopiesAsync(KeyEnvelope e, string? fileJson, string? dbJson, string? rootJson, List<EnvelopeCopyStatus> copies,
        List<string> warnings, CancellationToken ct)
    {
        var json = e.ToJson();
        var ok = true;
        if (fileJson != json) ok &= WriteFile(EnvelopePath, json, "keys folder", copies, warnings);
        if (rootJson != json) ok &= WriteFile(EvidenceRootEnvelopePath, json, "beside the evidence", copies, warnings, within: _evidenceRoot);
        if (dbJson != json && _scopes is not null)
        {
            try
            {
                using var scope = _scopes.CreateScope();
                await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
                var row = await db.KeyEnvelopes.FirstOrDefaultAsync(r => r.KeyId == e.KeyId, ct);
                if (row is null) db.KeyEnvelopes.Add(row = new KeyEnvelopeRecord { KeyId = e.KeyId });
                row.EnvelopeJson = json;
                row.UpdatedAtUtc = e.UpdatedUtc;
                await db.SaveChangesAsync(ct);
                Mark(copies, "database", "KeyEnvelopes", null);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                warnings.Add($"The database's copy of the evidence key envelope couldn't be written: {ex.GetBaseException().Message}");
                Mark(copies, "database", "KeyEnvelopes", ex.GetBaseException().Message);
            }
        }
        return ok;
    }

    // within: a folder that must already be there (the evidence store's): PROD-56, a store that has vanished is reported,
    // never recreated by writing this copy into it.
    private static bool WriteFile(string path, string json, string copy, List<EnvelopeCopyStatus> copies, List<string> warnings,
        string? within = null)
    {
        try
        {
            var write = Task.Run(() =>
            {
                if (within is not null && !Directory.Exists(within))
                    throw new DirectoryNotFoundException($"the evidence store's folder {within} isn't there");
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                var temp = path + ".new";
                File.WriteAllText(temp, json);
                File.Move(temp, path, overwrite: true);
            });
            if (!write.Wait(StoreVolume.TimeLimit)) throw new TimeoutException("no answer in time");
            Mark(copies, copy, path, null);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TimeoutException or AggregateException)
        {
            var why = ex.GetBaseException().Message;
            warnings.Add($"The evidence key envelope {copy} ({path}) couldn't be written: {why}");
            Mark(copies, copy, path, why);
            return false;
        }
    }

    private static void Mark(List<EnvelopeCopyStatus> copies, string copy, string where, string? problem)
    {
        copies.RemoveAll(c => c.Copy == copy);
        copies.Add(new EnvelopeCopyStatus(copy, where, problem is null, problem));
    }

    // ---- making and keeping the envelope ----

    private async Task<(byte[]?, KeyEnvelope?)> CreateAsync(Protection p, List<EnvelopeCopyStatus> copies, List<string> warnings, CancellationToken ct)
    {
        var key = RandomNumberGenerator.GetBytes(KeyWrap.KeySize);
        var now = DateTimeOffset.UtcNow;
        var envelope = new KeyEnvelope
        {
            KeyId = KeyWrap.KeyIdOf(key), CreatedUtc = now, UpdatedUtc = now,
            Server = new WrappedKey { Kind = p.Kind, Ref = p.Ref, Data = p.Wrap(key) },
        };
        SyncRecovery(envelope, key, warnings);
        // Kept in the keys folder and beside the evidence, or not used at all: a key only one place holds is one disk from lost.
        if (!await WriteCopiesAsync(envelope, null, null, null, copies, warnings, ct))
        {
            TryDelete(EnvelopePath);
            TryDelete(EvidenceRootEnvelopePath);
            CryptographicOperations.ZeroMemory(key);
            return (null, null);
        }
        var created = $"Evidence encryption key {envelope.KeyId} created, protected by {p.Describe}, with {envelope.Recovery.Count} recovery certificate(s).";
        await AuditAsync(AuditAction.Create, envelope.KeyId, created, ct);
        Emit(IncidentManager.Application.Security.SecurityEvents.EvidenceKeyChanged("KeyCreated", envelope.KeyId, created));
        return (key, envelope);
    }

    private async Task<KeyEnvelope> UpkeepAsync(KeyEnvelope envelope, byte[] key, Protection p, string? fileJson, string? dbJson, string? rootJson,
        List<KeyEnvelope> sameKey, List<EnvelopeCopyStatus> copies, List<string> warnings, CancellationToken ct)
    {
        var changes = new List<string>();
        // Review finding 1: the copy that opened first may be older than another copy of the same key (a keys folder
        // restored from before shares were issued or a drill was run). The newest of those records is kept, so a stale
        // copy can't erase the only record of a backup and drop the store back to storing files unencrypted.
        foreach (var other in sameKey)
        {
            if (other.Shares is { } shares && (envelope.Shares is null || shares.IssuedUtc > envelope.Shares.IssuedUtc))
            {
                envelope.Shares = shares;
                changes.Add("kept the record of shares issued from another copy");
            }
            if (other.LastDrillUtc is { } drill && (envelope.LastDrillUtc is null || drill > envelope.LastDrillUtc))
            {
                (envelope.LastDrillUtc, envelope.LastDrillBy) = (drill, other.LastDrillBy);
                changes.Add("kept the last recovery drill from another copy");
            }
            var missing = other.Records.Where(r => envelope.Records.All(m => m.Id != r.Id)).ToList();
            if (missing.Count > 0)
            {
                envelope.Records = envelope.Records.Concat(missing).OrderByDescending(r => r.AtUtc).Take(KeyEnvelope.MaxRecords)
                    .OrderBy(r => r.AtUtc).ToList();
                changes.Add("kept the keytool records from another copy");
            }
        }
        await RecordKeyToolActionsAsync(envelope, dbJson, ct);
        // A renewed certificate (or a new choice of protection): the key is re-encrypted to the current one. Review finding
        // 6: not to a certificate that isn't in the store (the envelope still opens with the one it names).
        if (envelope.Server.Kind != p.Kind || !string.Equals(envelope.Server.Ref, p.Ref, StringComparison.OrdinalIgnoreCase))
        {
            if (p.CanWrap)
            {
                envelope.Server = new WrappedKey { Kind = p.Kind, Ref = p.Ref, Data = p.Wrap(key) };
                changes.Add($"re-encrypted to {p.Describe}");
            }
            else warnings.Add($"The evidence key is still protected by {envelope.Server.Ref}: {p.Describe}, so it wasn't re-encrypted to it.");
        }
        if (SyncRecovery(envelope, key, warnings) is { Length: > 0 } recoveryChange) changes.Add(recoveryChange);
        // Copies naming another key aren't used or overwritten silently: they're reported.
        if (KeyEnvelope.Parse(rootJson) is { } otherRoot && otherRoot.KeyId != envelope.KeyId)
            warnings.Add($"The envelope beside the evidence names key {otherRoot.KeyId}, not {envelope.KeyId}: it was replaced by this key's.");
        if (changes.Count > 0) envelope.UpdatedUtc = DateTimeOffset.UtcNow;
        await WriteCopiesAsync(envelope, changes.Count > 0 ? null : fileJson, changes.Count > 0 ? null : dbJson,
            changes.Count > 0 ? null : rootJson, copies, warnings, ct);
        if (changes.Count > 0)
        {
            await AuditAsync(AuditAction.Update, envelope.KeyId, $"Evidence encryption key {envelope.KeyId}: {string.Join("; ", changes)}.", ct);
            if (changes.Any(c => c.StartsWith("re-encrypted", StringComparison.Ordinal) || c.Contains("recovery certificate", StringComparison.Ordinal)))
                Emit(IncidentManager.Application.Security.SecurityEvents.EvidenceKeyChanged("KeyProtectionChanged", envelope.KeyId,
                    string.Join("; ", changes)));
            _logger?.LogInformation("Evidence encryption key {KeyId}: {Changes}. Every envelope copy was rewritten; no file changes.",
                envelope.KeyId, string.Join("; ", changes));
        }
        return envelope;
    }

    // The recovery copies match the configured certificates and carry the current chain key; what changed, or "".
    private string SyncRecovery(KeyEnvelope envelope, byte[] key, List<string> warnings)
    {
        var configured = new List<X509Certificate2>();
        foreach (var path in _options.RecoveryCertificates.Where(p => !string.IsNullOrWhiteSpace(p)))
        {
            try { configured.Add(X509CertificateLoader.LoadCertificateFromFile(path)); }
            catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
            {
                warnings.Add($"Recovery certificate {path} couldn't be read: {ex.Message}");
            }
        }
        var chainId = _chainKeys.CurrentKeyId;
        var chainKey = chainId is null ? null : _chainKeys.Key(chainId);
        var added = 0;
        var kept = new List<RecoveryCopy>();
        foreach (var cert in configured)
        {
            var thumb = CertificateLookup.Normalize(cert.Thumbprint);
            var existing = envelope.Recovery.FirstOrDefault(r => string.Equals(r.Thumbprint, thumb, StringComparison.OrdinalIgnoreCase));
            if (existing is not null && existing.ChainKeyId == chainId) { kept.Add(existing); continue; }
            try
            {
                kept.Add(new RecoveryCopy
                {
                    Thumbprint = thumb, Subject = cert.Subject, NotAfter = cert.NotAfter.ToUniversalTime(),
                    Data = KeyWrap.ToCertificate(cert, KeyWrap.Pack(key, chainKey)), ChainKeyId = chainId,
                });
                if (existing is null) added++;
            }
            catch (CryptographicException ex)
            {
                // RSA-OAEP fits about 190 bytes in a 2048-bit key: the evidence key alone if the chain key doesn't fit.
                warnings.Add($"Recovery certificate {thumb} could hold the evidence key but not the chain key too ({ex.Message}).");
                kept.Add(new RecoveryCopy
                {
                    Thumbprint = thumb, Subject = cert.Subject, NotAfter = cert.NotAfter.ToUniversalTime(),
                    Data = KeyWrap.ToCertificate(cert, KeyWrap.Pack(key, null)), ChainKeyId = null,
                });
            }
        }
        var removed = envelope.Recovery.Count(r => !kept.Any(k => string.Equals(k.Thumbprint, r.Thumbprint, StringComparison.OrdinalIgnoreCase)));
        var refreshed = kept.Count(k => envelope.Recovery.Any(r => r.Thumbprint == k.Thumbprint && r.Data != k.Data));
        foreach (var c in configured) c.Dispose();
        envelope.Recovery = kept;
        var parts = new List<string>();
        if (added > 0) parts.Add($"{added} recovery certificate(s) added");
        if (removed > 0) parts.Add($"{removed} recovery certificate(s) no longer configured removed");
        if (refreshed > 0) parts.Add($"{refreshed} recovery copy(ies) updated to the current chain key");
        return string.Join("; ", parts);
    }

    private static List<RecoveryCertificateStatus> RecoveryStatus(KeyEnvelope e, List<string> warnings)
    {
        foreach (var r in e.Recovery.Where(r => r.NotAfter < DateTimeOffset.UtcNow.AddDays(60)))
            warnings.Add($"Recovery certificate {r.Thumbprint} ({r.Subject}) expires {r.NotAfter:yyyy-MM-dd}. It still opens the key " +
                         "after that; renew it when convenient and add the new one (Storage:Encryption:RecoveryCertificates).");
        return e.Recovery.Select(r => new RecoveryCertificateStatus(r.Thumbprint, r.Subject, r.NotAfter, true)).ToList();
    }

    // The key id named by any encrypted file found quickly (C10: bounded), or null.
    /// <summary>
    /// Before a new key is made: a key id that stored files are already encrypted under, or a reason it can't be told, or
    /// null when no file is encrypted. Review finding 3: this fails closed. A store that isn't there, a file that can't be
    /// read, or a check that doesn't finish in time all count as "can't tell", so no new key is made over files that may
    /// need an old one. To keep that affordable on a large store being encrypted for the first time, a file whose length
    /// is its recorded size is plain without being opened (CBE1 always adds a header and a tag per chunk); only the
    /// others' headers are read.
    /// </summary>
    private async Task<string?> EncryptedFileKeyIdAsync(CancellationToken ct)
    {
        var recorded = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        if (_scopes is not null)
        {
            try
            {
                using var scope = _scopes.CreateScope();
                await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
                foreach (var e in await db.Evidence.AsNoTracking().IgnoreQueryFilters().Select(e => new { e.StoragePath, e.SizeBytes }).ToListAsync(ct))
                    recorded.TryAdd(e.StoragePath.Replace('\\', '/'), e.SizeBytes);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return "(unknown: the database couldn't be read to check the stored files)";
            }
        }
        try
        {
            return await Task.Run(() => ScanForKeyId(recorded, ct), ct).WaitAsync(ScanTimeLimit, ct);
        }
        catch (TimeoutException)
        {
            return $"(unknown: the stored files couldn't all be checked within {ScanTimeLimit.TotalMinutes:0} minutes)";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"(unknown: the stored files couldn't be listed: {ex.Message})";
        }
    }

    /// <summary>How long the check before a new key may take: it runs only when no envelope exists anywhere (encryption
    /// turned on for the first time, or a disaster), so it can afford to be thorough.</summary>
    internal static TimeSpan ScanTimeLimit { get; set; } = TimeSpan.FromMinutes(2);

    private string? ScanForKeyId(Dictionary<string, long> recorded, CancellationToken ct)
    {
        if (!Directory.Exists(_evidenceRoot)) return "(unknown: the evidence store's folder isn't there)";
        foreach (var (root, sizes) in new[] { (_evidenceRoot, recorded), (_reportRoot, null) })
        {
            if (!Directory.Exists(root)) continue;   // reports: none generated yet
            foreach (var f in new DirectoryInfo(root).EnumerateFiles("*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var rel = Path.GetRelativePath(root, f.FullName).Replace('\\', '/');
                if (rel.StartsWith(".key/", StringComparison.Ordinal) || f.Name.StartsWith(".probe-", StringComparison.Ordinal)) continue;
                if (sizes is not null && sizes.TryGetValue(rel, out var size) && f.Length == size) continue;   // plain
                if (f.Length < Cbe1.HeaderSize) continue;   // too short to be encrypted
                var head = new byte[Cbe1.HeaderSize];
                try
                {
                    using var s = f.OpenRead();
                    if (s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false) == head.Length && Cbe1.IsCbe1(head))
                        return Cbe1.KeyIdOf(head) ?? "(unknown: a stored file's encryption header is damaged)";
                }
                catch (IOException ex)
                {
                    return $"(unknown: {rel} couldn't be read: {ex.Message})";
                }
            }
        }
        return null;
    }

    /// <summary>
    /// PROD-59: what casebook-keytool recorded in the envelope (shares issued, a drill, a recovery, an export) that CaseBook
    /// hasn't yet: each is written to the audit trail and sent to the SIEM once. "Yet" is the database copy, which CaseBook
    /// alone writes (the tool writes the keys folder's), plus what this run has already recorded.
    /// </summary>
    private async Task RecordKeyToolActionsAsync(KeyEnvelope envelope, string? dbJson, CancellationToken ct)
    {
        var known = KeyEnvelope.Parse(dbJson)?.Records.Select(r => r.Id).ToHashSet() ?? [];
        foreach (var r in envelope.Records.Where(r => !known.Contains(r.Id) && !_recorded.Contains(r.Id)).OrderBy(r => r.AtUtc))
        {
            var summary = $"casebook-keytool, run by {r.By} at {r.AtUtc.UtcDateTime:u}: {r.Summary}";
            await AuditAsync(r.Kind == KeyToolRecord.Exported ? AuditAction.Export : AuditAction.Update, envelope.KeyId, summary, ct,
                caseNumber: r.CaseNumber);
            Emit(r.Kind switch
            {
                KeyToolRecord.Exported => IncidentManager.Application.Security.SecurityEvents.EvidenceExportedOffline(r.By, r.CaseNumber, r.Summary),
                KeyToolRecord.SharesIssued => IncidentManager.Application.Security.SecurityEvents.EvidenceKeyChanged("SharesIssued", envelope.KeyId, r.Summary, r.By),
                KeyToolRecord.Drill => IncidentManager.Application.Security.SecurityEvents.EvidenceKeyChanged("RecoveryDrill", envelope.KeyId, r.Summary, r.By),
                _ => IncidentManager.Application.Security.SecurityEvents.EvidenceKeyChanged("KeyRecovered", envelope.KeyId, r.Summary, r.By),
            });
            _recorded.Add(r.Id);
            _logger?.LogInformation("Recorded a casebook-keytool action: {Summary}", summary);
        }
    }

    private void Emit(IncidentManager.Application.Security.SecurityEvent e) => _siem?.Emit(e);   // never throws, never blocks

    private async Task AuditAsync(AuditAction action, string keyId, string summary, CancellationToken ct, string? caseNumber = null)
    {
        if (_scopes is null) return;
        try
        {
            using var scope = _scopes.CreateScope();
            await scope.ServiceProvider.GetRequiredService<IAuditWriter>().RecordAsync(action, "EvidenceKey", keyId, caseNumber, summary, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger?.LogError(ex, "Couldn't record an evidence key change in the audit trail: {Summary}", summary);
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
