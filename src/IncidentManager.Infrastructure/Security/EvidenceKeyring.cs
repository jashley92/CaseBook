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
    private readonly SemaphoreSlim _gate = new(1, 1);   // C21: one load at a time, so an older one can't land after a newer

    private sealed record Loaded(EvidenceKeyState State, string? KeyId, byte[]? Key, string? Problem);
    private bool _loadedOnce;
    private volatile Loaded _now;

    public EvidenceKeyring(IOptions<EvidenceEncryptionOptions> options, IOptions<SealSigningOptions> integrity,
        IOptions<EvidenceStoreOptions> evidence, IOptions<ReportOutputOptions> reports, IChainKeyring chainKeys,
        IServiceScopeFactory? scopes = null, ILogger<EvidenceKeyring>? logger = null)
    {
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
            Replace(loaded);
            Health = health;
            // Before the first load the state reads Unavailable ("not loaded yet"), so the first load always logs: a key
            // that can't be opened at start-up gets its Critical line too.
            if (!_loadedOnce || loaded.State != before) LogChange(loaded);
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

    private sealed record Protection(string Describe, string Kind, string Ref, Func<byte[], string> Wrap, Func<WrappedKey, byte[]?> Unwrap);

    private async Task<(Loaded, EvidenceKeyHealth)> CheckAsync(CancellationToken ct)
    {
        var warnings = new List<string>();
        var copies = new List<EnvelopeCopyStatus>();
        if (!_options.Enabled)
            return (new Loaded(EvidenceKeyState.Off, null, null, null), Report(EvidenceKeyState.Off, null, null, copies, [], null, warnings));

        var protection = ResolveProtection(warnings);
        if (protection is null)
        {
            const string why = "There's no integrity certificate or chain key to protect the evidence key with. Set " +
                               "Integrity:ChainKey (Certificate) or Integrity:SigningKey (CertificateStore), or " +
                               "Storage:Encryption:CertificateThumbprint (OPERATIONS.md section 2).";
            return (new Loaded(EvidenceKeyState.NotConfigured, null, null, why), Report(EvidenceKeyState.NotConfigured, null, null, copies, [], null, warnings));
        }

        // The copies: the keys folder first (it's authoritative), then the database's, then the one beside the evidence.
        var fileJson = ReadFile(EnvelopePath, "keys folder", copies, ct);
        var (dbJson, dbReadable) = await ReadDatabaseAsync(copies, ct);
        var rootJson = ReadFile(EvidenceRootEnvelopePath, "beside the evidence", copies, ct);

        byte[]? key = null;
        KeyEnvelope? envelope = null;
        foreach (var json in new[] { fileJson, dbJson, rootJson })
        {
            if (KeyEnvelope.Parse(json) is not { } e || Open(e, protection) is not { } k) continue;
            if (KeyWrap.KeyIdOf(k) != e.KeyId) { CryptographicOperations.ZeroMemory(k); continue; }
            (key, envelope) = (k, e);
            break;
        }

        if (key is null || envelope is null)
        {
            var named = new[] { fileJson, dbJson, rootJson }.Select(KeyEnvelope.Parse).OfType<KeyEnvelope>().Select(e => e.KeyId).Distinct().ToList();
            if (named.Count > 0)
                return Unavailable($"The evidence key envelope (key {string.Join(", ", named)}) can't be opened with {protection.Describe}. " +
                                   "Restore the certificate, or recover the key with casebook-keytool recover (a recovery certificate or the shares).");
            if (!dbReadable)
                return Unavailable("The database couldn't be read to check whether an evidence key already exists, so no new key was made.");
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
            envelope = await UpkeepAsync(envelope, key, protection, fileJson, dbJson, rootJson, copies, warnings, ct);
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
                    WrappedKey.Certificate, CertificateLookup.Normalize(thumbprint), _ => throw new InvalidOperationException(ex.Message), _ => null);
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

    private async Task<(string? Json, bool Readable)> ReadDatabaseAsync(List<EnvelopeCopyStatus> copies, CancellationToken ct)
    {
        if (_scopes is null) return (null, true);
        try
        {
            using var scope = _scopes.CreateScope();
            await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
            var row = await db.KeyEnvelopes.AsNoTracking().OrderByDescending(r => r.UpdatedAtUtc).FirstOrDefaultAsync(ct);
            copies.Add(new EnvelopeCopyStatus("database", "KeyEnvelopes", row is not null && KeyEnvelope.Parse(row.EnvelopeJson) is not null,
                row is null ? "missing" : KeyEnvelope.Parse(row.EnvelopeJson) is null ? "damaged" : null));
            return (row?.EnvelopeJson, true);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            copies.Add(new EnvelopeCopyStatus("database", "KeyEnvelopes", false, ex.GetBaseException().Message));
            return (null, false);
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
        await AuditAsync(AuditAction.Create, envelope.KeyId,
            $"Evidence encryption key {envelope.KeyId} created, protected by {p.Describe}, with {envelope.Recovery.Count} recovery certificate(s).", ct);
        return (key, envelope);
    }

    private async Task<KeyEnvelope> UpkeepAsync(KeyEnvelope envelope, byte[] key, Protection p, string? fileJson, string? dbJson, string? rootJson,
        List<EnvelopeCopyStatus> copies, List<string> warnings, CancellationToken ct)
    {
        var changes = new List<string>();
        // A renewed certificate (or a new choice of protection): the key is re-encrypted to the current one.
        if (envelope.Server.Kind != p.Kind || !string.Equals(envelope.Server.Ref, p.Ref, StringComparison.OrdinalIgnoreCase))
        {
            envelope.Server = new WrappedKey { Kind = p.Kind, Ref = p.Ref, Data = p.Wrap(key) };
            changes.Add($"re-encrypted to {p.Describe}");
        }
        if (SyncRecovery(envelope, key, warnings) is { Length: > 0 } recoveryChange) changes.Add(recoveryChange);
        // Copies naming another key aren't used or overwritten silently: they're reported.
        foreach (var (json, copy) in new[] { (dbJson, "database"), (rootJson, "beside the evidence") })
            if (KeyEnvelope.Parse(json) is { } other && other.KeyId != envelope.KeyId)
                warnings.Add($"The envelope {copy} names key {other.KeyId}, not {envelope.KeyId}: it was replaced by the keys folder's.");
        if (changes.Count > 0) envelope.UpdatedUtc = DateTimeOffset.UtcNow;
        await WriteCopiesAsync(envelope, changes.Count > 0 ? null : fileJson, changes.Count > 0 ? null : dbJson,
            changes.Count > 0 ? null : rootJson, copies, warnings, ct);
        if (changes.Count > 0)
        {
            await AuditAsync(AuditAction.Update, envelope.KeyId, $"Evidence encryption key {envelope.KeyId}: {string.Join("; ", changes)}.", ct);
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
    private async Task<string?> EncryptedFileKeyIdAsync(CancellationToken ct)
    {
        try
        {
            return await Task.Run(() =>
            {
                var seen = 0;
                foreach (var root in new[] { _evidenceRoot, _reportRoot })
                {
                    if (!Directory.Exists(root)) continue;
                    foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        if (f.Contains($"{Path.DirectorySeparatorChar}.key{Path.DirectorySeparatorChar}", StringComparison.Ordinal)) continue;
                        if (++seen > 500) return null;
                        var head = new byte[Cbe1.HeaderSize];
                        try
                        {
                            using var s = File.OpenRead(f);
                            if (s.Read(head) == head.Length && Cbe1.KeyIdOf(head) is { } id) return id;
                        }
                        catch (IOException) { /* in use: the next */ }
                    }
                }
                return null;
            }, ct).WaitAsync(StoreVolume.TimeLimit, ct);
        }
        catch (TimeoutException)
        {
            return "(unknown: the store didn't answer in time)";   // can't tell, so no new key
        }
    }

    private async Task AuditAsync(AuditAction action, string keyId, string summary, CancellationToken ct)
    {
        if (_scopes is null) return;
        try
        {
            using var scope = _scopes.CreateScope();
            await scope.ServiceProvider.GetRequiredService<IAuditWriter>().RecordAsync(action, "EvidenceKey", keyId, null, summary, ct);
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
