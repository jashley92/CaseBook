using System.Security.Cryptography;
using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentManager.KeyTool;

/// <summary>One check a restore drill makes, as it's reported.</summary>
internal sealed record RestoreCheckResult(string Check, bool Passed, string Detail);

/// <summary>What a restore drill found, as <c>Test-CaseBookRestore.ps1</c> records it.</summary>
internal sealed record RestoreReport(DateTimeOffset CheckedAtUtc, string Site, bool Passed, IReadOnlyList<RestoreCheckResult> Checks)
{
    public string Summary => string.Join("; ", Checks.Select(c => $"{c.Check}: {(c.Passed ? "passed" : "FAILED")}"));
}

/// <summary>
/// verify-restore: proves a restored copy of CaseBook (its database, evidence store and keys folder, laid out as a site
/// folder's settings describe them) is whole, without the app: the database opens; the audit trail's hash chain is
/// intact from its first entry to its last; every seal's signature is authentic and its chain head still matches; every
/// evidence file the database lists is in the store at its recorded size, and a sample of them (or all) hash to their
/// recorded SHA-256; and with evidence encryption on, the evidence key opens. Read-only: nothing is written to the
/// database, the store or the envelope.
/// </summary>
internal static class RestoreCheck
{
    public static RestoreReport Run(Site site, int sample, bool hashAll, string? publicKeysFolder, Opening? how, TextWriter output)
    {
        var checks = new List<RestoreCheckResult>();
        void Add(string check, bool passed, string detail)
        {
            checks.Add(new RestoreCheckResult(check, passed, detail));
            output.WriteLine($"  {(passed ? "OK  " : "FAIL")} {check}: {detail}");
        }

        output.WriteLine($"Checking the restored copy described by {site.Folder}:");
        AppDbContext db;
        try
        {
            db = new AppDbContext(KeyToolCommands.DbOptionsFor(site));
            var cases = db.Cases.IgnoreQueryFilters().Count();
            var entries = db.AuditLog.Count();
            Add("Database", true, $"opens; {cases:N0} cases, {entries:N0} audit entries, {db.Evidence.IgnoreQueryFilters().Count():N0} evidence files, " +
                                  $"{db.IntegritySeals.Count():N0} seals");
        }
        catch (Exception ex) when (ex is InvalidOperationException or DbUpdateException or System.Data.Common.DbException)
        {
            Add("Database", false, $"doesn't open: {ex.Message}");
            return Finish(site, checks);
        }

        using (db)
        {
            // The evidence key first: the chain key may come from the same envelope, and the files need it.
            var (evidenceKey, envelopeKeyId) = CheckEvidenceKey(site, db, how, Add);
            try
            {
                CheckChain(site, db, Add);
                CheckSeals(site, db, publicKeysFolder, Add);
                CheckEvidence(site, db, evidenceKey, envelopeKeyId, sample, hashAll, Add);
            }
            finally
            {
                if (evidenceKey is not null) CryptographicOperations.ZeroMemory(evidenceKey);
            }
        }
        return Finish(site, checks);
    }

    private static RestoreReport Finish(Site site, List<RestoreCheckResult> checks) =>
        new(DateTimeOffset.UtcNow, site.Folder, checks.TrueForAll(c => c.Passed), checks);

    // With encryption on (an envelope, or files that name a key), the key must open here as it would for the app.
    private static (byte[]? Key, string? KeyId) CheckEvidenceKey(Site site, AppDbContext db, Opening? how, Action<string, bool, string> add)
    {
        KeyEnvelope envelope;
        try { envelope = KeyToolCommands.ReadEnvelope(site); }
        catch (InvalidOperationException)
        {
            var dbEnvelope = db.KeyEnvelopes.AsNoTracking().Select(k => k.EnvelopeJson).FirstOrDefault();
            if (dbEnvelope is null || KeyEnvelope.Parse(dbEnvelope) is not { } fromDb)
            {
                add("Evidence key", true, "evidence encryption isn't in use (no envelope in the keys folder, beside the evidence or in the database)");
                return (null, null);
            }
            envelope = fromDb;
        }
        try
        {
            var opened = KeyToolCommands.Open(envelope, how ?? new Opening());
            add("Evidence key", true, $"key {envelope.KeyId} opens ({opened.How})");
            if (opened.ChainKey is { } chain) CryptographicOperations.ZeroMemory(chain);
            return (opened.EvidenceKey, envelope.KeyId);
        }
        catch (Exception ex) when (ex is InvalidOperationException or CryptographicException)
        {
            add("Evidence key", false, $"key {envelope.KeyId} doesn't open here: {ex.Message} Give --cert, --pfx or --shares, as for casebook-keytool verify.");
            return (null, envelope.KeyId);
        }
    }

    // The whole audit trail, as the app's integrity check reads it: each entry's hash against the one before.
    private static void CheckChain(Site site, AppDbContext db, Action<string, bool, string> add)
    {
        IChainKeyring keys;
        try { keys = new ChainKeyring(Options.Create(site.IntegrityResolved)); }
        catch (Exception ex) when (ex is InvalidOperationException or CryptographicException or IOException)
        {
            add("Audit chain", false, $"the chain key can't be read here, so keyed entries can't be checked: {ex.Message}");
            return;
        }
        var keyedFrom = db.IntegritySeals.AsNoTracking().OrderByDescending(s => s.UpToSequence).ThenByDescending(s => s.SealedAtUtc)
            .Select(s => s.KeyedFromSequence).FirstOrDefault();
        var verifier = new HashChainService(keys).BeginVerify(keyedFrom);
        long count = 0, last = 0;
        foreach (var e in db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).AsEnumerable())
        {
            count++;
            last = e.Sequence;
            if (!verifier.Add(e)) break;
        }
        var result = verifier.Result;
        add("Audit chain", result.IsValid, result.IsValid
            ? $"intact: {count:N0} entries, through sequence {last:N0}"
            : $"broken at sequence {result.FirstBrokenSequence}: {result.Detail}");
    }

    // Each seal: its signature against the key it names, and its chain head against the entry it sealed.
    private static void CheckSeals(Site site, AppDbContext db, string? publicKeysFolder, Action<string, bool, string> add)
    {
        var keys = PublicKeys(site, publicKeysFolder, out var keyNote);
        try
        {
            var seals = db.IntegritySeals.AsNoTracking().OrderBy(s => s.UpToSequence).ToList();
            if (seals.Count == 0)
            {
                add("Seals", true, "none to check (nothing sealed yet)");
                return;
            }
            var heads = db.AuditLog.AsNoTracking().Where(a => seals.Select(s => s.UpToSequence).Contains(a.Sequence))
                .ToDictionary(a => a.Sequence, a => a.EntryHash);
            var failed = new List<string>();
            foreach (var seal in seals)
            {
                var signed = keys.TryGetValue(seal.KeyId, out var rsa) && SealAlgorithms.PaddingFor(seal.Algorithm) is { } padding
                    && TrySignature(seal.Signature) is { } sig
                    && rsa.VerifyData(System.Text.Encoding.UTF8.GetBytes(seal.BuildCanonicalContent()), sig, HashAlgorithmName.SHA256, padding);
                var headMatches = heads.TryGetValue(seal.UpToSequence, out var head) && head == seal.ChainHeadHash;
                if (!signed || !headMatches)
                    failed.Add($"seal at sequence {seal.UpToSequence}: " + (!keys.ContainsKey(seal.KeyId)
                        ? $"signed by key {seal.KeyId}, which isn't available here{keyNote}"
                        : !signed ? "signature doesn't verify" : "chain head differs (history rewritten after sealing)"));
            }
            add("Seals", failed.Count == 0, failed.Count == 0
                ? $"all {seals.Count:N0} authentic, chain heads unchanged (latest through sequence {seals[^1].UpToSequence:N0})"
                : $"{failed.Count} of {seals.Count}: {string.Join("; ", failed.Take(5))}{(failed.Count > 5 ? "; …" : "")}");
        }
        finally
        {
            foreach (var k in keys.Values) k.Dispose();
        }
    }

    private static byte[]? TrySignature(string s)
    {
        try { return Convert.FromBase64String(s); }
        catch (FormatException) { return null; }
    }

    // The seal keys by id: the restored site's (its signing key and retired folder), and any public keys given.
    private static Dictionary<string, RSA> PublicKeys(Site site, string? folder, out string note)
    {
        var keys = new Dictionary<string, RSA>(StringComparer.OrdinalIgnoreCase);
        note = "";
        var options = site.IntegrityResolved;
        try
        {
            using var signer = new RsaSealSigner(Options.Create(options));
            foreach (var k in signer.VerificationKeys) AddPem(keys, k.PublicKeyPem);
        }
        catch (Exception ex) when (ex is InvalidOperationException or CryptographicException or IOException or ArgumentException)
        {
            note = $" (the site's signing key couldn't be loaded here: {ex.Message} Give its public key with --public-keys.)";
            var retired = RsaSealSigner.RetiredFolder(options);
            if (Directory.Exists(retired))
                foreach (var f in Directory.EnumerateFiles(retired, "*.pem")) AddPem(keys, File.ReadAllText(f));
        }
        if (folder is not null)
        {
            if (!Directory.Exists(folder)) throw new InvalidOperationException($"--public-keys {folder} doesn't exist.");
            foreach (var f in Directory.EnumerateFiles(folder, "*.pem")) AddPem(keys, File.ReadAllText(f));
        }
        return keys;
    }

    private static void AddPem(Dictionary<string, RSA> keys, string pem)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            var pub = RSA.Create();
            pub.ImportSubjectPublicKeyInfo(rsa.ExportSubjectPublicKeyInfo(), out _);
            if (!keys.TryAdd(RsaSealSigner.KeyIdOf(pub), pub)) pub.Dispose();
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException) { /* not an RSA key: skipped */ }
        finally { rsa.Dispose(); }
    }

    // Every file the database lists is in the store at its recorded size; a sample (or all) hash to their record.
    private static void CheckEvidence(Site site, AppDbContext db, byte[]? key, string? keyId, int sample, bool hashAll,
        Action<string, bool, string> add)
    {
        var rows = db.Evidence.AsNoTracking().IgnoreQueryFilters()
            .Select(e => new { e.Id, e.StoragePath, e.SizeBytes, e.Sha256, e.OriginalFileName }).ToList();
        if (rows.Count == 0)
        {
            add("Evidence files", true, "none recorded");
            return;
        }
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(site.EvidenceRoot)) + Path.DirectorySeparatorChar;
        var problems = new List<string>();
        foreach (var r in rows)
        {
            var path = Path.GetFullPath(Path.Combine(root, r.StoragePath));
            if (!path.StartsWith(root, StringComparison.Ordinal)) { problems.Add($"{r.OriginalFileName}: its stored path leads outside the store"); continue; }
            if (!File.Exists(path)) { problems.Add($"{r.OriginalFileName}: missing ({r.StoragePath})"); continue; }
            var length = new FileInfo(path).Length;
            var plain = IsEncrypted(path) ? Cbe1.PlainLength(length) : length;
            if (plain != r.SizeBytes) problems.Add($"{r.OriginalFileName}: {plain:N0} bytes, recorded {r.SizeBytes:N0}");
        }
        add("Evidence files", problems.Count == 0, problems.Count == 0
            ? rows.Count == 1 ? "the one file present at its recorded size" : $"all {rows.Count:N0} present at their recorded size"
            : $"{problems.Count} of {rows.Count}: {string.Join("; ", problems.Take(5))}{(problems.Count > 5 ? "; …" : "")}");

        var picked = hashAll ? rows : rows.OrderBy(_ => RandomNumberGenerator.GetInt32(int.MaxValue)).Take(Math.Max(0, sample)).ToList();
        var mismatched = new List<string>();
        foreach (var r in picked)
        {
            var path = Path.GetFullPath(Path.Combine(root, r.StoragePath));
            if (!path.StartsWith(root, StringComparison.Ordinal) || !File.Exists(path)) continue;   // said above
            try
            {
                using var content = Open(path, keyId, key);
                var actual = Convert.ToHexString(SHA256.HashData(content));
                if (!string.Equals(actual, r.Sha256, StringComparison.OrdinalIgnoreCase)) mismatched.Add($"{r.OriginalFileName}: SHA-256 differs");
            }
            catch (Exception ex) when (ex is IOException or CryptographicException or UnauthorizedAccessException)
            {
                mismatched.Add($"{r.OriginalFileName}: couldn't be read ({ex.Message})");
            }
        }
        add(hashAll ? "Evidence hashes (all)" : "Evidence hashes (sample)", mismatched.Count == 0, mismatched.Count == 0
            ? $"{picked.Count:N0} of {rows.Count:N0} re-hashed; each matches its recorded SHA-256"
            : $"{mismatched.Count} of {picked.Count} re-hashed: {string.Join("; ", mismatched.Take(5))}{(mismatched.Count > 5 ? "; …" : "")}");
    }

    private static bool IsEncrypted(string path)
    {
        using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Span<byte> head = stackalloc byte[5];
        return f.Read(head) == 5 && Cbe1.IsCbe1(head);
    }

    // A stored file's content, as export reads it: decrypted when it's CBE1 under the key that opened, else as it is.
    private static Stream Open(string path, string? keyId, byte[]? key) =>
        key is null && IsEncrypted(path)
            ? throw new CryptographicException("it's encrypted, and the evidence key didn't open here")
            : KeyToolCommands.OpenContent(path, keyId ?? "", key ?? []);

    /// <summary>The report as JSON, for the drill's record and the status file.</summary>
    public static string ToJson(RestoreReport report) => JsonSerializer.Serialize(new
    {
        checkedAtUtc = report.CheckedAtUtc,
        passed = report.Passed,
        summary = report.Summary,
        checks = report.Checks.Select(c => new { check = c.Check, passed = c.Passed, detail = c.Detail }),
    }, Indented);

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
}
