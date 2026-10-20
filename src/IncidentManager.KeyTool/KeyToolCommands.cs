using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Secrets;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace IncidentManager.KeyTool;

/// <summary>Where a CaseBook install keeps what the keytool needs, read from its site folder's settings.</summary>
internal sealed record Site(string EnvelopePath, string EvidenceRoot, string ReportRoot, string Provider, string? ConnectionString,
    SealSigningOptions Integrity)
{
    public string RootEnvelopePath => Path.Combine(EvidenceRoot, ".key", "evidence-key.json");

    /// <summary>The site folder the settings were read from.</summary>
    public string Folder { get; init; } = "";

    /// <summary><see cref="Integrity"/> with its file paths resolved against the site folder, as the app (whose working
    /// directory it is) resolves them.</summary>
    public SealSigningOptions IntegrityResolved
    {
        get
        {
            string Full(string p) => string.IsNullOrWhiteSpace(p) ? p : Path.GetFullPath(Path.Combine(Folder, p));
            var o = Integrity;
            return new SealSigningOptions
            {
                SigningKeyPath = SigningKeyPath, AllowKeyGeneration = false, SigningKey = o.SigningKey,
                RetiredPublicKeysPath = Full(o.RetiredPublicKeysPath), ExportPath = Full(o.ExportPath),
                ChainKey = new ChainKeyOptions
                {
                    Enabled = o.ChainKey.Enabled, Source = o.ChainKey.Source, Secret = o.ChainKey.Secret, RetiredSecrets = o.ChainKey.RetiredSecrets,
                    CertificateThumbprint = o.ChainKey.CertificateThumbprint, StoreLocation = o.ChainKey.StoreLocation,
                    WrappedKeyPath = Full(o.ChainKey.WrappedKeyPath), RetiredWrappedKeysPath = Full(o.ChainKey.RetiredWrappedKeysPath),
                },
            };
        }
    }

    /// <summary>The seal-signing key file, as the app resolves <c>Integrity:SigningKeyPath</c> (signing-public-key).</summary>
    public string SigningKeyPath { get; init; } = "";

    /// <summary>CAP-05: <c>Storage:Encryption:CertificateThumbprint</c> and its store, when set (protect-secret's first choice).</summary>
    public string? EncryptionThumbprint { get; init; }
    public string EncryptionStore { get; init; } = "LocalMachine";

    /// <summary>The site folder's appsettings.json and appsettings.Production.json, as the app reads them.</summary>
    public static Site Load(string siteFolder)
    {
        var folder = Path.GetFullPath(siteFolder);
        if (!Directory.Exists(folder)) throw new InvalidOperationException($"The site folder {folder} doesn't exist.");
        var config = new ConfigurationBuilder()
            .AddJsonFile(Path.Combine(folder, "appsettings.json"), optional: true)
            .AddJsonFile(Path.Combine(folder, "appsettings.Production.json"), optional: true)
            .Build();
        string Full(string? path, string fallback) => Path.GetFullPath(Path.Combine(folder, string.IsNullOrWhiteSpace(path) ? fallback : path));
        var integrity = new SealSigningOptions();
        config.GetSection("Integrity").Bind(integrity);
        var envelope = config["Storage:Encryption:EnvelopePath"];
        var signing = Full(integrity.SigningKeyPath, "App_Data/keys/seal-signing.pem");
        var provider = config["Database:Provider"] ?? "Sqlite";
        var connection = config.GetConnectionString("Default");
        if (!provider.Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            // The app resolves a relative SQLite file against the site folder (its working directory); so does the tool,
            // wherever it's run from, rather than opening (or creating) an empty database beside the tool.
            var sqlite = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(connection ?? "Data Source=App_Data/incidentmanager.db");
            sqlite.DataSource = Full(sqlite.DataSource, "App_Data/incidentmanager.db");
            sqlite.Mode = Microsoft.Data.Sqlite.SqliteOpenMode.ReadWrite;
            connection = sqlite.ToString();
        }
        return new Site(
            string.IsNullOrWhiteSpace(envelope) ? Path.Combine(Path.GetDirectoryName(signing)!, "evidence-key.json") : Full(envelope, ""),
            Full(config["EvidenceStore:RootPath"], "App_Data/evidence-store"),
            Full(config["ReportOutput:RootPath"], "App_Data/report-output"),
            provider,
            connection,
            integrity)
        {
            SigningKeyPath = signing,
            Folder = folder,
            EncryptionThumbprint = config["Storage:Encryption:CertificateThumbprint"],
            EncryptionStore = config["Storage:Encryption:StoreLocation"] ?? "LocalMachine",
        };
    }
}

/// <summary>How to open the envelope: the server certificate (on the server), a recovery certificate, or shares.</summary>
internal sealed record Opening(string? PfxPath = null, string? PfxPassword = null, string? Thumbprint = null, string Store = "CurrentUser",
    IReadOnlyCollection<string>? Shares = null);

/// <summary>
/// PROD-57: casebook-keytool's commands. Each reads the envelope from the keys folder (or the copy beside the evidence when
/// that's all there is), never makes a key, and changes only the envelope's own record of shares issued, a drill, or (for
/// recover) its server copy; CaseBook copies the change to the database and beside the evidence at its next check.
/// </summary>
internal static class KeyToolCommands
{
    public static KeyEnvelope ReadEnvelope(Site site)
    {
        foreach (var path in new[] { site.EnvelopePath, site.RootEnvelopePath })
            if (File.Exists(path) && KeyEnvelope.Parse(File.ReadAllText(path)) is { } e) return e;
        throw new InvalidOperationException($"No evidence key envelope at {site.EnvelopePath} or {site.RootEnvelopePath}. Restore " +
                                            "evidence-key.json from a backup, or export the KeyEnvelopes row from a database backup into it.");
    }

    public static EnvelopeOpener.Opened Open(KeyEnvelope e, Opening how)
    {
        if (how.Shares is { Count: > 0 } shares) return EnvelopeOpener.WithShares(e, shares);
        if (how.PfxPath is { } pfx)
        {
            using var cert = X509CertificateLoader.LoadPkcs12FromFile(pfx, how.PfxPassword, X509KeyStorageFlags.EphemeralKeySet);
            return EnvelopeOpener.WithRecoveryCertificate(e, cert);
        }
        if (how.Thumbprint is { } thumb)
        {
            using var cert = CertificateLookup.FindRsa(thumb, how.Store, "--cert");
            return EnvelopeOpener.WithRecoveryCertificate(e, cert);
        }
        return EnvelopeOpener.WithServerCertificate(e);
    }

    /// <summary>
    /// CAP-05 (ADR 0018): encrypts a secret (the SMTP password, a webhook token or URL) to a certificate as a <c>@protected:</c>
    /// value for the site's configuration. <paramref name="thumbprint"/>, else the site's own integrity certificate: the
    /// evidence key's, the chain key's, then the seal-signing one (as the evidence key chooses, ADR 0017). Only the
    /// certificate's public key is used; the app-pool account needs read on its private key to open the value. Never
    /// writes or records the secret.
    /// </summary>
    public static string ProtectSecret(string secret, string? thumbprint, string store, Site? site, TextWriter info)
    {
        if (string.IsNullOrEmpty(secret)) throw new ArgumentException("The secret is empty.");
        if (string.IsNullOrWhiteSpace(thumbprint) && site is not null) (thumbprint, store) = DefaultCertificate(site, store);
        if (string.IsNullOrWhiteSpace(thumbprint))
            throw new ArgumentException("Give --cert <thumbprint> (a certificate in LocalMachine\\My the app-pool account can read the private key of), " +
                                        "or --site <folder> of a site with an integrity certificate configured.");
        using var cert = CertificateLookup.FindPublic(thumbprint, store, "--cert");
        var value = ProtectedSecret.Protect(secret, cert);
        info.WriteLine($"Encrypted to certificate {CertificateLookup.Normalize(cert.Thumbprint)} ({cert.Subject}, {store}\\My, expires " +
                       $"{cert.NotAfter.ToUniversalTime():yyyy-MM-dd}). The app-pool account needs read on its private key.");
        return value;
    }

    // The certificate the site already protects its keys with: the evidence key's, the chain key's, the signing one's.
    private static (string? Thumbprint, string Store) DefaultCertificate(Site site, string store)
    {
        if (!string.IsNullOrWhiteSpace(site.EncryptionThumbprint)) return (site.EncryptionThumbprint, site.EncryptionStore);
        if (site.Integrity.ChainKey is { Enabled: true, Source: ChainKeySource.Certificate } ck && !string.IsNullOrWhiteSpace(ck.CertificateThumbprint))
            return (ck.CertificateThumbprint, ck.StoreLocation);
        if (site.Integrity.SigningKey is { Source: SigningKeySource.CertificateStore } sk && !string.IsNullOrWhiteSpace(sk.CertificateThumbprint))
            return (sk.CertificateThumbprint, sk.StoreLocation);
        return (null, store);
    }

    /// <summary>
    /// CAP-05: checks a <c>@protected:</c> value opens here, as this account, exactly as CaseBook opens it. Says OK and the
    /// certificate, or why not; never the secret, nor anything about it (its length included).
    /// </summary>
    public static bool CheckSecret(string value, TextWriter output, Func<string, X509Certificate2>? findCertificate = null)
    {
        if (!ProtectedSecret.IsProtected(value))
        {
            output.WriteLine("Not a @protected: value (it should start with @protected:v1:).");
            return false;
        }
        if (ProtectedSecret.TryOpen(value.Trim(), findCertificate ?? ProtectedSecret.FindInStore, out _, out var reason))
        {
            // The secret itself is dropped unseen: not shown, not kept.
            output.WriteLine($"OK: the value opens with certificate {ProtectedSecret.ThumbprintOf(value)} on {Environment.MachineName}, as " +
                             $"{Environment.UserDomainName}\\{Environment.UserName}. CaseBook opens it the same way, as the app-pool account.");
            return true;
        }
        output.WriteLine($"It doesn't open here: {reason}.");
        return false;
    }

    /// <summary>
    /// Splits the key (and the chain key, when it's on and readable here) into <paramref name="count"/> shares, any
    /// <paramref name="threshold"/> of which rebuild it; prints them and, with <paramref name="outFolder"/>, writes one file
    /// each. Records that shares were issued (never the shares) in the envelope.
    /// </summary>
    public static IReadOnlyList<string> Split(Site site, int threshold, int count, string? outFolder, TextWriter output, Opening? how = null)
    {
        var e = ReadEnvelope(site);
        var opened = Open(e, how ?? new Opening());
        var chainKey = opened.ChainKey ?? ChainKeyFromConfig(site, output);
        var shares = KeyShares.Split(KeyWrap.Pack(opened.EvidenceKey, chainKey), e.KeyId, threshold, count);
        CryptographicOperations.ZeroMemory(opened.EvidenceKey);

        output.WriteLine($"Evidence key {e.KeyId}: {count} shares, any {threshold} of which rebuild it" +
                         (chainKey is null ? "." : ", with the audit chain key."));
        output.WriteLine("Give each to a different person or safe. Each holder can check theirs with: casebook-keytool check-share");
        output.WriteLine();
        for (var i = 0; i < shares.Count; i++) output.WriteLine($"Share {i + 1} of {count}:  {shares[i]}");
        if (outFolder is not null)
        {
            AdminOnlyFolder(outFolder);
            for (var i = 0; i < shares.Count; i++)
                File.WriteAllText(Path.Combine(outFolder, $"casebook-key-{e.KeyId}-share-{i + 1}-of-{count}.txt"),
                    $"CaseBook evidence key {e.KeyId}, share {i + 1} of {count} (any {threshold} rebuild it).\r\n{shares[i]}\r\n");
            output.WriteLine();
            output.WriteLine($"Written to {Path.GetFullPath(outFolder)}. Move each to its own USB stick or safe, then delete the folder.");
        }
        e.Shares = new SharesIssued
        {
            IssuedUtc = DateTimeOffset.UtcNow, Threshold = threshold, Count = count,
            ChainKeyId = chainKey is null ? null : ChainKeyring.KeyIdOf(chainKey),
        };
        e.Record(KeyToolRecord.SharesIssued, $"Evidence key {e.KeyId} split into {count} shares, any {threshold} of which rebuild it" +
                                             (chainKey is null ? "." : ", with the audit chain key."));
        Save(site, e, output);
        return shares;
    }

    /// <summary>Checks shares on their own (their checksums), offline: no key is rebuilt and nothing is recorded.</summary>
    public static void CheckShares(IEnumerable<string> shares, TextWriter output)
    {
        foreach (var text in shares)
        {
            var s = KeyShares.Decode(text);
            output.WriteLine($"OK: share {s.Number} for evidence key {s.KeyId}; {s.Threshold} shares rebuild the key.");
        }
    }

    /// <summary>A recovery drill: proves a backup opens the key, and records the date in the envelope.</summary>
    public static void Verify(Site site, Opening how, TextWriter output)
    {
        var e = ReadEnvelope(site);
        var opened = Open(e, how);
        CryptographicOperations.ZeroMemory(opened.EvidenceKey);
        output.WriteLine($"OK: evidence key {e.KeyId} opens with {opened.How}" + (opened.ChainKey is null ? "." : "; the audit chain key comes back with it."));
        e.LastDrillUtc = DateTimeOffset.UtcNow;
        e.LastDrillBy = $"{Environment.UserDomainName}\\{Environment.UserName}";
        e.Record(KeyToolRecord.Drill, $"Recovery drill: evidence key {e.KeyId} opens with {opened.How}.");
        Save(site, e, output);
    }

    /// <summary>
    /// Rebuilds the server's copy onto another certificate (a new server, or the old certificate lost), from a backup.
    /// With the chain key in the backup and the chain key on a certificate, its file is rewritten to the new one too.
    /// </summary>
    public static void Recover(Site site, Opening how, string toThumbprint, string toStore, bool writeChainKey, TextWriter output)
    {
        var e = ReadEnvelope(site);
        using var target = CertificateLookup.FindRsa(toThumbprint, toStore, "--to-cert");
        // Review finding 8: the new protection must be able to open what it protects, before anything is written.
        if (!target.HasPrivateKey)
            throw new InvalidOperationException($"Certificate {target.Thumbprint} has no private key on this machine (or this account can't " +
                                                "use it), so it couldn't open the key again. Install it with its private key first.");
        var opened = Open(e, how);
        var normalized = CertificateLookup.Normalize(target.Thumbprint);
        string? chainPath = null;
        if (writeChainKey && opened.ChainKey is { } chainToCheck) chainPath = ChainKeyTarget(site, chainToCheck, output);
        e.Server = new WrappedKey { Kind = WrappedKey.Certificate, Ref = normalized, Data = KeyWrap.ToCertificate(target, opened.EvidenceKey) };
        CryptographicOperations.ZeroMemory(opened.EvidenceKey);
        e.Record(KeyToolRecord.Recovered, $"Evidence key {e.KeyId} recovered with {opened.How} onto certificate {normalized} ({toStore})" +
                                          (chainPath is not null ? ", with the audit chain key." : "."));
        Save(site, e, output);
        // PROD-56: the copy beside the evidence only into a store that's there (never recreating one that vanished).
        if (Directory.Exists(site.EvidenceRoot)) TryWrite(site.RootEnvelopePath, e.ToJson(), output);
        else output.WriteLine($"The evidence store's folder ({site.EvidenceRoot}) isn't here; CaseBook writes the copy beside the evidence once it is.");
        output.WriteLine($"Evidence key {e.KeyId} is now protected by certificate {normalized} ({toStore}).");
        if (writeChainKey && opened.ChainKey is null)
            output.WriteLine("The backup used doesn't carry the audit chain key, so chain-key.json wasn't written.");
        if (chainPath is not null && opened.ChainKey is { } chainKey)
        {
            if (File.Exists(chainPath))
            {
                var aside = $"{chainPath}.replaced-{DateTime.UtcNow:yyyyMMddHHmmss}";
                File.Move(chainPath, aside);
                output.WriteLine($"The chain key file that couldn't be opened is kept as {aside}.");
            }
            var record = JsonSerializer.Serialize(new { Thumbprint = normalized, Wrapped = KeyWrap.ToCertificate(target, chainKey) });
            File.WriteAllText(chainPath, record);
            output.WriteLine($"The audit chain key ({ChainKeyring.KeyIdOf(chainKey)}) is written to {chainPath}, protected by the same certificate.");
        }
        output.WriteLine("Next: set Storage:Encryption:CertificateThumbprint (or the chain key's / signing certificate) to it in " +
                         "appsettings.Production.json, and restart the app pool. CaseBook re-checks the key every 5 minutes.");
    }

    /// <summary>
    /// Writes evidence (one case, or all) to <paramref name="outFolder"/> as the original files, with a manifest of each
    /// file's recorded and actual SHA-256. For eDiscovery, moving to another product, or a disaster. Not recorded in the
    /// audit trail (this tool doesn't write to the database); keep the manifest with the change record.
    /// </summary>
    public static (int Exported, int Mismatched) Export(Site site, string? caseNumber, string outFolder, Opening? how, TextWriter output)
    {
        var e = ReadEnvelope(site);
        var opened = Open(e, how ?? new Opening());
        using var db = new AppDbContext(DbOptions(site));
        var rows = (from ev in db.Evidence.AsNoTracking().IgnoreQueryFilters()
                    join c in db.Cases.AsNoTracking().IgnoreQueryFilters() on ev.CaseId equals c.Id
                    where caseNumber == null || c.CaseNumber == caseNumber
                    orderby c.CaseNumber, ev.CreatedAtUtc
                    select new { c.CaseNumber, ev.OriginalFileName, ev.StoragePath, ev.Sha256 }).ToList();
        if (caseNumber is not null && rows.Count == 0) throw new InvalidOperationException($"No evidence found for case {caseNumber}.");

        Directory.CreateDirectory(outFolder);
        var manifest = new StringBuilder("case,file,exported as,recorded sha256,actual sha256,matches\r\n");
        int exported = 0, mismatched = 0;
        var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows)
        {
            var source = Path.GetFullPath(Path.Combine(site.EvidenceRoot, r.StoragePath));
            // Review finding 11: a stored path leads inside the store, or the file isn't copied (as the app refuses it, S-07).
            var inside = source.StartsWith(Path.TrimEndingDirectorySeparator(site.EvidenceRoot) + Path.DirectorySeparatorChar, StringComparison.Ordinal);
            var folder = Path.Combine(outFolder, Safe(r.CaseNumber));
            Directory.CreateDirectory(folder);
            var name = Safe(r.OriginalFileName);
            var target = Path.Combine(folder, name);
            for (var n = 2; !taken.Add(target) || File.Exists(target); n++)
                target = Path.Combine(folder, $"{Path.GetFileNameWithoutExtension(name)} ({n}){Path.GetExtension(name)}");
            string actual;
            if (!inside) actual = "(refused: its stored path leads outside the evidence store)";
            else try
            {
                using var content = OpenContent(source, e.KeyId, opened.EvidenceKey);
                using var file = File.Create(target);
                using var sha = SHA256.Create();
                using (var hashing = new CryptoStream(file, sha, CryptoStreamMode.Write, leaveOpen: true)) content.CopyTo(hashing);
                actual = Convert.ToHexString(sha.Hash!).ToLowerInvariant();
            }
            catch (Exception ex) when (ex is IOException or CryptographicException or UnauthorizedAccessException)
            {
                actual = $"(couldn't be read: {ex.Message})";
            }
            var matches = string.Equals(actual, r.Sha256, StringComparison.OrdinalIgnoreCase);
            if (!matches) mismatched++;
            exported++;
            manifest.Append(CultureInfo.InvariantCulture, $"{Csv(r.CaseNumber)},{Csv(r.OriginalFileName)},{Csv(Path.GetRelativePath(outFolder, target))},{r.Sha256},{Csv(actual)},{(matches ? "yes" : "NO")}\r\n");
        }
        CryptographicOperations.ZeroMemory(opened.EvidenceKey);
        var manifestText = manifest.ToString();
        File.WriteAllText(Path.Combine(outFolder, "manifest.csv"), manifestText);
        output.WriteLine($"Exported {exported} file(s) to {Path.GetFullPath(outFolder)}; {mismatched} don't match their recorded SHA-256 (see manifest.csv).");
        // PROD-59: decrypted evidence left the store; CaseBook records it in the audit trail and the SIEM when it next reads
        // the envelope (within a minute while it runs). The manifest's own SHA-256 ties the record to the file list.
        var manifestSha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(manifestText))).ToLowerInvariant();
        e.Record(KeyToolRecord.Exported,
            $"Exported {exported} evidence file(s) decrypted ({(caseNumber is null ? "all cases" : $"case {caseNumber}")}) to {Path.GetFullPath(outFolder)} " +
            $"on {Environment.MachineName}; {mismatched} didn't match their record; manifest.csv SHA-256 {manifestSha}.", caseNumber);
        Save(site, e, output);
        return (exported, mismatched);
    }

    // A stored file's content: decrypted when it's CBE1 under this key, else as it is.
    internal static Stream OpenContent(string path, string keyId, byte[] key)
    {
        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var head = new byte[Cbe1.HeaderSize];
        if (file.Read(head) == head.Length && Cbe1.KeyIdOf(head) is { } id)
        {
            if (id != keyId) { file.Dispose(); throw new CryptographicException($"encrypted with key {id}, not {keyId}"); }
            return new Cbe1ReadStream(file, key);
        }
        file.Position = 0;
        return file;
    }

    // The chain key from its certificate-protected file, when the chain key is on that way and readable here.
    private static byte[]? ChainKeyFromConfig(Site site, TextWriter output)
    {
        if (site.Integrity.ChainKey is not { Enabled: true, Source: ChainKeySource.Certificate }) return null;
        try
        {
            var ring = new ChainKeyring(Options.Create(site.Integrity));
            return ring.CurrentKeyId is { } id ? ring.Key(id) : null;
        }
        catch (Exception ex) when (ex is InvalidOperationException or CryptographicException)
        {
            output.WriteLine($"Note: the audit chain key couldn't be read here ({ex.Message}); the shares carry the evidence key only.");
            return null;
        }
    }

    /// <summary>
    /// Review finding 8: where to write the recovered chain key, or a refusal. An existing chain-key.json that opens is left
    /// as it is; and the key must be the one the audit log's newest keyed entries name (the shares or a recovery copy may
    /// carry one retired since), checked against the database, so a working chain is never broken by a recovery.
    /// </summary>
    private static string ChainKeyTarget(Site site, byte[] chainKey, TextWriter output)
    {
        var path = string.IsNullOrWhiteSpace(site.Integrity.ChainKey.WrappedKeyPath)
            ? Path.Combine(Path.GetDirectoryName(site.EnvelopePath)!, "chain-key.json")
            : site.Integrity.ChainKey.WrappedKeyPath;
        if (File.Exists(path) && OpensHere(site))
            throw new InvalidOperationException($"{path} opens on this server, so it was left as it is. Leave out --chain-key.");
        var recovered = ChainKeyring.KeyIdOf(chainKey);
        string? newest;
        try
        {
            using var db = new AppDbContext(DbOptions(site));
            newest = db.AuditLog.AsNoTracking().Where(a => a.HashKeyId != null).OrderByDescending(a => a.Sequence)
                .Select(a => a.HashKeyId).FirstOrDefault();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new InvalidOperationException("The database couldn't be read to check which chain key the audit log uses " +
                                                $"({ex.GetBaseException().Message}), so chain-key.json wasn't written. Run it where the database is reachable.");
        }
        if (newest is not null && !string.Equals(newest, recovered, StringComparison.Ordinal))
            throw new InvalidOperationException($"This backup carries chain key {recovered}, but the audit log's newest entries are keyed with " +
                                                $"{newest}: it was replaced since. chain-key.json wasn't written; restore it from a backup of the keys folder.");
        output.WriteLine(newest is null
            ? $"No audit entry is keyed yet; chain key {recovered} will be written."
            : $"Chain key {recovered} is the one the audit log uses.");
        return path;
    }

    // Whether the site's chain key file opens here (its certificate present, with a usable private key).
    private static bool OpensHere(Site site)
    {
        try { return new ChainKeyring(Options.Create(site.Integrity)).CurrentKeyId is not null; }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return false;   // it doesn't open: the case recovery is for
        }
    }

    internal static DbContextOptions<AppDbContext> DbOptionsFor(Site site) => DbOptions(site);

    private static DbContextOptions<AppDbContext> DbOptions(Site site)
    {
        var options = new DbContextOptionsBuilder<AppDbContext>();
        if (site.Provider.Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
            options.UseSqlServer(site.ConnectionString ?? throw new InvalidOperationException("No database connection string in the site's settings."));
        else options.UseSqlite(site.ConnectionString!);
        return options.Options;
    }

    /// <summary>Review finding 11: shares written to a folder only administrators (and SYSTEM) can read.</summary>
    private static void AdminOnlyFolder(string folder)
    {
        var dir = Directory.CreateDirectory(folder);
        if (!OperatingSystem.IsWindows()) return;
        var acl = new System.Security.AccessControl.DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inherit = System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, System.Security.Principal.WellKnownSidType.LocalSystemSid })
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid, null),
                System.Security.AccessControl.FileSystemRights.FullControl, inherit, System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));
        if (System.Security.Principal.WindowsIdentity.GetCurrent().User is { } me)
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(me, System.Security.AccessControl.FileSystemRights.FullControl,
                inherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
        dir.SetAccessControl(acl);
    }

    /// <summary>Writes the envelope to the keys folder, for the commands outside this class.</summary>
    internal static void SaveEnvelope(Site site, KeyEnvelope e, TextWriter output) => Save(site, e, output);

    private static void Save(Site site, KeyEnvelope e, TextWriter output)
    {
        e.UpdatedUtc = DateTimeOffset.UtcNow;   // review finding 1: every change the tool makes is the newest copy
        if (!TryWrite(site.EnvelopePath, e.ToJson(), output))
            output.WriteLine("The envelope couldn't be updated here; CaseBook doesn't know about this yet. Run the tool on the server.");
    }

    private static bool TryWrite(string path, string json, TextWriter output)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path + ".new", json);
            File.Move(path + ".new", path, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            output.WriteLine($"Couldn't write {path}: {ex.Message}");
            return false;
        }
    }

    private static string Safe(string name)
    {
        var clean = new string(name.Select(c => c < 32 || Path.GetInvalidFileNameChars().Contains(c) || "<>:\"/\\|?*".Contains(c) ? '_' : c).ToArray())
            .Trim(' ', '.');
        return clean.Length == 0 ? "file" : IncidentManager.Application.Common.TextFit.Cap(clean, 150, marker: "")!;
    }

    // C13: a CSV cell, quoted, with a leading formula character neutralised.
    private static string Csv(string value)
    {
        var v = value.Length > 0 && "=+-@\t\r".Contains(value[0]) ? "'" + value : value;
        return "\"" + v.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}
