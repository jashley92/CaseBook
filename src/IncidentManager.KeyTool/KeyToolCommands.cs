using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using IncidentManager.Infrastructure.Persistence;
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
            integrity);
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
            Directory.CreateDirectory(outFolder);
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
        Save(site, e, output);
    }

    /// <summary>
    /// Rebuilds the server's copy onto another certificate (a new server, or the old certificate lost), from a backup.
    /// With the chain key in the backup and the chain key on a certificate, its file is rewritten to the new one too.
    /// </summary>
    public static void Recover(Site site, Opening how, string toThumbprint, string toStore, bool writeChainKey, TextWriter output)
    {
        var e = ReadEnvelope(site);
        var opened = Open(e, how);
        using var target = CertificateLookup.FindRsa(toThumbprint, toStore, "--to-cert");
        var normalized = CertificateLookup.Normalize(target.Thumbprint);
        e.Server = new WrappedKey { Kind = WrappedKey.Certificate, Ref = normalized, Data = KeyWrap.ToCertificate(target, opened.EvidenceKey) };
        e.UpdatedUtc = DateTimeOffset.UtcNow;
        CryptographicOperations.ZeroMemory(opened.EvidenceKey);
        Save(site, e, output);
        TryWrite(site.RootEnvelopePath, e.ToJson(), output);
        output.WriteLine($"Evidence key {e.KeyId} is now protected by certificate {normalized} ({toStore}).");
        if (opened.ChainKey is { } chainKey && writeChainKey)
        {
            var path = string.IsNullOrWhiteSpace(site.Integrity.ChainKey.WrappedKeyPath)
                ? Path.Combine(Path.GetDirectoryName(site.EnvelopePath)!, "chain-key.json")
                : site.Integrity.ChainKey.WrappedKeyPath;
            var record = JsonSerializer.Serialize(new { Thumbprint = normalized, Wrapped = KeyWrap.ToCertificate(target, chainKey) });
            File.WriteAllText(path, record);
            output.WriteLine($"The audit chain key ({ChainKeyring.KeyIdOf(chainKey)}) is written to {path}, protected by the same certificate.");
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
        var options = new DbContextOptionsBuilder<AppDbContext>();
        if (site.Provider.Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
            options.UseSqlServer(site.ConnectionString ?? throw new InvalidOperationException("No database connection string in the site's settings."));
        else options.UseSqlite(site.ConnectionString!);
        using var db = new AppDbContext(options.Options);
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
            var folder = Path.Combine(outFolder, Safe(r.CaseNumber));
            Directory.CreateDirectory(folder);
            var name = Safe(r.OriginalFileName);
            var target = Path.Combine(folder, name);
            for (var n = 2; !taken.Add(target) || File.Exists(target); n++)
                target = Path.Combine(folder, $"{Path.GetFileNameWithoutExtension(name)} ({n}){Path.GetExtension(name)}");
            string actual;
            try
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
        File.WriteAllText(Path.Combine(outFolder, "manifest.csv"), manifest.ToString());
        output.WriteLine($"Exported {exported} file(s) to {Path.GetFullPath(outFolder)}; {mismatched} don't match their recorded SHA-256 (see manifest.csv).");
        return (exported, mismatched);
    }

    // A stored file's content: decrypted when it's CBE1 under this key, else as it is.
    private static Stream OpenContent(string path, string keyId, byte[] key)
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

    private static void Save(Site site, KeyEnvelope e, TextWriter output)
    {
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
        return clean.Length == 0 ? "file" : clean.Length > 150 ? clean[..150] : clean;
    }

    // C13: a CSV cell, quoted, with a leading formula character neutralised.
    private static string Csv(string value)
    {
        var v = value.Length > 0 && "=+-@\t\r".Contains(value[0]) ? "'" + value : value;
        return "\"" + v.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}
