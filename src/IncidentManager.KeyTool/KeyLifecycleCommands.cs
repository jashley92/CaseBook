using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using IncidentManager.Infrastructure.Security;

namespace IncidentManager.KeyTool;

/// <summary>
/// The key changes OPERATIONS.md section 2 describes as several manual steps, each as one command: rotating the seal-signing
/// key, turning the audit chain key on, and retiring a recovery custodian. Each checks before it changes anything, and says
/// what's left to do (installing a certificate and restarting the app pool stay the administrator's).
/// </summary>
internal static class KeyLifecycleCommands
{
    /// <summary>
    /// rotate-signing-key: saves the current key's public half into the retired keys folder (so its seals still verify),
    /// then makes the new key as a PEM file or a PFX for the certificate store, and prints the settings to change. The
    /// site's settings aren't changed: the new key has to be installed first. Returns the new key id.
    /// </summary>
    public static string RotateSigningKey(Site site, string? pemOut, string? pfxOut, Func<string> pfxPassword, TextWriter output)
    {
        if ((pemOut is null) == (pfxOut is null)) throw new ArgumentException("Give --pem-out <file.pem> or --pfx-out <file.pfx>.");

        // 1. The current key's public half, where the app reads retired keys.
        var (oldId, oldPublic) = SigningKeyCommands.PublicKey(null, null, "LocalMachine", site);
        var retired = RsaSealSigner.RetiredFolder(site.IntegrityResolved);
        var retiredFile = Path.Combine(retired, $"{oldId}.pem");
        if (File.Exists(retiredFile))
            output.WriteLine($"The current key {oldId}'s public half is already in {retiredFile}.");
        else
        {
            Directory.CreateDirectory(retired);
            File.WriteAllText(retiredFile, oldPublic);
            output.WriteLine($"Saved the current key {oldId}'s public half to {retiredFile}, so the seals it signed still verify.");
        }

        // 2. The new key.
        string newId;
        if (pemOut is not null)
        {
            newId = SigningKeyCommands.NewKey(pemOut, output);
            output.WriteLine();
            output.WriteLine("Then:");
            output.WriteLine($"  1. Put the new key where Integrity:SigningKeyPath points ({site.SigningKeyPath}), replacing the old one, or");
            output.WriteLine("     set Integrity:SigningKeyPath to it. The app-pool account needs read on it; nobody else.");
        }
        else
        {
            var path = Path.GetFullPath(pfxOut!);
            if (File.Exists(path)) throw new InvalidOperationException($"{path} already exists; nothing was written.");
            using var rsa = RSA.Create(SigningKeyCommands.KeySizeBits);
            newId = RsaSealSigner.KeyIdOf(rsa);
            SigningKeyCommands.ToPfx(rsa, path, pfxPassword(), output);
            output.WriteLine();
            output.WriteLine("Then:");
            output.WriteLine($"  1. Import-PfxCertificate -FilePath '{path}' -CertStoreLocation Cert:\\LocalMachine\\My (not exportable), give the");
            output.WriteLine("     app-pool account read on its private key, and delete the PFX once it's kept somewhere safe.");
            output.WriteLine("  2. In appsettings.Production.json: Integrity:SigningKey:Source \"CertificateStore\", and");
            output.WriteLine("     Integrity:SigningKey:CertificateThumbprint the thumbprint printed above.");
        }
        output.WriteLine("  Recycle the app pool. The Integrity page shows the new key id " + newId + "; re-verify an older seal: it reports");
        output.WriteLine("  authentic, signed by " + oldId + ".");
        return newId;
    }

    /// <summary>
    /// enable-chain-key: turns the audit chain key on with a certificate, after checking the certificate's private key works
    /// here and that its backup is confirmed (it's one-way: keyed entries can only be checked while the key is held). Writes
    /// the settings, keeping the old file beside them.
    /// </summary>
    public static void EnableChainKey(Site site, string thumbprint, string store, bool backupConfirmed, TextWriter output)
    {
        var chain = site.Integrity.ChainKey;
        if (chain.Enabled)
            throw new InvalidOperationException($"The audit chain key is already on ({chain.Source}). To change its key, rotate it " +
                                                "(OPERATIONS.md section 2, The audit chain key).");

        // The account the app runs as needs the same; this proves the key isn't just present but usable.
        using var cert = CertificateLookup.FindRsa(thumbprint, store, "--cert");
        using (var pub = cert.GetRSAPublicKey()!)
        using (var priv = cert.GetRSAPrivateKey() ?? throw new InvalidOperationException($"Certificate {cert.Thumbprint} has no usable private key here."))
        {
            var probe = RandomNumberGenerator.GetBytes(32);
            if (!priv.Decrypt(pub.Encrypt(probe, RSAEncryptionPadding.OaepSHA256), RSAEncryptionPadding.OaepSHA256).AsSpan().SequenceEqual(probe))
                throw new InvalidOperationException($"Certificate {cert.Thumbprint}'s key didn't decrypt what it encrypted; it can't hold the chain key.");
        }
        var normalized = CertificateLookup.Normalize(cert.Thumbprint);
        output.WriteLine($"OK: certificate {normalized} ({cert.Subject}) in {store}\\My, private key usable by {Environment.UserDomainName}\\{Environment.UserName}.");

        var keyFile = ChainKeyFile(site);
        if (Path.GetFullPath(keyFile).StartsWith(site.Folder.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"The chain key file would be {keyFile}, inside the site folder, which an upgrade replaces. Set " +
                                                "Integrity:ChainKey:WrappedKeyPath (and RetiredWrappedKeysPath) under the data root's keys folder first.");

        if (!backupConfirmed)
        {
            output.WriteLine();
            output.WriteLine("Nothing was changed. Turning the chain key on is one-way: entries hashed with it can only be checked while the");
            output.WriteLine("key is held. Before turning it on, back up this certificate with its private key (to a password-protected PFX");
            output.WriteLine($"kept offline), and plan to back up {keyFile} once CaseBook has made it. Then run this again with --backup-done.");
            throw new ChainKeyNotConfirmedException();
        }

        SiteSettings.Edit(site.Folder, "enable-chain-key", root =>
        {
            var k = SiteSettings.Section(root, "Integrity", "ChainKey");
            k["Enabled"] = true;
            k["Source"] = "Certificate";
            k["CertificateThumbprint"] = normalized;
            k["StoreLocation"] = store;
        }, output);
        output.WriteLine("Integrity:ChainKey is on, with Source Certificate and this certificate.");
        output.WriteLine("Next: restart the app pool. CaseBook makes the key on its first start and keeps it, encrypted to the certificate,");
        output.WriteLine($"in {keyFile}. Back that file up with the certificate's PFX. The Integrity page shows the chain key's id.");
    }

    /// <summary>
    /// retire-custodian: removes a recovery certificate from Storage:Encryption:RecoveryCertificates and its lock from the
    /// envelope, and records it there for CaseBook to write to the audit trail (with what was done about their copies).
    /// Refused when it's the last backup of the key.
    /// </summary>
    public static void RetireCustodian(Site site, string thumbprint, string? note, TextWriter output)
    {
        var e = KeyToolCommands.ReadEnvelope(site);
        var normalized = CertificateLookup.Normalize(thumbprint);
        var copy = e.Recovery.FirstOrDefault(r => CertificateLookup.Normalize(r.Thumbprint) == normalized)
            ?? throw new InvalidOperationException($"The evidence key has no recovery lock for certificate {normalized}. Its locks: " +
                                                   (e.Recovery.Count == 0 ? "none" : string.Join(", ", e.Recovery.Select(r => $"{r.Thumbprint} ({r.Subject})"))) + ".");
        if (e.Recovery.Count == 1 && e.Shares is null)
            throw new InvalidOperationException($"{copy.Subject} holds the key's only backup. Add another recovery certificate (or issue shares) " +
                                                "and let CaseBook lock the key to it first; nothing was changed.");

        // The .cer files listed are matched by their thumbprint, so the setting can name them however it likes.
        var removed = SiteSettings.Edit(site.Folder, "retire-custodian", root =>
        {
            var gone = new List<string>();
            var enc = SiteSettings.Section(root, "Storage", "Encryption");
            if (enc["RecoveryCertificates"] is not JsonArray list) return gone;
            foreach (var item in list.ToList())
            {
                var path = item?.GetValue<string>();
                if (path is null) continue;
                var full = Path.GetFullPath(Path.Combine(site.Folder, path));
                if (!File.Exists(full)) continue;
                using var cer = X509CertificateLoader.LoadCertificateFromFile(full);
                if (CertificateLookup.Normalize(cer.Thumbprint) != normalized) continue;
                list.Remove(item);
                gone.Add(path);
            }
            return gone;
        }, output);
        if (removed.Count == 0)
            output.WriteLine($"Storage:Encryption:RecoveryCertificates doesn't list a .cer for {normalized}; only the envelope was changed.");
        else
            output.WriteLine($"Removed {string.Join(", ", removed)} from Storage:Encryption:RecoveryCertificates.");

        e.Recovery.Remove(copy);
        e.Record(KeyToolRecord.CustodianRetired, $"Recovery certificate {normalized} ({copy.Subject}) retired from evidence key {e.KeyId}" +
                                                 (string.IsNullOrWhiteSpace(note) ? "." : $": {note.Trim()}"));
        KeyToolCommands.SaveEnvelope(site, e, output);
        output.WriteLine($"{copy.Subject}'s lock is gone from the live envelope. Older copies of evidence-key.json (and backups taken");
        output.WriteLine("before now) still open with their .pfx: collect and destroy their .pfx and envelope copy, and say so with --note.");
        output.WriteLine("Next: restart the app pool (it reads RecoveryCertificates at start-up). CaseBook writes this to the audit trail.");
    }

    // As the app resolves it: WrappedKeyPath, or chain-key.json beside the envelope (the keys folder).
    private static string ChainKeyFile(Site site) =>
        string.IsNullOrWhiteSpace(site.IntegrityResolved.ChainKey.WrappedKeyPath)
            ? Path.Combine(Path.GetDirectoryName(site.EnvelopePath)!, "chain-key.json")
            : site.IntegrityResolved.ChainKey.WrappedKeyPath;
}

/// <summary>enable-chain-key without --backup-done: nothing changed, exit code 1.</summary>
internal sealed class ChainKeyNotConfirmedException() : InvalidOperationException("Run it again with --backup-done once the certificate is backed up.");

/// <summary>Changes the site's appsettings.Production.json, keeping the file as it was beside it.</summary>
internal static class SiteSettings
{
    private static readonly JsonDocumentOptions Read = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };
    private static readonly JsonSerializerOptions Write = new() { WriteIndented = true };

    public static void Edit(string siteFolder, string why, Action<JsonObject> change, TextWriter output) =>
        Edit(siteFolder, why, root => { change(root); return true; }, output);

    /// <summary>As <see cref="Edit(string, string, Action{JsonObject}, TextWriter)"/>, returning what the change found.</summary>
    public static T Edit<T>(string siteFolder, string why, Func<JsonObject, T> change, TextWriter output)
    {
        var path = Path.Combine(siteFolder, "appsettings.Production.json");
        var root = File.Exists(path)
            ? JsonNode.Parse(File.ReadAllText(path), documentOptions: Read) as JsonObject
              ?? throw new InvalidOperationException($"{path} isn't a JSON object; nothing was changed.")
            : new JsonObject();
        var result = change(root);
        if (File.Exists(path))
        {
            var kept = $"{path}.before-{why}-{DateTime.UtcNow:yyyyMMddHHmmss}";
            File.Copy(path, kept);
            output.WriteLine($"The settings as they were are kept as {kept}.");
        }
        File.WriteAllText(path, root.ToJsonString(Write));
        return result;
    }

    /// <summary>The object at <paramref name="names"/>, made when it's missing.</summary>
    public static JsonObject Section(JsonObject root, params string[] names)
    {
        var node = root;
        foreach (var name in names)
        {
            if (node[name] is not JsonObject next) { next = new JsonObject(); node[name] = next; }
            node = next;
        }
        return node;
    }
}
