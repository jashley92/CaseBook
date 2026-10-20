namespace IncidentManager.KeyTool;

// PROD-57: casebook-keytool. See KeyToolCommands and OPERATIONS.md (Evidence key: backups and recovery).
internal static class KeyToolProgram
{
    private const string Usage = """
        casebook-keytool <command> [options]

          split        --site <folder> [--threshold 3] [--shares 5] [--out <folder>]
                       Split the evidence key into shares (run on the server, as an administrator).
          check-share  <share> [<share> ...]
                       Check shares are intact, on any machine. Nothing is rebuilt or recorded.
          verify       --site <folder> (--pfx <file> | --cert <thumbprint> [--store CurrentUser|LocalMachine] | --shares)
                       A recovery drill: prove a backup opens the key, and record it.
          recover      --site <folder> (--pfx <file> | --cert <thumbprint> | --shares) --to-cert <thumbprint> [--to-store LocalMachine]
                       [--chain-key]
                       Rebuild the server's copy of the key onto another certificate.
          export       --site <folder> (--case <number> | --all) --out <folder> [--pfx <file> | --cert <thumbprint> | --shares]
                       Write evidence out as the original files, with a manifest of their SHA-256s.
          protect-secret [--cert <thumbprint> [--store LocalMachine|CurrentUser] | --site <folder>]
                       Read a secret (the SMTP password, a webhook token) from the console without echo, or from stdin, and
                       print it as a @protected: value for appsettings.Production.json. Without --cert, the site's
                       integrity certificate. Nothing else is printed to stdout.
          check-secret [<@protected: value>]
                       Check a @protected: value opens on this machine, as this account. Prints OK or why not; never the secret.

          verify-restore --site <folder> [--sample 200 | --hash-all] [--public-keys <folder>] [--out <file.json>]
                       [--pfx <file> | --cert <thumbprint> | --shares]
                       Check a restored copy (the database, evidence and keys the site folder's settings point at): the
                       audit chain, every seal, every evidence file present at its size and a sample re-hashed, and the
                       evidence key. Read-only. Exit code 0 when every check passes, 2 when one fails.

          new-signing-key    --out <file.pem>
                       Make a seal-signing key (RSA 3072) as a PEM file, readable by this account only, and its public half
                       beside it (<name>.public.pem). Prints the key id. Run it off the server.
          signing-key-pfx    --pem <file.pem> --out <file.pfx>
                       Put an existing PEM signing key in a password-protected PFX for the certificate store. Same key, same
                       key id.
          signing-public-key (--site <folder> | --pem <file> | --cert <thumbprint> [--store LocalMachine|CurrentUser]) [--out <file>]
                       Write a signing key's public half (PEM), for the retired keys folder or an examiner. Prints the key id.

          rotate-signing-key --site <folder> (--pem-out <file.pem> | --pfx-out <file.pfx>)
                       Rotate the seal-signing key: save the current key's public half into the retired keys folder, make
                       the new key (a PEM file, or a PFX for the certificate store) and say what to change. Settings untouched.
          enable-chain-key   --site <folder> --cert <thumbprint> [--store LocalMachine|CurrentUser] [--backup-done]
                       Turn the audit chain key on with a certificate: check its private key works here, then (with
                       --backup-done, once it's backed up) write Integrity:ChainKey. One-way. The old settings are kept.
          retire-custodian   --site <folder> --cert <thumbprint> [--note "<what was done with their copies>"]
                       Remove a recovery certificate from Storage:Encryption:RecoveryCertificates and the envelope, and record it
                       for the audit trail. Refused when it's the key's only backup. The old settings are kept.

          --site is the CaseBook site folder (where appsettings.Production.json is).
          --pfx asks for the PFX's password; --shares asks for the shares one per line.
        """;

    public static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            Console.WriteLine(Usage);
            return 0;
        }

        try
        {
            var command = args[0];
            var rest = args[1..];
            string? Opt(string name) => Array.IndexOf(rest, name) is var i and >= 0 && i + 1 < rest.Length ? rest[i + 1] : null;
            bool Flag(string name) => rest.Contains(name);
            Site SiteArg() => Site.Load(Opt("--site") ?? throw new ArgumentException("--site is needed: the CaseBook site folder."));

            Opening OpeningArg()
            {
                if (Flag("--shares")) return new Opening(Shares: ReadShares());
                if (Opt("--pfx") is { } pfx) return new Opening(PfxPath: pfx, PfxPassword: ReadSecret($"Password for {pfx}: "));
                if (Opt("--cert") is { } thumb) return new Opening(Thumbprint: thumb, Store: Opt("--store") ?? "CurrentUser");
                return new Opening();
            }

            switch (command)
            {
                case "split":
                    KeyToolCommands.Split(SiteArg(), int.Parse(Opt("--threshold") ?? "3", System.Globalization.CultureInfo.InvariantCulture),
                        int.Parse(Opt("--shares") ?? "5", System.Globalization.CultureInfo.InvariantCulture), Opt("--out"), Console.Out);
                    return 0;
                case "check-share":
                    KeyToolCommands.CheckShares(rest.Length > 0 ? rest : ReadShares(), Console.Out);
                    return 0;
                case "verify":
                    KeyToolCommands.Verify(SiteArg(), OpeningArg(), Console.Out);
                    return 0;
                case "recover":
                    KeyToolCommands.Recover(SiteArg(), OpeningArg(), Opt("--to-cert") ?? throw new ArgumentException("--to-cert is needed."),
                        Opt("--to-store") ?? "LocalMachine", Flag("--chain-key"), Console.Out);
                    return 0;
                case "export":
                    var all = Flag("--all");
                    var caseNumber = Opt("--case");
                    if (all == (caseNumber is not null)) throw new ArgumentException("Give --case <number> or --all.");
                    var (_, mismatched) = KeyToolCommands.Export(SiteArg(), caseNumber, Opt("--out") ?? throw new ArgumentException("--out is needed."),
                        OpeningArg(), Console.Out);
                    return mismatched == 0 ? 0 : 2;
                case "protect-secret":
                    // CAP-05: the prompt and the note go to stderr, so stdout carries the value alone (the installer reads it).
                    var site = Opt("--site") is { } folder ? Site.Load(folder) : null;
                    var secret = ReadSecretOnce("Secret to protect: ", confirm: true);
                    Console.Out.WriteLine(KeyToolCommands.ProtectSecret(secret, Opt("--cert"), Opt("--store") ?? "LocalMachine", site, Console.Error));
                    return 0;
                case "verify-restore":
                    var sample = int.Parse(Opt("--sample") ?? "200", System.Globalization.CultureInfo.InvariantCulture);
                    var report = RestoreCheck.Run(SiteArg(), sample, Flag("--hash-all"), Opt("--public-keys"),
                        Flag("--shares") || Opt("--pfx") is not null || Opt("--cert") is not null ? OpeningArg() : null, Console.Out);
                    if (Opt("--out") is { } reportOut) File.WriteAllText(reportOut, RestoreCheck.ToJson(report));
                    Console.Out.WriteLine(report.Passed ? "Every check passed." : "A check failed: this restore isn't verified.");
                    return report.Passed ? 0 : 2;
                case "new-signing-key":
                    SigningKeyCommands.NewKey(Opt("--out") ?? throw new ArgumentException("--out is needed: where to write the key."), Console.Out);
                    return 0;
                case "signing-key-pfx":
                    var pem = Opt("--pem") ?? throw new ArgumentException("--pem is needed: the PEM signing key.");
                    var pfxOut = Opt("--out") ?? throw new ArgumentException("--out is needed: where to write the PFX.");
                    SigningKeyCommands.ToPfx(pem, pfxOut, ReadSecretOnce("Password for the PFX: ", confirm: true), Console.Out);
                    return 0;
                case "signing-public-key":
                    var signingSite = Opt("--site") is { } signingFolder ? Site.Load(signingFolder) : null;
                    var (keyId, publicPem) = SigningKeyCommands.PublicKey(Opt("--pem"), Opt("--cert"), Opt("--store") ?? "LocalMachine", signingSite);
                    if (Opt("--out") is { } publicOut)
                    {
                        var full = Path.GetFullPath(publicOut);
                        if (File.Exists(full)) throw new InvalidOperationException($"{full} already exists; nothing was written.");
                        File.WriteAllText(full, publicPem);
                        Console.Out.WriteLine($"Public key of seal-signing key {keyId}: {full}");
                    }
                    else
                    {
                        Console.Error.WriteLine($"Seal-signing key {keyId}:");
                        Console.Out.Write(publicPem);
                        Console.Out.WriteLine();
                    }
                    return 0;
                case "rotate-signing-key":
                    KeyLifecycleCommands.RotateSigningKey(SiteArg(), Opt("--pem-out"), Opt("--pfx-out"),
                        () => ReadSecretOnce("Password for the PFX: ", confirm: true), Console.Out);
                    return 0;
                case "enable-chain-key":
                    KeyLifecycleCommands.EnableChainKey(SiteArg(), Opt("--cert") ?? throw new ArgumentException("--cert is needed: the certificate's thumbprint."),
                        Opt("--store") ?? "LocalMachine", Flag("--backup-done"), Console.Out);
                    return 0;
                case "retire-custodian":
                    KeyLifecycleCommands.RetireCustodian(SiteArg(), Opt("--cert") ?? throw new ArgumentException("--cert is needed: the recovery certificate's thumbprint."),
                        Opt("--note"), Console.Out);
                    return 0;
                case "check-secret":
                    var value = rest.Length > 0 && !rest[0].StartsWith("--", StringComparison.Ordinal) ? rest[0] : ReadSecretOnce("@protected: value: ", confirm: false);
                    return KeyToolCommands.CheckSecret(value, Console.Out) ? 0 : 1;
                default:
                    Console.Error.WriteLine($"Unknown command '{command}'.");
                    Console.Error.WriteLine(Usage);
                    return 1;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.Security.Cryptography.CryptographicException
                                       or FormatException or IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"casebook-keytool: {ex.Message}");
            return 1;
        }
    }

    private static List<string> ReadShares()
    {
        Console.WriteLine("Enter the shares, one per line; a blank line when done.");
        var shares = new List<string>();
        while (Console.ReadLine() is { Length: > 0 } line) shares.Add(line.Trim());
        return shares;
    }

    // CAP-05: a secret read without echo (prompted on stderr), or the first line of stdin when it's redirected (an installer
    // piping it in). Asked twice when typed, so a typo isn't protected.
    private static string ReadSecretOnce(string prompt, bool confirm)
    {
        if (Console.IsInputRedirected) return ReadRedirectedLine(Console.OpenStandardInput());
        var first = ReadHidden(prompt, Console.Error);
        if (confirm && ReadHidden("Again, to confirm: ", Console.Error) != first)
            throw new ArgumentException("The two entries differ; nothing was protected.");
        return first;
    }

    /// <summary>
    /// CAP-05 review: the first line of redirected stdin, read as UTF-8 (a BOM, if any, is dropped). Not through
    /// <see cref="Console.In"/>, which decodes in the console's OEM code page and would turn an accented letter into
    /// something else, so the value protected wouldn't be the password typed. The installer pipes it as UTF-8 to match.
    /// </summary>
    internal static string ReadRedirectedLine(Stream input)
    {
        using var reader = new StreamReader(input, new System.Text.UTF8Encoding(false), detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        return (reader.ReadLine() ?? "").TrimEnd('\r', '\n');
    }

    private static string ReadHidden(string prompt, TextWriter to)
    {
        to.Write(prompt);
        var secret = new System.Text.StringBuilder();
        while (true)
        {
            var k = Console.ReadKey(intercept: true);
            if (k.Key == ConsoleKey.Enter) break;
            if (k.Key == ConsoleKey.Backspace) { if (secret.Length > 0) secret.Length--; continue; }
            secret.Append(k.KeyChar);
        }
        to.WriteLine();
        return secret.ToString();
    }

    private static string ReadSecret(string prompt)
    {
        Console.Write(prompt);
        if (Console.IsInputRedirected) return Console.ReadLine() ?? "";
        var secret = new System.Text.StringBuilder();
        while (true)
        {
            var k = Console.ReadKey(intercept: true);
            if (k.Key == ConsoleKey.Enter) break;
            if (k.Key == ConsoleKey.Backspace) { if (secret.Length > 0) secret.Length--; continue; }
            secret.Append(k.KeyChar);
        }
        Console.WriteLine();
        return secret.ToString();
    }
}
