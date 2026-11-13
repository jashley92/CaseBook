using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using AwesomeAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// Release signing and the offline hash check (lib\TideUpgrade.ps1 Invoke-CaseBookBundleCheck, Test-CaseBookBundle.ps1,
/// tools/signing/New-ReleaseSigningKey.ps1), on every PowerShell here: Windows PowerShell 5.1 verifies with RSACng and
/// PowerShell 7 with RSA.Create(), so each signature check runs on each. Every key is a throwaway made by the test.
/// </summary>
public sealed class ReleaseSigningTests
{
    // Throwaway bundles and keys, and Check, which runs Invoke-CaseBookBundleCheck and says what it decided or why it refused.
    private const string SigningFixture = """
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('casebook-sign-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        function New-TestBundle([string] $Version = 'v9.9.9') {
            $src = Join-Path $dir ([guid]::NewGuid().ToString('N'))
            $root = Join-Path $src "casebook-$Version"
            New-Item -ItemType Directory -Path $root -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $root 'VERSION.txt') -Value "Version: $Version" -Encoding ascii
            Set-Content -LiteralPath (Join-Path $root 'payload.txt') -Value ([guid]::NewGuid().ToString()) -Encoding ascii
            $out = Join-Path $dir ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $out | Out-Null
            $zip = Join-Path $out "casebook-$Version.zip"
            [IO.Compression.ZipFile]::CreateFromDirectory($src, $zip)
            return $zip
        }
        function Write-TestSig([string] $Zip, $Rsa) {
            $sig = $Rsa.SignHash((Get-CaseBookFileSha256Bytes $Zip), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pss)
            [IO.File]::WriteAllBytes("$Zip.sig", $sig)
        }
        function Write-TestSha([string] $Zip, [string] $Hash) {
            if (-not $Hash) { $Hash = (Get-FileHash -LiteralPath $Zip -Algorithm SHA256).Hash.ToLowerInvariant() }
            Set-Content -LiteralPath "$Zip.sha256" -Value "$Hash  $(Split-Path -Leaf $Zip)" -Encoding ascii
        }
        function Check([hashtable] $A) {
            try {
                $r = Invoke-CaseBookBundleCheck @A
                [pscustomobject]@{ Ok = $true; KeyId = $r.KeyId; HashSource = $r.HashSource; Tag = $r.Tag; Warnings = @($r.Warnings); Error = '' }
            } catch {
                [pscustomobject]@{ Ok = $false; KeyId = $null; HashSource = $null; Tag = $null; Warnings = @(); Error = $_.Exception.Message }
            }
        }
        $rsa = New-CaseBookRsa
        $other = New-CaseBookRsa
        $keys = @(@{ Id = '0123456789abcdef'; Xml = $rsa.ToXmlString($false) })
        """;

    private static (bool Ok, string? KeyId, string? HashSource, string? Tag, string[] Warnings, string Error) Outcome(JsonElement r, string name)
    {
        var c = r.GetProperty(name);
        string? S(string p) => c.GetProperty(p).ValueKind == JsonValueKind.Null ? null : c.GetProperty(p).GetString();
        var w = c.GetProperty("Warnings");
        return (c.GetProperty("Ok").GetBoolean(), S("KeyId"), S("HashSource"), S("Tag"),
            w.ValueKind == JsonValueKind.Array ? w.EnumerateArray().Select(x => x.GetString()!).ToArray() : [],
            S("Error") ?? "");
    }

    [Fact]
    public void A_bundle_signed_by_a_pinned_key_is_accepted_and_one_changed_or_signed_by_another_key_is_refused()
    {
        foreach (var shell in Shells())
        {
            var r = Run(SigningFixture + """

                try {
                    $out = [ordered]@{}
                    $z = New-TestBundle; Write-TestSig $z $rsa
                    $out.valid = Check @{ ZipPath = $z; Keys = $keys }

                    $z = New-TestBundle; Write-TestSig $z $rsa
                    Add-Content -LiteralPath $z -Value 'x'
                    $out.tampered = Check @{ ZipPath = $z; Keys = $keys }

                    $z = New-TestBundle; Write-TestSig $z $other
                    $out.foreign = Check @{ ZipPath = $z; Keys = $keys }

                    $z = New-TestBundle; [IO.File]::WriteAllBytes("$z.sig", [byte[]](1..64))
                    $out.garbage = Check @{ ZipPath = $z; Keys = $keys }

                    # A second pinned key (a rotation) verifies too, and a pinned key that won't load is passed over.
                    $z = New-TestBundle; Write-TestSig $z $other
                    $out.rotated = Check @{ ZipPath = $z; Keys = @(@{ Id = 'badbadbadbadbad0'; Xml = '<RSAKeyValue>nonsense' }) + $keys + @(@{ Id = 'fedcba9876543210'; Xml = $other.ToXmlString($false) }) }

                    # Signed, but the .sha256 beside it (or -ExpectedSha256) disagrees: refused.
                    $z = New-TestBundle; Write-TestSig $z $rsa; Write-TestSha $z ('0' * 64)
                    $out.signedBadSha = Check @{ ZipPath = $z; Keys = $keys }
                } finally { Remove-Item -LiteralPath $dir -Recurse -Force }
                ConvertTo-Json -Depth 4 -Compress -InputObject $out
                """, shell);
            var valid = Outcome(r, "valid");
            valid.Ok.Should().BeTrue(shell + ": " + valid.Error);
            valid.KeyId.Should().Be("0123456789abcdef");
            valid.Tag.Should().Be("v9.9.9");
            valid.Warnings.Should().BeEmpty();
            foreach (var refused in new[] { "tampered", "foreign", "garbage" })
            {
                var o = Outcome(r, refused);
                o.Ok.Should().BeFalse("{0} on {1}", refused, shell);
                o.Error.Should().Contain("isn't a valid signature").And.Contain("0123456789abcdef").And.Contain("Nothing was changed");
            }
            Outcome(r, "rotated").KeyId.Should().Be("fedcba9876543210", shell);
            var badSha = Outcome(r, "signedBadSha");
            badSha.Ok.Should().BeFalse(shell);
            badSha.Error.Should().Contain("doesn't match").And.Contain(".sha256 beside it");
        }
    }

    [Fact]
    public void A_bundle_without_a_signature_is_refused_while_keys_are_pinned_unless_AllowUnsigned_and_checked_by_hash_when_none_are()
    {
        foreach (var shell in Shells())
        {
            var r = Run(SigningFixture + """

                try {
                    $out = [ordered]@{}
                    $z = New-TestBundle; Write-TestSha $z
                    $out.unsigned = Check @{ ZipPath = $z; Keys = $keys }
                    $out.allowed = Check @{ ZipPath = $z; Keys = $keys; AllowUnsigned = $true }
                    $out.noKeys = Check @{ ZipPath = $z; Keys = @() }

                    # No keys pinned, a .sig beside it: it can't be checked, so the hash decides, as before signing.
                    $z = New-TestBundle; Write-TestSig $z $other; Write-TestSha $z
                    $out.noKeysSigned = Check @{ ZipPath = $z; Keys = @() }
                    $z = New-TestBundle; Write-TestSig $z $other; Write-TestSha $z ('0' * 64)
                    $out.noKeysBadSha = Check @{ ZipPath = $z; Keys = @() }

                    # AllowUnsigned doesn't excuse a signature that's there and wrong.
                    $z = New-TestBundle; Write-TestSig $z $other
                    $out.allowedForeign = Check @{ ZipPath = $z; Keys = $keys; AllowUnsigned = $true }
                } finally { Remove-Item -LiteralPath $dir -Recurse -Force }
                ConvertTo-Json -Depth 4 -Compress -InputObject $out
                """, shell);
            var unsigned = Outcome(r, "unsigned");
            unsigned.Ok.Should().BeFalse(shell);
            unsigned.Error.Should().Contain("isn't signed").And.Contain("-AllowUnsigned").And.Contain("Nothing was changed");
            var allowed = Outcome(r, "allowed");
            allowed.Ok.Should().BeTrue(shell + ": " + allowed.Error);
            allowed.KeyId.Should().BeNull();
            allowed.HashSource.Should().Be("local");
            allowed.Warnings.Should().ContainSingle().Which.Should().Contain("isn't signed");
            var noKeys = Outcome(r, "noKeys");
            noKeys.Should().Match<(bool Ok, string? KeyId, string? HashSource, string? Tag, string[] Warnings, string Error)>(o => o.Ok && o.HashSource == "local" && o.Warnings.Length == 0);
            Outcome(r, "noKeysSigned").Should().Match<(bool Ok, string? KeyId, string? HashSource, string? Tag, string[] Warnings, string Error)>(o => o.Ok && o.KeyId == null && o.HashSource == "local");
            Outcome(r, "noKeysBadSha").Ok.Should().BeFalse(shell);
            Outcome(r, "allowedForeign").Error.Should().Contain("isn't a valid signature", shell);
        }
    }

    [Fact]
    public void The_hash_comes_from_ExpectedSha256_or_the_sha256_beside_the_zip_without_asking_github_and_from_the_release_otherwise()
    {
        // Invoke-WebRequest is replaced by a stand-in that records each request: with a .sha256 beside the zip, or
        // -ExpectedSha256, none is made.
        var r = Run(SigningFixture + """

            $script:requests = @()
            $script:answer = $null
            function Invoke-WebRequest { param($Uri, $OutFile, [switch] $UseBasicParsing, $TimeoutSec, $Proxy, [switch] $ProxyUseDefaultCredentials)
                $script:requests += $Uri
                if (-not $script:answer) { throw 'Unable to connect to the remote server' }
                Set-Content -LiteralPath $OutFile -Value $script:answer -Encoding ascii }
            $web = @{ UseBasicParsing = $true; TimeoutSec = 300; Proxy = 'http://127.0.0.1:9' }
            function Requests { $n = $script:requests.Count; $script:requests = @(); $n }
            try {
                $out = [ordered]@{}
                $z = New-TestBundle; $hash = (Get-FileHash -LiteralPath $z -Algorithm SHA256).Hash
                Write-TestSha $z
                $out.local = Check @{ ZipPath = $z; Keys = @(); Web = $web; Repository = 'casebook-test/no-such-repo' }
                $out.localRequests = Requests

                $z = New-TestBundle; $hash = (Get-FileHash -LiteralPath $z -Algorithm SHA256).Hash
                $out.expected = Check @{ ZipPath = $z; Keys = @(); Web = $web; ExpectedSha256 = $hash.ToLowerInvariant() }
                $out.expectedRequests = Requests
                $out.expectedWrong = Check @{ ZipPath = $z; Keys = @(); Web = $web; ExpectedSha256 = ('a' * 64) }
                $out.expectedJunk = Check @{ ZipPath = $z; Keys = @(); Web = $web; ExpectedSha256 = 'abc' }
                # What you typed wins over the file beside the zip.
                Write-TestSha $z ('0' * 64)
                $out.expectedOverLocal = Check @{ ZipPath = $z; Keys = @(); ExpectedSha256 = $hash }
                Remove-Item -LiteralPath "$z.sha256"
                Set-Content -LiteralPath "$z.sha256" -Value '<html>Not Found</html>' -Encoding ascii
                $out.localJunk = Check @{ ZipPath = $z; Keys = @() }
                Remove-Item -LiteralPath "$z.sha256"

                # Neither: the release's .sha256 on github.com, as before; a host that can't reach it is warned.
                $script:answer = "$($hash.ToLowerInvariant())  casebook-v9.9.9.zip"
                $out.release = Check @{ ZipPath = $z; Keys = @(); Web = $web; Repository = 'casebook-test/repo' }
                $out.releaseUri = @($script:requests)[0]
                $out.releaseRequests = Requests
                $script:answer = ('0' * 64)
                $out.releaseWrong = Check @{ ZipPath = $z; Keys = @(); Web = $web }
                $null = Requests
                $script:answer = $null
                $out.unreachable = Check @{ ZipPath = $z; Keys = @(); Web = $web }
                $out.unreachableRequests = Requests
                $out.offline = Check @{ ZipPath = $z; Keys = @() }

                # A valid signature needs no fetch.
                Write-TestSig $z $rsa
                $out.signed = Check @{ ZipPath = $z; Keys = $keys; Web = $web }
                $out.signedRequests = Requests
            } finally { Remove-Item -LiteralPath $dir -Recurse -Force }
            ConvertTo-Json -Depth 4 -Compress -InputObject $out
            """);
        var local = Outcome(r, "local");
        local.Should().Match<(bool Ok, string? KeyId, string? HashSource, string? Tag, string[] Warnings, string Error)>(o => o.Ok && o.HashSource == "local" && o.Warnings.Length == 0, local.Error);
        r.GetProperty("localRequests").GetInt32().Should().Be(0, "the .sha256 beside the zip is used with no request to github.com");
        Outcome(r, "expected").HashSource.Should().Be("expected");
        r.GetProperty("expectedRequests").GetInt32().Should().Be(0);
        Outcome(r, "expectedWrong").Error.Should().Contain("doesn't match the -ExpectedSha256 given").And.Contain("Nothing was changed");
        Outcome(r, "expectedJunk").Error.Should().Contain("64 hex characters");
        Outcome(r, "expectedOverLocal").Should().Match<(bool Ok, string? KeyId, string? HashSource, string? Tag, string[] Warnings, string Error)>(o => o.Ok && o.HashSource == "expected");
        Outcome(r, "localJunk").Error.Should().Contain("holds no SHA-256");
        Outcome(r, "release").HashSource.Should().Be("release");
        r.GetProperty("releaseUri").GetString().Should().Be("https://github.com/casebook-test/repo/releases/download/v9.9.9/casebook-v9.9.9.zip.sha256");
        r.GetProperty("releaseRequests").GetInt32().Should().Be(1);
        Outcome(r, "releaseWrong").Error.Should().Contain("doesn't match the v9.9.9 release's");
        var unreachable = Outcome(r, "unreachable");
        unreachable.Ok.Should().BeTrue("a host without github.com carries on, as before");
        unreachable.HashSource.Should().BeNull();
        unreachable.Warnings.Should().ContainSingle().Which.Should().Contain("Not checked against the release").And.Contain("-ExpectedSha256");
        r.GetProperty("unreachableRequests").GetInt32().Should().Be(1);
        Outcome(r, "offline").Warnings.Should().ContainSingle().Which.Should().Contain("-ExpectedSha256");
        Outcome(r, "signed").KeyId.Should().Be("0123456789abcdef");
        r.GetProperty("signedRequests").GetInt32().Should().Be(0);
    }

    [Fact]
    public void Test_CaseBookBundle_checks_a_bundle_offline_and_fails_when_it_is_not_verified()
    {
        foreach (var shell in Shells())
        {
            var r = Run(SigningFixture + """

                $test = Join-Path $deploy 'Test-CaseBookBundle.ps1'
                $keysFile = Join-Path $dir 'keys.ps1'
                Set-Content -LiteralPath $keysFile -Encoding ascii -Value ("`$CaseBookReleaseKeys = @(`n    @{ Id = '0123456789abcdef'; Xml = '" + $rsa.ToXmlString($false) + "' }`n)")
                $noKeys = Join-Path $dir 'none.ps1'
                Set-Content -LiteralPath $noKeys -Encoding ascii -Value "`$CaseBookReleaseKeys = @(`n)"
                function Go([hashtable] $A) {
                    try { $lines = @(& $test @A 6>&1 | ForEach-Object { "$_" }); [pscustomobject]@{ Ok = $true; Text = $lines -join "`n" } }
                    catch { [pscustomobject]@{ Ok = $false; Text = $_.Exception.Message } }
                }
                try {
                    $out = [ordered]@{}
                    $z = New-TestBundle; Write-TestSig $z $rsa
                    $out.signed = Go @{ BundleZip = $z; TrustedKeysPath = $keysFile }
                    # A .sha256 beside it, nothing pinned, and a repository and proxy that would fail any request.
                    $z = New-TestBundle; Write-TestSha $z
                    $out.local = Go @{ BundleZip = $z; TrustedKeysPath = $noKeys; Repository = 'casebook-test/no-such-repo'; Proxy = 'http://127.0.0.1:9' }
                    $out.unsigned = Go @{ BundleZip = $z; TrustedKeysPath = $keysFile }
                    $out.allowed = Go @{ BundleZip = $z; TrustedKeysPath = $keysFile; AllowUnsigned = $true }
                    $z = New-TestBundle
                    $out.nothing = Go @{ BundleZip = $z; TrustedKeysPath = $noKeys; Offline = $true }
                    $out.expected = Go @{ BundleZip = $z; TrustedKeysPath = $noKeys; ExpectedSha256 = (Get-FileHash -LiteralPath $z -Algorithm SHA256).Hash; Offline = $true }
                    $out.wrong = Go @{ BundleZip = $z; TrustedKeysPath = $noKeys; ExpectedSha256 = ('0' * 64) }
                    $out.missingKeys = Go @{ BundleZip = $z; TrustedKeysPath = (Join-Path $dir 'nope.ps1') }
                } finally { Remove-Item -LiteralPath $dir -Recurse -Force }
                ConvertTo-Json -Depth 4 -Compress -InputObject $out
                """, shell);
            (bool Ok, string Text) Go(string n) => (r.GetProperty(n).GetProperty("Ok").GetBoolean(), r.GetProperty(n).GetProperty("Text").GetString()!);
            Go("signed").Should().Match<(bool Ok, string Text)>(g => g.Ok && g.Text.Contains("OK: the v9.9.9 bundle is signed by CaseBook's release key 0123456789abcdef"), shell);
            Go("local").Ok.Should().BeTrue(shell + ": " + Go("local").Text);
            Go("local").Text.Should().Contain("SHA-256 matches casebook-v9.9.9.zip.sha256 beside it").And.NotContain("Not checked");
            Go("unsigned").Should().Match<(bool Ok, string Text)>(g => !g.Ok && g.Text.Contains("isn't signed"));
            Go("allowed").Should().Match<(bool Ok, string Text)>(g => g.Ok && g.Text.Contains("isn't signed") && g.Text.Contains("matches its SHA-256"));
            Go("nothing").Should().Match<(bool Ok, string Text)>(g => !g.Ok && g.Text.StartsWith("Not verified"));
            Go("expected").Ok.Should().BeTrue(shell);
            Go("wrong").Should().Match<(bool Ok, string Text)>(g => !g.Ok && g.Text.Contains("doesn't match"));
            Go("missingKeys").Should().Match<(bool Ok, string Text)>(g => !g.Ok && g.Text.Contains("-TrustedKeysPath not found"));
        }
    }

    [Fact]
    public void The_shipped_release_keys_load_and_each_is_a_well_formed_RSA_key()
    {
        // Shipped empty until the owner runs tools/signing/New-ReleaseSigningKey.ps1; then each key must load where the
        // upgrade verifies with it, and carry the id the Release workflow derives from the secret.
        foreach (var shell in Shells())
        {
            var r = Run("""
                $keys = @(Get-CaseBookTrustedKeys (Join-Path (Join-Path $deploy 'lib') 'CaseBookReleaseKeys.ps1'))
                $out = @($keys | ForEach-Object {
                    $rsa = New-CaseBookRsa
                    try { $rsa.FromXmlString($_.Xml); $size = $rsa.KeySize } catch { $size = 0 } finally { $rsa.Dispose() }
                    [pscustomobject]@{ Id = $_.Id; Xml = $_.Xml; Size = $size } })
                ConvertTo-Json -Depth 3 -Compress -InputObject @{ Keys = $out; Missing = @(Get-CaseBookTrustedKeys (Join-Path $deploy 'no-such-file.ps1')).Count }
                """, shell);
            r.GetProperty("Missing").GetInt32().Should().Be(0);
            foreach (var k in r.GetProperty("Keys").EnumerateArray())
            {
                k.GetProperty("Size").GetInt32().Should().BeGreaterThanOrEqualTo(3072, "key {0} loads on {1}", k.GetProperty("Id").GetString(), shell);
                k.GetProperty("Id").GetString().Should().Be(KeyId(k.GetProperty("Xml").GetString()!));
            }
        }
    }

    [Fact]
    public void The_key_script_writes_a_PEM_and_pins_its_public_key_and_the_upgrade_trusts_what_it_signs()
    {
        // -DryRun: no gh, and the public key goes to a copy of CaseBookReleaseKeys.ps1. The PEM is read back here with .NET,
        // the bundle signed with it, and each PowerShell's Test-CaseBookBundle.ps1 must accept the signature with the pinned key.
        foreach (var shell in Shells())
        {
            var work = Directory.CreateTempSubdirectory("casebook-key-").FullName;
            try
            {
                var keys = Path.Combine(work, "keys.ps1");
                var backup = Path.Combine(work, "release-key.pem");
                var r = KeyScript(keys, backup, shell);
                r.GetProperty("ok").GetBoolean().Should().BeTrue(shell + ": " + r.GetProperty("text").GetString());
                var printed = r.GetProperty("text").GetString()!;

                var pem = File.ReadAllText(backup);
                pem.Should().Contain("-----BEGIN PRIVATE KEY-----").And.Contain("offline or in a password manager");
                using var rsa = RSA.Create();
                rsa.ImportFromPem(pem);
                rsa.KeySize.Should().Be(3072);
                var id = Convert.ToHexStringLower(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()))[..16];
                var pinned = File.ReadAllText(keys);
                pinned.Should().Contain($"Id = '{id}'").And.Contain(rsa.ToXmlString(false));
                printed.Should().Contain(id).And.NotContain("BEGIN PRIVATE KEY").And.NotContain(pem.Split('\n')[5].Trim(), "the key is never shown");
                (pinned.IndexOf($"Id = '{id}'", StringComparison.Ordinal)).Should().BeLessThan(pinned.IndexOf("adds each key above this line", StringComparison.Ordinal));

                var zip = SignedBundle(work, rsa);
                BundleCheck(zip, keys, shell).Should().Contain($"signed by CaseBook's release key {id}");

                // A second run never overwrites the backup; a dry run never touches the repository's file.
                var again = KeyScript(keys, backup, shell);
                again.GetProperty("ok").GetBoolean().Should().BeFalse();
                again.GetProperty("text").GetString().Should().Contain("exists");
                var noKeysPath = Run("""
                    try { & (Join-Path (Join-Path (Join-Path (Split-Path -Parent $deploy) 'tools') 'signing') 'New-ReleaseSigningKey.ps1') -BackupPath (Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N') + '.pem')) -DryRun 6>$null; $m = 'ran' }
                    catch { $m = $_.Exception.Message }
                    ConvertTo-Json -Compress -InputObject @{ m = $m }
                    """, shell);
                noKeysPath.GetProperty("m").GetString().Should().Contain("-DryRun needs -KeysPath");
            }
            finally { Directory.Delete(work, true); }
        }
    }

    [OpenSslFact]
    public void A_bundle_signed_by_the_Release_workflows_openssl_command_verifies_in_PowerShell()
    {
        // The release job signs with openssl and derives the key id with openssl; PowerShell verifies with .NET. Both
        // sides must agree on the PSS parameters (SHA-256, MGF1-SHA-256, a 32-byte salt) and on the id.
        const string sign = "openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sign \"$key\"";
        const string derive = "openssl pkey -in \"$key\" -pubout -outform DER | sha256sum | cut -c1-16";
        var release = File.ReadAllText(Path.Combine(DeployScriptTests.RepoRoot(), ".github", "workflows", "release.yml"));
        release.Should().Contain(sign).And.Contain(derive);

        var work = Directory.CreateTempSubdirectory("casebook-openssl-").FullName;
        try
        {
            var keys = Path.Combine(work, "keys.ps1");
            var backup = Path.Combine(work, "release-key.pem");
            KeyScript(keys, backup, Shells().First()).GetProperty("ok").GetBoolean().Should().BeTrue();

            var zip = SignedBundle(work, null);
            OpenSsl(["dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sign", backup, "-out", zip + ".sig", zip]);
            var der = OpenSsl(["pkey", "-in", backup, "-pubout", "-outform", "DER"]);
            var id = Convert.ToHexStringLower(SHA256.HashData(der))[..16];
            File.ReadAllText(keys).Should().Contain($"Id = '{id}'", "the workflow's id for the secret is the one the key script pins");
            foreach (var shell in Shells())
                BundleCheck(zip, keys, shell).Should().Contain($"signed by CaseBook's release key {id}", shell);
        }
        finally { Directory.Delete(work, true); }
    }

    private static string KeyId(string xml)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(xml);
        return Convert.ToHexStringLower(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()))[..16];
    }

    private static JsonElement KeyScript(string keys, string backup, string shell) => Run($$"""
        try {
            $text = @(& (Join-Path (Join-Path (Join-Path (Split-Path -Parent $deploy) 'tools') 'signing') 'New-ReleaseSigningKey.ps1') `
                -BackupPath '{{backup.Replace("'", "''")}}' -KeysPath '{{keys.Replace("'", "''")}}' -DryRun 6>&1 | ForEach-Object { "$_" }) -join "`n"
            $ok = $true
        } catch { $text = $_.Exception.Message; $ok = $false }
        ConvertTo-Json -Compress -InputObject @{ ok = $ok; text = $text }
        """, shell);

    // A bundle with a VERSION.txt, signed with rsa when one is given.
    private static string SignedBundle(string work, RSA? rsa)
    {
        var src = Path.Combine(work, "src");
        Directory.CreateDirectory(Path.Combine(src, "casebook-v9.9.9"));
        File.WriteAllText(Path.Combine(src, "casebook-v9.9.9", "VERSION.txt"), "Version: v9.9.9\n");
        var zip = Path.Combine(work, "casebook-v9.9.9.zip");
        ZipFile.CreateFromDirectory(src, zip);
        if (rsa is not null)
            File.WriteAllBytes(zip + ".sig", rsa.SignHash(SHA256.HashData(File.ReadAllBytes(zip)), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        return zip;
    }

    // Test-CaseBookBundle.ps1's output, trusting the keys file given; a refusal fails the test with its message.
    private static string BundleCheck(string zip, string keys, string shell)
    {
        var r = Run($$"""
            try { $t = @(& (Join-Path $deploy 'Test-CaseBookBundle.ps1') '{{zip.Replace("'", "''")}}' -TrustedKeysPath '{{keys.Replace("'", "''")}}' -Offline 6>&1 | ForEach-Object { "$_" }) -join "`n" }
            catch { $t = 'REFUSED: ' + $_.Exception.Message }
            ConvertTo-Json -Compress -InputObject @{ t = $t }
            """, shell);
        var text = r.GetProperty("t").GetString()!;
        text.Should().NotStartWith("REFUSED", shell);
        return text;
    }

    private static byte[] OpenSsl(string[] args)
    {
        var psi = new ProcessStartInfo(OpenSslFactAttribute.Path()!, args) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        var stderr = p.StandardError.ReadToEndAsync();
        using var ms = new MemoryStream();
        p.StandardOutput.BaseStream.CopyTo(ms);
        p.WaitForExit(60_000).Should().BeTrue();
        p.ExitCode.Should().Be(0, "openssl {0}: {1}", string.Join(' ', args), stderr.Result);
        return ms.ToArray();
    }

    private static readonly string Deploy = Path.Combine(DeployScriptTests.RepoRoot(), "deploy");
    private static string? _shell;

    // Runs a script with $deploy set and lib\CaseBookRelease.ps1 dot-sourced, and parses the JSON it writes.
    private static JsonElement Run(string script, string? shell = null)
    {
        var file = Path.Combine(Path.GetTempPath(), "casebook-deploy-test-" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(file, "$ErrorActionPreference = 'Stop'\n$deploy = '" + Deploy.Replace("'", "''") + "'\n"
            + ". '" + Path.Combine(Deploy, "lib", "CaseBookRelease.ps1").Replace("'", "''") + "'\n" + script);
        try
        {
            var psi = new ProcessStartInfo(shell ?? Shell(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file])
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using var p = Process.Start(psi)!;
            var stderr = p.StandardError.ReadToEndAsync();
            var stdout = p.StandardOutput.ReadToEnd();
            p.WaitForExit(120_000).Should().BeTrue("PowerShell finishes");
            p.ExitCode.Should().Be(0, "the script ran: {0}", stderr.Result);
            return JsonDocument.Parse(stdout).RootElement.Clone();
        }
        finally { File.Delete(file); }
    }

    private static string Shell() => _shell ??= Shells().FirstOrDefault()
        ?? throw new InvalidOperationException("These tests need PowerShell: pwsh (PowerShell 7) or, on Windows, powershell.exe.");

    /// <summary>
    /// Every PowerShell here: pwsh, and on Windows also powershell.exe (5.1), which verifies with RSACng where
    /// PowerShell 7 uses RSA.Create(). A signature check runs on each.
    /// </summary>
    private static IEnumerable<string> Shells()
    {
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        foreach (var name in OperatingSystem.IsWindows() ? new[] { "pwsh.exe", "powershell.exe" } : ["pwsh"])
        {
            var hit = dirs.Select(d => Path.Combine(d, name)).FirstOrDefault(File.Exists);
            if (hit is not null) yield return hit;
        }
    }
}

/// <summary>A test that needs openssl on PATH (the Release workflow's signer), skipped where it isn't.</summary>
public sealed class OpenSslFactAttribute : FactAttribute
{
    public OpenSslFactAttribute()
    {
        if (Path() is null) Skip = "openssl isn't on PATH.";
    }

    public static string? Path()
    {
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        var name = OperatingSystem.IsWindows() ? "openssl.exe" : "openssl";
        return dirs.Select(d => System.IO.Path.Combine(d, name)).FirstOrDefault(File.Exists);
    }
}
