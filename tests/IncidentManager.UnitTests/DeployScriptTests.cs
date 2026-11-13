using System.Text.RegularExpressions;
using AwesomeAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Checks on the deploy scripts that no build or test would otherwise catch.</summary>
public partial class DeployScriptTests
{
    [Fact]
    public void The_kept_deploy_folder_is_not_readable_by_every_signed_in_user(/* BUG-704 */)
    {
        // The kept copy holds the answers file, so only Administrators, SYSTEM and the site's app pool may read it.
        var lib = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "lib", "CaseBookIis.ps1"));
        var start = lib.IndexOf("function Publish-CaseBookDeployScripts", StringComparison.Ordinal);
        start.Should().BeGreaterThan(-1);
        var end = lib.IndexOf("\nfunction ", start + 1, StringComparison.Ordinal);
        var body = lib[start..(end < 0 ? lib.Length : end)];
        body.Should().NotContain("S-1-5-11", "Authenticated Users must not be granted read on the kept deploy folder");
        body.Should().Contain("Get-CaseBookAppPoolSid", "the app pool is granted read by its own identity");
    }

    [Fact]
    public void The_deploy_scripts_are_plain_ascii(/* REV-79 */)
    {
        // Windows PowerShell 5.1 reads a BOM-less script in the ANSI code page, so a non-ASCII character (an em dash) turns
        // into mojibake, and in a string or a here-string changes what the script does. A leading UTF-8 BOM is allowed.
        var deploy = Path.Combine(RepoRoot(), "deploy");
        var offenders = Directory.EnumerateFiles(deploy, "*.ps*1", SearchOption.AllDirectories)
            .Select(f => (File: Path.GetRelativePath(deploy, f), Bytes: File.ReadAllBytes(f)))
            .Select(x => (x.File, Bytes: x.Bytes.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]) ? x.Bytes[3..] : x.Bytes))
            .Where(x => x.Bytes.Any(b => b > 127))
            .Select(x => x.File)
            .ToList();

        offenders.Should().BeEmpty();
    }

    [Fact]
    public void Every_sqlcmd_that_runs_a_script_file_turns_QUOTED_IDENTIFIER_on()
    {
        // BUG-143: sqlcmd defaults QUOTED_IDENTIFIER off, and the schema's filtered indexes fail without it.
        var deploy = Path.Combine(RepoRoot(), "deploy");
        var calls = Directory.EnumerateFiles(deploy, "*.ps1", SearchOption.AllDirectories)
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (File: Path.GetFileName(f), Line: i + 1, Text: line)))
            .Where(l => SqlcmdWithInputFile().IsMatch(l.Text))
            .ToList();

        calls.Should().NotBeEmpty();
        calls.Where(c => !UpperIFlag().IsMatch(c.Text)).Select(c => $"{c.File}:{c.Line}")
            .Should().BeEmpty("every sqlcmd.exe call that runs a .sql file needs -I");
    }

    [Fact]
    public void No_deploy_script_holds_a_stray_control_character()
    {
        // A script generator that wrote "files\retired" turned "\r" into a carriage return mid-line, so the path read
        // "files" and "etired-seal-keys". Tabs and line endings only.
        var deploy = Path.Combine(RepoRoot(), "deploy");
        Directory.EnumerateFiles(deploy, "*.ps*1", SearchOption.AllDirectories)
            // Split on \n only: ReadAllLines would take a lone \r as a line break and hide it.
            .SelectMany(f => File.ReadAllText(f).Split('\n').Select(l => l.TrimEnd('\r'))
                .Select((line, i) => (File: Path.GetRelativePath(deploy, f), Line: i + 1, Text: line)))
            .Where(x => x.Text.Any(c => c < ' ' && c != '\t'))
            .Select(x => $"{x.File}:{x.Line}")
            .Should().BeEmpty("a control character in a script is almost always a lost backslash escape");
    }

    [Fact]
    public void The_shipped_web_config_lets_api_reach_the_app(/* BUG-261 */)
    {
        // The SDK's default web.config wraps the aspNetCore handler in <location inheritInChildApplications="false">, and
        // IIS doesn't carry it into the <location path="CaseBook/api"> the installer adds, so /api went to IIS's
        // StaticFile handler (404). CaseBook ships its own web.config so publish adds the handler outside any wrapper.
        var webConfig = File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "web.config"));
        var withoutComments = XmlComment().Replace(webConfig, "");

        withoutComments.Should().Contain("<system.webServer>");
        withoutComments.Should().NotContain("<location");
        withoutComments.Should().NotContain("inheritInChildApplications");
    }

    [Fact]
    public void The_template_keeps_the_chain_key_under_the_data_root_where_it_always_was(/* BUG-544 */)
    {
        // Blank, these paths mean "beside SigningKeyPath", which with no SigningKeyPath is the site folder an upgrade
        // mirrors (deleting the key). Set explicitly, they must still be the folder and names the blank default gives a
        // fresh install, so an existing key isn't moved.
        using var doc = System.Text.Json.JsonDocument.Parse(
            File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "appsettings.Production.template.json")));
        var integrity = doc.RootElement.GetProperty("Integrity");
        var keysFolder = Path.GetDirectoryName(integrity.GetProperty("SigningKeyPath").GetString()!.Replace('\\', '/'))!.Replace('\\', '/');
        var chain = integrity.GetProperty("ChainKey");

        keysFolder.Should().Be("__DATA_ROOT__/keys");
        chain.GetProperty("WrappedKeyPath").GetString()!.Replace('\\', '/').Should().Be(keysFolder + "/chain-key.json");
        chain.GetProperty("RetiredWrappedKeysPath").GetString()!.Replace('\\', '/').Should().Be(keysFolder + "/chain-retired");
    }

    [Fact]
    public void Every_anonymous_endpoint_the_app_maps_is_carved_out_of_windows_auth_by_the_install_and_upgrade_scripts(/* CAP-37 */)
    {
        // IIS answers 401 before the app runs on any path that isn't carved out, so an endpoint the app maps anonymous
        // (a probe, the email logo, the calendar feed) only works on an installed site if the installer opens its path,
        // and on a site upgraded from before the path was added only if the upgrade opens it too.
        var program = File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "Program.cs"));
        var maps = MappedRoute().Matches(program).ToList();
        var anonymous = maps
            .Select((m, i) => (Path: m.Groups["path"].Value,
                Body: program[m.Index..(i + 1 < maps.Count ? maps[i + 1].Index : program.Length)]))
            .Where(x => x.Body.Contains(".AllowAnonymous()", StringComparison.Ordinal))
            .Select(x => x.Path)
            .ToList();
        anonymous.Should().Contain(["/health", "/health/live", "/branding/logo", "/agenda/feed.ics"]);

        // The paths live in one list in lib\CaseBookIis.ps1, which the installer sets and the upgrade checks and repairs.
        var lib = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "lib", "CaseBookIis.ps1"));
        var carved = AnonymousPaths().Match(lib);
        carved.Success.Should().BeTrue(@"lib\CaseBookIis.ps1 lists the carved-out paths in Get-CaseBookAnonymousPaths");
        var paths = QuotedItem().Matches(carved.Groups[1].Value).Select(m => "/" + m.Groups[1].Value).ToList();
        paths.Should().Contain("/api", "the token-authenticated API is carved out with the rest");
        paths.Should().NotContain("/agenda", "the signed-in /agenda/agenda.ics download stays Windows-authenticated");

        anonymous.Where(a => !paths.Any(p => a == p || a.StartsWith(p + "/", StringComparison.Ordinal)))
            .Should().BeEmpty("every anonymous endpoint needs its path carved out in Get-CaseBookAnonymousPaths");

        // Both scripts load that module and apply the carve-outs through it, and neither keeps a list of its own to drift.
        foreach (var script in new[] { "Install-CaseBook.ps1", "Upgrade-CaseBook.ps1" })
        {
            var text = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", script));
            text.Should().Contain(@"lib\CaseBookIis.ps1", script + " loads the shared module");
            text.Should().MatchRegex(@"Sync-CaseBookAnonymousCarveOuts\s+-SiteName", script + " applies the shared carve-outs");
            text.Should().NotMatchRegex(@"\$anonymousPaths\s*=", script + " has no list of its own");
            text.Should().NotContain(@"set config ""$SiteName/", script + " writes no carve-out by hand");
        }
        lib.Should().Contain("/commit:apphost", "the sections are locked at server scope, so the carve-out is a <location> entry");

        var verify = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "Verify-Install.ps1"));
        verify.Should().Contain("'/health/live'").And.Contain("'/branding/logo'").And.Contain("'/agenda/feed.ics'");
    }

    [Fact]
    public void The_websocket_helpers_check_the_feature_on_server_and_client_windows_and_the_site_configuration()
    {
        // Without the IIS WebSocket Protocol feature (or with system.webServer/webSocket off) Blazor's circuits fall back
        // to long polling, a request for every keystroke. One set of helpers, which the three scripts share.
        var lib = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "lib", "CaseBookIis.ps1"));
        lib.Should().Contain("Get-WindowsFeature -Name 'Web-WebSockets'", "Windows Server names it Web-WebSockets");
        lib.Should().Contain("Get-WindowsOptionalFeature -Online -FeatureName 'IIS-WebSockets'", "client Windows names it IIS-WebSockets");
        lib.Should().Contain("Install-WindowsFeature -Name 'Web-WebSockets'");
        lib.Should().Contain("Enable-WindowsOptionalFeature -Online -FeatureName 'IIS-WebSockets'");
        lib.Should().Contain("RestartNeeded", "the installer says when a restart is needed");
        lib.Should().Contain("-Filter 'system.webServer/webSocket' -Name 'enabled'");
        lib.Should().Contain("'MACHINE/WEBROOT/APPHOST'").And.Contain("\"MACHINE/WEBROOT/APPHOST/$SiteName\"",
            "it reads both the server's setting and the one the site gets");

        var fix = Function(lib, "Get-CaseBookWebSocketFix");
        fix.Should().Contain("Install-WindowsFeature Web-WebSockets")
            .And.Contain("reverse proxy or load balancer passes the Upgrade and Connection headers");
    }

    [Fact]
    public void The_installer_offers_websockets_and_installs_them_unasked_only_with_its_switch()
    {
        var install = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "Install-CaseBook.ps1"));
        install.Should().Contain("[switch] $InstallWebSockets").And.Contain(".PARAMETER InstallWebSockets");
        install.Should().Contain("Get-CaseBookWebSocketFeature").And.Contain("Install-CaseBookWebSocketFeature");
        install.Should().Contain("Get-CaseBookWebSocketConfig -SiteName $SiteName", "it also checks the site isn't turned off");
        install.Should().Contain("/section:system.webServer/webSocket /enabled:true /commit:apphost");

        // Asked only with a console; an unattended run warns and carries on, as with the runtime check.
        var confirm = Function(install, "Confirm-WebSocketChange");
        confirm.Should().Contain("if ($InstallWebSockets) { return $true }");
        confirm.Should().Contain("if (-not $interactive) { return $false }");
        install.Should().Contain("[Environment]::UserInteractive").And.Contain("NonI(nteractive)");
        install.Should().MatchRegex(@"Write-Warning \(""Carrying on without the IIS WebSocket Protocol feature");

        // The feature check comes before the publish, so the pool started at the end has it.
        install.IndexOf("$wsFeature = Get-CaseBookWebSocketFeature", StringComparison.Ordinal)
            .Should().BeLessThan(install.IndexOf("& dotnet publish", StringComparison.Ordinal));
    }

    [Fact]
    public void The_upgrade_only_warns_about_websockets()
    {
        var upgrade = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "Upgrade-CaseBook.ps1"));
        var start = upgrade.IndexOf("# 3h. WEBSOCKETS.", StringComparison.Ordinal);
        start.Should().BeGreaterThan(-1);
        var check = upgrade[start..upgrade.IndexOf("# BUG-314", start, StringComparison.Ordinal)];

        check.Should().Contain("Get-CaseBookWebSocketProblem -SiteName $SiteName").And.Contain("Write-Warn2");
        check.Should().NotContain("throw", "a missing WebSocket feature never stops an upgrade");
        check.Should().NotContain("Install-CaseBookWebSocketFeature", "the upgrade changes no IIS feature");
        check.Should().Contain("catch", "a check that can't run is a warning too");
        // Before the confirmation, so -WhatIf reports it.
        start.Should().BeLessThan(upgrade.IndexOf("# --- 4. Confirm", StringComparison.Ordinal));
    }

    [Fact]
    public void Verify_install_fails_on_missing_websockets_and_tries_a_real_handshake()
    {
        var verify = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "Verify-Install.ps1"));
        var start = verify.IndexOf("# 5. WebSockets.", StringComparison.Ordinal);
        start.Should().BeGreaterThan(-1);
        var check = verify[start..verify.IndexOf("# ===", start, StringComparison.Ordinal)];

        check.Should().Contain("Bad \"IIS WebSocket Protocol feature", "a missing feature is a FAIL");
        check.Should().Contain("Get-CaseBookWebSocketConfig -SiteName $wsSite");
        check.Should().Contain("/_blazor").And.Contain("/negotiate?negotiateVersion=1");
        check.Should().Contain("-UseDefaultCredentials", "the negotiate request signs in as the smoke test does");
        check.Should().Contain("System.Net.WebSockets.ClientWebSocket").And.Contain("UseDefaultCredentials = $true");
        check.Should().Contain("-replace '^http', 'ws'", "https becomes wss, http ws");
        check.Should().Contain("Upgrade/").And.Contain("Fix: $wsFix");
        verify.Should().Contain("[string] $SiteName").And.Contain(".PARAMETER SiteName");
    }

    // A function's body, from its declaration to the next one.
    private static string Function(string script, string name)
    {
        var start = script.IndexOf("function " + name, StringComparison.Ordinal);
        start.Should().BeGreaterThan(-1, name + " exists");
        var end = script.IndexOf("\nfunction ", start + 1, StringComparison.Ordinal);
        return script[start..(end < 0 ? script.Length : end)];
    }

    [GeneratedRegex(@"app\.Map(Get|Post|HealthChecks)\(\s*""(?<path>/[^""]*)""", RegexOptions.None, 1000)]
    private static partial Regex MappedRoute();

    [GeneratedRegex(@"function\s+Get-CaseBookAnonymousPaths\s*\{\s*return\s+@\(([^)]*)\)", RegexOptions.None, 1000)]
    private static partial Regex AnonymousPaths();

    [GeneratedRegex("<!--.*?-->", RegexOptions.Singleline, 1000)]
    private static partial Regex XmlComment();

    [GeneratedRegex("'([^']+)'", RegexOptions.None, 1000)]
    private static partial Regex QuotedItem();

    [GeneratedRegex(@"sqlcmd(\.exe)?\b.*\s-i\s", RegexOptions.None)]
    private static partial Regex SqlcmdWithInputFile();

    [GeneratedRegex(@"\s-I(\s|$)", RegexOptions.None)]
    private static partial Regex UpperIFlag();

    internal static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }
}

/// <summary>
/// BUG-600 (C12): a date the deploy scripts write into a file name, a file or a version record is formatted with the
/// invariant culture. Windows PowerShell's <c>Get-Date -Format</c> and <c>.ToString('yyyy...')</c> use the server's
/// culture, whose calendar can be Thai Buddhist (2569) or Hijri (1448): ledger digest names then sorted out of order,
/// and Verify-LedgerDigests -Latest picked the wrong digests.
/// </summary>
public partial class DeployScriptCultureTests
{
    private static readonly string Deploy = Path.Combine(DeployScriptTests.RepoRoot(), "deploy");

    private static IEnumerable<(string File, int Line, string Text)> ScriptLines() =>
        Directory.EnumerateFiles(Deploy, "*.ps*1", SearchOption.AllDirectories)
            // Comment lines too: one in a here-string is written into a generated file.
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (File: Path.GetRelativePath(Deploy, f), Line: i + 1, Text: line)));

    [GeneratedRegex(@"Get-Date\b[^|;]*-Format\b|\[datetime\]::Parse\(|-as\s+\[datetime\]|\.ToShort(Date|Time)String\(|\.ToLong(Date|Time)String\(", RegexOptions.IgnoreCase, 1000)]
    private static partial Regex CultureDate();

    // A date format pattern passed to ToString without a culture.
    [GeneratedRegex(@"\.ToString\(\s*'[^']*(yyyy|HH|dd|MM)[^']*'\s*\)", RegexOptions.None, 1000)]
    private static partial Regex ToStringWithDatePattern();

    [Fact]
    public void Dates_are_formatted_with_the_invariant_culture()
    {
        var offenders = ScriptLines()
            .Where(l => CultureDate().IsMatch(l.Text) || ToStringWithDatePattern().IsMatch(l.Text))
            .Select(l => $"{l.File}:{l.Line}: {l.Text.Trim()}")
            .ToList();

        offenders.Should().BeEmpty("use Get-CaseBookStamp (lib\\CaseBookStamp.ps1) or pass [Globalization.CultureInfo]::InvariantCulture");
    }

    [Fact]
    public void Ledger_digests_are_named_and_ordered_by_an_invariant_stamp()
    {
        var export = File.ReadAllText(Path.Combine(Deploy, "Export-LedgerDigest.ps1"));
        var verify = File.ReadAllText(Path.Combine(Deploy, "Verify-LedgerDigests.ps1"));

        export.Should().Contain("Get-CaseBookStamp").And.Contain(@"lib\CaseBookStamp.ps1");
        verify.Should().Contain("ConvertFrom-CaseBookStamp").And.Contain(@"lib\CaseBookStamp.ps1");
        verify.Should().NotMatchRegex(@"Sort-Object\s+(-Property\s+)?Name\b", "the newest digest is the latest stamp, not the last name");

        var stamp = File.ReadAllText(Path.Combine(Deploy, "lib", "CaseBookStamp.ps1"));
        stamp.Should().Contain("InvariantCulture").And.Contain("ParseExact");
    }

    [Fact]
    public void The_upgrade_script_keeps_its_byte_order_mark()
    {
        // It has carried a UTF-8 BOM since v1.5; a rewrite that drops it changes how Windows PowerShell 5.1 reads it.
        var bytes = File.ReadAllBytes(Path.Combine(Deploy, "Upgrade-CaseBook.ps1"));
        bytes.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]).Should().BeTrue();
        File.ReadAllText(Path.Combine(Deploy, "Upgrade-CaseBook.ps1")).Should().Contain(@"lib\CaseBookStamp.ps1");
    }

    [Fact]
    public void The_upgrade_checks_a_bundle_against_its_release_before_expanding_it()
    {
        // A bundle's signature and SHA-256 are checked by the installed script (lib\CaseBookRelease.ps1), before anything
        // in it is used: before the handover to the bundle's own script, and before it's expanded.
        var script = File.ReadAllText(Path.Combine(Deploy, "Upgrade-CaseBook.ps1"));
        var check = script.IndexOf("$check = Invoke-CaseBookBundleCheck", StringComparison.Ordinal);
        check.Should().BeGreaterThan(-1);
        var handover = script.IndexOf("& $bundleScript @pass", StringComparison.Ordinal);
        var expand = script.IndexOf("ZipFile]::ExtractToDirectory($zipPath, $staging)", StringComparison.Ordinal);
        expand.Should().BeGreaterThan(-1);
        check.Should().BeLessThan(handover).And.BeLessThan(expand);
        script.Should().Contain(@"lib\CaseBookRelease.ps1").And.Contain(@"lib\CaseBookReleaseKeys.ps1");
        File.ReadAllText(Path.Combine(Deploy, "lib", "CaseBookRelease.ps1"))
            .Should().Contain("/releases/download/$Tag/casebook-$Tag.zip.sha256");
        script.Should().Contain("ReleaseHashChecked", "the handover tells the bundle's script the check already ran");
    }

    [Fact]
    public void The_upgrade_hands_over_before_expanding_the_whole_bundle()
    {
        // The bundle's script is compared and extracted straight from the zip, so a handover doesn't expand the app twice.
        var script = File.ReadAllText(Path.Combine(Deploy, "Upgrade-CaseBook.ps1"));
        var handover = script.IndexOf("& $bundleScript @pass", StringComparison.Ordinal);
        var expand = script.IndexOf("ZipFile]::ExtractToDirectory($zipPath, $staging)", StringComparison.Ordinal);
        handover.Should().BeGreaterThan(-1);
        expand.Should().BeGreaterThan(handover);
        script.Should().NotContain("Expand-Archive -Path $BundleZip", "Expand-Archive is many times slower in Windows PowerShell 5.1");
    }
}
