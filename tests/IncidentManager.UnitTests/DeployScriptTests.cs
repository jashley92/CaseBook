using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Checks on the deploy scripts that no build or test would otherwise catch.</summary>
public partial class DeployScriptTests
{
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
    public void The_shipped_web_config_lets_api_reach_the_app(/* BUG-261 */)
    {
        // The SDK's default web.config wraps the aspNetCore handler in <location inheritInChildApplications="false">, and
        // IIS doesn't carry it into the <location path="CaseBook/api"> the installer adds, so /api went to IIS's
        // StaticFile handler (404). CaseBook ships its own web.config so publish adds the handler outside any wrapper.
        var webConfig = File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "web.config"));
        var withoutComments = Regex.Replace(webConfig, "<!--.*?-->", "", RegexOptions.Singleline);

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
    public void Every_anonymous_endpoint_the_app_maps_is_carved_out_of_windows_auth_by_the_installer(/* CAP-37 */)
    {
        // IIS answers 401 before the app runs on any path that isn't carved out, so an endpoint the app maps anonymous
        // (a probe, the email logo, the calendar feed) only works on an installed site if the installer opens its path.
        var program = File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "Program.cs"));
        var maps = MappedRoute().Matches(program).ToList();
        var anonymous = maps
            .Select((m, i) => (Path: m.Groups["path"].Value,
                Body: program[m.Index..(i + 1 < maps.Count ? maps[i + 1].Index : program.Length)]))
            .Where(x => x.Body.Contains(".AllowAnonymous()", StringComparison.Ordinal))
            .Select(x => x.Path)
            .ToList();
        anonymous.Should().Contain(["/health", "/health/live", "/branding/logo", "/agenda/feed.ics"]);

        var install = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "Install-CaseBook.ps1"));
        var carved = AnonymousPaths().Match(install);
        carved.Success.Should().BeTrue("the installer lists the carved-out paths in $anonymousPaths");
        var paths = Regex.Matches(carved.Groups[1].Value, "'([^']+)'").Select(m => "/" + m.Groups[1].Value).Append("/api").ToList();
        paths.Should().NotContain("/agenda", "the signed-in /agenda/agenda.ics download stays Windows-authenticated");

        anonymous.Where(a => !paths.Any(p => a == p || a.StartsWith(p + "/", StringComparison.Ordinal)))
            .Should().BeEmpty("every anonymous endpoint needs its path carved out in Install-CaseBook.ps1");

        var verify = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "Verify-Install.ps1"));
        verify.Should().Contain("'/health/live'").And.Contain("'/branding/logo'").And.Contain("'/agenda/feed.ics'");
    }

    [GeneratedRegex(@"app\.Map(Get|Post|HealthChecks)\(\s*""(?<path>/[^""]*)""", RegexOptions.None, 1000)]
    private static partial Regex MappedRoute();

    [GeneratedRegex(@"\$anonymousPaths\s*=\s*@\(([^)]*)\)", RegexOptions.None, 1000)]
    private static partial Regex AnonymousPaths();

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
}
