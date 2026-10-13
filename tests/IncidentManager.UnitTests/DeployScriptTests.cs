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

    [GeneratedRegex(@"sqlcmd(\.exe)?\b.*\s-i\s", RegexOptions.None)]
    private static partial Regex SqlcmdWithInputFile();

    [GeneratedRegex(@"\s-I(\s|$)", RegexOptions.None)]
    private static partial Regex UpperIFlag();

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }
}
