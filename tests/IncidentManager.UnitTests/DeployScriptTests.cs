using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Checks on the deploy scripts that no build or test would otherwise catch.</summary>
public partial class DeployScriptTests
{
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
