using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-341 (B2 review): <c>InputFileChangeEventArgs.GetMultipleFiles</c> throws past its limit, outside a handler's
/// per-file catch, and a drop of 51 files on the timeline composer took the circuit down after the Evidence tab had been
/// fixed. Every call goes through <c>DroppedFiles</c>, which never throws for a count, so a new handler can't bring it back.
/// </summary>
public class DroppedFilesGuardTests
{
    private static readonly Regex Call = new(@"\.GetMultipleFiles\s*\(", RegexOptions.None, TimeSpan.FromSeconds(1));

    private const string Helper = "src/IncidentManager.Web/Components/Shared/DroppedFiles.cs";

    [Fact]
    public void Every_GetMultipleFiles_call_goes_through_DroppedFiles()
    {
        var root = ComponentSourceScanner.RepoRoot();
        var calls = Directory.EnumerateFiles(Path.Combine(root, "src"), "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
            .Select(f => (Path: Path.GetRelativePath(root, f).Replace('\\', '/'), File: f))
            .Where(s => !s.Path.Contains("/bin/", StringComparison.Ordinal) && !s.Path.Contains("/obj/", StringComparison.Ordinal))
            .SelectMany(s => File.ReadAllLines(s.File).Select((line, i) => (s.Path, Line: i + 1, Text: line)))
            .Where(l => Call.IsMatch(l.Text))
            .ToList();

        calls.Should().NotBeEmpty("the helper itself calls it");
        calls.Where(c => c.Path != Helper).Select(c => $"{c.Path}:{c.Line}").Should().BeEmpty(
            "GetMultipleFiles throws past its limit (BUG-341); read a drop's files with DroppedFiles.UpTo or DroppedFiles.First");
    }

    private static readonly Regex ArgsParameter = new(@"\bInputFileChangeEventArgs\s+(?<name>@?\w+)", RegexOptions.None, TimeSpan.FromSeconds(1));

    // BUG-341 sibling: InputFileChangeEventArgs.File throws when two or more files arrive, and the paste shim puts every
    // pasted image in a picker, so two pasted screenshots took the Evidence tab down. In each file, a `.File` read on a
    // name declared there as an InputFileChangeEventArgs (a handler's parameter) is flagged; `.FileCount` isn't `.File`.
    [Fact]
    public void No_handler_reads_InputFileChangeEventArgs_File()
    {
        var root = ComponentSourceScanner.RepoRoot();
        var reads = Directory.EnumerateFiles(Path.Combine(root, "src"), "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
            .Select(f => (Path: Path.GetRelativePath(root, f).Replace('\\', '/'), File: f))
            .Where(s => s.Path != Helper && !s.Path.Contains("/bin/", StringComparison.Ordinal) && !s.Path.Contains("/obj/", StringComparison.Ordinal))
            .SelectMany(s =>
            {
                var lines = File.ReadAllLines(s.File);
                var names = lines.SelectMany(l => ArgsParameter.Matches(l).Select(m => m.Groups["name"].Value.TrimStart('@')))
                    .Distinct(StringComparer.Ordinal).ToList();
                if (names.Count == 0) return [];
                var read = new Regex(@"(?<![\w.])(?:" + string.Join('|', names.Select(Regex.Escape)) + @")\s*\??\.\s*File\b",
                    RegexOptions.None, TimeSpan.FromSeconds(1));
                return lines.Select((line, i) => (s.Path, Line: i + 1, Text: line)).Where(l => read.IsMatch(l.Text));
            })
            .ToList();

        reads.Select(c => $"{c.Path}:{c.Line}").Should().BeEmpty(
            "InputFileChangeEventArgs.File throws for two or more files (a paste or drop can bring them); use DroppedFiles.First");
    }
}
