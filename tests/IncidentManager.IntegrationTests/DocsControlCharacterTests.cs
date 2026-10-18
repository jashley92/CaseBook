using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// A script that writes "\03" meaning a path's backslash and "03" once left a control character in INSTALL.md, so the
/// path read "deploy\sql␃-Enable-FullText.sql". No doc holds a control character other than tab, CR and LF.
/// </summary>
public sealed class DocsControlCharacterTests
{
    private static readonly Regex Control = new(@"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", RegexOptions.None, TimeSpan.FromSeconds(1));

    [Fact]
    public void No_doc_holds_a_control_character()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "IncidentManager.sln"))) root = root.Parent;
        var hits = new[] { "docs", "deploy", "integrations" }
            .Select(d => Path.Combine(root!.FullName, d))
            .Where(Directory.Exists)
            .SelectMany(d => Directory.EnumerateFiles(d, "*.md", SearchOption.AllDirectories))
            .Append(Path.Combine(root!.FullName, "README.md"))
            .Where(File.Exists)
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (f, i, line)))
            .Where(x => Control.IsMatch(x.line))
            .Select(x => $"{Path.GetRelativePath(root!.FullName, x.f)}:{x.i + 1}")
            .ToList();
        hits.Should().BeEmpty("a control character in a doc is almost always a lost backslash escape");
    }
}
