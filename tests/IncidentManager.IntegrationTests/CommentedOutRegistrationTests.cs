using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Batch-4 review B1: a lost line break left <c>builder.Services.Configure&lt;RetentionOptions&gt;(...)</c> at the end of a
/// comment, so the retention job ran on its defaults whatever the administrator set. This scans the app's source for a
/// startup call hidden at the end of a <c>//</c> comment, the shape that slip leaves behind.
/// </summary>
public sealed class CommentedOutRegistrationTests
{
    private static readonly Regex HiddenCall = new(
        @"^\s*//(?!/).*\b(builder|services|app)\.(Services\.)?[A-Z]\w*(<[^>]*>)?\(.*\);\s*$",
        RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    [Fact]
    public void No_startup_call_hides_at_the_end_of_a_comment()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "IncidentManager.sln"))) root = root.Parent;
        var src = Path.Combine(root!.FullName, "src");
        var hits = Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                        && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (f, i, line)))
            .Where(x => HiddenCall.IsMatch(x.line))
            .Select(x => $"{Path.GetRelativePath(src, x.f)}:{x.i + 1}: {x.line.Trim()}")
            .ToList();
        hits.Should().BeEmpty("a call at the end of a comment never runs; put it on its own line");
    }
}
