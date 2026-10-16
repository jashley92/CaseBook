using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Common;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C12 (BUG-598, BUG-573): a stored hash is shortened through <see cref="ShortHash.Of"/>, never sliced with a fixed
/// range. A damaged or tampered row can hold a short hash, and the slice threw at the moment the app most needed to
/// say something about that row.
/// </summary>
public partial class StoredSliceTests
{
    [Theory]
    [InlineData("0123456789abcdef0123", "0123456789ab…")]
    [InlineData("0123456789ab", "0123456789ab")]
    [InlineData("abc", "abc")]
    [InlineData("", "(none)")]
    [InlineData(null, "(none)")]
    public void ShortHash_never_throws_on_a_short_or_missing_hash(string? hash, string expected) =>
        ShortHash.Of(hash).Should().Be(expected);

    // A member whose name says it holds a hash or digest, sliced or cut to a fixed length.
    [GeneratedRegex(@"\.\w*(?:Sha256|Sha1|Hash|Digest|Thumbprint)\w*\s*(?:\[\.\.|\.Substring\(|\.AsSpan\(0,)", RegexOptions.None, 1000)]
    private static partial Regex StoredHashSlice();

    // BUG-615: the same through a pattern variable: `x.EntryHash is { Length: > 0 } h ? h[..12] : ...`.
    [GeneratedRegex(@"\b\w*(?:Sha256|Sha1|Hash|Digest|Thumbprint)\w*\s+is\b[^;]*?(?<![.\w])(?<v>[a-z_]\w*)\b(?=[^;]*?(?<![.\w])\k<v>\s*(?:\[\.\.|\.Substring\(|\.AsSpan\(0,))",
        RegexOptions.None, 1000)]
    private static partial Regex PatternVariableSlice();

    private static bool Slices(string line) => StoredHashSlice().IsMatch(line) || PatternVariableSlice().IsMatch(line);

    [Theory]
    [InlineData("var s = e.EntryHash[..12];", true)]
    [InlineData("var s = e.EntryHash is { Length: > 0 } h ? h[..12] : \"\";", true)]
    [InlineData("if (row.ContentSha256 is string d && d.Length > 0) return d.Substring(0, 8);", true)]
    [InlineData("var s = e.EntryHash is { Length: > 0 } h ? ShortHash.Of(h) : \"\";", false)]
    [InlineData("var s = e.EntryHash is null ? \"\" : other[..12];", false)]
    public void The_scan_sees_a_slice_through_a_pattern_variable(string line, bool flagged) => Slices(line).Should().Be(flagged);

    /// <summary>Slices that are safe, with the reason (the value is computed here, or its length is checked first).</summary>
    private static readonly (string File, string Code, string Why)[] Computed =
    [
        // (the computed hex slices slice Convert.ToHexString(...), which the pattern doesn't match)
        ("StoredReportTable.razor", "ContentSha256 is { Length: > 16 } h ? h[..16]", "the pattern checks the length first"),
    ];

    [Fact]
    public void No_stored_hash_is_sliced_to_a_fixed_length()
    {
        var root = Path.Combine(EdgeArithmeticTests.RepoRoot(), "src");
        var hits = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}"))
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (File: f, Line: i + 1, Text: line)))
            .Where(l => Slices(l.Text))
            .Where(l => !Computed.Any(c => Path.GetFileName(l.File) == c.File && l.Text.Contains(c.Code, StringComparison.Ordinal)))
            .Select(l => $"{Path.GetRelativePath(root, l.File)}:{l.Line}: {l.Text.Trim()}")
            .ToList();

        hits.Should().BeEmpty("a stored hash can be short; shorten it with ShortHash.Of");
    }
}
