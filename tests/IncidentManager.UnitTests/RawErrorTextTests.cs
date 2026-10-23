using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-91, BUG-720: a catch-all never shows the exception's own text. Only validation, permission and stale-edit messages
/// are written for the person; anything else (a database's message naming a table or a constraint, a file share's path)
/// goes through <c>UserFacingError.Describe</c>, which logs it and words it. A catch filtered to those types may show
/// its message.
/// </summary>
public sealed partial class RawErrorTextTests
{
    [Fact]
    public void No_catch_all_in_a_component_shows_the_exceptions_own_text()
    {
        var offenders = new List<string>();
        foreach (var file in Directory.GetFiles(ComponentsRoot(), "*.*", SearchOption.AllDirectories)
                     .Where(f => f.EndsWith(".razor", StringComparison.Ordinal) || f.EndsWith(".cs", StringComparison.Ordinal)))
        {
            var code = File.ReadAllText(file);
            foreach (Match m in CatchAll().Matches(code))
            {
                var body = Block(code, m.Index + m.Length);
                if (Regex.IsMatch(body, $@"\b{m.Groups["v"].Value}\.Message\b"))
                    offenders.Add($"{Path.GetRelativePath(ComponentsRoot(), file)}:{code[..m.Index].Count(c => c == '\n') + 1}");
            }
        }
        offenders.Should().BeEmpty();
    }

    // The body of the block whose opening brace is just before `from`.
    private static string Block(string code, int from)
    {
        var depth = 1;
        for (var i = from; i < code.Length; i++)
        {
            if (code[i] == '{') depth++;
            else if (code[i] == '}' && --depth == 0) return code[from..i];
        }
        return code[from..];
    }

    // catch (Exception ex), unfiltered or filtered only to leave out a cancellation or by a condition on state (not type).
    [GeneratedRegex(@"catch \(Exception (?<v>\w+)\)(?: when \((?!\k<v> is (?!not OperationCanceledException))[^\n]*\))?\s*\{")]
    private static partial Regex CatchAll();
}
