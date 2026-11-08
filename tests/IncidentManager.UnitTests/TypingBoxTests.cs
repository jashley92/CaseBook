using System.Text.RegularExpressions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// A text box written as <c>value="@x" @oninput="..."</c> loses keystrokes when typing outruns the server: a render that
/// was started for an earlier keystroke writes that older text back over what's been typed since. <c>@bind:get</c> /
/// <c>@bind:set</c> with <c>@bind:event="oninput"</c> tells Blazor the browser already has the value, so it isn't written
/// back. The scan: no input or textarea pairs a <c>value</c> with <c>@oninput</c>.
/// </summary>
public partial class TypingBoxTests
{
    [Fact]
    public void No_box_pairs_a_value_with_oninput()
    {
        var found = Sources().SelectMany(s => Boxes(Markup(s))
            .Where(m => ValueAttr().IsMatch(m.Value) && OnInput().IsMatch(m.Value))
            .Select(m => $"{s.File}:{s.RawLineOf(m.Index)}")).ToList();
        Assert.True(found.Count == 0,
            "These boxes can lose fast keystrokes; use @bind:get, @bind:set and @bind:event=\"oninput\":\n" + string.Join("\n", found));
    }

    [Theory]
    [InlineData("""<input class="x" value="@_q" @oninput="OnInput" />""", true)]
    [InlineData("<textarea rows=\"2\"\n    value=\"@Draft(t.Id)\"\n    @oninput=\"e => Set(t.Id, e.Value?.ToString())\"></textarea>", true)]
    [InlineData("""<input value="@(none ? "" : _form[k])" @oninput="e => _form[k] = e.Value?.ToString()" />""", true)]
    [InlineData("""<input @bind:get="_q" @bind:set="OnInput" @bind:event="oninput" />""", false)]
    [InlineData("""<input value="@_q" @onchange="OnChange" />""", false)]
    public void The_scan_finds_the_pair_across_lines_and_lambdas(string markup, bool flagged) =>
        Assert.Equal(flagged, Boxes(markup).Any(m => ValueAttr().IsMatch(m.Value) && OnInput().IsMatch(m.Value)));

    [Fact]
    public void The_scan_reads_the_known_boxes()
    {
        // The scan has to see these, or it proves nothing: each binds on input.
        var picker = Sources().Single(s => s.File == "Shared/AttackMatrixPicker.razor");
        Assert.Contains(Boxes(Markup(picker)), m => m.Value.Contains("@bind:get=\"_filter\"", StringComparison.Ordinal));
        Assert.True(Sources().Sum(s => Boxes(Markup(s)).Count()) > 50);
    }

    private static IEnumerable<Match> Boxes(string markup) => Box().Matches(markup);

    // An input or textarea start tag; a quoted attribute value may hold ">" (a lambda's "=>").
    [GeneratedRegex(@"<(?:input|textarea)\b(?:[^>""]|""[^""]*"")*>", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Box();

    [GeneratedRegex(@"\svalue\s*=\s*""@", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex ValueAttr();

    [GeneratedRegex(@"@oninput\s*=", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex OnInput();
}
