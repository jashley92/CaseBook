using System.Text.RegularExpressions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// A click on a modal dialog's text (a heading, a label, the space between controls) moves focus to the nearest focusable
/// ancestor. Without <c>tabindex="-1"</c> on the dialog that's the page, so the dialog's own Escape handler no longer
/// hears the key. The scan: every <c>aria-modal="true"</c> element has <c>tabindex="-1"</c>, unless its Escape doesn't
/// depend on focus (listed below with why).
/// </summary>
public partial class DialogFocusTests
{
    // Dialogs whose Escape doesn't hang on focus being inside them.
    private static readonly Dictionary<string, int> EscapeNotOnFocus = new(StringComparer.Ordinal)
    {
        // The palette and its shortcuts sheet: keymap.js sends "escape" from anywhere, and CommandPalette.Escape closes either.
        ["Shared/CommandPalette.razor"] = 2,
        // The idle-lock warning has no Escape: it closes only by Stay signed in or Lock now.
        ["Shared/IdleGuard.razor"] = 1,
    };

    [Fact]
    public void Every_modal_dialog_can_take_focus_itself()
    {
        var found = Sources().SelectMany(s => ModalTags(Markup(s))
            .Where(m => !NoTab().IsMatch(m.Value))
            .Select(m => (s.File, $"line {s.RawLineOf(m.Index)}")));
        var (offenders, stale) = Against(EscapeNotOnFocus, found);
        Assert.True(offenders.Count == 0,
            "A click on these dialogs' text drops focus to the page and Escape stops working; add tabindex=\"-1\":\n" + string.Join("\n", offenders));
        Assert.True(stale.Count == 0, "A fixed dialog comes off the list:\n" + string.Join("\n", stale));
    }

    [Fact]
    public void The_scan_reads_the_known_dialogs()
    {
        var picker = Sources().Single(s => s.File == "Shared/AttackMatrixPicker.razor");
        Assert.Single(ModalTags(Markup(picker)));
        Assert.True(Sources().Sum(s => ModalTags(Markup(s)).Count()) >= 15);
    }

    [Theory]
    [InlineData("""<div class="modal d-block im-trap" tabindex="-1" role="dialog" aria-modal="true">""", false)]
    [InlineData("<aside class=\"p\" role=\"dialog\"\n    aria-modal=\"true\" tabindex=\"-1\" @onkeydown=\"e => Key(e)\">", false)]
    [InlineData("""<div class="atkm-panel" role="dialog" aria-modal="true" @onkeydown="OnPanelKey">""", true)]
    public void The_scan_tells_a_focusable_dialog_from_one_that_is_not(string markup, bool flagged) =>
        Assert.Equal(flagged, ModalTags(markup).Any(m => !NoTab().IsMatch(m.Value)));

    private static IEnumerable<Match> ModalTags(string markup) =>
        Tag().Matches(markup).Where(m => Modal().IsMatch(m.Value));

    // A start tag; a quoted attribute value may hold ">" (a lambda's "=>").
    [GeneratedRegex(@"<[a-z][\w-]*\b(?:[^>""]|""[^""]*"")*>", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Tag();

    [GeneratedRegex(@"\saria-modal\s*=\s*""true""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Modal();

    [GeneratedRegex(@"\stabindex\s*=\s*""-1""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex NoTab();
}
