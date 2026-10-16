using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// C6 (BUG-328, 330, 340, 370, 389, 399, 425, 449, 451, 536, 545): a keyboard save reaches only the form that owns
/// focus, runs once for a held key, and reads what's on screen. The scans: every key handler that acts on Enter ignores
/// repeats (<c>e.Repeat</c>); a plain Enter (keymap.js flushes a field only for Ctrl/Cmd+Enter) reads only fields that
/// bind on input (or choices and date components, which report on change); and a region that handles Ctrl/Cmd+Enter
/// itself is marked <c>im-own-keys</c> (or is a dialog), so keymap.js doesn't also submit the tab's composer.
/// </summary>
/// <remarks>What it can't see: a handler given as a lambda that calls nothing named; a tab's SubmitAsync that routes to
/// the wrong form inside one region (BUG-602's notes composer); a pause that the same button satisfies (BUG-602's Save
/// view and New case), which needs a second, different control and is a behaviour, not a shape.</remarks>
public partial class KeyboardPathTests
{
    // Wave 2b: key handlers acting on Enter without a repeat check.
    private static readonly Dictionary<string, int> NoRepeatCheck = new(StringComparer.Ordinal)
    {
        // wave 2b, U4 (pages, admin, other shared)
        ["Pages/Cases.razor"] = 1,   // OnListKey
        ["Shared/AttackMatrixPicker.razor"] = 1,   // IsActivate
        ["Shared/CommandPalette.razor"] = 1,   // OnKeyDown
    };

    // Wave 2b: fields a plain Enter saves that bind on change (the save reads the value from before the typing).
    private static readonly Dictionary<string, int> StaleOnEnter = new(StringComparer.Ordinal)
    {

    };

    // Wave 2b: regions with their own Ctrl/Cmd+Enter that keymap.js would also send to the case.
    private static readonly Dictionary<string, int> NotOwnKeys = new(StringComparer.Ordinal)
    {

    };

    [Fact]
    public void Key_handlers_that_act_on_Enter_ignore_a_held_key()
    {
        var found = Components().SelectMany(c => c.Parts.SelectMany(p => Methods(p.Code))
            .Where(m => m.Parameters.Contains("KeyboardEventArgs", StringComparison.Ordinal) && Enter().IsMatch(m.Body) && !m.Body.Contains("Repeat", StringComparison.Ordinal))
            .Select(m => (c.File, m.Name)));
        var (offenders, stale) = Against(NoRepeatCheck, found);
        offenders.Should().BeEmpty("a held Enter repeats; only the first press acts (BUG-536, BUG-545)");
        stale.Should().BeEmpty("a fixed site comes off the wave-2b list");
    }

    [Fact]
    public void A_plain_Enter_reads_only_fields_bound_on_input()
    {
        var (offenders, stale) = Against(StaleOnEnter, Components().SelectMany(c => Fields(c.File, c.Parts))
            .Where(f => f.PlainEnter && f.BindsOnChange).Select(f => (f.File, $"line {f.Line} {f.Tag} {f.Bind}")));
        offenders.Should().BeEmpty("a plain @bind tells the server on change (blur), so an Enter save read the old value (BUG-449)");
        stale.Should().BeEmpty("a fixed site comes off the wave-2b list");
    }

    [Fact]
    public void A_region_with_its_own_Ctrl_Enter_is_marked_own_keys()
    {
        var found = Components().SelectMany(c => Regions(c.File, c.Parts))
            .Where(r => r.CtrlEnter && !r.OwnKeys).Select(r => (r.File, $"line {r.Line} <{r.Tag}> {r.Handler}"));
        var (offenders, stale) = Against(NotOwnKeys, found);
        offenders.Should().BeEmpty("keymap.js leaves Ctrl/Cmd+Enter to .im-own-keys (and dialogs); elsewhere it also submits the tab (BUG-370)");
        stale.Should().BeEmpty("a fixed site comes off the wave-2b list");
    }

    // Wave 2b: a tab's SubmitAsync (the workspace's Ctrl/Cmd+Enter) that picks a form by whether another form is open,
    // not by where the keys were pressed (BUG-602: Ctrl+Enter in the notes composer saved the in-place note edit).
    private static readonly Dictionary<string, int> RoutedByState = new(StringComparer.Ordinal)
    {
        // wave 2b, U1 (timeline, notes): the notes lens hands the composer's Ctrl+Enter to an open note edit. Give the
        // edit its own keys (.im-own-keys and its own Ctrl+Enter handler) and drop the IsEditing branch.
        ["Pages/CaseTabs/CaseTimelineTab.razor"] = 1,
    };

    [Fact]
    public void A_tabs_Ctrl_Enter_goes_to_its_composer_not_to_another_open_form()
    {
        var found = Components().SelectMany(c => c.Parts.SelectMany(p => Methods(p.Code))
            .Where(m => m.Name == "SubmitAsync" && OtherFormOpen().IsMatch(m.Body)).Select(m => (c.File, m.Name)));
        var (offenders, stale) = Against(RoutedByState, found);
        offenders.Should().BeEmpty("a form with its own Ctrl/Cmd+Enter is an .im-own-keys region; the tab's submit is the composer's");
        stale.Should().BeEmpty("a fixed site comes off the wave-2b list");
    }

    [GeneratedRegex(@"\{\s*IsEditing\s*:\s*true\s*\}|\.IsEditing\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex OtherFormOpen();

    [Fact]
    public void The_scan_reads_the_known_forms()
    {
        // A guard on the guard: the Tasks tab's edit row is an own-keys region with Ctrl+Enter, and its title binds on input.
        var tasks = Components().Single(c => c.File == "Pages/CaseTabs/CaseTasksTab.razor");
        Regions(tasks.File, tasks.Parts).Should().Contain(r => r.CtrlEnter && r.OwnKeys);
        Fields(tasks.File, tasks.Parts).Should().Contain(f => f.Bind.Contains("_editTitle", StringComparison.Ordinal) && !f.BindsOnChange);
        const string razor = "<div @onkeydown=\"OnKey\"><input @bind=\"_name\" /></div>\n@code { private void OnKey(KeyboardEventArgs e) { if (e.Key == \"Enter\") Save(); } }";
        var snippet = new Source("Pages/X.razor", Strip(razor), StripComments(razor));
        Fields("Pages/X.razor", [snippet]).Should().ContainSingle(f => f.PlainEnter && f.BindsOnChange);
        Regions("Pages/X.razor", [snippet]).Should().ContainSingle(r => !r.CtrlEnter);
    }

    private sealed record Field(string File, int Line, string Tag, string Bind, bool PlainEnter, bool BindsOnChange);
    private sealed record Region(string File, int Line, string Tag, string Handler, bool CtrlEnter, bool OwnKeys);

    private sealed record Element(string Tag, string Attrs, int Line);

    // Walks the markup's tags, keeping the open elements, and calls back for each opening tag with its ancestors.
    private static void Walk(Source s, Action<Element, IReadOnlyList<Element>> visit)
    {
        var markup = Markup(s);
        var stack = new List<Element>();
        foreach (Match t in Tag().Matches(markup))
        {
            var name = t.Groups["name"].Value;
            if (t.Groups["close"].Success)
            {
                var at = stack.FindLastIndex(e => e.Tag == name);
                if (at >= 0) stack.RemoveRange(at, stack.Count - at);
                continue;
            }
            var el = new Element(name, t.Groups["attrs"].Value, s.RawLineOf(t.Index));
            visit(el, stack);
            if (!t.Groups["self"].Success && !Void.Contains(name.ToLowerInvariant())) stack.Add(el);
        }
    }

    private static readonly HashSet<string> Void = ["input", "br", "img", "hr", "meta", "link", "col", "source", "wbr"];

    private static IEnumerable<Field> Fields(string file, IReadOnlyList<Source> parts)
    {
        var handlers = HandlerKinds(parts);
        var found = new List<Field>();
        foreach (var s in parts)
        {
            Walk(s, (el, ancestors) =>
            {
                if (!el.Tag.Equals("input", StringComparison.OrdinalIgnoreCase) && !el.Tag.Equals("textarea", StringComparison.OrdinalIgnoreCase)) return;
                if (NotText().IsMatch(el.Attrs)) return;
                var bind = BindAttr().Match(el.Attrs);
                if (!bind.Success) return;
                var plainEnter = ancestors.Append(el).Any(a => KeyHandler(a.Attrs) is { } h && handlers.TryGetValue(h, out var k) && k.PlainEnter);
                found.Add(new Field(file, el.Line, el.Tag, bind.Value, plainEnter, !OnInput().IsMatch(el.Attrs)));
            });
        }
        return found;
    }

    private static IEnumerable<Region> Regions(string file, IReadOnlyList<Source> parts)
    {
        var handlers = HandlerKinds(parts);
        var found = new List<Region>();
        foreach (var s in parts)
        {
            Walk(s, (el, ancestors) =>
            {
                if (KeyHandler(el.Attrs) is not { } h) return;
                var ctrl = handlers.TryGetValue(h, out var k) && k.CtrlEnter;
                var own = ancestors.Append(el).Any(a => OwnKeysOrDialog().IsMatch(a.Attrs));
                found.Add(new Region(file, el.Line, el.Tag, h, ctrl, own));
            });
        }
        return found;
    }

    // What each key handler (a method taking KeyboardEventArgs) acts on.
    private static Dictionary<string, (bool PlainEnter, bool CtrlEnter)> HandlerKinds(IReadOnlyList<Source> parts) =>
        parts.SelectMany(p => Methods(p.Code))
            .Where(m => m.Parameters.Contains("KeyboardEventArgs", StringComparison.Ordinal))
            .GroupBy(m => m.Name, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g =>
            {
                var body = g.First().Body;
                var enter = Enter().IsMatch(body);
                var ctrl = Ctrl().IsMatch(body);
                // Ctrl/Cmd+Enter only when every Enter it acts on asks for the modifier; a plain Enter otherwise.
                return (enter && !ctrl, enter && ctrl);
            }, StringComparer.Ordinal);

    // The method an @onkeydown calls: a method group, or the first method a lambda calls with the event.
    private static string? KeyHandler(string attrs)
    {
        var m = KeyDown().Match(attrs);
        if (!m.Success) return null;
        var v = m.Groups["v"].Value;
        var call = Regex.Match(v, @"(?<name>[A-Z]\w*)\s*\(\s*\w+\s*[,)]", RegexOptions.None, TimeSpan.FromSeconds(1));
        return call.Success ? call.Groups["name"].Value : Regex.Match(v, @"^\s*(\w+)\s*$", RegexOptions.None, TimeSpan.FromSeconds(1)).Groups[1].Value is { Length: > 0 } g ? g : null;
    }

    [GeneratedRegex(@"<(?<close>/)?(?<name>[A-Za-z][\w.]*)(?<attrs>(?:""[^""]*""|'[^']*'|[^'"">])*?)(?<self>/)?>", RegexOptions.Singleline, matchTimeoutMilliseconds: 2000)]
    private static partial Regex Tag();

    [GeneratedRegex(@"@onkeydown\s*=\s*""(?<v>[^""]*)""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex KeyDown();

    [GeneratedRegex(@"@bind(?:-Value)?\s*=\s*""[^""]*""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex BindAttr();

    [GeneratedRegex(@"@bind:event\s*=\s*""oninput""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex OnInput();

    [GeneratedRegex(@"type\s*=\s*""(?:checkbox|radio|file|hidden|range|color|button|submit|date|datetime-local|time|number)""", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 1000)]
    private static partial Regex NotText();

    [GeneratedRegex(@"class\s*=\s*""[^""]*\b(?:im-own-keys|im-trap|im-action-host|modal|cmdk|atkm-panel|tactic-modal)\b|aria-modal\s*=\s*""true""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex OwnKeysOrDialog();

    [GeneratedRegex(@"""Enter""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Enter();

    // The modifier is required (`&& e.CtrlKey`, `(e.CtrlKey || e.MetaKey) &&`, `!(e.CtrlKey || e.MetaKey)) return`), not
    // excluded (`|| e.CtrlKey || e.MetaKey) return`: a plain Enter that leaves Ctrl+Enter to keymap.js).
    [GeneratedRegex(@"&&\s*\(?\s*\w+\.(?:CtrlKey|MetaKey)\b|\b(?:CtrlKey|MetaKey)\s*\)?\s*&&|!\s*\(\s*\w+\.(?:CtrlKey|MetaKey)\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Ctrl();
}
