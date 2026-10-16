using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-566 (BUG-418's class): a component can be disposed while one of its awaits is pending (the layout's time-zone
/// @key rebuilds the page on every fresh circuit; the user leaves; an AuthorizeView re-renders). Dispose then runs before
/// the code after the await, so anything that code registers with something that outlives the component (a singleton
/// notifier, a scoped event, a timer, a palette provider, a JS-side registry) is never undone. ComponentBase also still
/// runs OnParametersSet(Async) after a disposed OnInitializedAsync. These checks read the component sources and fail
/// when such a registration has no disposed check in front of it, so a new member of the class can't come back.
/// C5 (wave 2): the reader is the shared <see cref="ComponentSourceScanner"/>, and it now also sees JS-side registrations
/// (imKeymap.register*, imMedia.watch, markdownEditor.init, imDateField.attach, ...), <c>+= async (</c>, <c>+= _field;</c>
/// and <c>+= this.X</c> handlers, tuple and nested-generic returns, and async lambdas.
/// </summary>
public partial class ComponentLifetimeTests
{
    [Fact]
    public void Nothing_long_lived_is_registered_after_an_await_without_a_disposed_check()
    {
        var offenders = new List<string>();
        foreach (var (file, code) in ComponentSources())
        {
            foreach (var m in AsyncMethods(code))
                offenders.AddRange(LateRegistrations(m.Body).Select(r => $"{file} {m.Name}: {r}"));
        }

        offenders.Should().BeEmpty("a registration made after an await needs an `if (_disposed) return;` after that await");
    }

    // A registration is late when an await comes before it with no disposed check between. One made through JS is itself
    // awaited, so for it the await that counts is the one before its own; a disposed check straight after it (undoing it,
    // as the markdown editors do) also passes.
    private static IEnumerable<string> LateRegistrations(string body)
    {
        foreach (Match reg in Registration().Matches(body))
        {
            var js = reg.Value.StartsWith('"');
            var before = body.LastIndexOf("await ", reg.Index, StringComparison.Ordinal);
            // For a JS registration, the await before its own one, passing over other JS registrations (another branch
            // of the same if, as the entity graph's two renders are).
            while (js && before > 0)
            {
                before = body.LastIndexOf("await ", before - 1, StringComparison.Ordinal);
                if (before < 0 || !Registration().IsMatch(StatementsAfter(body, before, 1)) || !StatementsAfter(body, before, 1).Contains('"')) break;
            }
            if (before < 0) continue;   // still in the synchronous part: Dispose can't have run yet
            if (DisposedCheck().IsMatch(body[before..reg.Index])) continue;
            if (js && DisposedCheck().IsMatch(StatementsAfter(body, reg.Index, 2))) continue;
            yield return reg.Value.Trim();
        }
    }

    // The text of the next few statements after an offset (the undo that follows an awaited JS registration).
    private static string StatementsAfter(string body, int index, int statements)
    {
        var i = index;
        for (var n = 0; n < statements && i >= 0 && i < body.Length; n++) i = body.IndexOf(';', i + 1);
        return i < 0 ? body[index..] : body[index..Math.Min(body.Length, i + 1)];
    }

    [Fact]
    public void A_component_that_awaits_in_OnInitializedAsync_checks_disposed_before_registering_in_OnParametersSet()
    {
        var offenders = new List<string>();
        foreach (var (file, code) in ComponentSources())
        {
            var methods = Methods(code).ToList();
            if (!methods.Any(m => m.Name == "OnInitializedAsync" && m.Body.Contains("await ", StringComparison.Ordinal))) continue;
            foreach (var m in methods.Where(m => m.Name is "OnParametersSet" or "OnParametersSetAsync"))
            {
                foreach (Match reg in Registration().Matches(m.Body))
                {
                    if (!DisposedCheck().IsMatch(m.Body[..reg.Index]))
                        offenders.Add($"{file} {m.Name}: {reg.Value.Trim()}");
                }
            }
        }

        offenders.Should().BeEmpty("ComponentBase runs OnParametersSet(Async) even when the component was disposed during OnInitializedAsync");
    }

    [Fact]
    public void Teardown_lists_are_not_added_to_after_an_await_without_a_disposed_check()
    {
        // The JS-side registrations Dispose undoes by walking a list (_mdEditors, _mediaWatches): an id added after the
        // awaited registration but after Dispose walked the list is never undone, and the markdown editor's shared
        // registry then keeps a later mount of the same editor id from attaching.
        var offenders = new List<string>();
        foreach (var (file, code) in ComponentSources())
        {
            var methods = Methods(code).ToList();
            var torn = methods.Where(m => m.Name is "Dispose" or "DisposeAsync")
                .SelectMany(m => TeardownLoop().Matches(m.Body).Select(x => x.Groups[1].Value))
                .ToHashSet(StringComparer.Ordinal);
            if (torn.Count == 0) continue;
            foreach (var m in methods.Where(m => m.IsAsync))
            {
                foreach (var list in torn)
                {
                    var add = list + ".Add(";
                    for (var i = m.Body.IndexOf(add, StringComparison.Ordinal); i >= 0; i = m.Body.IndexOf(add, i + 1, StringComparison.Ordinal))
                    {
                        var lastAwait = m.Body.LastIndexOf("await ", i, StringComparison.Ordinal);
                        if (lastAwait >= 0 && !DisposedCheck().IsMatch(m.Body[lastAwait..i]))
                            offenders.Add($"{file} {m.Name}: {list}.Add");
                    }
                }
            }
        }

        offenders.Should().BeEmpty("a teardown list filled after Dispose walked it leaks the registration");
    }

    [Fact]
    public void The_scanner_finds_the_lifecycle_methods_it_checks()
    {
        // A guard on the guard: if parsing broke, the checks above would pass by seeing nothing.
        var all = ComponentSources().SelectMany(s => Methods(s.Code).Select(m => (s.File, m.Name))).ToList();
        all.Should().Contain(("Pages/Cases.razor", "OnInitializedAsync"));
        all.Should().Contain(("Pages/CaseWorkspace.razor", "OnParametersSetAsync"));
        all.Should().Contain(("Shared/NotificationBell.razor", "OnInitializedAsync"));
        all.Should().Contain(("Pages/CaseTabs/CaseNotesTab.razor", "DisposeAsync"));
        all.Should().Contain(("Pages/CaseWorkspace.razor", "OnAuthStateChanged<lambda>"), "async lambdas are read as methods");
        var bell = ComponentSources().Single(s => s.File == "Shared/NotificationBell.razor").Code;
        Registration().IsMatch(Methods(bell).Single(m => m.Name == "OnInitializedAsync").Body).Should().BeTrue();
        var ws = ComponentSources().Single(s => s.File == "Pages/CaseWorkspace.razor").Code;
        Registration().Matches(Methods(ws).Single(m => m.Name == "RegisterWithBrowserAsync").Body)
            .Select(r => r.Value).Should().Contain(["\"imKeymap.registerCase\"", "\"imMedia.watch\""], "JS registries are seen");
    }

    // C5: the forms the BUG-566 reader missed, each of which is a registration it must see.
    [Theory]
    [InlineData("private async Task<(bool Ok, string Why)> A() { await X(); Bus.Changed += OnChanged; }")]
    [InlineData("private async Task<IReadOnlyList<Dictionary<string, int>>> A() { await X(); Bus.Changed += OnChanged; }")]
    [InlineData("private async Task A() { await X(); Bus.Changed += async (s, e) => await Y(); }")]
    [InlineData("private async Task A() { await X(); Bus.Changed += _handler; }")]
    [InlineData("private async Task A() { await X(); Bus.Changed += this.OnChanged; }")]
    [InlineData("private async Task A() { await X(); await JS.InvokeVoidAsync(\"imKeymap.register\", _ref); }")]
    [InlineData("private async Task A() { await X(); await JS.InvokeVoidAsync(\"markdownEditor.init\", id, seed); }")]
    [InlineData("private async Task A() { await X(); _w = await JS.InvokeAsync<int>(\"imMedia.watch\", _ref, q); }")]
    [InlineData("private async Task A() { await X(); await JS.InvokeVoidAsync(\"imDateField.attach\", _el, _ref); }")]
    [InlineData("private void A() { _ = InvokeAsync(async () => { await X(); Bus.Changed += OnChanged; }); }")]
    [InlineData("protected override async Task OnInitializedAsync() { await X(); Edits.Track(this, \"the task\", () => _dirty, Region); }")]
    public void The_scanner_sees_every_form_of_late_registration(string snippet)
    {
        var code = ComponentSourceScanner.Strip(snippet);
        AsyncMethods(code).SelectMany(m => LateRegistrations(m.Body)).Should().NotBeEmpty(snippet);
    }

    [Theory]
    [InlineData("private async Task A() { await X(); if (_disposed) return; Bus.Changed += OnChanged; }")]
    [InlineData("private async Task A() { Bus.Changed += OnChanged; await X(); }")]
    [InlineData("private async Task A() { await JS.InvokeVoidAsync(\"imKeymap.register\", _ref); }")]
    [InlineData("private async Task A() { await X(); await JS.InvokeVoidAsync(\"markdownEditor.init\", id, s); if (Disposed) { await D(); return; } }")]
    [InlineData("private async Task A() { await X(); _count += _step; }")]
    public void The_scanner_passes_a_guarded_or_early_registration(string snippet)
    {
        var code = ComponentSourceScanner.Strip(snippet);
        AsyncMethods(code).SelectMany(m => LateRegistrations(m.Body)).Should().BeEmpty(snippet);
    }

    private static IEnumerable<(string File, string Code)> ComponentSources() =>
        ComponentSourceScanner.Sources().Select(s => (s.File, ComponentSourceScanner.BlankGuardedBlocks(s.Code)));

    private static IEnumerable<ComponentSourceScanner.Method> AsyncMethods(string code) => Methods(code).Where(m => m.IsAsync);

    private static IEnumerable<ComponentSourceScanner.Method> Methods(string code) => ComponentSourceScanner.Methods(code);

    // Something that outlives the component: a notifier or presence subscription, an event handler (a method group, a
    // field, this.X, a lambda, an async lambda), a timer, a .NET reference handed to JS, a palette provider, an
    // options-change hook, an unsaved-edit check (BUG-578's UnsavedEdits.Track, by the injected name Edits), or a JS-side
    // registry entry (keyboard, viewport watch, markdown editor, date field, graph, idle timer, display preferences).
    [GeneratedRegex(@"\.Subscribe\w*\(|[\w.]+\s*\+=\s*(?:[A-Z]\w*\s*;|\(?[\w\s,]*\)?\s*=>|async\b|this\.\w+\s*;)|(?:\w+\.)+\w+\s*\+=\s*_\w+\s*;|new\s+(?:System\.Threading\.)?(?:Periodic)?Timer\s*\(|DotNetObjectReference\.Create\(|\.Set\(\s*this\b|\.OnChange\(|\bEdits\.Track\(|""(?:imKeymap\.register\w*|imMedia\.watch\w*|markdownEditor\.init|imDateField\.attach|entityGraph\.render|imIdle\.start|imPrefs\.register)""",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Registration();

    [GeneratedRegex(@"if\s*\(\s*(?:_disposed|Disposed|_gone)\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex DisposedCheck();

    [GeneratedRegex(@"foreach\s*\(\s*var\s+\w+\s+in\s+(_\w+)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex TeardownLoop();
}
