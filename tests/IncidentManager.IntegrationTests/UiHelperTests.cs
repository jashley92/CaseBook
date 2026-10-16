using FluentAssertions;
using IncidentManager.Web.Components.Shared;
using IncidentManager.Web.Services;
using Microsoft.JSInterop;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Wave 2's shared UI helpers, which the structural tests (ComponentContinuationTests, EditPreservationTests,
/// InFlightGuardTests) ask the components to use: their behaviour, so adopting one does what its name says.
/// </summary>
public class UiHelperTests
{
    // --- BUG-601 (C5) ---
    [Fact]
    public void A_load_overtaken_by_a_newer_one_or_an_invalidation_is_not_current()
    {
        var seq = new LoadSequence();
        var first = seq.Begin();
        var second = seq.Begin();
        seq.IsCurrent(first).Should().BeFalse();
        seq.IsCurrent(second).Should().BeTrue();
        seq.Invalidate();
        seq.IsCurrent(second).Should().BeFalse("a reset or dispose drops the load in flight");
    }

    [Fact]
    public void Keyed_loads_supersede_only_their_own_key()
    {
        var loads = new KeyedLoad<string>();
        var a1 = loads.Begin("A");
        var b = loads.Begin("B");
        var a2 = loads.Begin("A");
        loads.IsCurrent(a1).Should().BeFalse();
        loads.IsCurrent(a2).Should().BeTrue();
        loads.IsCurrent(b).Should().BeTrue("another key's load runs alongside");
        loads.IsCurrentFor(a2, "A").Should().BeTrue();
        loads.IsCurrentFor(a2, "B").Should().BeFalse("it was for A");
        loads.IsCurrentFor(null, "A").Should().BeFalse();
        loads.Invalidate("A");
        loads.IsCurrent(a2).Should().BeFalse();
        loads.IsCurrent(b).Should().BeTrue();
        loads.Invalidate();
        loads.IsCurrent(b).Should().BeFalse();
    }

    [Fact]
    public void A_save_closes_only_the_form_session_it_was_for()
    {
        var form = new FormSession<Guid>();
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        var sa = form.Open(a);
        var sb = form.Open(b);   // another row's form opened while A saved
        form.CloseIf(sa).Should().BeFalse();
        form.IsOpenFor(b).Should().BeTrue("A's continuation leaves B's form (and its text) alone");
        form.CloseIf(sb).Should().BeTrue();
        form.IsOpen.Should().BeFalse();

        var first = form.Open(a);
        form.Close();
        var reopened = form.Open(a);
        form.IsCurrent(first).Should().BeFalse("a reopening of the same row is a new session");
        form.IsCurrent(reopened).Should().BeTrue();
    }

    [Fact]
    public void Clearing_after_a_save_keeps_what_was_typed_during_it()
    {
        DraftText.ClearIfUnchanged("check the proxy", "check the proxy").Should().Be("");
        DraftText.ClearIfUnchanged("check the proxy logs", "check the proxy").Should().Be("check the proxy logs");
        DraftText.ClearIfUnchanged((string?)"a", "a", null).Should().BeNull();
        DraftText.ClearIfUnchanged((string?)"ab", "a", null).Should().Be("ab");
    }

    // --- BUG-578 (C7) ---
    [Fact]
    public void A_second_rows_edit_is_refused_while_one_is_open()
    {
        var toasts = new ToastService();
        var slot = new EditSlot<Guid>();
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        slot.TryOpen(a, toasts, "task").Should().BeTrue();
        slot.TryOpen(a, toasts, "task").Should().BeFalse("the same row's edit is already open: no re-seed");
        toasts.Toasts.Should().BeEmpty();
        slot.TryOpen(b, toasts, "task").Should().BeFalse();
        slot.IsOpenFor(a).Should().BeTrue();
        toasts.Toasts.Should().ContainSingle().Which.Message.Should().Be("Save or cancel the task you're editing, then try again.");
        slot.Close();
        slot.TryOpen(b, toasts, "task").Should().BeTrue();
    }

    [Fact]
    public async Task Unsaved_edits_are_asked_by_region_and_forgotten_with_their_owner()
    {
        var js = new FakeJs();
        var edits = new UnsavedEdits(js);
        var tab = new EditRegion("tab", ".tabbody");
        var pane = new EditRegion("pane", ".im-nownext");
        var owner = new object();
        var dirty = true;
        edits.Track(owner, "the task you're editing", () => dirty, tab);
        using var paneEdit = edits.Track(new object(), "the brief you're editing", () => true, pane);

        edits.Pending(tab).Should().Equal("the task you're editing");
        edits.Pending().Should().HaveCount(2);
        dirty = false;
        edits.Pending(tab).Should().BeEmpty("a check reads the owner's state when asked");
        dirty = true;

        js.Dirty[".tabbody"] = ["inv-md-1"];
        (await edits.PendingAsync(null, tab)).Should().Equal("the task you're editing", UnsavedEdits.MarkdownWhat);
        (await edits.PendingAsync(["inv-md-1"], tab)).Should().Equal(["the task you're editing"], "a kept editor's text isn't lost");
        js.Calls.Should().Contain(c => c.Within == ".tabbody");

        edits.Forget(owner);
        edits.Pending(tab).Should().BeEmpty();
        paneEdit.Dispose();
        edits.Pending().Should().BeEmpty();
        UnsavedEdits.Describe(["a", "b", "c"]).Should().Be("a, b and c");
    }

    [Fact]
    public async Task Unsaved_edits_dont_obstruct_when_the_browser_cant_be_asked()
    {
        var edits = new UnsavedEdits(new FakeJs { Throw = true });
        (await edits.PendingAsync()).Should().BeEmpty();
    }

    // --- BUG-603 (C8) ---
    [Fact]
    public async Task A_second_run_while_one_is_under_way_is_ignored()
    {
        var flight = new InFlight();
        var gate = new TaskCompletionSource();
        var runs = 0;
        var first = flight.Run(async () => { runs++; await gate.Task; });
        flight.Busy.Should().BeTrue();
        (await flight.Run(() => { runs++; return Task.CompletedTask; })).Should().BeFalse();
        gate.SetResult();
        (await first).Should().BeTrue();
        flight.Busy.Should().BeFalse();
        runs.Should().Be(1);
        await FluentActions.Awaiting(() => flight.Run(() => throw new InvalidOperationException("refused")))
            .Should().ThrowAsync<InvalidOperationException>();
        flight.Busy.Should().BeFalse("a failed run frees it");
    }

    private sealed class FakeJs : IJSRuntime
    {
        public Dictionary<string, string[]> Dirty { get; } = new(StringComparer.Ordinal);
        public List<(string? Within, string[] Except)> Calls { get; } = [];
        public bool Throw { get; init; }

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args) =>
            InvokeAsync<TValue>(identifier, CancellationToken.None, args);

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
        {
            if (Throw) throw new JSException("no browser");
            identifier.Should().Be("markdownEditor.dirtyIds");
            var within = args?[0] as string;
            var except = args?[1] as IEnumerable<string> ?? [];
            Calls.Add((within, except.ToArray()));
            var ids = (within is null ? Dirty.Values.SelectMany(v => v) : Dirty.GetValueOrDefault(within) ?? [])
                .Where(id => !except.Contains(id)).ToArray();
            return new ValueTask<TValue>((TValue)(object)ids);
        }
    }
}
