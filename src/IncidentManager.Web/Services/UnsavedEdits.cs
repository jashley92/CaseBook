using Microsoft.JSInterop;

namespace IncidentManager.Web.Services;

/// <summary>
/// BUG-578 (C7): where on the page an editor lives, so whatever is about to hide one (a tab switch, the Now/Next pane
/// stepping aside, a side panel moving to another item) can ask only about the editors it would hide. The case workspace
/// hands one to each of its parts as a cascading value; a component reads it with
/// <c>[CascadingParameter] public EditRegion? Region { get; set; }</c> and passes it to <see cref="UnsavedEdits.Track"/>.
/// Outside the workspace there is none (null), which is "the page".
/// </summary>
/// <param name="Name">For reading in a debugger: "tab", "pane", "entity panel".</param>
/// <param name="Selector">The CSS selector of the part's element, so its markdown editors (EasyMDE, which keeps its text
/// in the browser) are asked about too.</param>
public sealed record EditRegion(string Name, string Selector);

/// <summary>
/// BUG-578 (C7): the unsaved text on the page (one per circuit). Anything that hides, replaces or re-seeds an editor
/// first asks here, and keeps (or asks before losing) what it says. A component with typed-but-unsaved input registers
/// it once, with a check that reads its own state:
/// <code>
/// [Inject] UnsavedEdits Edits { get; set; }
/// [CascadingParameter] public EditRegion? Region { get; set; }
/// protected override void OnInitialized() =>
///     Edits.Track(this, "the task you're editing", () => _editingTaskId is not null, Region);
/// public void Dispose() => Edits.Forget(this);
/// </code>
/// Markdown editors need nothing: <see cref="PendingAsync"/> asks markdown-editor.js about the ones inside a region.
/// The checks run on the circuit's dispatcher (from event handlers), like the components that registered them.
/// </summary>
public sealed class UnsavedEdits(IJSRuntime js)
{
    private sealed record Entry(object Owner, string What, Func<bool> IsDirty, EditRegion? Region);

    private readonly List<Entry> _entries = [];

    /// <summary>What a markdown editor holding text is called in the prompt.</summary>
    public const string MarkdownWhat = "text in an editor";

    /// <summary>Registers an edit that can be unsaved. <paramref name="what"/> names it in the prompt ("the task you're
    /// editing"); <paramref name="isDirty"/> says whether it holds unsaved input now. Disposing the result, or
    /// <see cref="Forget"/> on the owner, takes it off.</summary>
    public IDisposable Track(object owner, string what, Func<bool> isDirty, EditRegion? region = null)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(isDirty);
        var entry = new Entry(owner, what, isDirty, region);
        _entries.Add(entry);
        return new Registration(this, entry);
    }

    /// <summary>Takes off everything <paramref name="owner"/> registered (call it from the owner's Dispose).</summary>
    public void Forget(object owner) => _entries.RemoveAll(e => ReferenceEquals(e.Owner, owner));

    /// <summary>What holds unsaved input now, from the registered checks: everywhere when <paramref name="within"/> is
    /// empty, else only inside those regions.</summary>
    public IReadOnlyList<string> Pending(params EditRegion[] within) =>
        _entries.ToList()   // a check may re-register; read a copy
            .Where(e => within.Length == 0 || (e.Region is { } r && within.Contains(r)))
            .Where(e => Dirty(e))
            .Select(e => e.What)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    /// <summary><see cref="Pending"/>, plus the markdown editors holding text (anywhere, or inside the regions), less
    /// <paramref name="keptEditors"/>: editor ids whose text survives what's about to happen (FR-02's stashed composer
    /// survives a tab switch). If the browser can't be asked, its editors don't obstruct.</summary>
    public async Task<IReadOnlyList<string>> PendingAsync(IReadOnlyCollection<string>? keptEditors = null, params EditRegion[] within)
    {
        var pending = Pending(within).ToList();
        string[] dirty;
        try
        {
            dirty = within.Length == 0
                ? await js.InvokeAsync<string[]>("markdownEditor.dirtyIds", null, keptEditors ?? [])
                : (await Task.WhenAll(within.Select(r => js.InvokeAsync<string[]>("markdownEditor.dirtyIds", r.Selector, keptEditors ?? []).AsTask())))
                    .SelectMany(ids => ids).ToArray();
        }
        catch (Exception ex) when (ex is JSException or JSDisconnectedException or InvalidOperationException or TaskCanceledException)
        {
            dirty = [];   // can't tell: don't obstruct
        }
        if (dirty.Length > 0 && !pending.Contains(MarkdownWhat)) pending.Add(MarkdownWhat);
        return pending;
    }

    // A check that throws (its owner half torn down) holds nothing worth stopping for.
    private static bool Dirty(Entry e)
    {
        try { return e.IsDirty(); }
        catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException) { return false; }
    }

    /// <summary>The prompt's wording for a list from <see cref="Pending"/>: "the task you're editing and text in an
    /// editor".</summary>
    public static string Describe(IReadOnlyList<string> pending) => pending.Count switch
    {
        0 => "",
        1 => pending[0],
        _ => string.Join(", ", pending.Take(pending.Count - 1)) + " and " + pending[^1],
    };

    private sealed class Registration(UnsavedEdits edits, Entry entry) : IDisposable
    {
        public void Dispose() => edits._entries.Remove(entry);
    }
}
