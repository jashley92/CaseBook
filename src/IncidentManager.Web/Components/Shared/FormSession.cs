using IncidentManager.Web.Services;

namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// BUG-601 (C5): which row's form is open, and which opening of it. A save that finishes after its form was closed, or
/// after another row's form opened, closes only the form it was for, so another row's edit (and what's typed in it)
/// stays open:
/// <code>
/// private readonly FormSession&lt;Guid&gt; _edit = new();
/// // open:   _edit.Open(task.Id); then seed the fields
/// // markup: @if (_edit.IsOpenFor(t.Id)) { the form }
/// // save:   if (_edit.Current is not { } s) return; await Cases.UpdateAsync(...); _edit.CloseIf(s);
/// </code>
/// </summary>
public class FormSession<TKey> where TKey : notnull
{
    private int _openings;

    /// <summary>One opening of the form for one key.</summary>
    public readonly record struct Session(TKey Key, int Opening);

    /// <summary>The form open now, or null.</summary>
    public Session? Current { get; private set; }

    public bool IsOpen => Current is not null;

    /// <summary>Whether the form is open for <paramref name="key"/>.</summary>
    public bool IsOpenFor(TKey key) => Current is { } s && EqualityComparer<TKey>.Default.Equals(s.Key, key);

    /// <summary>Opens the form for <paramref name="key"/> (a new session, even for the same key).</summary>
    public Session Open(TKey key)
    {
        var s = new Session(key, ++_openings);
        Current = s;
        return s;
    }

    /// <summary>Whether <paramref name="session"/> is the form open now (a save's continuation asks before acting on it).</summary>
    public bool IsCurrent(Session session) => Current == session;

    /// <summary>Closes the form if it is still <paramref name="session"/>; true when it did.</summary>
    public bool CloseIf(Session session)
    {
        if (Current != session) return false;
        Current = null;
        return true;
    }

    /// <summary>Closes whatever form is open (Cancel, Escape, a case switch).</summary>
    public void Close() => Current = null;
}

/// <summary>
/// BUG-578 (C7): a <see cref="FormSession{TKey}"/> that won't replace an edit in progress. The owner's decision: starting
/// an edit on a second row while one is open is refused with the standard toast, so the open edit and its text are kept:
/// <code>
/// private readonly EditSlot&lt;Guid&gt; _edit = new();
/// private void BeginEdit(ActionItem t)
/// {
///     if (!_edit.TryOpen(t.Id, Toasts, "task")) return;   // "Save or cancel the task you're editing, then try again."
///     _editTitle = t.Title;
/// }
/// // Save: as FormSession (CloseIf the session it saved); Cancel: _edit.Close().
/// </code>
/// </summary>
public sealed class EditSlot<TKey> : FormSession<TKey> where TKey : notnull
{
    /// <summary>
    /// Opens the edit for <paramref name="key"/> when nothing is open, and says whether the caller should seed the form
    /// now. Another row's edit open: refused with <see cref="EditSlot.Refusal"/> (false). This row's edit already open:
    /// false with no toast, so a second Edit click doesn't re-seed over what's been typed.
    /// </summary>
    public bool TryOpen(TKey key, ToastService toasts, string what)
    {
        ArgumentNullException.ThrowIfNull(toasts);
        if (IsOpenFor(key)) return false;
        if (IsOpen)
        {
            toasts.Info(EditSlot.Refusal(what));
            return false;
        }
        Open(key);
        return true;
    }
}

/// <summary>BUG-578: the wording <see cref="EditSlot{TKey}"/> refuses with, for an edit that isn't a slot.</summary>
public static class EditSlot
{
    /// <summary>The standard refusal (owner decision, wave 2).</summary>
    public static string Refusal(string what) => $"Save or cancel the {what} you're editing, then try again.";
}
