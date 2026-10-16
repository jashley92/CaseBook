namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// BUG-601 (C5): clearing a text box after its text was saved. The save is awaited, and anything typed into the box
/// while it ran is in the field by then, so a plain <c>_title = "";</c> after the await wipes it. The box is cleared only
/// if it still holds what was sent:
/// <code>
/// var sent = _title;
/// await Cases.AddActionItemAsync(CaseId, sent, ...);
/// _title = DraftText.ClearIfUnchanged(_title, sent);          // a non-null field: "" when unchanged
/// _note = DraftText.ClearIfUnchanged(_note, sentNote, null);  // a nullable one: null when unchanged
/// </code>
/// </summary>
public static class DraftText
{
    /// <summary>"" when <paramref name="current"/> is still <paramref name="sent"/>, else what's there now.</summary>
    public static string ClearIfUnchanged(string current, string sent) =>
        string.Equals(current, sent, StringComparison.Ordinal) ? "" : current;

    /// <summary><paramref name="cleared"/> when <paramref name="current"/> is still <paramref name="sent"/>, else what's
    /// there now.</summary>
    public static string? ClearIfUnchanged(string? current, string? sent, string? cleared) =>
        string.Equals(current, sent, StringComparison.Ordinal) ? cleared : current;
}
