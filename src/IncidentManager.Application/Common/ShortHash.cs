namespace IncidentManager.Application.Common;

/// <summary>
/// BUG-598: the short form of a stored hash for a message or label. A stored hash is data, not a constant: a damaged
/// or tampered row can hold a short or empty one, and slicing it with <c>[..12]</c> threw (after the custody row was
/// saved, so the audit line was lost and a retry recorded the transfer twice; BUG-573 on the Integrity page).
/// </summary>
public static class ShortHash
{
    /// <summary>The first <paramref name="length"/> characters of <paramref name="hash"/> and an ellipsis, or the whole
    /// value when it is no longer than that; "(none)" for a missing one.</summary>
    public static string Of(string? hash, int length = 12)
    {
        if (string.IsNullOrEmpty(hash)) return "(none)";
        return hash.Length <= length ? hash : string.Concat(hash.AsSpan(0, length), TextFit.Ellipsis);
    }
}
