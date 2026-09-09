namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Resolves the org's <b>display label</b> for a taxonomy member (X-02). Labels-only: the stored canonical
/// value and the code-defined set are unchanged, so this never affects ordinal logic, the hash canonical,
/// or regulatory behaviour — only what the member is called on screen and in reports. Backed by live
/// configuration (DB override + appsettings), so a rename takes effect without a restart.
/// </summary>
public interface ITaxonomyDisplay
{
    /// <summary>
    /// The configured label for <paramref name="member"/> of <paramref name="kind"/> (e.g. kind
    /// "Classification", member "Breach"), or <paramref name="fallback"/> when no override is set.
    /// </summary>
    string Label(string kind, string member, string fallback);

    /// <summary>
    /// Whether <paramref name="member"/> of <paramref name="kind"/> has been hidden from pick-lists (X-02
    /// slice 3). Hiding affects only new selection — a stored value is never rewritten and still displays.
    /// </summary>
    bool IsHidden(string kind, string member);

    /// <summary>
    /// The admin-configured display order for <paramref name="kind"/> as a list of member values, or an empty
    /// list when unset (callers then keep the code-defined order). Members omitted from a non-empty list sort
    /// after the listed ones, in their natural order.
    /// </summary>
    IReadOnlyList<string> Order(string kind);
}
