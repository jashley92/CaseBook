using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A named, reusable case-queue filter set (PROD-09 / E-02b): the owner, a display name, and the exact
/// query string that reproduces the filtered Cases list (e.g. <c>classification=Breach&amp;sla=true</c>).
/// Personal by default; when <see cref="IsShared"/> is set the whole team sees it as a shared view.
///
/// This is user convenience state, not case data — deliberately NOT audited or hash-chained (see the
/// interceptor's NotAudited set), like <see cref="EntityLayout"/>.
/// </summary>
public class SavedView : Entity
{
    /// <summary>The user who created (and owns) this view. Only the owner may rename/share/delete it.</summary>
    public string OwnerUserId { get; set; } = "";

    /// <summary>Display name shown in the views menu (e.g. "My triage queue").</summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// The Cases query string that reproduces the filters, without a leading '?'
    /// (e.g. <c>scope=mine&amp;sla=true&amp;classification=Breach</c>). Empty = the unfiltered list.
    /// </summary>
    public string Query { get; set; } = "";

    /// <summary>When true, every user who can see the Cases queue sees this as a shared team view.</summary>
    public bool IsShared { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }
}
