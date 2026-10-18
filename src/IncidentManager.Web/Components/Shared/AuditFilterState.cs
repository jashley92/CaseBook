using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// Audit-trail filter state (E-24) behind <see cref="AuditFilterRow"/>. A case's Audit tab keeps it in the workspace,
/// so the analyst's filters outlive the tab's re-mount (UX-13: the workspace keys its tab body by the active tab, so an
/// extracted tab is recreated on every switch); the Integrity page keeps its own (CAP-03), seeded from the address.
/// </summary>
public sealed class AuditFilterState
{
    // Filter selections (bound by the filter row's controls).
    public string Actor { get; set; } = "";
    public string Action { get; set; } = "";
    public string Entity { get; set; } = "";
    public DateTime? From { get; set; }
    public DateTime? To { get; set; }
    /// <summary>CAP-03: a case number, on the cross-case trail (a case's own tab is always its case).</summary>
    public string Case { get; set; } = "";
    /// <summary>CAP-03: one setting's history (Administration's "History" link); there's no control for it, only a chip.</summary>
    public string SettingKey { get; set; } = "";

    // Facet lists for the Actor / Entity dropdowns, fetched once per case (or once for the whole trail) and cached here.
    public IReadOnlyList<string> Actors { get; set; } = [];
    public IReadOnlyList<string> EntityTypes { get; set; } = [];
    public bool FacetsLoaded { get; set; }

    /// <summary>The server-side filter these selections make. "To" is inclusive to the end of the day.</summary>
    public AuditQueryFilter ToQuery(string? caseNumber) => new()
    {
        CaseNumber = string.IsNullOrWhiteSpace(caseNumber) ? null : caseNumber.Trim(),
        Actor = string.IsNullOrWhiteSpace(Actor) ? null : Actor,
        Action = IncidentManager.Domain.Common.EnumNames.OrNull<AuditAction>(Action),   // BUG-592: a name, never "99"
        EntityType = string.IsNullOrWhiteSpace(Entity) ? null : Entity,
        SettingKey = string.IsNullOrWhiteSpace(SettingKey) ? null : SettingKey,
        FromUtc = From is { } f ? new DateTimeOffset(f.Date, TimeSpan.Zero) : null,
        // BUG-463: the end of the day without AddDays(1), which threw for 9999-12-31 (as the CSV export does it).
        ToUtc = To is { } t ? new DateTimeOffset(DateOnly.FromDateTime(t).ToDateTime(TimeOnly.MaxValue), TimeSpan.Zero) : null
    };

    /// <summary>Back to no filter (the facet lists stay).</summary>
    public void Clear()
    {
        Actor = Action = Entity = Case = SettingKey = "";
        From = To = null;
    }

    /// <summary>
    /// The export's query string for a filter and its days (dates as yyyy-MM-dd, UTC; BUG-511: Gregorian whatever the
    /// server culture, as the endpoint reads it).
    /// </summary>
    public static string QueryString(AuditQueryFilter f, DateTime? fromDay, DateTime? toDay)
    {
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        var qs = new List<string>();
        if (f.CaseNumber is { } c) qs.Add($"case={Uri.EscapeDataString(c)}");
        if (f.Actor is { } actor) qs.Add($"actor={Uri.EscapeDataString(actor)}");
        if (f.Action is { } act) qs.Add($"action={act}");
        if (f.EntityType is { } et) qs.Add($"entity={Uri.EscapeDataString(et)}");
        if (f.SettingKey is { } key) qs.Add($"key={Uri.EscapeDataString(key)}");
        if (fromDay is { } from) qs.Add($"from={from.ToString("yyyy-MM-dd", inv)}");
        if (toDay is { } to) qs.Add($"to={to.ToString("yyyy-MM-dd", inv)}");
        return string.Join("&", qs);
    }
}
