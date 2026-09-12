namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// One node in a breadcrumb trail (UX-08). A crumb with an <see cref="Href"/> renders as a link — the
/// back affordance up to an ancestor route; the trailing crumb (the current page) leaves it null and is
/// marked <c>aria-current="page"</c>. An optional <see cref="Icon"/> is a Bootstrap-Icons class.
/// </summary>
public sealed record Crumb(string Label, string? Href = null, string? Icon = null);
