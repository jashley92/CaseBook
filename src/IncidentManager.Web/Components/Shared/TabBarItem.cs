namespace IncidentManager.Web.Components.Shared;

/// <summary>UX-52: the two tab levels: a page's (or a case's) views, and the lenses or parts inside one view.</summary>
public enum TabLevel { Page, Sub }

/// <summary>
/// UX-52: one tab. A link when <see cref="Href"/> is set, else a button reporting <see cref="Key"/>. <see cref="Count"/>
/// is a quiet number beside the label; <see cref="Attention"/> is a short coloured note for something that needs doing
/// (colour only for attention, UX-54).
/// </summary>
public sealed record TabBarItem(string Label, string? Href = null, string? Key = null, int? Count = null,
    string? Attention = null, string? Icon = null, string? Title = null);
