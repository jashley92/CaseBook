namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// UX-54: how a status reads. Plain and Muted are words only; Danger (breached, overdue, malicious, critical) and Warn (at
/// risk, due soon) carry colour and an icon; Ok is a quiet green for a met target, used sparingly.
/// </summary>
public enum StatusTone { Plain, Muted, Ok, Warn, Danger }
