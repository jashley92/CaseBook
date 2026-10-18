using IncidentManager.Domain.Entities;

namespace IncidentManager.Application.Security;

/// <summary>CAP-06: what an administrator did to a row of reference data (event 5405).</summary>
public enum ReferenceDataAction { Created, Changed, Deleted }

/// <summary>CAP-06: the kinds of reference data event 5405 names (its target type). A contract, like the ids: append only.</summary>
public static class ReferenceDataKinds
{
    public const string StageGate = "StageGate";
    public const string DataElement = "DataElement";
    public const string DeadlineRule = "DeadlineRule";            // a jurisdiction's notification window
    public const string CaseTemplate = "CaseTemplate";            // a playbook
    public const string CaseOutcome = "CaseOutcome";
    public const string TaxonomyLabel = "TaxonomyLabel";
    public const string TaxonomyOrder = "TaxonomyOrder";          // which options show, and in what order
    public const string ReportProfile = "ReportProfile";
    public const string ReportTemplate = "ReportTemplate";        // a Word template
    public const string EmailTemplate = "EmailTemplate";
    public const string ConfigurationBundle = "ConfigurationBundle";   // a bundle imported over the reference data
    public const string Team = "Team";                            // CAP-36: a team that owns cases, or who is in it
}

/// <summary>
/// CAP-06: the case a lifecycle event (5506-5515) is about, as the SIEM sees it: its number, the detection platform's
/// id when one is recorded, and whether it's an exercise. Ids and labels only, nothing from the case's content.
/// </summary>
public readonly record struct CaseSubject(string CaseNumber, string? DetectionCaseId, bool IsExercise)
{
    public static CaseSubject Of(Case c) => new(c.CaseNumber, c.DetectionCaseId, c.IsExercise);
}

/// <summary>
/// CAP-06: the reference-data changes one save makes, held until it's saved and then emitted (5405). A list editor's
/// reorder is one event, not one per row it moved.
/// </summary>
public sealed class ReferenceDataLog(string kind)
{
    private readonly List<(string Name, ReferenceDataAction Action, Guid? Id)> _changes = [];
    private bool _reordered;

    public void Add(string name, ReferenceDataAction action, Guid? id = null) => _changes.Add((name, action, id));

    public void Reordered() => _reordered = true;

    public void Emit(ISecurityEventSink? sink, Abstractions.ICurrentUser user)
    {
        foreach (var (name, action, id) in _changes) sink.ReferenceDataChanged(user, kind, name, action, id);
        if (_reordered) sink.ReferenceDataChanged(user, kind, "(display order)", ReferenceDataAction.Changed);
    }
}

public static class SecurityEventEmit
{
    /// <summary>
    /// CAP-06: emits an event after the action it reports is saved. Best effort: building or queueing it never fails
    /// the action (the sink promises not to throw; this holds if one does, or a factory meets a value it didn't expect).
    /// </summary>
    public static void EmitSafely(this ISecurityEventSink? sink, Func<SecurityEvent> build)
    {
        if (sink is null) return;
        try { sink.Emit(build()); }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Deliberately swallowed: the stream is best effort and the audit chain is the record (OPERATIONS §5).
        }
    }

    /// <summary>CAP-06: <see cref="SecurityEvents.ReferenceDataChanged"/> for the current user, best effort.</summary>
    public static void ReferenceDataChanged(this ISecurityEventSink? sink, Abstractions.ICurrentUser user, string kind, string name,
        ReferenceDataAction action, Guid? id = null) =>
        sink.EmitSafely(() => SecurityEvents.ReferenceDataChanged(kind, name, action, user.UserId, user.UserPrincipalName, id));
}
