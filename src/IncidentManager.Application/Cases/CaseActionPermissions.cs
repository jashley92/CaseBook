using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// F-21: the one reviewed source of truth for the <see cref="Permission"/> each mutating
/// <see cref="CaseService"/> use case requires. Every write asserts its entry here at the service
/// boundary (via <c>CaseService.Require</c>), so authorization for <em>actions</em> is guaranteed
/// structurally — belt-and-suspenders behind the Blazor UI gates, and the backstop any future non-UI
/// caller (an inbound XSIAM/SOAR webhook, a background trigger, a new endpoint) inherits for free.
/// <para>
/// The map mirrors the component gates: most edits require <see cref="Permission.EditCases"/>;
/// reclassification requires <see cref="Permission.ChangeClassification"/>; the legal referral and hold
/// require <see cref="Permission.ManageLegal"/>; archive/restore requires <see cref="Permission.Administer"/>.
/// Read use cases are deliberately absent — they carry no entry and are never gated here, because
/// need-to-know <em>data</em> scoping is enforced separately in the query layer (<c>CaseQueryExtensions</c>).
/// </para>
/// The keys are method names (matched against <see cref="System.Runtime.CompilerServices.CallerMemberNameAttribute"/>);
/// a mutation with no entry fails closed (<c>Require</c> throws), and a unit test asserts every mutating
/// method is covered so a newly added write can never ship unguarded.
/// </summary>
public static class CaseActionPermissions
{
    public static readonly IReadOnlyDictionary<string, Permission> Required =
        new Dictionary<string, Permission>(StringComparer.Ordinal)
        {
            // Intake & identity
            [nameof(CaseService.CreateAsync)] = Permission.EditCases,
            [nameof(CaseService.RenumberAsync)] = Permission.EditCases,

            // Lifecycle & classification
            [nameof(CaseService.ReclassifyAsync)] = Permission.ChangeClassification,
            [nameof(CaseService.ChangePhaseAsync)] = Permission.EditCases,
            [nameof(CaseService.ReopenAsync)] = Permission.EditCases,
            [nameof(CaseService.ChangeSeverityAsync)] = Permission.EditCases,

            // Regulatory / legal milestones
            [nameof(CaseService.ReferToLegalAsync)] = Permission.ManageLegal,
            [nameof(CaseService.SetLegalHoldAsync)] = Permission.ManageLegal,
            [nameof(CaseService.MarkReportedAsync)] = Permission.EditCases,
            [nameof(CaseService.ClearReportedAsync)] = Permission.EditCases,
            [nameof(CaseService.RecordMaterialityAsync)] = Permission.EditCases,

            // Case content
            [nameof(CaseService.UpdateDetailsAsync)] = Permission.EditCases,
            [nameof(CaseService.UpdateImpactAssessmentAsync)] = Permission.EditCases,
            [nameof(CaseService.AssignAsync)] = Permission.EditCases,
            [nameof(CaseService.UnassignAsync)] = Permission.EditCases,

            // Timeline
            [nameof(CaseService.AddTimelineEntryAsync)] = Permission.EditCases,
            [nameof(CaseService.AddEventStepAsync)] = Permission.EditCases,
            [nameof(CaseService.EditEventStepAsync)] = Permission.EditCases,
            [nameof(CaseService.EditInvestigationEntryAsync)] = Permission.EditCases,

            // Entities & graph
            [nameof(CaseService.AddEntityAsync)] = Permission.EditCases,
            [nameof(CaseService.EditEntityAsync)] = Permission.EditCases,
            [nameof(CaseService.RemoveEntityAsync)] = Permission.EditCases,
            [nameof(CaseService.LinkEntitiesAsync)] = Permission.EditCases,
            [nameof(CaseService.UnlinkAsync)] = Permission.EditCases,
            [nameof(CaseService.SaveGraphLayoutAsync)] = Permission.EditCases,

            // Case linking (E-14)
            [nameof(CaseService.LinkCaseAsync)] = Permission.EditCases,
            [nameof(CaseService.RemoveCaseLinkAsync)] = Permission.EditCases,

            // Techniques
            [nameof(CaseService.AddTechniqueAsync)] = Permission.EditCases,
            [nameof(CaseService.RemoveTechniqueAsync)] = Permission.EditCases,

            // Notes
            [nameof(CaseService.AddNoteAsync)] = Permission.EditCases,
            [nameof(CaseService.EditNoteAsync)] = Permission.EditCases,

            // Reporting profile & retention
            [nameof(CaseService.SetReportProfileAsync)] = Permission.EditCases,
            [nameof(CaseService.SetArchivedAsync)] = Permission.Administer,

            // Action items / playbooks
            [nameof(CaseService.AddActionItemAsync)] = Permission.EditCases,
            [nameof(CaseService.ApplyTemplateAsync)] = Permission.EditCases,
            [nameof(CaseService.SetActionItemStatusAsync)] = Permission.EditCases,
        };
}
