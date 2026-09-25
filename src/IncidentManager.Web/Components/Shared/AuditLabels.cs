using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Components.Shared;

/// <summary>Display names for audit actions, so audit tables and filters don't show raw enum identifiers.</summary>
public static class AuditLabels
{
    public static string Label(AuditAction a) => a switch
    {
        AuditAction.Create => "Created",
        AuditAction.Update => "Updated",
        AuditAction.SoftDelete => "Removed",
        AuditAction.Access => "Viewed",
        AuditAction.Login => "Signed in",
        AuditAction.Logout => "Signed out",
        AuditAction.ClassificationChanged => "Reclassified",
        AuditAction.StatusChanged => "Phase changed",
        AuditAction.EvidenceUploaded => "Evidence uploaded",
        AuditAction.EvidenceDownloaded => "Evidence downloaded",
        AuditAction.ReportGenerated => "Report generated",
        AuditAction.ReportFinalized => "Report finalized",
        AuditAction.LegalReferral => "Referred to Legal",
        AuditAction.IntegritySeal => "Integrity seal",
        AuditAction.IntegrityVerification => "Integrity check",
        AuditAction.Export => "Exported",
        AuditAction.EvidenceTransferred => "Evidence transferred",
        _ => a.ToString()
    };

    /// <summary>Display name for an audited record type. Type names are the stored filter values; this is only the label.</summary>
    public static string Entity(string? type) => type switch
    {
        null or "" => "—",
        "ActionItem" => "Task",
        "ActionItemComment" => "Task comment",
        "AdGroupRoleMapping" => "AD group mapping",
        "AnalystNote" => "Note",
        "AppSetting" => "Setting",
        "CaseAssignment" => "Assignment",
        "CaseComment" => "Discussion post",
        "CaseDataElement" => "Case data element",
        "CaseEntity" => "Entity",
        "CaseLink" => "Related case link",
        "CaseTechnique" => "ATT&CK technique",
        "CaseTemplate" => "Case template",
        "CaseTemplateStep" => "Template step",
        "ClassificationChange" => "Classification change",
        "DataElement" => "Data element",
        "EntityRelationship" => "Entity relationship",
        "ImprovementAction" => "Improvement action",
        "MaterialityChange" => "Materiality change",
        "NotificationRule" => "Notification rule",
        "PostIncidentReview" => "Lessons-learned review",
        "ReportProfile" => "Report profile",
        "SeverityChange" => "Severity change",
        "StageGate" => "Stage gate",
        "StageGateRequirement" => "Stage gate requirement",
        "StatusChange" => "Phase change",
        "TimelineEntry" => "Timeline entry",
        "ApiToken" => "API token",
        "PendingImport" => "Pending import",
        "IntegritySeal" => "Integrity seal",
        "SavedView" => "Saved view",
        "EmailTemplate" => "Email template",
        _ => type
    };
}
