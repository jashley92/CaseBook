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
        AuditAction.StatusChanged => "Status changed",
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
}
