using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// The persistence surface the application layer depends on. Implemented by the EF Core
/// context in Infrastructure, keeping handlers free of a concrete DbContext dependency.
/// Disposable so services obtained from <see cref="IAppDbContextFactory"/> can be scoped to a single
/// operation with <c>using</c> (H-08).
/// </summary>
public interface IAppDbContext : IDisposable, IAsyncDisposable
{
    DbSet<Case> Cases { get; }
    DbSet<ClassificationChange> ClassificationChanges { get; }
    DbSet<MaterialityChange> MaterialityChanges { get; }
    DbSet<StatusChange> StatusChanges { get; }
    DbSet<AssignmentChange> AssignmentChanges { get; }
    DbSet<EntityVerdictChange> EntityVerdictChanges { get; }   // HR-05
    DbSet<AccountDirectorySnapshot> AccountDirectorySnapshots { get; }   // BUG-416
    DbSet<SeverityChange> SeverityChanges { get; }
    DbSet<TimelineEntry> TimelineEntries { get; }
    DbSet<AnalystNote> Notes { get; }
    DbSet<Domain.Entities.Evidence> Evidence { get; }
    DbSet<ChainOfCustodyEvent> CustodyEvents { get; }
    DbSet<ActionItem> ActionItems { get; }
    DbSet<ActionItemComment> ActionItemComments { get; }
    DbSet<CaseAssignment> Assignments { get; }
    DbSet<EvidenceCitation> EvidenceCitations { get; }   // BUG-70: for the record check
    DbSet<CaseEntity> CaseEntities { get; }
    DbSet<EntityRelationship> EntityRelationships { get; }
    DbSet<EntityLayout> EntityLayouts { get; }
    DbSet<CaseTechnique> CaseTechniques { get; }
    DbSet<CaseLink> CaseLinks { get; }
    DbSet<CaseTemplate> CaseTemplates { get; }
    DbSet<CaseTemplateStep> CaseTemplateSteps { get; }
    DbSet<StageGate> StageGates { get; }
    DbSet<StageGateRequirement> StageGateRequirements { get; }
    DbSet<GatePassage> GatePassages { get; }
    DbSet<Report> Reports { get; }
    DbSet<ReportProfile> ReportProfiles { get; }
    DbSet<ReportTemplate> ReportTemplates { get; }
    DbSet<DataElement> DataElements { get; }
    DbSet<CaseOutcome> CaseOutcomes { get; }   // HR-01
    DbSet<Team> Teams { get; }   // CAP-36
    DbSet<TeamMember> TeamMembers { get; }   // CAP-36
    DbSet<NotificationRule> NotificationRules { get; }
    DbSet<CaseDataElement> CaseDataElements { get; }
    DbSet<AppUser> Users { get; }
    DbSet<AuditLogEntry> AuditLog { get; }
    DbSet<CaseAccessEvent> CaseAccessEvents { get; }
    DbSet<AlertDelivery> AlertDeliveries { get; }   // BUG-101
    DbSet<SavedView> SavedViews { get; }
    DbSet<PinnedCase> PinnedCases { get; }
    DbSet<OpenCaseTab> OpenCaseTabs { get; }
    DbSet<UserNotificationPreference> UserNotificationPreferences { get; }
    DbSet<UserDisplayPreference> UserDisplayPreferences { get; }
    DbSet<TransitionTimeCorrection> TransitionTimeCorrections { get; }
    DbSet<JurisdictionNotice> JurisdictionNotices { get; }   // BUG-09
    DbSet<CaseParty> CaseParties { get; }   // CAP-34
    DbSet<CaseBrief> CaseBriefs { get; }
    DbSet<PostIncidentReview> PostIncidentReviews { get; }
    DbSet<ImprovementAction> ImprovementActions { get; }
    DbSet<PendingImport> PendingImports { get; }
    DbSet<ApiToken> ApiTokens { get; }
    DbSet<IntegritySeal> IntegritySeals { get; }
    DbSet<AppSetting> AppSettings { get; }
    DbSet<Role> Roles { get; }
    DbSet<AdGroupRoleMapping> RoleMappings { get; }

    /// <summary>
    /// An optional analyst-supplied reason for the change about to be saved (why an IOC or timeline
    /// entry was corrected). Set immediately before <see cref="SaveChangesAsync"/>; the audit-chain
    /// interceptor stamps it onto the resulting audit entries and then clears it.
    /// </summary>
    string? PendingChangeReason { get; set; }

    /// <summary>
    /// C18: the save about to be made is CaseBook keeping its own records (<see cref="Integrity.IntegrityUpkeep"/>): its
    /// update entries carry the upkeep reason. Set immediately before the save; the interceptor clears it.
    /// </summary>
    bool PendingUpkeep { get; set; }

    /// <summary>
    /// CAP-12 review: audit entries for an act that changes no audited row (an evidence package's hand-over), to be
    /// written by the next save, in its transaction: the audit-chain interceptor chains them after the save's own entries,
    /// under the same gate, so the rows saved beside them (custody, which the chain leaves out) and the entries commit or
    /// fail together. Add them immediately before <see cref="SaveChangesAsync"/>; the interceptor takes and clears them.
    /// </summary>
    IList<AuditNote> PendingAuditNotes { get; }

    Task<int> SaveChangesAsync(CancellationToken ct = default);
}

/// <summary>CAP-12 review: one audit entry for <see cref="IAppDbContext.PendingAuditNotes"/>, as
/// <see cref="IAuditWriter.RecordAsync"/> takes it.</summary>
public sealed record AuditNote(Domain.Enums.AuditAction Action, string EntityType, string? EntityId, string? CaseNumber, string Summary);
