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
    DbSet<StatusChange> StatusChanges { get; }
    DbSet<SeverityChange> SeverityChanges { get; }
    DbSet<TimelineEntry> TimelineEntries { get; }
    DbSet<AnalystNote> Notes { get; }
    DbSet<Domain.Entities.Evidence> Evidence { get; }
    DbSet<ChainOfCustodyEvent> CustodyEvents { get; }
    DbSet<ActionItem> ActionItems { get; }
    DbSet<CaseAssignment> Assignments { get; }
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
    DbSet<DataElement> DataElements { get; }
    DbSet<CaseDataElement> CaseDataElements { get; }
    DbSet<AppUser> Users { get; }
    DbSet<AuditLogEntry> AuditLog { get; }
    DbSet<CaseAccessEvent> CaseAccessEvents { get; }
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

    Task<int> SaveChangesAsync(CancellationToken ct = default);
}
