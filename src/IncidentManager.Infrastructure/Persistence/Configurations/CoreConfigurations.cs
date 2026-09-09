using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentManager.Infrastructure.Persistence.Configurations;

public sealed class ClassificationChangeConfiguration : IEntityTypeConfiguration<ClassificationChange>
{
    public void Configure(EntityTypeBuilder<ClassificationChange> b)
    {
        b.ToTable("ClassificationChanges");
        b.Property(x => x.Reason).HasMaxLength(2000);
        b.Property(x => x.ChangedBy).HasMaxLength(200);
        b.HasIndex(x => x.CaseId);
    }
}

public sealed class StatusChangeConfiguration : IEntityTypeConfiguration<StatusChange>
{
    public void Configure(EntityTypeBuilder<StatusChange> b)
    {
        b.ToTable("StatusChanges");
        b.Property(x => x.Reason).HasMaxLength(2000);
        b.Property(x => x.ChangedBy).HasMaxLength(200);
        b.HasIndex(x => x.CaseId);
    }
}

public sealed class SeverityChangeConfiguration : IEntityTypeConfiguration<SeverityChange>
{
    public void Configure(EntityTypeBuilder<SeverityChange> b)
    {
        b.ToTable("SeverityChanges");
        b.Property(x => x.Reason).HasMaxLength(2000);
        b.Property(x => x.ChangedBy).HasMaxLength(200);
        b.HasIndex(x => x.CaseId);
    }
}

public sealed class TimelineEntryConfiguration : IEntityTypeConfiguration<TimelineEntry>
{
    public void Configure(EntityTypeBuilder<TimelineEntry> b)
    {
        b.ToTable("TimelineEntries");
        b.Property(x => x.Description).HasMaxLength(16000).IsRequired();
        b.Property(x => x.Source).HasMaxLength(200);
        b.Property(x => x.TechniqueId).HasMaxLength(20);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.CaseId);
        b.HasIndex(x => x.OccurredAtUtc);
        // Investigation entries are versioned (supersede on edit); most reads want only the current row.
        b.HasIndex(x => new { x.CaseId, x.Kind, x.IsCurrent });

        // Event-step attribution: multi-tactic children, plus actor/target links into the case's IOCs.
        // Restrict so a referenced entity can't be deleted out from under the attack record.
        b.HasMany(x => x.Tactics).WithOne().HasForeignKey(x => x.TimelineEntryId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne<CaseEntity>().WithMany().HasForeignKey(x => x.ActorEntityId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<CaseEntity>().WithMany().HasForeignKey(x => x.TargetEntityId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => x.ActorEntityId);
        b.HasIndex(x => x.TargetEntityId);
    }
}

public sealed class EventStepTacticConfiguration : IEntityTypeConfiguration<EventStepTactic>
{
    public void Configure(EntityTypeBuilder<EventStepTactic> b)
    {
        b.ToTable("EventStepTactics");
        b.HasIndex(x => x.TimelineEntryId);
    }
}

public sealed class AnalystNoteConfiguration : IEntityTypeConfiguration<AnalystNote>
{
    public void Configure(EntityTypeBuilder<AnalystNote> b)
    {
        b.ToTable("AnalystNotes");
        b.Property(x => x.Body).HasMaxLength(16000).IsRequired();
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => new { x.CaseId, x.IsCurrent });
    }
}

public sealed class EvidenceConfiguration : IEntityTypeConfiguration<Evidence>
{
    public void Configure(EntityTypeBuilder<Evidence> b)
    {
        b.ToTable("Evidence");
        b.Property(x => x.OriginalFileName).HasMaxLength(500).IsRequired();
        b.Property(x => x.ContentType).HasMaxLength(200);
        b.Property(x => x.Sha256).HasMaxLength(64).IsRequired();
        b.Property(x => x.StoragePath).HasMaxLength(500).IsRequired();
        b.Property(x => x.Description).HasMaxLength(2000);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.CaseId);
        b.HasIndex(x => x.Sha256);
        b.HasMany(x => x.CustodyEvents).WithOne().HasForeignKey(x => x.EvidenceId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class ChainOfCustodyEventConfiguration : IEntityTypeConfiguration<ChainOfCustodyEvent>
{
    public void Configure(EntityTypeBuilder<ChainOfCustodyEvent> b)
    {
        b.ToTable("ChainOfCustodyEvents");
        b.Property(x => x.Actor).HasMaxLength(200);
        b.Property(x => x.Action).HasMaxLength(100);
        b.Property(x => x.Details).HasMaxLength(2000);
        b.HasIndex(x => x.EvidenceId);
    }
}

public sealed class ActionItemConfiguration : IEntityTypeConfiguration<ActionItem>
{
    public void Configure(EntityTypeBuilder<ActionItem> b)
    {
        b.ToTable("ActionItems");
        b.Property(x => x.Title).HasMaxLength(400).IsRequired();
        b.Property(x => x.Description).HasMaxLength(4000);
        b.Property(x => x.Owner).HasMaxLength(200);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => new { x.CaseId, x.Status });
    }
}

public sealed class CaseAssignmentConfiguration : IEntityTypeConfiguration<CaseAssignment>
{
    public void Configure(EntityTypeBuilder<CaseAssignment> b)
    {
        b.ToTable("CaseAssignments");
        b.Property(x => x.UserId).HasMaxLength(200).IsRequired();
        b.Property(x => x.UserDisplayName).HasMaxLength(200);
        b.Property(x => x.AssignedBy).HasMaxLength(200);
        b.HasIndex(x => new { x.CaseId, x.UserId }).IsUnique();
        b.HasIndex(x => x.UserId);
    }
}

public sealed class CaseEntityConfiguration : IEntityTypeConfiguration<CaseEntity>
{
    public void Configure(EntityTypeBuilder<CaseEntity> b)
    {
        b.ToTable("CaseEntities");
        b.Property(x => x.Value).HasMaxLength(2000).IsRequired();
        b.Property(x => x.Label).HasMaxLength(400);
        b.Property(x => x.Description).HasMaxLength(4000);
        b.Property(x => x.Source).HasMaxLength(200);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.CaseId);
        b.HasIndex(x => new { x.CaseId, x.Type, x.Value });
    }
}

public sealed class EntityRelationshipConfiguration : IEntityTypeConfiguration<EntityRelationship>
{
    public void Configure(EntityTypeBuilder<EntityRelationship> b)
    {
        b.ToTable("EntityRelationships");
        b.Property(x => x.Description).HasMaxLength(2000);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.CaseId);
        b.HasIndex(x => x.SourceEntityId);
        b.HasIndex(x => x.TargetEntityId);
    }
}

public sealed class CaseLinkConfiguration : IEntityTypeConfiguration<CaseLink>
{
    public void Configure(EntityTypeBuilder<CaseLink> b)
    {
        b.ToTable("CaseLinks");
        b.Property(x => x.Description).HasMaxLength(2000);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.CaseId);
        b.HasIndex(x => x.RelatedCaseId);
        // No FK navigations (a link spans two Case aggregates); columns are indexed and the exact
        // (source, target, type) triple is unique. The service additionally rejects the reverse
        // direction so a pair is never linked twice. Cases are archived, never hard-deleted, so
        // dangling references aren't a concern in practice.
        b.HasIndex(x => new { x.CaseId, x.RelatedCaseId, x.Type }).IsUnique();
    }
}

public sealed class CaseTemplateConfiguration : IEntityTypeConfiguration<CaseTemplate>
{
    public void Configure(EntityTypeBuilder<CaseTemplate> b)
    {
        b.ToTable("CaseTemplates");
        b.Property(x => x.Name).HasMaxLength(200).IsRequired();
        b.Property(x => x.Description).HasMaxLength(2000);
        b.Property(x => x.DefaultDataTypes).HasMaxLength(2000);
        b.Property(x => x.SummaryBoilerplate).HasMaxLength(8000);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.Name).IsUnique();
        // Steps are cascade-owned by the template row (deleting a template removes its playbook steps).
        b.HasMany(x => x.Steps).WithOne().HasForeignKey(x => x.TemplateId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class CaseTemplateStepConfiguration : IEntityTypeConfiguration<CaseTemplateStep>
{
    public void Configure(EntityTypeBuilder<CaseTemplateStep> b)
    {
        b.ToTable("CaseTemplateSteps");
        b.Property(x => x.Title).HasMaxLength(400).IsRequired();
        b.Property(x => x.Description).HasMaxLength(4000);
        b.Property(x => x.OwnerHint).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.TemplateId);
    }
}

public sealed class ReportProfileConfiguration : IEntityTypeConfiguration<ReportProfile>
{
    public void Configure(EntityTypeBuilder<ReportProfile> b)
    {
        b.ToTable("ReportProfiles");
        b.Property(x => x.Name).HasMaxLength(200).IsRequired();
        b.Property(x => x.Description).HasMaxLength(2000);
        b.Property(x => x.SectionLayout).HasMaxLength(1000);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.Name).IsUnique();
    }
}

public sealed class DataElementConfiguration : IEntityTypeConfiguration<DataElement>
{
    public void Configure(EntityTypeBuilder<DataElement> b)
    {
        b.ToTable("DataElements");
        b.Property(x => x.Key).HasMaxLength(100).IsRequired();
        b.Property(x => x.Label).HasMaxLength(200).IsRequired();
        b.Property(x => x.NotificationJurisdictions).HasMaxLength(400);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.ModifiedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        // Key is the stable identity referenced by cases and matched by imports — unique, never renamed.
        b.HasIndex(x => x.Key).IsUnique();
    }
}

public sealed class CaseDataElementConfiguration : IEntityTypeConfiguration<CaseDataElement>
{
    public void Configure(EntityTypeBuilder<CaseDataElement> b)
    {
        b.ToTable("CaseDataElements");
        b.Property(x => x.ElementKey).HasMaxLength(100).IsRequired();
        // A case references each element key at most once. The key is a loose stable reference to
        // DataElement.Key (the X-02 taxonomy pattern) — no FK, so archiving a reference element never
        // dangles a historical case; the display label is resolved by key at read time.
        b.HasIndex(x => new { x.CaseId, x.ElementKey }).IsUnique();
    }
}

public sealed class StageGateConfiguration : IEntityTypeConfiguration<StageGate>
{
    public void Configure(EntityTypeBuilder<StageGate> b)
    {
        b.ToTable("StageGates");
        b.Property(x => x.Name).HasMaxLength(200).IsRequired();
        b.Property(x => x.Description).HasMaxLength(2000);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        // At most one active gate per transition; inactive history may accumulate, so the uniqueness
        // is filtered to active rows (SQL Server) — enforced in the service on providers without it.
        b.HasIndex(x => new { x.Trigger, x.IsActive });
        // Requirements are cascade-owned by the gate row.
        b.HasMany(x => x.Requirements).WithOne().HasForeignKey(x => x.GateId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class StageGateRequirementConfiguration : IEntityTypeConfiguration<StageGateRequirement>
{
    public void Configure(EntityTypeBuilder<StageGateRequirement> b)
    {
        b.ToTable("StageGateRequirements");
        b.Property(x => x.CheckKey).HasMaxLength(100);
        b.Property(x => x.Label).HasMaxLength(400).IsRequired();
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.GateId);
    }
}

public sealed class GatePassageConfiguration : IEntityTypeConfiguration<GatePassage>
{
    public void Configure(EntityTypeBuilder<GatePassage> b)
    {
        b.ToTable("GatePassages");
        b.Property(x => x.PassedBy).HasMaxLength(200);
        b.Property(x => x.OverrideJustification).HasMaxLength(2000);
        b.Property(x => x.Commentary).HasMaxLength(4000);
        b.Property(x => x.Detail).HasMaxLength(8000);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.CaseId);
        // Owned by the case aggregate: deleting a case (archival is the norm) removes its passages.
        b.HasOne<Case>().WithMany(c => c.GatePassages).HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class CaseTechniqueConfiguration : IEntityTypeConfiguration<CaseTechnique>
{
    public void Configure(EntityTypeBuilder<CaseTechnique> b)
    {
        b.ToTable("CaseTechniques");
        b.Property(x => x.TechniqueId).HasMaxLength(20).IsRequired();
        b.Property(x => x.Name).HasMaxLength(400);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.CaseId);
        b.HasIndex(x => new { x.CaseId, x.TechniqueId }).IsUnique();
    }
}

public sealed class EntityLayoutConfiguration : IEntityTypeConfiguration<EntityLayout>
{
    public void Configure(EntityTypeBuilder<EntityLayout> b)
    {
        b.ToTable("EntityLayouts");
        b.HasIndex(x => x.CaseId);
        b.HasIndex(x => x.EntityId).IsUnique();
    }
}

public sealed class ReportConfiguration : IEntityTypeConfiguration<Report>
{
    public void Configure(EntityTypeBuilder<Report> b)
    {
        b.ToTable("Reports");
        b.Property(x => x.FileName).HasMaxLength(400);
        b.Property(x => x.StoragePath).HasMaxLength(500);
        b.Property(x => x.ContentSha256).HasMaxLength(64);
        b.Property(x => x.ApprovedBy).HasMaxLength(200);
        b.Property(x => x.CreatedBy).HasMaxLength(200);
        b.HasIndex(x => x.CaseId);
    }
}

public sealed class AppUserConfiguration : IEntityTypeConfiguration<AppUser>
{
    public void Configure(EntityTypeBuilder<AppUser> b)
    {
        b.ToTable("Users");
        b.Property(x => x.Sid).HasMaxLength(200).IsRequired();
        b.Property(x => x.UserPrincipalName).HasMaxLength(200);
        b.Property(x => x.DisplayName).HasMaxLength(200);
        b.Property(x => x.Email).HasMaxLength(300);
        b.Property(x => x.RolesCsv).HasMaxLength(400);
        b.HasIndex(x => x.Sid).IsUnique();
    }
}

public sealed class AuditLogEntryConfiguration : IEntityTypeConfiguration<AuditLogEntry>
{
    public void Configure(EntityTypeBuilder<AuditLogEntry> b)
    {
        b.ToTable("AuditLog");
        b.Property(x => x.Actor).HasMaxLength(200);
        b.Property(x => x.EntityType).HasMaxLength(100);
        b.Property(x => x.EntityId).HasMaxLength(100);
        b.Property(x => x.CaseNumber).HasMaxLength(200);
        b.Property(x => x.Summary).HasMaxLength(2000);
        b.Property(x => x.Reason).HasMaxLength(2000);
        b.Property(x => x.PrevHash).HasMaxLength(64);
        b.Property(x => x.EntryHash).HasMaxLength(64);
        b.HasIndex(x => x.Sequence).IsUnique();
        b.HasIndex(x => x.CaseNumber);
        b.HasIndex(x => x.AtUtc);
    }
}

public sealed class CaseAccessEventConfiguration : IEntityTypeConfiguration<CaseAccessEvent>
{
    public void Configure(EntityTypeBuilder<CaseAccessEvent> b)
    {
        b.ToTable("CaseAccessEvents");
        b.Property(x => x.ActorUserId).HasMaxLength(200).IsRequired();
        b.Property(x => x.CaseNumber).HasMaxLength(200);
        b.Property(x => x.TargetLabel).HasMaxLength(500);
        // Coalesce/lookup: find the most recent matching session for (actor, case, type, target).
        b.HasIndex(x => new { x.ActorUserId, x.CaseId, x.AccessType, x.LastSeenUtc });
        // Console + per-case panel reads.
        b.HasIndex(x => x.LastSeenUtc);
        b.HasIndex(x => x.CaseId);
        // No FK to Case: CaseId is a soft reference so archival/purge never trips on the access log.
    }
}

public sealed class IntegritySealConfiguration : IEntityTypeConfiguration<IntegritySeal>
{
    public void Configure(EntityTypeBuilder<IntegritySeal> b)
    {
        b.ToTable("IntegritySeals");
        b.Property(x => x.ChainHeadHash).HasMaxLength(64);
        b.Property(x => x.Signature).HasMaxLength(1024);
        b.Property(x => x.Algorithm).HasMaxLength(50);
        b.Property(x => x.KeyId).HasMaxLength(100);
        b.Property(x => x.SealedBy).HasMaxLength(200);
        b.HasIndex(x => x.SealedAtUtc);
    }
}

public sealed class AppSettingConfiguration : IEntityTypeConfiguration<AppSetting>
{
    public void Configure(EntityTypeBuilder<AppSetting> b)
    {
        b.ToTable("AppSettings");
        b.Property(x => x.Key).HasMaxLength(200).IsRequired();
        b.Property(x => x.Value).HasMaxLength(8000);
        b.Property(x => x.UpdatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.Key).IsUnique();
    }
}

public sealed class RoleConfiguration : IEntityTypeConfiguration<Role>
{
    public void Configure(EntityTypeBuilder<Role> b)
    {
        b.ToTable("Roles");
        b.Property(x => x.Name).HasMaxLength(100).IsRequired();
        b.Property(x => x.Description).HasMaxLength(400);
        b.Property(x => x.PermissionsCsv).HasMaxLength(1000);
        b.Property(x => x.UpdatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => x.Name).IsUnique();
    }
}

public sealed class AdGroupRoleMappingConfiguration : IEntityTypeConfiguration<AdGroupRoleMapping>
{
    public void Configure(EntityTypeBuilder<AdGroupRoleMapping> b)
    {
        b.ToTable("AdGroupRoleMappings");
        b.Property(x => x.AdGroup).HasMaxLength(400).IsRequired();
        b.Property(x => x.RoleName).HasMaxLength(100).IsRequired();
        b.Property(x => x.UpdatedBy).HasMaxLength(200);
        b.Property(x => x.RowHash).HasMaxLength(64);
        b.HasIndex(x => new { x.AdGroup, x.RoleName }).IsUnique();
        b.HasIndex(x => x.RoleName);
    }
}
