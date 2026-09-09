using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentManager.Infrastructure.Persistence.Configurations;

public sealed class CaseConfiguration : IEntityTypeConfiguration<Case>
{
    public void Configure(EntityTypeBuilder<Case> b)
    {
        b.ToTable("Cases");
        b.HasKey(c => c.Id);

        b.Property(c => c.CaseNumber).HasMaxLength(200).IsRequired();
        // CaseNumber (auto or analyst-chosen) is the primary uniqueness guard, and the only one Complex
        // Events need — they are date-numbered (no sequence). IRP items carry a per-year sequence guarded
        // by a partial unique index so two auto IRP cases can never share (Year, Sequence), even under
        // concurrent creation; custom-numbered cases own their CaseNumber and are excluded. The filter uses
        // bare identifiers accepted by both SQLite and SQL Server.
        b.HasIndex(c => c.CaseNumber).IsUnique();
        b.HasIndex(c => new { c.Year, c.Sequence })
            .IsUnique()
            .HasFilter("Classification IS NOT NULL AND HasCustomNumber = 0")
            .HasDatabaseName("IX_Cases_IrpSequence");

        b.Property(c => c.DescriptiveName).HasMaxLength(200).IsRequired();
        b.Property(c => c.Title).HasMaxLength(300).IsRequired();
        b.Property(c => c.Summary).HasMaxLength(8000);
        b.Property(c => c.ImpactedAssets).HasMaxLength(4000);
        b.Property(c => c.DataTypesInvolved).HasMaxLength(4000);
        b.Property(c => c.DetectionCaseId).HasMaxLength(100);
        b.Property(c => c.IncidentCommander).HasMaxLength(200);
        b.Property(c => c.CreatedBy).HasMaxLength(200);
        b.Property(c => c.ModifiedBy).HasMaxLength(200);
        b.Property(c => c.RowHash).HasMaxLength(64);

        b.OwnsOne(c => c.ThirdParty, tp =>
        {
            tp.Property(p => p.VendorName).HasMaxLength(300).HasColumnName("ThirdParty_VendorName");
            tp.Property(p => p.VendorContact).HasMaxLength(300).HasColumnName("ThirdParty_VendorContact");
            tp.Property(p => p.VendorReference).HasMaxLength(200).HasColumnName("ThirdParty_VendorReference");
        });
        b.Navigation(c => c.ThirdParty).IsRequired(false);

        b.OwnsOne(c => c.LegalReferral, lr =>
        {
            lr.Property(p => p.IsReferred).HasColumnName("Legal_IsReferred");
            lr.Property(p => p.ReferredAtUtc).HasColumnName("Legal_ReferredAtUtc");
            lr.Property(p => p.ReferredBy).HasMaxLength(200).HasColumnName("Legal_ReferredBy");
            lr.Property(p => p.ReferredToContact).HasMaxLength(300).HasColumnName("Legal_ReferredToContact");
            lr.Property(p => p.RegulatoryRelevanceNote).HasMaxLength(4000).HasColumnName("Legal_RelevanceNote");
        });

        b.HasMany(c => c.ClassificationChanges).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.StatusChanges).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.SeverityChanges).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.TimelineEntries).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.Notes).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.Evidence).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.ActionItems).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.Assignments).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.Entities).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.EntityRelationships).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.EntityLayouts).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.Techniques).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.DataElements).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(c => c.Reports).WithOne().HasForeignKey(x => x.CaseId).OnDelete(DeleteBehavior.Cascade);

        b.HasIndex(c => c.Classification);
        b.HasIndex(c => c.Phase);
        b.HasIndex(c => c.IsArchived);
    }
}
