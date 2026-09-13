using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace IncidentManager.Infrastructure.Persistence;

public sealed class AppDbContext : DbContext, IAppDbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Case> Cases => Set<Case>();
    public DbSet<ClassificationChange> ClassificationChanges => Set<ClassificationChange>();
    public DbSet<StatusChange> StatusChanges => Set<StatusChange>();
    public DbSet<SeverityChange> SeverityChanges => Set<SeverityChange>();
    public DbSet<TimelineEntry> TimelineEntries => Set<TimelineEntry>();
    public DbSet<AnalystNote> Notes => Set<AnalystNote>();
    public DbSet<Evidence> Evidence => Set<Evidence>();
    public DbSet<ChainOfCustodyEvent> CustodyEvents => Set<ChainOfCustodyEvent>();
    public DbSet<ActionItem> ActionItems => Set<ActionItem>();
    public DbSet<CaseAssignment> Assignments => Set<CaseAssignment>();
    public DbSet<CaseEntity> CaseEntities => Set<CaseEntity>();
    public DbSet<EntityRelationship> EntityRelationships => Set<EntityRelationship>();
    public DbSet<EntityLayout> EntityLayouts => Set<EntityLayout>();
    public DbSet<CaseTechnique> CaseTechniques => Set<CaseTechnique>();
    public DbSet<CaseLink> CaseLinks => Set<CaseLink>();
    public DbSet<CaseTemplate> CaseTemplates => Set<CaseTemplate>();
    public DbSet<CaseTemplateStep> CaseTemplateSteps => Set<CaseTemplateStep>();
    public DbSet<StageGate> StageGates => Set<StageGate>();
    public DbSet<StageGateRequirement> StageGateRequirements => Set<StageGateRequirement>();
    public DbSet<GatePassage> GatePassages => Set<GatePassage>();
    public DbSet<Report> Reports => Set<Report>();
    public DbSet<ReportProfile> ReportProfiles => Set<ReportProfile>();
    public DbSet<DataElement> DataElements => Set<DataElement>();
    public DbSet<CaseDataElement> CaseDataElements => Set<CaseDataElement>();
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<AuditLogEntry> AuditLog => Set<AuditLogEntry>();
    public DbSet<CaseAccessEvent> CaseAccessEvents => Set<CaseAccessEvent>();
    public DbSet<IntegritySeal> IntegritySeals => Set<IntegritySeal>();
    public DbSet<AppSetting> AppSettings => Set<AppSetting>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<AdGroupRoleMapping> RoleMappings => Set<AdGroupRoleMapping>();
    public DbSet<SavedView> SavedViews => Set<SavedView>();

    /// <summary>
    /// Ambient reason for the current unit of work (see <see cref="IAppDbContext.PendingChangeReason"/>).
    /// Not persisted; read and cleared by the audit-chain interceptor during the save it decorates.
    /// </summary>
    public string? PendingChangeReason { get; set; }

    // SaveChangesAsync(CancellationToken) is inherited from DbContext and satisfies IAppDbContext.

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);

        // Keys are client-generated Guids assigned in the entity constructor. Tell EF not to
        // treat them as store-generated, otherwise a new child added to a tracked aggregate
        // (its Id already set) is mistaken for an existing row and issued an UPDATE, not INSERT.
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var key in entityType.GetKeys())
            {
                foreach (var property in key.Properties)
                {
                    if (property.ClrType == typeof(Guid))
                        property.ValueGenerated = Microsoft.EntityFrameworkCore.Metadata.ValueGenerated.Never;
                }
            }
        }

        // SQLite (dev) cannot order by or compare DateTimeOffset. Store it as UTC ticks so
        // sorting and range filters work. SQL Server (prod) keeps the native datetimeoffset type.
        if (Database.IsSqlite())
        {
            var toTicks = new ValueConverter<DateTimeOffset, long>(
                v => v.UtcTicks,
                v => new DateTimeOffset(v, TimeSpan.Zero));
            var toTicksNullable = new ValueConverter<DateTimeOffset?, long?>(
                v => v.HasValue ? v.Value.UtcTicks : null,
                v => v.HasValue ? new DateTimeOffset(v.Value, TimeSpan.Zero) : null);

            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                foreach (var property in entityType.GetProperties())
                {
                    if (property.ClrType == typeof(DateTimeOffset))
                        property.SetValueConverter(toTicks);
                    else if (property.ClrType == typeof(DateTimeOffset?))
                        property.SetValueConverter(toTicksNullable);
                }
            }
        }
    }
}
