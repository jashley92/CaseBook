using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Query.SqlExpressions;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace IncidentManager.Infrastructure.Persistence;

public sealed class AppDbContext : DbContext, IAppDbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Case> Cases => Set<Case>();
    public DbSet<ClassificationChange> ClassificationChanges => Set<ClassificationChange>();
    public DbSet<MaterialityChange> MaterialityChanges => Set<MaterialityChange>();
    public DbSet<StatusChange> StatusChanges => Set<StatusChange>();
    public DbSet<SeverityChange> SeverityChanges => Set<SeverityChange>();
    public DbSet<TimelineEntry> TimelineEntries => Set<TimelineEntry>();
    public DbSet<AnalystNote> Notes => Set<AnalystNote>();
    public DbSet<Evidence> Evidence => Set<Evidence>();
    public DbSet<ChainOfCustodyEvent> CustodyEvents => Set<ChainOfCustodyEvent>();
    public DbSet<ActionItem> ActionItems => Set<ActionItem>();
    public DbSet<ActionItemComment> ActionItemComments => Set<ActionItemComment>();
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
    public DbSet<ReportTemplate> ReportTemplates => Set<ReportTemplate>();
    public DbSet<DataElement> DataElements => Set<DataElement>();
    public DbSet<NotificationRule> NotificationRules => Set<NotificationRule>();
    public DbSet<CaseDataElement> CaseDataElements => Set<CaseDataElement>();
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<AuditLogEntry> AuditLog => Set<AuditLogEntry>();
    public DbSet<CaseAccessEvent> CaseAccessEvents => Set<CaseAccessEvent>();
    public DbSet<IntegritySeal> IntegritySeals => Set<IntegritySeal>();
    public DbSet<AppSetting> AppSettings => Set<AppSetting>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<AdGroupRoleMapping> RoleMappings => Set<AdGroupRoleMapping>();
    public DbSet<SavedView> SavedViews => Set<SavedView>();
    public DbSet<PinnedCase> PinnedCases => Set<PinnedCase>();
    public DbSet<UserNotificationPreference> UserNotificationPreferences => Set<UserNotificationPreference>();
    public DbSet<UserDisplayPreference> UserDisplayPreferences => Set<UserDisplayPreference>();
    public DbSet<CaseComment> CaseComments => Set<CaseComment>();
    public DbSet<PostIncidentReview> PostIncidentReviews => Set<PostIncidentReview>();
    public DbSet<ImprovementAction> ImprovementActions => Set<ImprovementAction>();
    public DbSet<PendingImport> PendingImports => Set<PendingImport>();
    public DbSet<ApiToken> ApiTokens => Set<ApiToken>();

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

        // F-08: DbTime.TicksBetween, so elapsed-time aggregates (SLA met/missed, mean time to contain) run in the
        // database. SQLite already holds ticks, so it's a subtraction; SQL Server counts nanoseconds and scales
        // to ticks (DATEDIFF_BIG's nanosecond range is about 292 years).
        var ticksBetween = typeof(DbTime).GetMethod(nameof(DbTime.TicksBetween))!;
        var longMapping = this.GetService<IRelationalTypeMappingSource>().FindMapping(typeof(long))!;
        if (Database.IsSqlite())
        {
            modelBuilder.HasDbFunction(ticksBetween).HasTranslation(a =>
                new SqlBinaryExpression(ExpressionType.Subtract, a[1], a[0], typeof(long), longMapping));
        }
        else
        {
            modelBuilder.HasDbFunction(ticksBetween).HasTranslation(a => new SqlBinaryExpression(ExpressionType.Divide,
                new SqlFunctionExpression("DATEDIFF_BIG", [new SqlFragmentExpression("nanosecond"), a[0], a[1]],
                    nullable: true, argumentsPropagateNullability: [false, true, true], typeof(long), longMapping),
                new SqlConstantExpression(100L, longMapping), typeof(long), longMapping));
        }
    }
}
