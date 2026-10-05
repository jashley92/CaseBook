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
    public DbSet<AssignmentChange> AssignmentChanges => Set<AssignmentChange>();
    public DbSet<EntityVerdictChange> EntityVerdictChanges => Set<EntityVerdictChange>();   // HR-05
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
    public DbSet<CaseOutcome> CaseOutcomes => Set<CaseOutcome>();   // HR-01
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
    public DbSet<OpenCaseTab> OpenCaseTabs => Set<OpenCaseTab>();
    public DbSet<UserNotificationPreference> UserNotificationPreferences => Set<UserNotificationPreference>();
    public DbSet<UserDisplayPreference> UserDisplayPreferences => Set<UserDisplayPreference>();
    public DbSet<TransitionTimeCorrection> TransitionTimeCorrections => Set<TransitionTimeCorrection>();
    public DbSet<CaseBrief> CaseBriefs => Set<CaseBrief>();
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
        // database. SQLite already holds ticks, so it's a subtraction. SQL Server can't count nanoseconds across
        // more than ~292 years (one mistyped year would fail the whole dashboard), so it counts whole seconds and
        // adds the difference of the sub-second parts: still exact to the tick, over any valid date range.
        var ticksBetween = typeof(DbTime).GetMethod(nameof(DbTime.TicksBetween))!;
        var mappings = this.GetService<IRelationalTypeMappingSource>();
        var longMapping = mappings.FindMapping(typeof(long))!;
        var intMapping = mappings.FindMapping(typeof(int))!;
        if (Database.IsSqlite())
        {
            modelBuilder.HasDbFunction(ticksBetween).HasTranslation(a =>
                new SqlBinaryExpression(ExpressionType.Subtract, a[1], a[0], typeof(long), longMapping));
        }
        else
        {
            SqlExpression Fn(string name, Type type, RelationalTypeMapping mapping, string part, params SqlExpression[] args) =>
                new SqlFunctionExpression(name, [new SqlFragmentExpression(part), .. args], nullable: true,
                    argumentsPropagateNullability: [false, .. args.Select(_ => true)], type, mapping);
            SqlExpression Binary(ExpressionType op, SqlExpression l, SqlExpression r, Type type, RelationalTypeMapping mapping) =>
                new SqlBinaryExpression(op, l, r, type, mapping);

            modelBuilder.HasDbFunction(ticksBetween).HasTranslation(a => Binary(ExpressionType.Add,
                Binary(ExpressionType.Multiply, Fn("DATEDIFF_BIG", typeof(long), longMapping, "second", a[0], a[1]),
                    new SqlConstantExpression(TimeSpan.TicksPerSecond, longMapping), typeof(long), longMapping),
                Binary(ExpressionType.Divide,
                    Binary(ExpressionType.Subtract, Fn("DATEPART", typeof(int), intMapping, "nanosecond", a[1]),
                        Fn("DATEPART", typeof(int), intMapping, "nanosecond", a[0]), typeof(int), intMapping),
                    new SqlConstantExpression(100, intMapping), typeof(int), intMapping),
                typeof(long), longMapping));
        }
    }
}
