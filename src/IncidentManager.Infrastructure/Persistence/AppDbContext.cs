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
    public DbSet<AccountDirectorySnapshot> AccountDirectorySnapshots => Set<AccountDirectorySnapshot>();   // BUG-416
    public DbSet<SeverityChange> SeverityChanges => Set<SeverityChange>();
    public DbSet<TimelineEntry> TimelineEntries => Set<TimelineEntry>();
    public DbSet<AnalystNote> Notes => Set<AnalystNote>();
    public DbSet<Evidence> Evidence => Set<Evidence>();
    public DbSet<ChainOfCustodyEvent> CustodyEvents => Set<ChainOfCustodyEvent>();
    public DbSet<ActionItem> ActionItems => Set<ActionItem>();
    public DbSet<ActionItemComment> ActionItemComments => Set<ActionItemComment>();
    public DbSet<CaseAssignment> Assignments => Set<CaseAssignment>();
    public DbSet<EvidenceCitation> EvidenceCitations => Set<EvidenceCitation>();   // BUG-70
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
    public DbSet<Team> Teams => Set<Team>();   // CAP-36
    public DbSet<TeamMember> TeamMembers => Set<TeamMember>();   // CAP-36
    public DbSet<NotificationRule> NotificationRules => Set<NotificationRule>();
    public DbSet<CaseDataElement> CaseDataElements => Set<CaseDataElement>();
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<AuditLogEntry> AuditLog => Set<AuditLogEntry>();
    public DbSet<CaseAccessEvent> CaseAccessEvents => Set<CaseAccessEvent>();
    public DbSet<NotificationMark> NotificationMarks => Set<NotificationMark>();   // BUG-95
    public DbSet<AlertDelivery> AlertDeliveries => Set<AlertDelivery>();   // BUG-101
    public DbSet<HeldEmail> HeldEmails => Set<HeldEmail>();   // BUG-617
    public DbSet<KeyEnvelopeRecord> KeyEnvelopes => Set<KeyEnvelopeRecord>();   // PROD-57
    public DbSet<SmtpSignInRecord> SmtpSignIns => Set<SmtpSignInRecord>();   // CAP-05
    public DbSet<StoredSecretRecord> StoredSecrets => Set<StoredSecretRecord>();   // CAP-40
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
    public DbSet<JurisdictionNotice> JurisdictionNotices => Set<JurisdictionNotice>();
    public DbSet<CaseParty> CaseParties => Set<CaseParty>();   // CAP-34
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

    /// <summary>C18: see <see cref="IAppDbContext.PendingUpkeep"/>. Not persisted; read and cleared by the interceptor.</summary>
    public bool PendingUpkeep { get; set; }

    /// <summary>CAP-12 review: see <see cref="IAppDbContext.PendingAuditNotes"/>. Not persisted; taken by the interceptor.</summary>
    public IList<AuditNote> PendingAuditNotes { get; } = new List<AuditNote>();

    // SaveChangesAsync(CancellationToken) is inherited from DbContext and satisfies IAppDbContext; both save paths below
    // check column lengths first.
    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        ColumnLengthGuard.Check(ChangeTracker);
        var checkedCases = BumpCaseEditVersions();
        try { return base.SaveChanges(acceptAllChangesOnSuccess); }
        catch (DbUpdateException ex) when (IsLostRace(ex)) { throw new Application.Cases.ConcurrentEditException(ex); }
        catch (DbUpdateException ex) when (checkedCases.Count > 0)
        {
            if (CaseChangedMeanwhile(checkedCases)) throw new Application.Cases.ConcurrentEditException(ex);
            throw;
        }
    }

    public override async Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        ColumnLengthGuard.Check(ChangeTracker);
        var checkedCases = BumpCaseEditVersions();
        try { return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken); }
        catch (DbUpdateException ex) when (IsLostRace(ex)) { throw new Application.Cases.ConcurrentEditException(ex); }
        catch (DbUpdateException ex) when (checkedCases.Count > 0)
        {
            if (await CaseChangedMeanwhileAsync(checkedCases, cancellationToken)) throw new Application.Cases.ConcurrentEditException(ex);
            throw;
        }
    }

    // BUG-113: the case's edit version didn't match, or (whichever the database checks first) a second current brief.
    private static bool IsLostRace(DbUpdateException ex) =>
        ex is DbUpdateConcurrencyException
        || ex.InnerException?.Message is { } m
           && (m.Contains("IX_CaseBriefs_OneCurrent", StringComparison.Ordinal)
               || m.Contains("CaseBriefs.CaseId, CaseBriefs.IsCurrent", StringComparison.Ordinal));

    // BUG-581: the database may insert a new child of a case (an assignment, a data element, a technique) before it checks
    // the case's version, so a save that lost the race fails on the child's unique index instead. Whatever the database
    // refused, a case this save checked that has moved on since it was read means the race was lost. Read afresh, after
    // the failed save has rolled back; if the read itself fails, the database's own error stands.
    private bool CaseChangedMeanwhile(Dictionary<Guid, Guid> checkedCases)
    {
        try { return Changed(checkedCases, CurrentVersions(checkedCases).ToList()); }
        catch (Exception e) when (e is System.Data.Common.DbException or InvalidOperationException) { return false; }
    }

    private async Task<bool> CaseChangedMeanwhileAsync(Dictionary<Guid, Guid> checkedCases, CancellationToken ct)
    {
        try { return Changed(checkedCases, await CurrentVersions(checkedCases).ToListAsync(ct)); }
        catch (Exception e) when (e is System.Data.Common.DbException or InvalidOperationException) { return false; }
    }

    private IQueryable<KeyValuePair<Guid, Guid>> CurrentVersions(Dictionary<Guid, Guid> checkedCases)
    {
        var ids = checkedCases.Keys.ToList();
        return Cases.AsNoTracking().IgnoreQueryFilters().Where(c => ids.Contains(c.Id))
            .Select(c => new KeyValuePair<Guid, Guid>(c.Id, EF.Property<Guid>(c, CaseEditVersion)));
    }

    // A case removed meanwhile has moved on too.
    private static bool Changed(Dictionary<Guid, Guid> checkedCases, List<KeyValuePair<Guid, Guid>> now)
    {
        var current = now.ToDictionary(x => x.Key, x => x.Value);
        return checkedCases.Any(c => !current.TryGetValue(c.Key, out var v) || v != c.Value);
    }

    /// <summary>BUG-113: the case's shadow concurrency token, renewed by every save that changes the case or anything on it.</summary>
    public const string CaseEditVersion = "EditVersion";

    /// <summary>
    /// BUG-113: a save that changes a loaded case, or adds, changes or removes anything on it (a status change, a brief),
    /// renews the case's edit version. EF checks the version the case was loaded with, so of two saves made from the same
    /// starting point only the first lands; the second is refused instead of closing the case twice or leaving two current
    /// briefs. A shadow property, so it stays out of the audit trail and the row hash.
    /// </summary>
    /// <returns>BUG-581: the cases whose version this save checks, each with the version it was read at.</returns>
    private Dictionary<Guid, Guid> BumpCaseEditVersions()
    {
        var checkedCases = new Dictionary<Guid, Guid>();
        var cases = ChangeTracker.Entries<Case>().Where(e => e.State is EntityState.Modified or EntityState.Unchanged).ToList();
        if (cases.Count == 0) return checkedCases;
        var touched = new HashSet<Guid>();
        foreach (var e in ChangeTracker.Entries())
        {
            if (e.Entity is Case || e.State is not (EntityState.Added or EntityState.Modified or EntityState.Deleted)) continue;
            if (e.Metadata.FindProperty("CaseId") is not null && e.Property("CaseId").CurrentValue is Guid id) touched.Add(id);
        }
        foreach (var c in cases)
            if ((c.State == EntityState.Modified && !OnlyHashRecorded(c)) || touched.Contains(c.Entity.Id))
            {
                if (c.Property(CaseEditVersion).OriginalValue is Guid read) checkedCases[c.Entity.Id] = read;
                c.Property(CaseEditVersion).CurrentValue = Guid.NewGuid();
            }
        return checkedCases;
    }

    // BUG-658: upkeep that only records a case's hash (the integrity upgrade) changes nothing a user sees, so a user with
    // the case open can still save. Its update is still checked against the version it read. Upkeep that fills a value
    // (the kept jurisdictions) renews it: a save from the case as it was would hash it without the value.
    private bool OnlyHashRecorded(Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry<Case> c) =>
        PendingUpkeep
        && c.Properties.Where(p => p.IsModified).All(p => p.Metadata.Name is nameof(Case.RowHash) or CaseEditVersion)
        && !c.References.Any(r => r.TargetEntry is { State: EntityState.Added or EntityState.Modified or EntityState.Deleted } t
                                  && t.Metadata.IsOwned());

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);

        LeaveOutRemovedCases(modelBuilder);

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

    /// <summary>
    /// An administrator's removal of a case (one opened by mistake, or a bad import): a removed case, and everything filed
    /// under it, is left out of every query, so nothing finds it again by its number, a search, a count or an IOC it held.
    /// A row with a case id is kept only while its case is there and not removed (a case link: both its cases). The
    /// forensic records keep it: the audit trail, the chain of custody and the seals carry no case id, and the access log,
    /// alert deliveries and held mail (an optional case id) are left alone. What must see a removed case asks with
    /// <c>IgnoreQueryFilters</c>: Administration's removed cases, the purge, the number checks, the integrity checks.
    /// </summary>
    private void LeaveOutRemovedCases(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Case>().HasQueryFilter(c => c.RemovedAtUtc == null);
        foreach (var entityType in modelBuilder.Model.GetEntityTypes().ToList())
        {
            var clr = entityType.ClrType;
            if (clr == typeof(Case) || entityType.IsOwned()) continue;
            if (entityType.FindProperty("CaseId") is not { } caseId || caseId.ClrType != typeof(Guid)) continue;
            var e = System.Linq.Expressions.Expression.Parameter(clr, "e");
            var body = LiveCase(e, "CaseId");
            if (clr == typeof(CaseLink)) body = System.Linq.Expressions.Expression.AndAlso(body, LiveCase(e, nameof(CaseLink.RelatedCaseId)));
            modelBuilder.Entity(clr).HasQueryFilter(System.Linq.Expressions.Expression.Lambda(body, e));
        }
    }

    // this.Cases.Any(c => c.Id == e.<property>): the Case filter applies inside, so a removed case's rows drop out with it.
    private System.Linq.Expressions.Expression LiveCase(System.Linq.Expressions.ParameterExpression e, string property)
    {
        var c = System.Linq.Expressions.Expression.Parameter(typeof(Case), "c");
        var match = System.Linq.Expressions.Expression.Lambda<Func<Case, bool>>(
            System.Linq.Expressions.Expression.Equal(System.Linq.Expressions.Expression.Property(c, nameof(Case.Id)),
                System.Linq.Expressions.Expression.Property(e, property)), c);
        var cases = System.Linq.Expressions.Expression.Property(System.Linq.Expressions.Expression.Constant(this), nameof(Cases));
        return System.Linq.Expressions.Expression.Call(typeof(Queryable), nameof(Queryable.Any), [typeof(Case)], cases,
            System.Linq.Expressions.Expression.Quote(match));
    }
}
