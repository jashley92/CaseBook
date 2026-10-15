using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Access;
using IncidentManager.Application.Admin;
using IncidentManager.Application.ApiTokens;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Config;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Reporting;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-567: the config import writes settings, taxonomy, roles, AD mappings, playbooks, gates, Word templates, report
/// profiles, outcomes, data elements and deadline rules under GuardGate then the template library's FileGate. Every admin
/// write to those (and the API token create, which grants roles) must wait for it, or it interleaves with an import (or
/// another admin's save) between a check and its save. This walks every admin write <see cref="AdminActionPermissions"/>
/// maps on those services, so a new one fails here until it's probed, and a probe fails unless it waits for the gates.
/// </summary>
public sealed class ImportWriterGateTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };
    private readonly List<SqliteConnection> _connections = [];

    /// <summary>The admin services whose writes touch what a config import writes.</summary>
    private static readonly Type[] ImportWritten =
    [
        typeof(AdminSettingsService), typeof(TaxonomyAdminService), typeof(RoleService), typeof(CaseTemplateService),
        typeof(StageGateService), typeof(ReportTemplateService), typeof(ReportProfileService), typeof(CaseOutcomeService),
        typeof(DataElementService), typeof(NotificationRuleService), typeof(ApiTokenService),
    ];

    /// <summary>The other guarded services, and why the import doesn't share their data.</summary>
    private static readonly Dictionary<Type, string> NotImportWritten = new()
    {
        [typeof(EmailTemplateAdminService)] = "email templates aren't in a bundle (their keys aren't importable settings)",
        [typeof(IntegrityService)] = "seals are records, not configuration",
        [typeof(ConfigBundleService)] = "the import itself",
        [typeof(ComplianceBundleService)] = "reads only",
        [typeof(IAccessLogService)] = "reads only",
        [typeof(AccessReviewService)] = "reads only",
    };

    /// <summary>Mapped methods on <see cref="ImportWritten"/> services that write nothing.</summary>
    private static readonly HashSet<string> Reads = new(StringComparer.Ordinal)
    {
        AdminActionPermissions.Key<ApiTokenService>(nameof(ApiTokenService.ListAllAsync)),
    };

    public void Dispose()
    {
        foreach (var c in _connections) c.Dispose();
    }

    [Fact]
    public void Every_guarded_admin_service_is_classed_as_import_written_or_not()
    {
        foreach (var t in AdminActionPermissions.GuardedServices)
            (ImportWritten.Contains(t) ^ NotImportWritten.ContainsKey(t)).Should().BeTrue(
                $"{t.Name} must be listed once: does the config import write what it writes? If so its writes take GuardGate.");
    }

    [Fact]
    public void Every_import_written_admin_write_has_a_probe()
    {
        var writes = Writes();
        var probes = Probes().Keys.ToHashSet(StringComparer.Ordinal);
        writes.Except(probes).Should().BeEmpty("each of these writes something the config import writes: probe it below, and take GuardGate in it");
        probes.Except(writes).Should().BeEmpty("a probe names a write that isn't mapped (stale)");
    }

    [Fact]
    public async Task Every_import_written_admin_write_waits_for_the_import(/* BUG-567 */)
    {
        var prepared = Probes().ToDictionary(p => p.Key, p => p.Value(), StringComparer.Ordinal);

        var running = new Dictionary<string, Task>(StringComparer.Ordinal);
        // As ImportAsync takes them: GuardGate, then the template library's gate.
        using (await GuardGate.EnterAsync())
        using (await ReportTemplateService.EnterFileGateAsync())
        {
            foreach (var (key, run) in prepared) running[key] = Task.Run(run);
            await Task.Delay(500);
            running.Where(r => r.Value.IsCompleted).Select(r => r.Key).Should()
                .BeEmpty("these ran while an import held the gates, between its checks and its save");
        }
        // Released: each runs now, in whatever order (they're refused or succeed; only that they waited matters here).
        foreach (var t in running.Values)
            try { await t; }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException) { }
    }

    private static HashSet<string> Writes() =>
        AdminActionPermissions.Required.Keys
            .Where(k => ImportWritten.Any(t => k.StartsWith(t.Name + ".", StringComparison.Ordinal)))
            .Where(k => !Reads.Contains(k))
            .ToHashSet(StringComparer.Ordinal);

    private static string K<T>(string method) => AdminActionPermissions.Key<T>(method);

    // Each probe sets up its own database (before the gates are held) and returns the call to make. Arguments are valid
    // as far as anything checked before the gate goes, so a call that completes didn't wait.
    private Dictionary<string, Func<Func<Task>>> Probes()
    {
        var some = Guid.NewGuid();
        var labelled = TaxonomyCatalog.Kinds[0];
        var ordered = TaxonomyCatalog.Kinds.First(k => k.AllowVisibilityOrder);
        return new(StringComparer.Ordinal)
        {
            [K<AdminSettingsService>(nameof(AdminSettingsService.SetAsync))] = Svc(f => new AdminSettingsService(f, _user, _clock, new NoOpReloader()),
                s => s.SetAsync(SettingsCatalog.ByKey.Keys.First(), null)),
            [K<AdminSettingsService>(nameof(AdminSettingsService.ResetAsync))] = Svc(f => new AdminSettingsService(f, _user, _clock, new NoOpReloader()),
                s => s.ResetAsync(SettingsCatalog.ByKey.Keys.First())),
            [K<TaxonomyAdminService>(nameof(TaxonomyAdminService.SetLabelAsync))] = Svc(f => new TaxonomyAdminService(f, _clock, _user, new NoOpReloader()),
                s => s.SetLabelAsync(labelled.Id, labelled.Members[0].Value, "Relabelled")),
            [K<TaxonomyAdminService>(nameof(TaxonomyAdminService.ResetAsync))] = Svc(f => new TaxonomyAdminService(f, _clock, _user, new NoOpReloader()),
                s => s.ResetAsync(labelled.Id, labelled.Members[0].Value)),
            [K<TaxonomyAdminService>(nameof(TaxonomyAdminService.SetVisibilityOrderAsync))] = Svc(f => new TaxonomyAdminService(f, _clock, _user, new NoOpReloader()),
                s => s.SetVisibilityOrderAsync(ordered.Id, ordered.Members.Select(m => m.Value).Reverse().ToList(), [])),
            [K<RoleService>(nameof(RoleService.CreateRoleAsync))] = Svc(Roles, s => s.CreateRoleAsync("Probe role", null, [Permission.ViewCases])),
            [K<RoleService>(nameof(RoleService.UpdateRoleAsync))] = Svc(Roles, s => s.UpdateRoleAsync(some, null, [Permission.ViewCases])),
            [K<RoleService>(nameof(RoleService.DeleteRoleAsync))] = Svc(Roles, s => s.DeleteRoleAsync(some)),
            [K<RoleService>(nameof(RoleService.AddMappingAsync))] = Svc(Roles, s => s.AddMappingAsync("CORP\\Probe", "SysAdmin")),
            [K<RoleService>(nameof(RoleService.RemoveMappingAsync))] = Svc(Roles, s => s.RemoveMappingAsync(some)),
            [K<CaseTemplateService>(nameof(CaseTemplateService.CreateAsync))] = Svc(f => new CaseTemplateService(f, _user, _clock), s => s.CreateAsync(Template())),
            [K<CaseTemplateService>(nameof(CaseTemplateService.UpdateAsync))] = Svc(f => new CaseTemplateService(f, _user, _clock), s => s.UpdateAsync(some, Template())),
            [K<CaseTemplateService>(nameof(CaseTemplateService.DeleteAsync))] = Svc(f => new CaseTemplateService(f, _user, _clock), s => s.DeleteAsync(some)),
            [K<StageGateService>(nameof(StageGateService.CreateAsync))] = Svc(f => new StageGateService(f, _user, _clock), s => s.CreateAsync(Gate())),
            [K<StageGateService>(nameof(StageGateService.UpdateAsync))] = Svc(f => new StageGateService(f, _user, _clock), s => s.UpdateAsync(some, Gate())),
            [K<StageGateService>(nameof(StageGateService.DeleteAsync))] = Svc(f => new StageGateService(f, _user, _clock), s => s.DeleteAsync(some)),
            [K<ReportTemplateService>(nameof(ReportTemplateService.UploadAsync))] = Svc(Library, s => s.UploadAsync("Probe pack", "probe.docx", [1, 2, 3])),
            [K<ReportTemplateService>(nameof(ReportTemplateService.ReplaceFileAsync))] = Svc(Library, s => s.ReplaceFileAsync(some, "probe.docx", [1, 2, 3])),
            [K<ReportTemplateService>(nameof(ReportTemplateService.RenameAsync))] = Svc(Library, s => s.RenameAsync(some, "Renamed")),
            [K<ReportTemplateService>(nameof(ReportTemplateService.SetActiveAsync))] = Svc(Library, s => s.SetActiveAsync(some, false)),
            [K<ReportTemplateService>(nameof(ReportTemplateService.SetLessonsDefaultAsync))] = Svc(Library, s => s.SetLessonsDefaultAsync(some, true)),
            [K<ReportTemplateService>(nameof(ReportTemplateService.DeleteAsync))] = Svc(Library, s => s.DeleteAsync(some)),
            [K<ReportProfileService>(nameof(ReportProfileService.CreateAsync))] = Svc(f => new ReportProfileService(f, _user, _clock), s => s.CreateAsync(Profile())),
            [K<ReportProfileService>(nameof(ReportProfileService.UpdateAsync))] = Svc(f => new ReportProfileService(f, _user, _clock), s => s.UpdateAsync(some, Profile())),
            [K<ReportProfileService>(nameof(ReportProfileService.DeleteAsync))] = Svc(f => new ReportProfileService(f, _user, _clock), s => s.DeleteAsync(some)),
            [K<CaseOutcomeService>(nameof(CaseOutcomeService.SaveAsync))] = Svc(f => new CaseOutcomeService(f, _user, _clock),
                s => s.SaveAsync([new CaseOutcomeRow(null, "Probe outcome", null)])),
            [K<CaseOutcomeService>(nameof(CaseOutcomeService.SetArchivedAsync))] = Svc(f => new CaseOutcomeService(f, _user, _clock), s => s.SetArchivedAsync(some, true)),
            [K<CaseOutcomeService>(nameof(CaseOutcomeService.DeleteAsync))] = Svc(f => new CaseOutcomeService(f, _user, _clock), s => s.DeleteAsync(some)),
            [K<DataElementService>(nameof(DataElementService.SaveAsync))] = Svc(f => new DataElementService(f, _user, _clock),
                s => s.SaveAsync([new DataElementRow(null, "Probe element", null)])),
            [K<DataElementService>(nameof(DataElementService.SetArchivedAsync))] = Svc(f => new DataElementService(f, _user, _clock), s => s.SetArchivedAsync(some, true)),
            [K<DataElementService>(nameof(DataElementService.DeleteAsync))] = Svc(f => new DataElementService(f, _user, _clock), s => s.DeleteAsync(some)),
            [K<NotificationRuleService>(nameof(NotificationRuleService.SaveAsync))] = Svc(f => new NotificationRuleService(f, _user, _clock),
                s => s.SaveAsync(null, "ZZ", "Probe", 72)),
            [K<NotificationRuleService>(nameof(NotificationRuleService.SetArchivedAsync))] = Svc(f => new NotificationRuleService(f, _user, _clock), s => s.SetArchivedAsync(some, true)),
            [K<NotificationRuleService>(nameof(NotificationRuleService.DeleteAsync))] = Svc(f => new NotificationRuleService(f, _user, _clock), s => s.DeleteAsync(some)),
            [K<ApiTokenService>(nameof(ApiTokenService.CreateSystemAsync))] = Svc(f => new ApiTokenService(f, _user, _clock, new NoRoles()),
                s => s.CreateSystemAsync("Probe token", ["SysAdmin"], _clock.UtcNow.AddDays(30))),
        };
    }

    private RoleService Roles(IAppDbContextFactory f) => new(f, _user, _clock, new NoRoles());

    private ReportTemplateService Library(IAppDbContextFactory f) => new(f, _user, _clock, new OkEngine(), new MemoryStore());

    private static TemplateInput Template() => new("Probe playbook", null, true, 1, null, null, null, null, []);

    private static StageGateInput Gate() => new(StageGateTrigger.PromoteToAdverseEvent, "Probe gate", null, false, []);

    private static ReportProfileInput Profile() => new("Probe profile", null, true, 1, null);

    // A fresh database per probe, so the calls released together don't share a connection.
    private Func<Func<Task>> Svc<TService>(Func<IAppDbContextFactory, TService> make, Func<TService, Task> call) => () =>
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        _connections.Add(connection);
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        using (var db = new AppDbContext(options)) db.Database.EnsureCreated();
        var svc = make(new TestDbContextFactory(options));
        return () => call(svc);
    };

    private sealed class NoOpReloader : ISettingsReloader { public void Reload() { } }

    private sealed class NoRoles : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) => new HashSet<Permission>();
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
        public void Invalidate() { }
    }

    private sealed class OkEngine : IReportTemplateEngine
    {
        public TemplateCheck Check(byte[] docx) => new([], []);
        public byte[] Render(byte[] template, CaseReportModel model, string? banner = null) => template;
        public byte[] Starter() => [];
        public byte[] LessonsStarter() => [];
    }

    private sealed class MemoryStore : IReportTemplateStore
    {
        private readonly Dictionary<Guid, byte[]> _files = [];
        public Task SaveAsync(Guid templateId, byte[] docx, CancellationToken ct = default) { lock (_files) _files[templateId] = docx; return Task.CompletedTask; }
        public Task<byte[]?> GetAsync(Guid templateId, CancellationToken ct = default) { lock (_files) return Task.FromResult(_files.GetValueOrDefault(templateId)); }
        public Task DeleteAsync(Guid templateId, CancellationToken ct = default) { lock (_files) _files.Remove(templateId); return Task.CompletedTask; }
    }
}
