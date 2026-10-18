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
using IncidentManager.Domain.Entities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using System.Linq.Expressions;
using System.Reflection;
using System.Text.RegularExpressions;
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
        typeof(TeamService),   // CAP-36: a bundle carries the teams
    ];

    /// <summary>The other guarded services, and why the import doesn't share their data.</summary>
    private static readonly Dictionary<Type, string> NotImportWritten = new()
    {
        [typeof(EmailTemplateAdminService)] = "email templates aren't in a bundle (their keys aren't importable settings)",
        [typeof(IntegrityService)] = "seals are records, not configuration",
        [typeof(ConfigBundleService)] = "the import itself",
        [typeof(ComplianceBundleService)] = "reads only",
        [typeof(IAccessLogService)] = "reads only",
        [typeof(AccessReviewService)] = "reads, and CAP-15's recorded review, which is an audit entry, not configuration",
        [typeof(IncidentManager.Application.Compliance.RetentionReviewService)] = "CAP-10: archives cases (case state), not configuration",
        [typeof(OffboardingService)] = "CAP-30: revokes a person's API tokens and voids their calendar link, neither of which a configuration bundle carries",
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
        // C1: by method, not by name, so a second overload of a mapped write (SetAsync with an expected value, SetLabelAsync
        // with several labels) needs its own probe.
        var writes = Writes();
        var probes = Probes().Keys.ToHashSet();
        writes.Except(probes).Select(Name).Should().BeEmpty("each of these writes something the config import writes: probe it below, and take GuardGate in it");
        probes.Except(writes).Select(Name).Should().BeEmpty("a probe names a write that isn't mapped (stale)");
    }

    [Fact]
    public async Task Every_import_written_admin_write_waits_for_the_import(/* BUG-567 */)
    {
        var prepared = Probes().ToDictionary(p => Name(p.Key), p => p.Value(), StringComparer.Ordinal);

        var running = new Dictionary<string, Task>(StringComparer.Ordinal);
        // As ImportAsync takes them: GuardGate, then the template library's gate.
        using (await GuardGate.EnterAsync())
        using (await ReportTemplateService.EnterFileGateAsync())
        {
            foreach (var (key, run) in prepared) running[key] = Task.Run(run.Call);
            await Task.Delay(500);
            running.Where(r => r.Value.IsCompleted).Select(r => r.Key).Should()
                .BeEmpty("these ran while an import held the gates, between its checks and its save");
        }
        // Released: each runs now, in whatever order (they're refused or succeed; only that they waited matters here).
        foreach (var t in running.Values)
            try { await t; }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException) { }
        prepared.Where(p => p.Value.Check.Violations.Count > 0).Select(p => p.Key).Should().BeEmpty("each saved under its own gate");
    }

    [Fact]
    public async Task Every_import_written_save_runs_under_its_gate()
    {
        // C1: one at a time and with no gate held by the test, each probe's writes to what the import writes must run while
        // the matching gate is taken (GuardGate for configuration, the library's FileGate for templates and profiles). The
        // hold test above shows a write waits; this shows the save itself is inside the gate, not before or after it.
        var wrote = new List<string>();
        var violations = new List<string>();
        foreach (var (method, prepare) in Probes())
        {
            var probe = prepare();
            try { await probe.Call(); }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException) { }
            catch (DbUpdateException) when (probe.Check.Violations.Count > 0) { /* the refused write, reported below */ }
            violations.AddRange(probe.Check.Violations.Select(v => $"{Name(method)}: {v}"));
            if (probe.Check.Writes > 0) wrote.Add(Name(method));
        }
        violations.Should().BeEmpty("a write to what the config import writes runs under the import's gate");
        // Each probe either reaches a save (and so is checked here) or is known to stop before writing (a missing row).
        var all = Probes().Keys.Select(Name).ToHashSet(StringComparer.Ordinal);
        all.Except(wrote).Except(StopsBeforeWriting).Should().BeEmpty("these probes wrote nothing: make them reach the save, or list them in StopsBeforeWriting");
        StopsBeforeWriting.Intersect(wrote).Should().BeEmpty("these are listed as stopping before writing but wrote (update the list)");
    }

    /// <summary>Probes that stop before any write (the row isn't there), so only the hold test covers them.</summary>
    private static readonly HashSet<string> StopsBeforeWriting = new(StringComparer.Ordinal)
    {
        "RoleService.UpdateRoleAsync(Guid, String, IEnumerable`1, String, CancellationToken)",
        "RoleService.DeleteRoleAsync(Guid, CancellationToken)",
        "RoleService.RemoveMappingAsync(Guid, CancellationToken)",
        "CaseTemplateService.UpdateAsync(Guid, TemplateInput, String, CancellationToken)",
        "CaseTemplateService.DeleteAsync(Guid, CancellationToken)",
        "StageGateService.UpdateAsync(Guid, StageGateInput, String, CancellationToken)",
        "StageGateService.DeleteAsync(Guid, CancellationToken)",
        "ReportTemplateService.ReplaceFileAsync(Guid, String, Byte[], CancellationToken)",
        "ReportTemplateService.RenameAsync(Guid, String, CancellationToken)",
        "ReportTemplateService.SetActiveAsync(Guid, Boolean, CancellationToken)",
        "ReportTemplateService.SetLessonsDefaultAsync(Guid, Boolean, CancellationToken)",
        "ReportTemplateService.DeleteAsync(Guid, CancellationToken)",
        "ReportProfileService.UpdateAsync(Guid, ReportProfileInput, String, CancellationToken)",
        "ReportProfileService.DeleteAsync(Guid, CancellationToken)",
        "CaseOutcomeService.SetArchivedAsync(Guid, Boolean, CancellationToken)",
        "CaseOutcomeService.DeleteAsync(Guid, CancellationToken)",
        "DataElementService.SetArchivedAsync(Guid, Boolean, CancellationToken)",
        "DataElementService.DeleteAsync(Guid, CancellationToken)",
        "NotificationRuleService.SetArchivedAsync(Guid, Boolean, CancellationToken)",
        "NotificationRuleService.DeleteAsync(Guid, CancellationToken)",
        "TeamService.UpdateAsync(Guid, TeamEdit, String, CancellationToken)",   // CAP-36
        "TeamService.SetActiveAsync(Guid, Boolean, String, CancellationToken)",
        // Nothing is stored in an empty database, so there's nothing to reset.
        "AdminSettingsService.ResetAsync(String, CancellationToken)",
        "TaxonomyAdminService.ResetAsync(String, String, CancellationToken)",
        // An empty database has no SysAdmin role to map to.
        "RoleService.AddMappingAsync(String, String, CancellationToken)",
        // Writes ApiTokens, which the import doesn't; its gate covers the role check (the hold test shows it waits).
        "ApiTokenService.CreateSystemAsync(String, IEnumerable`1, DateTimeOffset, CancellationToken)",
    };

    /// <summary>What the config import writes, by entity, and the gate a writer of it holds while it saves.</summary>
    private static readonly Dictionary<Type, string> GateFor = new()
    {
        [typeof(AppSetting)] = nameof(GuardGate), [typeof(Role)] = nameof(GuardGate), [typeof(AdGroupRoleMapping)] = nameof(GuardGate),
        [typeof(CaseTemplate)] = nameof(GuardGate), [typeof(CaseTemplateStep)] = nameof(GuardGate),
        [typeof(StageGate)] = nameof(GuardGate), [typeof(StageGateRequirement)] = nameof(GuardGate),
        [typeof(CaseOutcome)] = nameof(GuardGate), [typeof(DataElement)] = nameof(GuardGate), [typeof(NotificationRule)] = nameof(GuardGate),
        [typeof(ReportTemplate)] = FileGate, [typeof(ReportProfile)] = FileGate,
        [typeof(Team)] = nameof(GuardGate),   // CAP-36
    };

    private const string FileGate = "FileGate";

    /// <summary>The DbSets of <see cref="GateFor"/>, as the source names them.</summary>
    private static readonly string[] ImportWrittenSets =
    [
        "AppSettings", "Roles", "RoleMappings", "CaseTemplates", "CaseTemplateSteps", "StageGates", "StageGateRequirements",
        "CaseOutcomes", "DataElements", "NotificationRules", "ReportTemplates", "ReportProfiles", "Teams",
    ];

    /// <summary>Files outside the <see cref="ImportWritten"/> services that write those sets, and why that's safe.</summary>
    private static readonly Dictionary<string, string> UngatedWriters = new(StringComparer.Ordinal)
    {
        ["ConfigBundleService.Import.cs"] = "the import itself, which takes both gates",
        ["EmailTemplateAdminService.cs"] = "writes email-template AppSettings keys, which aren't importable settings",
        ["DevDataSeeder.cs"] = "development seed data, written at start-up before any request",
        ["RoleSeeder.cs"] = "built-in roles, written at start-up before any request",
        ["RowHashUpgrade.cs"] = "C18: records row hashes and writes its marker setting once, at start-up before any request",
    };

    /// <summary>Writer methods in gated services that take no gate themselves, and the caller that holds it for them.</summary>
    private static readonly Dictionary<string, string> GateHeldByCaller = new(StringComparer.Ordinal)
    {
        ["TaxonomyAdminService.cs SaveLabelEditsAsync"] = "SaveLabelsAsync takes GuardGate before its retry loop",
        ["TaxonomyAdminService.cs Add"] = "a staging helper of SaveLabelEditsAsync and SetVisibilityOrderAsync",
        ["TaxonomyAdminService.cs SaveAsync"] = "the save helper of SaveLabelEditsAsync and SetVisibilityOrderAsync",
    };

    private static readonly Regex WriteCall = new(
        @"\.(?<set>" + string.Join("|", ImportWrittenSets) + @")\s*\.\s*(Add|AddRange|Remove|RemoveRange|Update|UpdateRange|Attach|ExecuteUpdate\w*|ExecuteDelete\w*)\(",
        RegexOptions.None, TimeSpan.FromSeconds(5));

    private static readonly Regex SetUse = new(
        @"\b(db|fresh|recheck|ctx|context)\.(?<set>" + string.Join("|", ImportWrittenSets) + @")\b(?!\s*\.\s*AsNoTracking)",
        RegexOptions.None, TimeSpan.FromSeconds(5));

    private static readonly Regex GateLine = new(@"GuardGate\.EnterAsync\(|EnterFileGateAsync\(|FileGate\.WaitAsync\(",
        RegexOptions.None, TimeSpan.FromSeconds(5));

    private static readonly Regex Member = new(@"^    (public|private|internal|protected)\b[^=;]*\(", RegexOptions.None, TimeSpan.FromSeconds(5));

    [Fact]
    public void The_import_written_sets_are_what_the_import_writes()
    {
        var import = File.ReadAllText(Path.Combine(SourceRoot(), "IncidentManager.Application", "Config", "ConfigBundleService.Import.cs"));
        var written = new Regex(@"\bdb\.(?<set>\w+)\s*\.\s*(Add|AddRange|Remove|RemoveRange|Where|FirstOrDefaultAsync|ToListAsync)\(",
                RegexOptions.None, TimeSpan.FromSeconds(5))
            .Matches(import).Select(m => m.Groups["set"].Value).ToHashSet(StringComparer.Ordinal);
        written.Except(ImportWrittenSets).Should().BeEmpty("the import writes these too: add them to ImportWrittenSets and GateFor");
        using var database = TestDatabase.Open(TestDatabase.Sqlite);
        using var db = database.NewContext();
        foreach (var set in ImportWrittenSets)
            GateFor.Keys.Should().Contain(typeof(AppDbContext).GetProperty(set)!.PropertyType.GetGenericArguments()[0], $"{set} needs a gate in GateFor");
    }

    [Fact]
    public void Every_write_of_import_written_data_is_gated_before_its_first_query()
    {
        // C1: a writer of what the import writes is one of the gated services (or explained), and its gate is taken before
        // anything it awaits: a look made before the gate is a check the import can change before the save.
        var gatedFiles = ImportWritten.Select(t => t.Name + ".cs").ToHashSet(StringComparer.Ordinal);
        var problems = new List<string>();
        foreach (var path in Directory.EnumerateFiles(SourceRoot(), "*.cs", SearchOption.AllDirectories))
        {
            if (path.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)) continue;
            var file = Path.GetFileName(path);
            foreach (var (name, body) in Members(File.ReadAllLines(path)))
            {
                var joined = string.Join("\n", body);
                var writes = WriteCall.IsMatch(joined) || (SetUse.IsMatch(joined) && joined.Contains("SaveChanges", StringComparison.Ordinal));
                if (!writes) continue;
                if (UngatedWriters.ContainsKey(file)) continue;
                if (!gatedFiles.Contains(file)) { problems.Add($"{file} {name}: writes import-written data outside a gated service"); continue; }
                if (GateHeldByCaller.ContainsKey($"{file} {name}")) continue;
                var gate = body.FindIndex(l => GateLine.IsMatch(l));
                if (gate < 0) { problems.Add($"{file} {name}: takes no gate"); continue; }
                var firstAwait = body.FindIndex(l => l.Contains("await ", StringComparison.Ordinal) && !GateLine.IsMatch(l));
                if (firstAwait >= 0 && firstAwait < gate) problems.Add($"{file} {name}: awaits before the gate: {body[firstAwait].Trim()}");
            }
        }
        problems.Should().BeEmpty();
    }

    // The members of a file, split at its class-member declarations (four-space indent), as (name, lines).
    private static IEnumerable<(string Name, List<string> Body)> Members(string[] lines)
    {
        string? name = null;
        var body = new List<string>();
        foreach (var line in lines)
        {
            if (Member.Match(line) is { Success: true } m)
            {
                if (name is not null) yield return (name, body);
                var open = line.IndexOf('(', StringComparison.Ordinal);
                name = line[..open].Trim().Split(' ')[^1];
                body = [];
            }
            body.Add(line);
        }
        if (name is not null) yield return (name, body);
    }

    private static string SourceRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) dir = dir.Parent;
        dir.Should().NotBeNull();
        return Path.Combine(dir!.FullName, "src");
    }

    private static HashSet<MethodInfo> Writes() =>
        ImportWritten.SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(m => AdminActionPermissions.Required.ContainsKey(AdminActionPermissions.Key(m.DeclaringType!, m.Name)))
            .Where(m => !Reads.Contains(AdminActionPermissions.Key(m.DeclaringType!, m.Name)))
            .ToHashSet();

    private static string Name(MethodInfo m) =>
        $"{m.DeclaringType!.Name}.{m.Name}({string.Join(", ", m.GetParameters().Select(p => p.ParameterType.Name))})";

    private static readonly CancellationToken None = CancellationToken.None;

    // Each probe sets up its own database (before the gates are held) and returns the call to make. Arguments are valid
    // as far as anything checked before the gate goes, so a call that completes didn't wait. Keyed by the method the
    // expression calls, so each overload is its own probe.
    private Dictionary<MethodInfo, Func<Probe>> Probes()
    {
        var some = Guid.NewGuid();
        var labelled = TaxonomyCatalog.Kinds[0];
        var member = labelled.Members[0].Value;
        var labels = (IReadOnlyDictionary<string, string?>)new Dictionary<string, string?> { [member] = "Relabelled" };
        var ordered = TaxonomyCatalog.Kinds.First(k => k.AllowVisibilityOrder);
        var order = (IReadOnlyList<string>)ordered.Members.Select(m => m.Value).Reverse().ToList();
        var hidden = (IReadOnlyCollection<string>)Array.Empty<string>();
        var setting = SettingsCatalog.ByKey.Keys.First();
        var view = new[] { Permission.ViewCases };
        var template = Template();
        var gate = Gate();
        var profile = Profile();
        var file = new byte[] { 1, 2, 3 };
        var outcomes = (IReadOnlyList<CaseOutcomeRow>)[new CaseOutcomeRow(null, "Probe outcome", null)];
        var elements = (IReadOnlyList<DataElementRow>)[new DataElementRow(null, "Probe element", null)];
        var sysAdmin = new[] { "SysAdmin" };
        var expires = _clock.UtcNow.AddDays(30);
        var probes = new Dictionary<MethodInfo, Func<Probe>>();
        void Add<TService>(Func<IAppDbContextFactory, TService> make, Expression<Func<TService, Task>> call) =>
            probes.Add(((MethodCallExpression)call.Body).Method, Svc(make, call.Compile()));

        AdminSettingsService Settings(IAppDbContextFactory f) => new(f, _user, _clock, new NoOpReloader());
        TaxonomyAdminService Taxonomy(IAppDbContextFactory f) => new(f, _clock, _user, new NoOpReloader());
        Add(Settings, s => s.SetAsync(setting, null, None));
        Add(Settings, s => s.SetAsync(setting, "x", null, None));
        Add(Settings, s => s.ResetAsync(setting, None));
        Add(Taxonomy, s => s.SetLabelAsync(labelled.Id, member, "Relabelled", None));
        Add(Taxonomy, s => s.SetLabelAsync(labelled.Id, labels, None));
        Add(Taxonomy, s => s.ResetAsync(labelled.Id, member, None));
        Add(Taxonomy, s => s.SetVisibilityOrderAsync(ordered.Id, order, hidden, null, None));
        Add(Roles, s => s.CreateRoleAsync("Probe role", null, view, None));
        Add(Roles, s => s.UpdateRoleAsync(some, null, view, null, None));
        Add(Roles, s => s.DeleteRoleAsync(some, None));
        Add(Roles, s => s.AddMappingAsync("CORP\\Probe", "SysAdmin", None));
        Add(Roles, s => s.RemoveMappingAsync(some, None));
        Add(Playbooks, s => s.CreateAsync(template, None));
        Add(Playbooks, s => s.UpdateAsync(some, template, null, None));
        Add(Playbooks, s => s.DeleteAsync(some, None));
        Add(Gates, s => s.CreateAsync(gate, None));
        Add(Gates, s => s.UpdateAsync(some, gate, null, None));
        Add(Gates, s => s.DeleteAsync(some, None));
        Add(Library, s => s.UploadAsync("Probe pack", "probe.docx", file, None));
        Add(Library, s => s.ReplaceFileAsync(some, "probe.docx", file, None));
        Add(Library, s => s.RenameAsync(some, "Renamed", None));
        Add(Library, s => s.SetActiveAsync(some, false, None));
        Add(Library, s => s.SetLessonsDefaultAsync(some, true, None));
        Add(Library, s => s.DeleteAsync(some, None));
        Add(Profiles, s => s.CreateAsync(profile, None));
        Add(Profiles, s => s.UpdateAsync(some, profile, null, None));
        Add(Profiles, s => s.DeleteAsync(some, None));
        Add(Outcomes, s => s.SaveAsync(outcomes, None));
        Add(Outcomes, s => s.SetArchivedAsync(some, true, None));
        Add(Outcomes, s => s.DeleteAsync(some, None));
        Add(Elements, s => s.SaveAsync(elements, None));
        Add(Elements, s => s.SetArchivedAsync(some, true, None));
        Add(Elements, s => s.DeleteAsync(some, None));
        Add(Rules, s => s.SaveAsync(null, "ZZ", "Probe", 72, null, None));
        Add(Rules, s => s.SetArchivedAsync(some, true, None));
        Add(Rules, s => s.DeleteAsync(some, None));
        Add(f => new ApiTokenService(f, _user, _clock, new NoRoles()), s => s.CreateSystemAsync("Probe token", sysAdmin, expires, None));
        var team = new TeamEdit("Probe team", null, null, []);   // CAP-36
        Add(Teams, s => s.CreateAsync(team, None));
        Add(Teams, s => s.UpdateAsync(some, team, null, None));
        Add(Teams, s => s.SetActiveAsync(some, false, null, None));
        return probes;
    }

    private RoleService Roles(IAppDbContextFactory f) => new(f, _user, _clock, new NoRoles());
    private CaseTemplateService Playbooks(IAppDbContextFactory f) => new(f, _user, _clock);
    private StageGateService Gates(IAppDbContextFactory f) => new(f, _user, _clock);
    private ReportProfileService Profiles(IAppDbContextFactory f) => new(f, _user, _clock);
    private CaseOutcomeService Outcomes(IAppDbContextFactory f) => new(f, _user, _clock);
    private DataElementService Elements(IAppDbContextFactory f) => new(f, _user, _clock);
    private NotificationRuleService Rules(IAppDbContextFactory f) => new(f, _user, _clock);
    private TeamService Teams(IAppDbContextFactory f) => new(f, _user, _clock);

    private ReportTemplateService Library(IAppDbContextFactory f) => new(f, _user, _clock, new OkEngine(), new MemoryStore());

    private static TemplateInput Template() => new("Probe playbook", null, true, 1, null, null, null, null, []);

    private static StageGateInput Gate() => new(StageGateTrigger.PromoteToAdverseEvent, "Probe gate", null, false, []);

    private static ReportProfileInput Profile() => new("Probe profile", null, true, 1, null);

    private sealed record Probe(Func<Task> Call, GateCheck Check);

    // A fresh database per probe, so the calls released together don't share a connection. Its writes are checked
    // against the gates from the first statement after the schema is made.
    private Func<Probe> Svc<TService>(Func<IAppDbContextFactory, TService> make, Func<TService, Task> call) => () =>
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        _connections.Add(connection);
        var check = new GateCheck();
        var builder = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        using (var db = new AppDbContext(builder.Options))
        {
            db.Database.EnsureCreated();
            check.Watch(db.Model);
        }
        var svc = make(new TestDbContextFactory(builder.AddInterceptors(check).Options));
        return new Probe(() => call(svc), check);
    };

    /// <summary>
    /// C1: refuses (and records) a statement that writes what the config import writes while its gate isn't taken. Run
    /// on the database commands, so a bulk ExecuteUpdate/ExecuteDelete is checked as well as SaveChanges.
    /// </summary>
    private sealed class GateCheck : DbCommandInterceptor
    {
        private static readonly Regex Write = new(@"\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+""(?<table>\w+)""",
            RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));
        private readonly Dictionary<string, string> _gateByTable = new(StringComparer.OrdinalIgnoreCase);
        private int _writes;

        public List<string> Violations { get; } = [];
        public int Writes => Volatile.Read(ref _writes);

        public void Watch(Microsoft.EntityFrameworkCore.Metadata.IModel model)
        {
            foreach (var (type, gate) in GateFor)
                if (model.FindEntityType(type)?.GetTableName() is { } table) _gateByTable[table] = gate;
        }

        private void Check(System.Data.Common.DbCommand command)
        {
            foreach (Match m in Write.Matches(command.CommandText))
            {
                if (!_gateByTable.TryGetValue(m.Groups["table"].Value, out var gate)) continue;
                Interlocked.Increment(ref _writes);
                var taken = gate == FileGate ? ReportTemplateService.FileGateTaken : GuardGate.IsTaken;
                if (taken) continue;
                var problem = $"wrote {m.Groups["table"].Value} without {gate}";
                lock (Violations) Violations.Add(problem);
                throw new GateNotTakenException(problem);
            }
        }

        public override InterceptionResult<int> NonQueryExecuting(System.Data.Common.DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
        { Check(command); return result; }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(System.Data.Common.DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        { Check(command); return ValueTask.FromResult(result); }

        public override InterceptionResult<System.Data.Common.DbDataReader> ReaderExecuting(System.Data.Common.DbCommand command, CommandEventData eventData,
            InterceptionResult<System.Data.Common.DbDataReader> result)
        { Check(command); return result; }

        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(System.Data.Common.DbCommand command,
            CommandEventData eventData, InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
        { Check(command); return ValueTask.FromResult(result); }
    }

    // Not an InvalidOperationException or ArgumentException, so a probe's expected refusals don't swallow it.
    private sealed class GateNotTakenException(string message) : Exception(message);

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
