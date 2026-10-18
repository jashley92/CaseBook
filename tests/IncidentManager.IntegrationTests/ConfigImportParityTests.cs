using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Config;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Reporting;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// C2 (BUG-440, 517, 533, 559, 568): the config import preview must say what the import does. For each change a bundle
/// can carry (the mutators below, at least one per <see cref="ConfigBundle"/> section), the preview's add and update
/// counts are the import's, the rows the import writes are exactly the ones the preview lists, a second import of the
/// same bundle changes nothing, and a bundle the import refuses is refused by the preview with the same words.
/// </summary>
public sealed class ConfigImportParityTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 8, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), "im-config-parity", Guid.NewGuid().ToString("N"));
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly RsaSealSigner _signer;
    private readonly WordTemplateEngine _engine = new();
    private readonly TouchRecorder _touched = new();
    private readonly TestDbContextFactory _factory;
    private readonly FileReportTemplateStore _store;
    private readonly ConfigBundleService _config;

    public ConfigImportParityTests()
    {
        _connection.Open();
        _signer = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_workDir, "k.pem"), AllowKeyGeneration = true }));
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection)
            .AddInterceptors(_touched, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier())).Options;
        using (var db = new AppDbContext(options)) db.Database.EnsureCreated();
        _factory = new TestDbContextFactory(options);
        _store = new FileReportTemplateStore(Options.Create(new ReportTemplateOptions { RootPath = Path.Combine(_workDir, "templates") }),
            Options.Create(new ReportBrandingOptions()));
        var auditOnly = new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier())).Options);   // its rows aren't config
        _config = new ConfigBundleService(_factory, _signer, new AuditWriter(auditOnly, _hasher, _user, _clock), _user, _clock,
            templateEngine: _engine, templateStore: _store);
    }

    private async Task SeedAsync()
    {
        using (var db = _factory.CreateAppDbContext())
        {
            await DevDataSeeder.SeedDataElementsAsync(db, _clock);
            await DevDataSeeder.SeedCaseOutcomesAsync(db, _clock);
            await DevDataSeeder.SeedDefaultReportProfilesAsync(db, _clock);
            await DevDataSeeder.SeedStarterTemplatesAsync(db, _clock);
            await DevDataSeeder.SeedDefaultStageGatesAsync(db, _clock);
            Stamp(db.Roles.Add(new Role { Name = "IR Lead", Description = "Custom", PermissionsCsv = "ViewCases,EditCases" }).Entity);
            Stamp(db.Roles.Add(new Role { Name = "Ops Admin", Description = "Admins", PermissionsCsv = "ViewCases,Administer" }).Entity);
            db.RoleMappings.Add(new AdGroupRoleMapping { AdGroup = "CORP\\SOC", RoleName = "IR Lead", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            db.RoleMappings.Add(new AdGroupRoleMapping { AdGroup = "CORP\\Admins", RoleName = "Ops Admin", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            db.AppSettings.Add(new AppSetting { Key = "Reporting:OrganizationName", Value = "Northwind Mutual", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            db.NotificationRules.Add(new NotificationRule { Code = "NY", Label = "New York", WindowHours = 72, IsActive = true, CreatedBy = "admin1", CreatedAtUtc = _clock.UtcNow });
            // CAP-36: a team with a member: the member stays here, and never travels.
            var team = db.Teams.Add(new Team { Key = "SocTier1", Name = "SOC tier 1", CreatedBy = "admin1", CreatedAtUtc = _clock.UtcNow }).Entity;
            db.TeamMembers.Add(new TeamMember { TeamId = team.Id, UserId = "analyst1", AddedBy = "admin1", AddedAtUtc = _clock.UtcNow });
            await db.SaveChangesAsync();
        }
        var templates = new ReportTemplateService(_factory, _user, _clock, _engine, _store);
        var upload = await templates.UploadAsync("Examiner pack", "examiner.docx", _engine.Starter());
        await templates.SetLessonsDefaultAsync(upload.Id!.Value, true);
        using var db2 = _factory.CreateDbContext();
        (await db2.ReportProfiles.OrderBy(p => p.SortOrder).FirstAsync()).TemplateId = upload.Id;
        await db2.SaveChangesAsync();
    }

    private void Stamp(Role r) { r.UpdatedAtUtc = _clock.UtcNow; r.UpdatedBy = "admin1"; }

    private ConfigBundleEnvelope Signed(ConfigBundle bundle) => new(
        ConfigBundleJson.FormatTag, ConfigBundleJson.CurrentSchemaVersion, "test", _clock.UtcNow, _user.UserId, "test-host",
        _signer.Algorithm, _signer.KeyId, _signer.PublicKeyPem, _signer.Sign(ConfigBundleJson.Canonicalize(bundle)), bundle);

    // --- the mutators: one change a bundle can carry, by the ConfigBundle section it's in -------------------------------

    private sealed record Mutator(string Section, Func<ConfigBundle, ConfigBundle> Apply);

    private static T[] Set<T>(IReadOnlyList<T> items, Func<T, bool> which, Func<T, T> change) =>
        items.Select(i => which(i) ? change(i) : i).ToArray();

    private static readonly Dictionary<string, Mutator> Mutators = new()
    {
        ["nothing"] = new(nameof(ConfigBundle.Settings), b => b),
        ["setting changed"] = new(nameof(ConfigBundle.Settings), b => b with
            { Settings = Set(b.Settings, s => s.Key == "Reporting:OrganizationName", s => s with { Value = "Contoso" }) }),
        ["setting added"] = new(nameof(ConfigBundle.Settings), b => b with
            { Settings = [.. b.Settings, new ConfigSetting("Taxonomy:Classification:Label:Breach", "Major incident")] }),
        // CAP-10 and CAP-15: the retention-review email and the access-review reminder travel in a bundle as settings.
        ["retention email turned on"] = new(nameof(ConfigBundle.Settings), b => b with
            { Settings = [.. b.Settings, new ConfigSetting("Notifications:RetentionReview:Email", "true"), new ConfigSetting("Retention:CaseYears", "10")] }),
        ["access review reminder set"] = new(nameof(ConfigBundle.Settings), b => b with
            { Settings = [.. b.Settings, new ConfigSetting("Governance:AccessReview:ReminderDays", "30")] }),
        // CAP-31: how long a decided import keeps its document travels as a setting too.
        ["decided import retention set"] = new(nameof(ConfigBundle.Settings), b => b with
            { Settings = [.. b.Settings, new ConfigSetting("Retention:DecidedImportDays", "30")] }),
        // CAP-28 exclusions: the organization's domains and ranges are its configuration, so they travel in a bundle, written
        // as a person would paste them (stored lowercased, one per line, as the page stores them).
        ["related exclusions set"] = new(nameof(ConfigBundle.Settings), b => b with
        {
            Settings = [.. b.Settings, new ConfigSetting(RelatedExclusionSettings.DomainsKey, "Contoso.com, corp.contoso.local."),
                new ConfigSetting(RelatedExclusionSettings.RangesKey, "10.0.0.0/8; FD00::/8 198.51.100.0/24"),
                new ConfigSetting(RelatedExclusionSettings.FreeMailKey, "False")],
        }),
        ["role changed"] = new(nameof(ConfigBundle.Roles), b => b with
            { Roles = Set(b.Roles, r => r.Name == "IR Lead", r => r with { PermissionsCsv = "EditCases,ViewCases,ViewAllCases" }) }),
        ["role permissions reordered"] = new(nameof(ConfigBundle.Roles), b => b with
            { Roles = Set(b.Roles, r => r.Name == "IR Lead", r => r with { PermissionsCsv = "EditCases , ViewCases" }) }),
        ["role and mapping added"] = new(nameof(ConfigBundle.RoleMappings), b => b with
        {
            Roles = [.. b.Roles, new ConfigRole("Hunters", "Threat hunting", false, "ViewCases")],
            RoleMappings = [.. b.RoleMappings, new ConfigRoleMapping(" CORP\\Hunt ", "hunters"), new ConfigRoleMapping("corp\\hunt", "Hunters")],
        }),
        ["mapping in another case"] = new(nameof(ConfigBundle.RoleMappings), b => b with
            { RoleMappings = Set(b.RoleMappings, m => m.RoleName == "IR Lead", m => m with { AdGroup = "corp\\soc ", RoleName = "ir lead" }) }),
        ["playbook steps out of order"] = new(nameof(ConfigBundle.CaseTemplates), b => b with
            { CaseTemplates = Set(b.CaseTemplates, t => t == b.CaseTemplates[0], t => t with { Steps = t.Steps.Reverse().ToArray() }) }),
        ["playbook described"] = new(nameof(ConfigBundle.CaseTemplates), b => b with
            { CaseTemplates = Set(b.CaseTemplates, t => t == b.CaseTemplates[0], t => t with { Description = "Revised", DefaultSeverity = " High " }) }),
        ["gate described"] = new(nameof(ConfigBundle.StageGates), b => b with
            { StageGates = Set(b.StageGates, g => g == b.StageGates[0], g => g with { Description = "Revised" }) }),
        ["gate threshold below its floor"] = new(nameof(ConfigBundle.StageGates), b => b with
        {
            StageGates = Set(b.StageGates, g => g == b.StageGates[0], g => g with
            {
                CommentaryMinLength = -5,
                Requirements = [.. g.Requirements.Reverse(), new ConfigGateRequirement(99, "MachineCheck", GateCheckKeys.AtLeastOneEvidence, -3, "Evidence", true)],
            })
        }),
        ["gate for a comma-list transition"] = new(nameof(ConfigBundle.StageGates), b => b with
            { StageGates = [.. b.StageGates, b.StageGates[0] with { Name = "Listed", Trigger = "EscalateToIncident,EscalateToBreach", IsActive = false }] }),
        ["word template hash in capitals"] = new(nameof(ConfigBundle.ReportTemplates), b => b with
            { ReportTemplates = Set(b.ReportTemplates!, _ => true, t => t with { Sha256 = t.Sha256.ToUpperInvariant() }) }),
        ["word template file in a folder"] = new(nameof(ConfigBundle.ReportTemplates), b => b with
            { ReportTemplates = Set(b.ReportTemplates!, _ => true, t => t with { FileName = "templates\\" + t.FileName }) }),
        ["lessons default moves to a new template"] = new(nameof(ConfigBundle.ReportTemplates), b => b with
        {
            ReportTemplates = [b.ReportTemplates![0] with { Name = "Lessons pack", FileName = "lessons.docx" }],
        }),
        ["profile described"] = new(nameof(ConfigBundle.ReportProfiles), b => b with
            { ReportProfiles = Set(b.ReportProfiles, p => p == b.ReportProfiles[0], p => p with { Description = "Revised", Template = p.Template?.ToUpperInvariant() }) }),
        ["data element relabelled and added"] = new(nameof(ConfigBundle.DataElements), b => b with
        {
            DataElements = [.. Set(b.DataElements, d => d == b.DataElements[0], d => d with { Label = "Renamed" }),
                new ConfigDataElement("Passport_No-2", "Passport", 40, true, false, "US;NY")],
        }),
        ["rule code padded and lower-case"] = new(nameof(ConfigBundle.NotificationRules), b => b with
            { NotificationRules = Set(b.NotificationRules, r => r.Code == "NY", r => r with { Code = " ny ", Label = "New York " }) }),
        ["rule added and retimed"] = new(nameof(ConfigBundle.NotificationRules), b => b with
        {
            NotificationRules = [.. Set(b.NotificationRules, r => r.Code == "NY", r => r with { WindowHours = 96 }),
                new ConfigNotificationRule(" ca", " California ", 720, true, false)],
        }),
        ["outcome relabelled"] = new(nameof(ConfigBundle.CaseOutcomes), b => b with
            { CaseOutcomes = Set(b.CaseOutcomes!, o => o == b.CaseOutcomes![0], o => o with { Label = "Renamed" }) }),
        // CAP-36: a team renamed and given a detection source, and one added (with no members and no webhook here).
        ["team renamed and added"] = new(nameof(ConfigBundle.Teams), b => b with
        {
            Teams = [.. Set(b.Teams!, t => t.Key == "SocTier1", t => t with { Name = "SOC tier one", DetectionSourceLabel = "EDR",
                    DetectionLinkTemplate = "https://edr.example/case/{0}" }),
                new ConfigTeam("Fraud", "Fraud desk", true, null, null)],
        }),
        ["team retired"] = new(nameof(ConfigBundle.Teams), b => b with
            { Teams = Set(b.Teams!, t => t.Key == "SocTier1", t => t with { IsActive = false }) }),
    };

    public static TheoryData<string> MutatorNames() => [.. Mutators.Keys];

    [Theory]
    [MemberData(nameof(MutatorNames))]
    public async Task The_preview_lists_exactly_what_the_import_writes(string mutator)
    {
        await SeedAsync();
        var bundle = Mutators[mutator].Apply(await _config.BuildBundleAsync());

        var diff = await _config.PreviewAsync(bundle);
        _touched.Rows.Clear();
        var result = await _config.ImportAsync(Signed(bundle));

        (result.Added, result.Updated).Should().Be((diff.Added, diff.Updated), "the preview's counts are the import's");
        _touched.Rows.Should().BeEquivalentTo(diff.Changes.Select(c => $"{c.Section}: {c.Name}"),
            "every row the import writes is listed, and every listed one is written");

        var again = await _config.PreviewAsync(bundle);
        again.Changes.Should().BeEmpty("the same bundle again changes nothing");
        _touched.Rows.Clear();
        var second = await _config.ImportAsync(Signed(bundle));
        (second.Added, second.Updated).Should().Be((0, 0));
        _touched.Rows.Should().BeEmpty();
    }

    [Fact]
    public async Task A_padded_lower_case_rule_code_is_the_rule_already_here(/* C2 minor */)
    {
        await SeedAsync();
        var bundle = Mutators["rule code padded and lower-case"].Apply(await _config.BuildBundleAsync());

        (await _config.PreviewAsync(bundle)).Changes.Should().BeEmpty("trimmed and upper-cased it's NY, as the page saves it");
        await _config.ImportAsync(Signed(bundle));

        using var db = _factory.CreateDbContext();
        (await db.NotificationRules.Select(r => new { r.Code, r.Label }).SingleAsync()).Should().Be(new { Code = "NY", Label = "New York" });
    }

    [Fact]
    public async Task Related_exclusions_round_trip_through_a_bundle(/* CAP-28 exclusions */)
    {
        await SeedAsync();
        using (var db = _factory.CreateAppDbContext())
        {
            db.AppSettings.Add(new AppSetting { Key = RelatedExclusionSettings.DomainsKey, Value = "contoso.com\ncorp.contoso.local", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            db.AppSettings.Add(new AppSetting { Key = RelatedExclusionSettings.RangesKey, Value = "", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            db.AppSettings.Add(new AppSetting { Key = RelatedExclusionSettings.FreeMailKey, Value = "false", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            await db.SaveChangesAsync();
        }
        var bundle = await _config.BuildBundleAsync();
        bundle.Settings.Where(s => s.Key.StartsWith("RelatedIndicators:", StringComparison.Ordinal)).Should().HaveCount(3);

        using (var db = _factory.CreateAppDbContext())
        {
            db.AppSettings.RemoveRange(db.AppSettings.Where(s => s.Key.StartsWith("RelatedIndicators:")));
            await db.SaveChangesAsync();
        }
        await _config.ImportAsync(Signed(bundle));

        using var check = _factory.CreateDbContext();
        (await check.AppSettings.Where(s => s.Key.StartsWith("RelatedIndicators:")).ToDictionaryAsync(s => s.Key, s => s.Value))
            .Should().BeEquivalentTo(new Dictionary<string, string?>
            {
                [RelatedExclusionSettings.DomainsKey] = "contoso.com\ncorp.contoso.local",
                [RelatedExclusionSettings.RangesKey] = "",
                [RelatedExclusionSettings.FreeMailKey] = "false",
            }, "a cleared range list travels as cleared, not as the default");
    }

    // --- refusals: what the import refuses, the preview refuses in the same words, and nothing is written ---------------

    private static readonly Dictionary<string, Func<ConfigBundle, ConfigBundle>> Refused = new()
    {
        ["setting twice"] = b => b with { Settings = [.. b.Settings, new ConfigSetting("Reporting:OrganizationName", "Contoso")] },
        // CAP-28 exclusions: what the page refuses, the bundle can't bring in.
        ["excluded range not CIDR"] = b => b with { Settings = [.. b.Settings, new ConfigSetting(RelatedExclusionSettings.RangesKey, "10.0.0.0/8\n10.1.2.3/8")] },
        ["excluded domain a public suffix"] = b => b with { Settings = [.. b.Settings, new ConfigSetting(RelatedExclusionSettings.DomainsKey, "co.uk")] },
        ["role twice"] = b => b with { Roles = [.. b.Roles, new ConfigRole("Ops", null, false, "ViewCases"), new ConfigRole("ops", null, false, "ViewCases")] },
        ["role name with a comma"] = b => b with { Roles = [.. b.Roles, new ConfigRole("Readers,SysAdmin", null, false, "ViewCases")] },
        ["last administrator"] = b => b with { Roles = Set(b.Roles, r => r.Name == "Ops Admin", r => r with { PermissionsCsv = "ViewCases" }) },
        ["rule code twice once padded"] = b => b with { NotificationRules = [.. b.NotificationRules, new ConfigNotificationRule("NY ", "Again", 72, true, false)] },
        ["data element key with a comma"] = b => b with { DataElements = [.. b.DataElements, new ConfigDataElement("Tax,Id", "Tax id", 50, true, false, null)] },   // BUG-590
        ["data element key with a semicolon"] = b => b with { DataElements = [.. b.DataElements, new ConfigDataElement("Tax;NY", "Tax id", 50, true, false, null)] },
        ["data element key with a space"] = b => b with { DataElements = [.. b.DataElements, new ConfigDataElement("Tax Id", "Tax id", 50, true, false, null)] },
        ["playbook classification by number"] = b => b with   // BUG-592
            { CaseTemplates = Set(b.CaseTemplates, t => t == b.CaseTemplates[0], t => t with { DefaultClassification = "7" }) },
        ["playbook severity as a list"] = b => b with
            { CaseTemplates = Set(b.CaseTemplates, t => t == b.CaseTemplates[0], t => t with { DefaultSeverity = "Low,High" }) },
        ["playbook step of an unknown kind"] = b => b with
            { CaseTemplates = Set(b.CaseTemplates, t => t == b.CaseTemplates[0], t => t with { Steps = [t.Steps[0] with { Kind = (TaskKind)99 }] }) },
        // CAP-36
        ["team key with a space"] = b => b with { Teams = [.. b.Teams!, new ConfigTeam("Soc Two", "SOC two", true, null, null)] },
        ["team twice"] = b => b with { Teams = [.. b.Teams!, new ConfigTeam("Fraud", "Fraud", true, null, null), new ConfigTeam("fraud", "Fraud two", true, null, null)] },
        ["team named as another"] = b => b with { Teams = [.. b.Teams!, new ConfigTeam("Other", "SOC tier 1", true, null, null)] },
        ["team link without its placeholder"] = b => b with
            { Teams = Set(b.Teams!, t => t.Key == "SocTier1", t => t with { DetectionLinkTemplate = "https://edr.example/case" }) },
    };

    public static TheoryData<string> RefusedNames() => [.. Refused.Keys];

    [Theory]
    [MemberData(nameof(RefusedNames))]
    public async Task What_the_import_refuses_the_preview_refuses_in_the_same_words(string refusal)
    {
        await SeedAsync();
        var bundle = Refused[refusal](await _config.BuildBundleAsync());

        var preview = await Record(() => _config.PreviewAsync(bundle));
        _touched.Rows.Clear();
        var import = await Record(() => _config.ImportAsync(Signed(bundle)));

        preview.Should().NotBeNull("the preview refuses it");
        import.Should().NotBeNull("the import refuses it");
        preview!.Message.Should().Be(import!.Message);
        preview.Should().BeOfType(import.GetType());
        _touched.Rows.Should().BeEmpty("nothing is written");
    }

    private static async Task<Exception?> Record(Func<Task> act)
    {
        try { await act(); return null; }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException) { return ex; }
    }

    [Fact]
    public void Every_bundle_section_has_a_mutator()
    {
        var sections = typeof(ConfigBundle).GetProperties()
            .Where(p => p.PropertyType.IsGenericType && p.PropertyType.GetGenericTypeDefinition() == typeof(IReadOnlyList<>))
            .Select(p => p.Name).ToList();
        sections.Should().HaveCount(11, "the sections known when this was written; a new one needs a mutator here");
        Mutators.Values.Select(m => m.Section).Distinct().Should().BeEquivalentTo(sections,
            "a section without a mutator could preview one thing and import another");
    }

    /// <summary>Records each configuration row a save adds or changes, named as the preview names it.</summary>
    private sealed class TouchRecorder : SaveChangesInterceptor
    {
        public List<string> Rows { get; } = [];

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            foreach (var e in eventData.Context!.ChangeTracker.Entries()
                         .Where(e => e.State is EntityState.Added or EntityState.Modified))
            {
                var row = e.Entity switch
                {
                    AppSetting s => $"Setting: {s.Key}",
                    Role r => $"Role: {r.Name}",
                    AdGroupRoleMapping m => $"AD mapping: {m.AdGroup} → {m.RoleName}",
                    CaseTemplate t => $"Case template: {t.Name}",
                    StageGate g => $"Stage gate: {g.Name}",
                    ReportTemplate t => $"Word template: {t.Name}",
                    ReportProfile p => $"Report profile: {p.Name}",
                    CaseOutcome o => $"Case outcome: {o.Key}",
                    DataElement d => $"Data element: {d.Label}",
                    NotificationRule r => $"Notification rule: {r.Code}",
                    Team t => $"Team: {t.Key}",   // CAP-36
                    CaseTemplateStep or StageGateRequirement => null,   // replaced with their parent, which is listed
                    _ => $"unlisted: {e.Entity.GetType().Name}",
                };
                if (row is not null) Rows.Add(row);
            }
            return base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }

    public void Dispose()
    {
        _connection.Dispose();
        try { Directory.Delete(_workDir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
