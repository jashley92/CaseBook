using FluentAssertions;
using IncidentManager.Application.Abstractions;
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
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>X-07 slice 1: the config bundle export captures the editable configuration, signs it, bounds the
/// settings to the whitelist, and records itself in the audit trail.</summary>
public sealed class ConfigBundleServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 8, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), "im-config-tests", Guid.NewGuid().ToString("N"));
    private readonly RsaSealSigner _signer;

    public ConfigBundleServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _signer = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_workDir, "k.pem") }));
        using var db = NewContext();
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private ConfigBundleService NewService(AppDbContext db) =>
        new(NewFactory(), _signer, new AuditWriter(db, _hasher, _user, _clock), _user, _clock);

    private async Task SeedConfigAsync(AppDbContext db)
    {
        await DevDataSeeder.SeedDataElementsAsync(db, _clock);
        await DevDataSeeder.SeedDefaultReportProfilesAsync(db, _clock);
        await DevDataSeeder.SeedStarterTemplatesAsync(db, _clock);
        await DevDataSeeder.SeedDefaultStageGatesAsync(db, _clock);

        db.Roles.Add(new Role { Name = "IR Lead", Description = "Custom", IsSystem = false, PermissionsCsv = "ViewCases,EditCases", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
        db.RoleMappings.Add(new AdGroupRoleMapping { AdGroup = "CORP\\SOC", RoleName = "IR Lead", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
        db.AppSettings.Add(new AppSetting { Key = "Reporting:OrganizationName", Value = "Northwind Mutual", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
        db.AppSettings.Add(new AppSetting { Key = "Taxonomy:Classification:Label:Breach", Value = "Major Incident", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Export_captures_every_editable_section()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);

        var bundle = await NewService(db).BuildBundleAsync();

        bundle.DataElements.Should().HaveCount(13);
        bundle.ReportProfiles.Should().NotBeEmpty();
        bundle.CaseTemplates.Should().NotBeEmpty();
        bundle.StageGates.Should().NotBeEmpty();
        bundle.Roles.Should().Contain(r => r.Name == "IR Lead" && r.PermissionsCsv.Contains("EditCases"));
        bundle.RoleMappings.Should().ContainSingle(m => m.AdGroup == "CORP\\SOC" && m.RoleName == "IR Lead");
        // A template with steps round-trips its ordered steps.
        bundle.CaseTemplates.Should().Contain(t => t.Steps.Count > 0);
    }

    [Fact]
    public async Task Only_whitelisted_and_taxonomy_settings_are_exported()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        // A non-editable/security key that must never leave the server, added out-of-band.
        db.AppSettings.Add(new AppSetting { Key = "ConnectionStrings:Default", Value = "secret", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "x" });
        await db.SaveChangesAsync();

        var bundle = await NewService(db).BuildBundleAsync();

        bundle.Settings.Should().Contain(s => s.Key == "Reporting:OrganizationName" && s.Value == "Northwind Mutual");
        bundle.Settings.Should().Contain(s => s.Key == "Taxonomy:Classification:Label:Breach");
        bundle.Settings.Should().NotContain(s => s.Key == "ConnectionStrings:Default");
    }

    [Fact]
    public async Task The_signature_verifies_over_the_canonical_bundle()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);

        var export = await NewService(db).ExportAsync();

        export.Envelope.Format.Should().Be(ConfigBundleJson.FormatTag);
        export.Envelope.SchemaVersion.Should().Be(ConfigBundleJson.CurrentSchemaVersion);
        export.Envelope.PublicKeyPem.Should().Contain("PUBLIC KEY");
        _signer.Verify(ConfigBundleJson.Canonicalize(export.Envelope.Bundle), export.Envelope.Signature)
            .Should().BeTrue("the signature covers the canonical bundle payload");
        // Tampering with the payload breaks verification.
        var tampered = export.Envelope.Bundle with { Roles = Array.Empty<ConfigRole>() };
        _signer.Verify(ConfigBundleJson.Canonicalize(tampered), export.Envelope.Signature).Should().BeFalse();
    }

    [Fact]
    public async Task Canonicalization_is_deterministic()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);

        var a = ConfigBundleJson.Canonicalize(await svc.BuildBundleAsync());
        var b = ConfigBundleJson.Canonicalize(await svc.BuildBundleAsync());

        a.Should().Be(b);
    }

    [Fact]
    public async Task The_export_is_audited_and_the_chain_stays_valid()
    {
        await using (var db = NewContext())
        {
            await SeedConfigAsync(db);
            await NewService(db).ExportAsync();
        }

        await using var verify = NewContext();
        var chain = await verify.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        chain.Should().Contain(a => a.EntityType == "ConfigBundle" && a.Action == AuditAction.Export);
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Reimporting_an_unchanged_bundle_shows_no_changes()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var bundle = await svc.BuildBundleAsync();

        var diff = await svc.PreviewAsync(bundle);

        diff.HasChanges.Should().BeFalse();
        diff.Added.Should().Be(0);
        diff.Updated.Should().Be(0);

        // And applying it is a no-op.
        var result = await svc.ImportAsync(bundle);
        result.Changed.Should().Be(0);
    }

    [Fact]
    public async Task Import_adds_new_items_and_updates_changed_ones()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();

        // A brand-new custom data element, plus a relabelled report profile.
        var newElement = new ConfigDataElement("PassportNumber", "Passport number", 20, true, false, "US,NY");
        var profiles = live.ReportProfiles
            .Select(p => p == live.ReportProfiles[0] ? p with { Description = "Reworded for the IRP" } : p).ToList();
        var incoming = live with
        {
            DataElements = live.DataElements.Append(newElement).ToList(),
            ReportProfiles = profiles
        };

        var result = await svc.ImportAsync(incoming);

        result.Added.Should().BeGreaterThanOrEqualTo(1);
        result.Updated.Should().BeGreaterThanOrEqualTo(1);

        var after = await svc.BuildBundleAsync();
        var imported = after.DataElements.Single(e => e.Key == "PassportNumber");
        imported.Label.Should().Be("Passport number");
        imported.NotificationJurisdictions.Should().Be("US,NY");
        after.ReportProfiles[0].Description.Should().Be("Reworded for the IRP");
    }

    [Fact]
    public async Task A_parameterized_gate_check_round_trips_its_threshold(/* X-06(b) stage 2 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();

        // Tighten the Incident gate to require at least 3 entities (a parameterized check).
        var incidentGate = live.StageGates.Single(g => g.Trigger == nameof(StageGateTrigger.EscalateToIncident));
        var tightened = incidentGate with
        {
            CommentaryMinLength = 25,
            Requirements = new[]
            {
                new ConfigGateRequirement(0, nameof(GateRequirementKind.MachineCheck),
                    GateCheckKeys.AtLeastOneEntity, 3, "At least 3 entities / IOCs added", true)
            }
        };
        var incoming = live with
        {
            StageGates = live.StageGates.Select(g => g == incidentGate ? tightened : g).ToList()
        };

        await svc.ImportAsync(incoming);

        // The exported form carries the threshold...
        var after = await svc.BuildBundleAsync();
        var afterGate = after.StageGates.Single(g => g.Trigger == nameof(StageGateTrigger.EscalateToIncident));
        afterGate.CommentaryMinLength.Should().Be(25, "the commentary minimum round-trips too");
        var req = afterGate.Requirements.Single();
        req.Check.Should().Be(GateCheckKeys.AtLeastOneEntity);
        req.CheckParam.Should().Be(3);
        // ...and it is persisted on the requirement row.
        var stored = await db.StageGateRequirements.AsNoTracking()
            .FirstAsync(r => r.CheckKey == GateCheckKeys.AtLeastOneEntity);
        stored.CheckParam.Should().Be(3);
    }

    [Fact]
    public async Task Notification_rules_round_trip_through_export_and_import()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        await DevDataSeeder.SeedNotificationRulesAsync(db, _clock); // seeds NY, US at 72h
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();

        live.NotificationRules.Should().Contain(r => r.Code == "NY" && r.WindowHours == 72);

        // Retime NY and add a new jurisdiction rule.
        var incoming = live with
        {
            NotificationRules = live.NotificationRules
                .Select(r => r.Code == "NY" ? r with { WindowHours = 36 } : r)
                .Append(new ConfigNotificationRule("CA", "California", 720, true, false))
                .ToList()
        };

        var result = await svc.ImportAsync(incoming);
        result.Added.Should().BeGreaterThanOrEqualTo(1);
        result.Updated.Should().BeGreaterThanOrEqualTo(1);

        var after = await svc.BuildBundleAsync();
        after.NotificationRules.Single(r => r.Code == "CA").WindowHours.Should().Be(720);
        after.NotificationRules.Single(r => r.Code == "NY").WindowHours.Should().Be(36);
    }

    [Fact]
    public async Task A_pre_v2_bundle_without_notification_rules_still_imports()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();

        // Simulate a v1 bundle: the field is absent (null) rather than an empty list.
        var v1 = live with { NotificationRules = null! };
        var act = async () => await svc.ImportAsync(v1);
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task A_non_editable_setting_in_a_bundle_is_ignored_on_import()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();

        var incoming = live with
        {
            Settings = live.Settings
                .Append(new ConfigSetting("ConnectionStrings:Default", "hacked"))
                .Append(new ConfigSetting("Reporting:TeamName", "Cyber Defense")).ToList()
        };

        await svc.ImportAsync(incoming);

        var settings = await db.AppSettings.AsNoTracking().ToDictionaryAsync(s => s.Key, s => s.Value);
        settings.Should().ContainKey("Reporting:TeamName");
        settings.Should().NotContainKey("ConnectionStrings:Default");
    }

    [Fact]
    public async Task Import_is_non_destructive_leaving_unlisted_config_intact()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();

        // A bundle that omits every report profile must not delete the live ones.
        var incoming = live with { ReportProfiles = Array.Empty<ConfigReportProfile>() };
        await svc.ImportAsync(incoming);

        (await db.ReportProfiles.CountAsync()).Should().BeGreaterThan(0, "import never deletes");
    }

    [Fact]
    public async Task ParseAndVerify_accepts_a_real_export_and_rejects_tampering()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var export = await svc.ExportAsync();

        var (_, ok) = svc.ParseAndVerify(export.Content);
        ok.SignatureValid.Should().BeTrue();
        ok.SignedByThisInstance.Should().BeTrue();

        // Re-serialize the envelope with an altered payload but the original signature → verification fails.
        var envelope = System.Text.Json.JsonSerializer.Deserialize<ConfigBundleEnvelope>(
            System.Text.Encoding.UTF8.GetString(export.Content), ConfigBundleJson.File)!;
        var tampered = envelope with { Bundle = envelope.Bundle with { Roles = Array.Empty<ConfigRole>() } };
        var bytes = System.Text.Encoding.UTF8.GetBytes(
            System.Text.Json.JsonSerializer.Serialize(tampered, ConfigBundleJson.File));

        var (_, bad) = svc.ParseAndVerify(bytes);
        bad.SignatureValid.Should().BeFalse();
    }

    [Fact]
    public async Task A_foreign_file_is_rejected_with_a_clear_message()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var act = () => svc.ParseAndVerify(System.Text.Encoding.UTF8.GetBytes("{\"hello\":true}"));
        act.Should().Throw<InvalidOperationException>().WithMessage("*not a CaseBook configuration bundle*");
    }

    [Fact]
    public async Task The_import_is_audited_and_the_chain_stays_valid()
    {
        await using (var db = NewContext())
        {
            await SeedConfigAsync(db);
            var svc = NewService(db);
            var live = await svc.BuildBundleAsync();
            var incoming = live with
            {
                DataElements = live.DataElements.Append(new ConfigDataElement("GeneticData", "Genetic data", 21, true, false, null)).ToList()
            };
            await svc.ImportAsync(incoming);
        }

        await using var verify = NewContext();
        var chain = await verify.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        chain.Should().Contain(a => a.EntityType == "ConfigBundle" && a.Action == AuditAction.Update);
        chain.Should().Contain(a => a.EntityType == nameof(DataElement));
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    // ── S-18: import is an admin action whose access changes are streamed and take effect immediately ──

    private sealed class CountingDirectory : IRoleDirectory
    {
        public int Invalidations { get; private set; }
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) => new HashSet<Permission>();
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
        public void Invalidate() => Invalidations++;
    }

    private sealed class CountingReloader : ISettingsReloader
    {
        public int Reloads { get; private set; }
        public void Reload() => Reloads++;
    }

    [Fact]
    public async Task Only_an_administrator_can_import_or_export()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var bundle = await svc.BuildBundleAsync();
        _user.RoleSet = [AppRole.IncidentCommander];

        await svc.Invoking(s => s.ImportAsync(bundle)).Should()
            .ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
        await svc.Invoking(s => s.ExportAsync()).Should()
            .ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
    }

    [Fact]
    public async Task Imported_roles_mappings_and_settings_are_streamed_and_applied_immediately()
    {
        await using var db = NewContext();
        var sink = new CapturingSecurityEventSink();
        var directory = new CountingDirectory();
        var reloader = new CountingReloader();
        var svc = new ConfigBundleService(NewFactory(), _signer, new AuditWriter(db, _hasher, _user, _clock), _user, _clock,
            reloader, directory, sink);
        var live = await svc.BuildBundleAsync();
        var incoming = live with
        {
            Roles = live.Roles.Append(new ConfigRole("Shadow Admin", null, false, "ViewCases,Administer")).ToList(),
            RoleMappings = live.RoleMappings.Append(new ConfigRoleMapping("Some-Group", "Shadow Admin")).ToList(),
            Settings = live.Settings.Append(new ConfigSetting("Security:IdleTimeoutMinutes", "0")).ToList(),
        };

        await svc.ImportAsync(incoming);

        sink.Events.Select(e => e.Action).Should().Contain(["RoleImported", "AdGroupMappingImported", "SettingChanged"]);
        sink.Events.Should().Contain(e => e.Detail == "Some-Group → Shadow Admin");
        directory.Invalidations.Should().Be(1);
        reloader.Reloads.Should().Be(1);
    }

    [Fact]
    public async Task An_imported_setting_is_validated_like_the_settings_page()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var incoming = live with
        {
            Settings = live.Settings.Append(new ConfigSetting("Security:IdleTimeoutMinutes", "not a number")).ToList()
        };

        await svc.Invoking(s => s.ImportAsync(incoming)).Should().ThrowAsync<Exception>();
        (await db.AppSettings.AsNoTracking().AnyAsync(x => x.Key == "Security:IdleTimeoutMinutes")).Should().BeFalse();
    }

    // --- PROD-47: the Word template library travels in the bundle ---

    private readonly WordTemplateEngine _engine = new();
    private readonly List<SqliteConnection> _extraConnections = [];

    /// <summary>A separate instance: its own database and template store, sharing this test's user and clock.</summary>
    private (IAppDbContextFactory Factory, FileReportTemplateStore Store, ConfigBundleService Config) NewInstance(string name)
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        _extraConnections.Add(connection);
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        var store = new FileReportTemplateStore(
            Options.Create(new ReportTemplateOptions { RootPath = Path.Combine(_workDir, name, "templates") }),
            Options.Create(new ReportBrandingOptions()));
        var factory = new TestDbContextFactory(options);
        var config = new ConfigBundleService(factory, _signer, new AuditWriter(db, _hasher, _user, _clock), _user, _clock,
            templateEngine: _engine, templateStore: store);
        return (factory, store, config);
    }

    /// <summary>Seeds report profiles and a library template set as the first profile's default.</summary>
    private async Task<(Guid TemplateId, string Profile)> SeedTemplateDefaultAsync(IAppDbContextFactory factory, FileReportTemplateStore store)
    {
        using (var db = (AppDbContext)factory.CreateDbContext())
            await DevDataSeeder.SeedDefaultReportProfilesAsync(db, _clock);
        var templates = new IncidentManager.Application.Admin.ReportTemplateService(factory, _user, _clock, _engine, store);
        var upload = await templates.UploadAsync("Examiner pack", "examiner.docx", _engine.Starter());
        upload.Id.Should().NotBeNull();
        using var db2 = factory.CreateDbContext();
        var profile = await db2.ReportProfiles.OrderBy(p => p.SortOrder).FirstAsync();
        profile.TemplateId = upload.Id;
        await db2.SaveChangesAsync();
        return (upload.Id!.Value, profile.Name);
    }

    [Fact]
    public async Task Word_templates_and_profile_defaults_are_promoted_to_another_instance()
    {
        var source = NewInstance("source");
        var (sourceTemplateId, profileName) = await SeedTemplateDefaultAsync(source.Factory, source.Store);
        var export = await source.Config.ExportAsync();
        export.Envelope.SchemaVersion.Should().Be(3);
        var bundle = export.Envelope.Bundle;
        bundle.ReportTemplates.Should().ContainSingle(t => t.Name == "Examiner pack" && t.FileName == "examiner.docx");
        bundle.ReportProfiles.Single(p => p.Name == profileName).Template.Should().Be("Examiner pack");

        var target = NewInstance("target");
        var (parsed, verification) = target.Config.ParseAndVerify(export.Content);
        verification.SignatureValid.Should().BeTrue();
        (await target.Config.PreviewAsync(parsed.Bundle)).Items
            .Should().Contain(i => i.Section == "Word template" && i.Name == "Examiner pack" && i.Change == ConfigChange.Add);

        await target.Config.ImportAsync(parsed.Bundle);

        using (var db = target.Factory.CreateDbContext())
        {
            var t = await db.ReportTemplates.SingleAsync();
            t.Name.Should().Be("Examiner pack");
            t.Id.Should().NotBe(sourceTemplateId, "the target instance gives the template its own id");
            (await db.ReportProfiles.SingleAsync(p => p.Name == profileName)).TemplateId.Should().Be(t.Id);
            (await target.Store.GetAsync(t.Id)).Should().Equal(
                Convert.FromBase64String(bundle.ReportTemplates!.Single().ContentBase64), "the file is stored on the target");
        }

        // Re-importing the same bundle changes nothing.
        var again = await target.Config.ImportAsync(parsed.Bundle);
        again.Added.Should().Be(0);
        again.Updated.Should().Be(0);
    }

    [Fact]
    public async Task A_v2_bundle_still_verifies_and_leaves_the_template_library_alone()
    {
        var instance = NewInstance("v2");
        var (templateId, profileName) = await SeedTemplateDefaultAsync(instance.Factory, instance.Store);
        var live = await instance.Config.BuildBundleAsync();
        var v2 = live with { ReportTemplates = null, ReportProfiles = live.ReportProfiles.Select(p => p with { Template = null }).ToList() };

        // The new fields are left out of the canonical form when absent, so a v2 bundle's signature is unchanged.
        var canonical = ConfigBundleJson.Canonicalize(v2);
        canonical.Should().NotContain("reportTemplates").And.NotContain("\"template\"");

        await instance.Config.ImportAsync(v2);

        using var db = instance.Factory.CreateDbContext();
        (await db.ReportProfiles.SingleAsync(p => p.Name == profileName)).TemplateId.Should().Be(templateId,
            "an older bundle carries no defaults, so it doesn't clear one");
        (await db.ReportTemplates.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task A_bundle_template_that_fails_its_checks_stops_the_import_before_anything_is_written()
    {
        var source = NewInstance("bad-src");
        await SeedTemplateDefaultAsync(source.Factory, source.Store);
        var bundle = await source.Config.BuildBundleAsync();
        var template = bundle.ReportTemplates!.Single();

        var target = NewInstance("bad-dst");
        using (var db = (AppDbContext)target.Factory.CreateDbContext())
            await DevDataSeeder.SeedDefaultReportProfilesAsync(db, _clock);

        // Content that doesn't match its recorded hash.
        var altered = _engine.Starter();
        altered[^1] ^= 0xFF;
        var tampered = bundle with { ReportTemplates = [template with { ContentBase64 = Convert.ToBase64String(altered) }] };
        await target.Config.Invoking(c => c.PreviewAsync(tampered)).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*doesn't match its recorded SHA-256*");
        await target.Config.Invoking(c => c.ImportAsync(tampered)).Should().ThrowAsync<InvalidOperationException>();

        // A profile default that would end up archived.
        var archived = bundle with { ReportTemplates = [template with { IsActive = false }] };
        await target.Config.Invoking(c => c.ImportAsync(archived)).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*would be archived*");

        // A macro-enabled file isn't a template, whatever the bundle calls it.
        var macro = bundle with { ReportTemplates = [template with { FileName = "examiner.docm" }] };
        await target.Config.Invoking(c => c.ImportAsync(macro)).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*only .docx*");

        using var check = target.Factory.CreateDbContext();
        (await check.ReportTemplates.CountAsync()).Should().Be(0, "nothing is written when a template fails");
        (await check.ReportProfiles.CountAsync(p => p.TemplateId != null)).Should().Be(0);
    }

    public void Dispose()
    {
        _connection.Dispose();
        foreach (var c in _extraConnections) c.Dispose();
    }
}
