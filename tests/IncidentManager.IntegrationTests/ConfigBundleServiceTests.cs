using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Config;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
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

    public void Dispose() => _connection.Dispose();
}
