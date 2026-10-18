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
        _signer = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_workDir, "k.pem"), AllowKeyGeneration = true }));
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

    private ConfigBundleService NewService(AppDbContext db, ITrustedBundleKeys? trusted = null, CapturingSecurityEventSink? siem = null) =>
        new(NewFactory(), _signer, new AuditWriter(NewFactory(), _hasher, _user, _clock), _user, _clock, siem: siem, trustedKeys: trusted);

    private async Task SeedConfigAsync(AppDbContext db)
    {
        await DevDataSeeder.SeedDataElementsAsync(db, _clock);
        await DevDataSeeder.SeedCaseOutcomesAsync(db, _clock);
        await DevDataSeeder.SeedDefaultReportProfilesAsync(db, _clock);
        await DevDataSeeder.SeedStarterTemplatesAsync(db, _clock);
        await DevDataSeeder.SeedDefaultStageGatesAsync(db, _clock);

        db.Roles.Add(new Role { Name = "IR Lead", Description = "Custom", IsSystem = false, PermissionsCsv = "ViewCases,EditCases", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
        db.RoleMappings.Add(new AdGroupRoleMapping { AdGroup = "CORP\\SOC", RoleName = "IR Lead", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
        db.AppSettings.Add(new AppSetting { Key = "Reporting:OrganizationName", Value = "Northwind Mutual", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
        db.AppSettings.Add(new AppSetting { Key = "Taxonomy:Classification:Label:Breach", Value = "Major Incident", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
        await db.SaveChangesAsync();
    }

    /// <summary>Wraps a bundle in an envelope signed by this test's key, as an export would.</summary>
    private ConfigBundleEnvelope Signed(ConfigBundle bundle) => new(
        ConfigBundleJson.FormatTag, ConfigBundleJson.CurrentSchemaVersion, "test", _clock.UtcNow, _user.UserId, "test-host",
        _signer.Algorithm, _signer.KeyId, _signer.PublicKeyPem, _signer.Sign(ConfigBundleJson.Canonicalize(bundle)), bundle);

    [Fact]
    public async Task Export_captures_every_editable_section()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);

        var bundle = await NewService(db).BuildBundleAsync();

        bundle.DataElements.Should().HaveCount(13);
        bundle.CaseOutcomes.Should().HaveCount(6);   // HR-01
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
    public async Task The_export_name_uses_the_gregorian_calendar_on_any_culture(/* BUG-531 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);

        var was = System.Globalization.CultureInfo.CurrentCulture;
        ConfigExport export;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("th-TH");
            export = await NewService(db).ExportAsync();
        }
        finally { System.Globalization.CultureInfo.CurrentCulture = was; }

        export.FileName.Should().Be("casebook-config-20260908-120000.json", "th-TH would have named it 2569");
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

    // A bundle carries settings from another instance (or an older release); each must pass today's rules. The preview
    // rejects it with every problem listed, and applying it anyway writes nothing.
    [Fact]
    public async Task A_bundle_with_a_setting_outside_its_limits_is_rejected_at_preview_and_import()
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var bad = live with
        {
            Settings = live.Settings.Where(s => s.Key is not ("Sla:Containment:High" or "Sla:AtRiskThresholdPercent"))
                .Append(new ConfigSetting("Sla:Containment:High", "9000"))
                .Append(new ConfigSetting("Sla:AtRiskThresholdPercent", "101"))
                .Append(new ConfigSetting("Reporting:OrganizationName", "Renamed by the bundle")).ToList(),
        };

        var preview = () => svc.PreviewAsync(bad);
        (await preview.Should().ThrowAsync<ArgumentException>())
            .Which.Message.Should().Contain("Containment: High (hours)").And.Contain("At-risk threshold (%)");

        var import = () => svc.ImportAsync(Signed(bad));
        await import.Should().ThrowAsync<ArgumentException>();
        (await db.AppSettings.AsNoTracking().AnyAsync(s => s.Value == "Renamed by the bundle"))
            .Should().BeFalse("nothing from a rejected bundle is written");
    }

    // BUG-468: every email is sent from Email:From, so a bundle can't bring one that doesn't parse (or a blank one).
    [Theory]
    [InlineData("CaseBook")]
    [InlineData("")]
    public async Task A_bundle_with_a_sender_address_no_email_could_be_sent_from_is_rejected(string from)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var bad = live with
        {
            Settings = live.Settings.Where(s => s.Key != "Email:From").Append(new ConfigSetting("Email:From", from)).ToList(),
        };

        var preview = () => svc.PreviewAsync(bad);
        (await preview.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("From address");
        var import = () => svc.ImportAsync(Signed(bad));
        await import.Should().ThrowAsync<ArgumentException>();
        (await db.AppSettings.AsNoTracking().AnyAsync(s => s.Key == "Email:From")).Should().BeFalse();
    }

    [Fact]
    public async Task A_bundle_that_would_remove_the_last_administrator_access_is_refused()
    {
        // BUG-17: role edits and deletes keep the S-17 anti-lockout rule; an import overwriting a role didn't.
        await using var db = NewContext();
        await SeedConfigAsync(db);
        db.RoleMappings.RemoveRange(db.RoleMappings);
        var admins = new Role { Name = "SOC-Admins", IsSystem = false, UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "t" };
        admins.SetPermissions([Permission.Administer, Permission.ViewCases], "t", _clock.UtcNow);
        db.Roles.Add(admins);
        db.RoleMappings.Add(new AdGroupRoleMapping { AdGroup = "SOC-Admins-Group", RoleName = "SOC-Admins", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "t" });
        await db.SaveChangesAsync();

        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var incoming = live with
        {
            Roles = live.Roles.Select(r => r.Name == "SOC-Admins" ? r with { PermissionsCsv = "ViewCases" } : r).ToList()
        };

        var import = () => svc.ImportAsync(Signed(incoming));
        await import.Should().ThrowAsync<InvalidOperationException>().WithMessage("*last administrator access*");
        (await db.Roles.AsNoTracking().SingleAsync(r => r.Name == "SOC-Admins")).PermissionsCsv.Should().Contain("Administer");
    }

    [Fact]
    public async Task A_mapping_that_differs_only_in_case_is_not_added_again(/* BUG-136 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var existing = live.RoleMappings[0];
        var incoming = live with
        {
            RoleMappings = live.RoleMappings
                .Append(new ConfigRoleMapping(existing.AdGroup.ToLowerInvariant(), existing.RoleName.ToUpperInvariant()))
                .Append(new ConfigRoleMapping("corp\\new-group", "IR Lead"))
                .Append(new ConfigRoleMapping("CORP\\NEW-GROUP", "ir lead"))
                .ToList()
        };

        await svc.ImportAsync(Signed(incoming));

        (await db.RoleMappings.AsNoTracking().CountAsync()).Should().Be(live.RoleMappings.Count + 1,
            "SQL Server's unique index ignores case, so these are the same mappings");
    }

    [Fact]
    public async Task The_preview_counts_mappings_as_the_import_applies_them(/* BUG-568 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var existing = live.RoleMappings[0];
        // The same mapping in another case and with spaces round it, and one new mapping listed twice.
        var incoming = live with
        {
            RoleMappings = live.RoleMappings
                .Append(new ConfigRoleMapping(existing.AdGroup.ToLowerInvariant(), existing.RoleName.ToUpperInvariant()))
                .Append(new ConfigRoleMapping($"  {existing.AdGroup} ", $" {existing.RoleName}  "))
                .Append(new ConfigRoleMapping("corp\\new-group", "IR Lead"))
                .Append(new ConfigRoleMapping(" CORP\\NEW-GROUP", "ir lead "))
                .ToList()
        };

        var diff = await svc.PreviewAsync(incoming);
        var mappings = diff.Items.Where(i => i.Section == "AD mapping").ToList();
        mappings.Should().ContainSingle(i => i.Change == ConfigChange.Add);
        mappings.Should().NotContain(i => i.Change == ConfigChange.Update);
        var result = await svc.ImportAsync(Signed(incoming));
        (result.Added, result.Updated).Should().Be((diff.Added, diff.Updated)).And.Be((1, 0));
    }

    [Fact]
    public async Task A_bundle_signed_with_an_unknown_key_imports_only_with_its_key_id_typed()
    {
        // BUG-19: the signature is checked against the key in the bundle, so anyone can re-sign an edited bundle with
        // their own key and it verifies. It proves the bundle is unchanged since signing, not who made it. CAP-16: the
        // admin names the key by typing its id; a wrong id, the id the file states for another key, or none is refused.
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var siem = new CapturingSecurityEventSink();
        var svc = NewService(db, siem: siem);
        var live = await svc.BuildBundleAsync();
        var incoming = live with { DataElements = live.DataElements.Append(new ConfigDataElement("Passport", "Passport", 20, true, false, "US")).ToList() };
        var other = OtherSigner("other.pem");
        var envelope = SignedBy(other, incoming);

        var (_, verification) = svc.ParseAndVerify(Bytes(envelope));
        verification.Trust.Should().Be(ConfigBundleTrust.Unknown);
        verification.CarriedKeyId.Should().Be(other.KeyId, "the id is computed from the carried key as a seal key's is");

        await svc.Invoking(s => s.ImportAsync(envelope)).Should().ThrowAsync<InvalidOperationException>().WithMessage("*neither holds nor trusts*");
        await svc.Invoking(s => s.ImportAsync(envelope, confirmedKeyId: _signer.KeyId)).Should().ThrowAsync<InvalidOperationException>();
        (await db.DataElements.AsNoTracking().AnyAsync(e => e.Key == "Passport")).Should().BeFalse();

        await svc.ImportAsync(envelope, confirmedKeyId: "  " + other.KeyId.ToUpperInvariant() + " ");
        (await db.DataElements.AsNoTracking().AnyAsync(e => e.Key == "Passport")).Should().BeTrue();
        (await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).LastAsync(a => a.EntityType == "ConfigBundle"))
            .Summary.Should().Contain(other.KeyId).And.Contain("typed to confirm");
        siem.Events.Should().Contain(e => e.EventId == IncidentManager.Application.Security.SecurityEventIds.ReferenceDataChanged
            && (e.Detail ?? "").Contains(other.KeyId));
    }

    [Fact]
    public async Task A_bundle_signed_with_a_trusted_key_imports_without_a_typed_id_and_names_the_key(/* CAP-16 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var other = OtherSigner("test-server.pem");
        var folder = Path.Combine(_workDir, "trusted");
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "test-server.pem"), other.PublicKeyPem);
        var trusted = new TrustedBundleKeys(folder);
        trusted.Keys.Should().ContainSingle().Which.KeyId.Should().Be(other.KeyId);
        var siem = new CapturingSecurityEventSink();
        var svc = NewService(db, trusted, siem);
        svc.TrustedKeys.Should().ContainSingle(k => k.FileName == "test-server.pem");

        var live = await svc.BuildBundleAsync();
        var incoming = live with { DataElements = live.DataElements.Append(new ConfigDataElement("Passport", "Passport", 20, true, false, "US")).ToList() };
        var envelope = SignedBy(other, incoming);
        var (_, verification) = svc.ParseAndVerify(Bytes(envelope));
        verification.Trust.Should().Be(ConfigBundleTrust.TrustedKey);
        verification.TrustedKeyFile.Should().Be("test-server.pem");

        await svc.ImportAsync(envelope);
        (await db.DataElements.AsNoTracking().AnyAsync(e => e.Key == "Passport")).Should().BeTrue();
        (await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).LastAsync(a => a.EntityType == "ConfigBundle"))
            .Summary.Should().Contain($"trusted key {other.KeyId} (test-server.pem)");
        siem.Events.Should().Contain(e => e.EventId == IncidentManager.Application.Security.SecurityEventIds.ReferenceDataChanged
            && (e.Detail ?? "").Contains($"trusted key {other.KeyId}"));
    }

    [Fact]
    public async Task Re_importing_this_servers_own_bundle_still_needs_nothing_and_says_whose_key(/* CAP-16, ADR 0007/0016 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db, new TrustedBundleKeys(Path.Combine(_workDir, "no-such-folder")));
        var live = await svc.BuildBundleAsync();
        var incoming = live with { DataElements = live.DataElements.Append(new ConfigDataElement("Passport", "Passport", 20, true, false, "US")).ToList() };

        svc.ParseAndVerify(Bytes(Signed(incoming))).Verification.Trust.Should().Be(ConfigBundleTrust.ThisServer);
        await svc.ImportAsync(Signed(incoming));
        (await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).LastAsync(a => a.EntityType == "ConfigBundle"))
            .Summary.Should().Contain($"this server's key {_signer.KeyId}");
        svc.TrustedKeys.Should().BeEmpty("a folder that isn't there holds no keys");
    }

    [Fact]
    public async Task A_bundle_that_borrows_a_trusted_keys_id_is_refused(/* CAP-16, as BUG-221 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var source = OtherSigner("source.pem");
        var folder = Path.Combine(_workDir, "trusted-borrowed");
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "source.pem"), source.PublicKeyPem);
        var svc = NewService(db, new TrustedBundleKeys(folder));
        var forger = OtherSigner("forger2.pem");
        var live = await svc.BuildBundleAsync();
        var signed = SignedBy(forger, live) with { KeyId = source.KeyId };

        svc.Invoking(s => s.ParseAndVerify(Bytes(signed))).Should().Throw<InvalidOperationException>().WithMessage("*trusted key*different one*");
        await svc.Invoking(s => s.ImportAsync(signed, confirmedKeyId: forger.KeyId)).Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public void A_file_in_the_trusted_keys_folder_that_isnt_a_key_stops_startup(/* CAP-16, as F-24 */)
    {
        var folder = Path.Combine(_workDir, "trusted-bad");
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "typo.pem"), "not a key");
        var load = () => new TrustedBundleKeys(folder);
        load.Should().Throw<InvalidOperationException>().WithMessage("*typo.pem*Config:TrustedBundleKeys*");
        new TrustedBundleKeys((string?)null).Keys.Should().BeEmpty();
    }

    private RsaSealSigner OtherSigner(string file) =>
        new(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_workDir, file), AllowKeyGeneration = true }));

    private ConfigBundleEnvelope SignedBy(RsaSealSigner signer, ConfigBundle bundle) => new(
        ConfigBundleJson.FormatTag, ConfigBundleJson.CurrentSchemaVersion, "test", _clock.UtcNow, "someone", "elsewhere",
        signer.Algorithm, signer.KeyId, signer.PublicKeyPem, signer.Sign(ConfigBundleJson.Canonicalize(bundle)), bundle);

    private static byte[] Bytes(ConfigBundleEnvelope envelope) =>
        System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(envelope, ConfigBundleJson.File));

    [Fact]
    public async Task A_bundle_that_borrows_this_servers_key_id_is_refused(/* BUG-221 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var incoming = live with { DataElements = live.DataElements.Append(new ConfigDataElement("Passport", "Passport", 20, true, false, "US")).ToList() };
        var other = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_workDir, "forger.pem"), AllowKeyGeneration = true }));
        // Signed with another key, but stating this server's (public) key id.
        var forged = new ConfigBundleEnvelope(ConfigBundleJson.FormatTag, ConfigBundleJson.CurrentSchemaVersion, "test", _clock.UtcNow,
            "someone", "elsewhere", other.Algorithm, _signer.KeyId, other.PublicKeyPem, other.Sign(ConfigBundleJson.Canonicalize(incoming)), incoming);
        var bytes = System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(forged, ConfigBundleJson.File));

        var parse = () => svc.ParseAndVerify(bytes);
        parse.Should().Throw<InvalidOperationException>().WithMessage("*carries is a different one*");
        var import = () => svc.ImportAsync(forged, confirmedKeyId: ConfigBundleService.CarriedKeyId(other.PublicKeyPem));
        await import.Should().ThrowAsync<InvalidOperationException>().WithMessage("*carries is a different one*");
        (await db.DataElements.AsNoTracking().AnyAsync(e => e.Key == "Passport")).Should().BeFalse();
    }

    [Fact]
    public async Task The_preview_leaves_out_a_gate_for_a_transition_this_version_lacks(/* REV-54 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var future = live.StageGates[0] with { Name = "Future gate", Trigger = "EscalateToSomethingNew", IsActive = false };

        var diff = await svc.PreviewAsync(live with { StageGates = live.StageGates.Append(future).ToList() });

        diff.Items.Should().NotContain(i => i.Name == "Future gate");
        diff.Warnings.Should().Contain(w => w.Contains("Future gate") && w.Contains("won't be imported"));
    }

    [Fact]
    public async Task A_bundle_item_the_admin_pages_would_refuse_is_refused(/* REV-49 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();

        var zeroWindow = live with { NotificationRules = [new ConfigNotificationRule("ny", "New York", 0, true, false)] };
        await ((Func<Task>)(() => svc.PreviewAsync(zeroWindow))).Should().ThrowAsync<ArgumentException>().WithMessage("*window must be 1 to*");
        var noOutcomes = live with { CaseOutcomes = (live.CaseOutcomes ?? []).Select(o => o with { IsActive = false }).ToList() };
        if (noOutcomes.CaseOutcomes!.Count > 0)
            await ((Func<Task>)(() => svc.ImportAsync(Signed(noOutcomes)))).Should().ThrowAsync<ArgumentException>()
                .WithMessage("*no case outcome active*");
        // BUG-353: a key longer than its column is named before anything is written.
        var longKey = live with { DataElements = [.. live.DataElements, new ConfigDataElement(new string('K', 101), "Long one", 99, true, false, null)] };
        await ((Func<Task>)(() => svc.PreviewAsync(longKey))).Should().ThrowAsync<ArgumentException>()
            .WithMessage("*\"Long one\" has a key longer than 100 characters*");
        await ((Func<Task>)(() => svc.ImportAsync(Signed(longKey)))).Should().ThrowAsync<ArgumentException>()
            .WithMessage("*key longer than 100*");

        await svc.ImportAsync(Signed(live with { NotificationRules = [new ConfigNotificationRule("ny", "New York", 72, true, false)] }));
        (await db.NotificationRules.AsNoTracking().Select(r => r.Code).ToListAsync()).Should().Contain("NY", "codes are upper-case, as the page saves them");
    }

    [Fact]
    public async Task A_rule_code_holding_a_separator_is_refused_and_a_live_one_is_named(/* BUG-558 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();

        var combined = live with { NotificationRules = [new ConfigNotificationRule("NY,CA", "New York and California", 72, true, false)] };
        await ((Func<Task>)(() => svc.PreviewAsync(combined))).Should().ThrowAsync<ArgumentException>().WithMessage("*one jurisdiction*\"NY,CA\"*");
        await ((Func<Task>)(() => svc.ImportAsync(Signed(combined)))).Should().ThrowAsync<ArgumentException>().WithMessage("*one jurisdiction*");
        (await db.NotificationRules.AnyAsync(r => r.Code == "NY,CA")).Should().BeFalse();

        // One saved here before the check is named by the preview, not rewritten.
        db.NotificationRules.Add(new IncidentManager.Domain.Entities.NotificationRule
            { Code = "TX;FL", Label = "Old", WindowHours = 72, IsActive = true, CreatedBy = "admin", CreatedAtUtc = _clock.UtcNow });
        await db.SaveChangesAsync();
        var diff = await svc.PreviewAsync(live);
        diff.Warnings!.Should().ContainSingle(w => w.Contains("\"TX;FL\"") && w.Contains("never applies"));
        (await db.NotificationRules.AsNoTracking().CountAsync(r => r.Code == "TX;FL")).Should().Be(1);
    }

    [Fact]
    public async Task A_bundle_gets_the_admin_pages_rules_for_roles_mappings_gates_and_taxonomy(/* WF-45 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();

        var unusable = live with { RoleMappings = [.. live.RoleMappings, new ConfigRoleMapping("SOC-Ghosts", "NoSuchRole"), new ConfigRoleMapping("  ", "Analyst")] };
        (await svc.PreviewAsync(unusable)).Warnings.Should().Contain(w => w.Contains("2 AD mappings won't be imported"));
        await svc.ImportAsync(Signed(unusable));
        (await db.RoleMappings.AsNoTracking().ToListAsync()).Should().NotContain(m => m.AdGroup == "SOC-Ghosts" || m.AdGroup.Trim() == "");

        var kind = IncidentManager.Application.Admin.TaxonomyCatalog.Kinds.First(k => k.AllowVisibilityOrder);
        var hideAll = live with { Settings = [.. live.Settings, .. kind.Members.Select(m =>
            new ConfigSetting(IncidentManager.Application.Admin.TaxonomyCatalog.HiddenKey(kind.Id, m.Value), "true"))] };
        await ((Func<Task>)(() => svc.PreviewAsync(hideAll))).Should().ThrowAsync<ArgumentException>().WithMessage("*at least one must stay visible*");

        var template = live.StageGates[0];
        var zeroGate = new ConfigStageGate(template.Trigger, false, "Imported evidence gate", null,
            [new ConfigGateRequirement(0, "MachineCheck", GateCheckKeys.AtLeastOneEvidence, 0, "Evidence attached", true)], -5);
        var numbered = live with
        {
            Roles = [.. live.Roles, new ConfigRole("Numbered", null, false, "ViewCases,7,-1")],
            RoleMappings = [.. live.RoleMappings, new ConfigRoleMapping("SOC-Numbered", "numbered")],
            StageGates = [.. live.StageGates, zeroGate],
        };
        await svc.ImportAsync(Signed(numbered));

        var role = await db.Roles.AsNoTracking().SingleAsync(r => r.Name == "Numbered");
        role.PermissionsCsv.Should().Be("ViewCases", "a number isn't a permission name");
        (await db.RoleMappings.AsNoTracking().SingleAsync(m => m.AdGroup == "SOC-Numbered")).RoleName.Should().Be("Numbered");
        var gate = await db.StageGates.AsNoTracking().Include(g => g.Requirements).SingleAsync(g => g.Name == "Imported evidence gate");
        gate.Requirements.Single().CheckParam.Should().Be(1, "the threshold is clamped to the check's floor");
        gate.CommentaryMinLength.Should().Be(0);
    }

    [Fact]
    public async Task An_order_saved_before_an_option_was_added_still_imports(/* BUG-424 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var kind = IncidentManager.Application.Admin.TaxonomyCatalog.Kinds.Single(k => k.Id == "EntityType");
        var orderKey = IncidentManager.Application.Admin.TaxonomyCatalog.OrderKey(kind.Id);
        ConfigBundle WithOrder(IEnumerable<string> members) => live with
        {
            Settings = [.. live.Settings.Where(s => s.Key != orderKey), new ConfigSetting(orderKey, string.Join(",", members))]
        };

        // Customised before the Command line type existed: every other member, reversed.
        var older = kind.Members.Select(m => m.Value).Where(v => v != nameof(EntityType.CommandLine)).Reverse().ToList();
        older.Should().HaveCount(kind.Members.Count - 1);
        await svc.ImportAsync(Signed(WithOrder(older)));
        (await db.AppSettings.AsNoTracking().SingleAsync(s => s.Key == orderKey)).Value.Should().Be(string.Join(",", older));

        // Still refused: a member named twice, or one the kind doesn't have.
        await ((Func<Task>)(() => svc.PreviewAsync(WithOrder([.. older, older[0]])))).Should().ThrowAsync<ArgumentException>()
            .WithMessage("*each at most once*");
        await ((Func<Task>)(() => svc.PreviewAsync(WithOrder([.. older, "Spaceship"])))).Should().ThrowAsync<ArgumentException>()
            .WithMessage("*only its own options*");
    }

    [Fact]
    public async Task A_bundle_that_leaves_two_active_gates_on_one_transition_is_refused(/* BUG-237 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var existing = live.StageGates.First(g => g.IsActive);
        var second = existing with { Name = "Second " + existing.Name };
        var clash = live with { StageGates = live.StageGates.Append(second).ToList() };

        var preview = () => svc.PreviewAsync(clash);
        await preview.Should().ThrowAsync<ArgumentException>().WithMessage("*2 active gates*");
        var import = () => svc.ImportAsync(Signed(clash));
        await import.Should().ThrowAsync<ArgumentException>().WithMessage("*2 active gates*");
        (await db.StageGates.AsNoTracking().AnyAsync(g => g.Name == second.Name)).Should().BeFalse();

        // Deactivating the live one in the same bundle is fine: the transition still has one.
        var swap = live with { StageGates = live.StageGates.Select(g => g == existing ? g with { IsActive = false } : g).Append(second).ToList() };
        await svc.ImportAsync(Signed(swap));
        (await db.StageGates.AsNoTracking().CountAsync(g => g.IsActive && g.Name.EndsWith(existing.Name))).Should().Be(1);
    }

    [Fact]
    public async Task Two_live_gates_with_one_name_stop_an_import_with_their_name_not_a_raw_error(/* BUG-538 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var bundle = await svc.BuildBundleAsync();
        var gate = bundle.StageGates.First(g => g.IsActive);
        // Stored before the name check ran under GuardGate (two saves at once).
        db.StageGates.Add(new StageGate { Trigger = Enum.Parse<StageGateTrigger>(gate.Trigger), Name = gate.Name.ToUpperInvariant(),
            IsActive = false, CreatedBy = "admin2", CreatedAtUtc = _clock.UtcNow });
        await db.SaveChangesAsync();

        (await svc.Invoking(s => s.PreviewAsync(bundle)).Should().ThrowAsync<ArgumentException>())
            .Which.Message.Should().Contain($"More than one stage gate on this server is named \"{gate.Name}\"").And.Contain("Rename one");
        (await svc.Invoking(s => s.ImportAsync(Signed(bundle))).Should().ThrowAsync<ArgumentException>())
            .Which.Message.Should().Contain("More than one stage gate on this server is named");

        // A bundle that doesn't carry that gate leaves both rows alone, so the duplicate doesn't stop it.
        var without = bundle with { StageGates = bundle.StageGates.Where(g => g != gate).ToList() };
        await svc.Invoking(s => s.ImportAsync(Signed(without))).Should().NotThrowAsync();
        (await db.StageGates.AsNoTracking().Select(g => g.Name).ToListAsync())
            .Count(n => n.Equals(gate.Name, StringComparison.OrdinalIgnoreCase)).Should().Be(2);
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
        var result = await svc.ImportAsync(Signed(bundle));
        result.Changed.Should().Be(0);
    }

    [Fact]
    public async Task Items_named_differently_only_in_case_update_the_live_one(/* BUG-200 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var profile = live.ReportProfiles[0];
        var incoming = live with
        {
            ReportProfiles = live.ReportProfiles.Select(p => p == profile ? p with { Name = p.Name.ToUpperInvariant() } : p).ToList()
        };

        var diff = await svc.PreviewAsync(incoming);
        var upper = profile.Name.ToUpperInvariant();
        diff.Items.Single(i => i.Section == "Report profile" && i.Name == upper)
            .Change.Should().Be(ConfigChange.Update, "it's the same profile: SQL Server's unique index ignores case");
        await svc.ImportAsync(Signed(incoming));
        (await db.ReportProfiles.AsNoTracking().CountAsync()).Should().Be(live.ReportProfiles.Count);

        var twice = live with { ReportProfiles = live.ReportProfiles.Append(profile with { Name = profile.Name.ToLowerInvariant() }).ToList() };
        await svc.Invoking(s => s.PreviewAsync(twice)).Should().ThrowAsync<ArgumentException>().WithMessage("*differ only in case*");
    }

    [Fact]
    public async Task A_name_that_differs_only_in_case_is_taken_once_and_then_unchanged(/* BUG-240 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var gate = live.StageGates[0];
        var upper = gate.Name.ToUpperInvariant();
        var recased = live with { StageGates = live.StageGates.Select(g => g == gate ? g with { Name = upper } : g).ToList() };

        (await svc.ImportAsync(Signed(recased))).Updated.Should().Be(1);
        (await db.StageGates.AsNoTracking().CountAsync(g => g.Name == upper)).Should().Be(1);
        (await svc.ImportAsync(Signed(recased))).Updated.Should().Be(0, "the second import of the same bundle changes nothing");
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

        var result = await svc.ImportAsync(Signed(incoming));

        result.Added.Should().BeGreaterThanOrEqualTo(1);
        result.Updated.Should().BeGreaterThanOrEqualTo(1);

        var after = await svc.BuildBundleAsync();
        var imported = after.DataElements.Single(e => e.Key == "PassportNumber");
        imported.Label.Should().Be("Passport number");
        imported.NotificationJurisdictions.Should().Be("US,NY");
        after.ReportProfiles[0].Description.Should().Be("Reworded for the IRP");
    }

    [Fact]
    public async Task Case_outcomes_travel_by_key_and_an_older_bundle_leaves_them_alone()
    {
        // HR-01: a custom outcome and a relabel are promoted; a pre-v4 bundle (no outcomes) changes nothing.
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var incoming = live with
        {
            CaseOutcomes = live.CaseOutcomes!.Select(o => o.Key == "Inconclusive" ? o with { Label = "Undetermined" } : o)
                .Append(new ConfigCaseOutcome("InsiderMisuse", "Insider misuse", "A person with access misused it.", 7, true, false)).ToList()
        };

        await svc.ImportAsync(Signed(incoming));
        var after = await svc.BuildBundleAsync();
        after.CaseOutcomes!.Single(o => o.Key == "InsiderMisuse").Label.Should().Be("Insider misuse");
        after.CaseOutcomes!.Single(o => o.Key == "Inconclusive").Label.Should().Be("Undetermined");

        await svc.ImportAsync(Signed(after with { CaseOutcomes = null }));
        (await svc.BuildBundleAsync()).CaseOutcomes.Should().HaveCount(7);
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

        await svc.ImportAsync(Signed(incoming));

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

        var result = await svc.ImportAsync(Signed(incoming));
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
        var act = async () => await svc.ImportAsync(Signed(v1));
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

        await svc.ImportAsync(Signed(incoming));

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
        await svc.ImportAsync(Signed(incoming));

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
    public async Task A_bundle_exported_before_step_kinds_still_verifies_and_tampering_still_fails(/* BUG-335 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var bundle = await svc.BuildBundleAsync();
        bundle.CaseTemplates.SelectMany(t => t.Steps).Should().NotBeEmpty().And.OnlyContain(s => s.Kind == TaskKind.General);

        // What v1.0.x / v1.1.x signed and wrote: the same payload, with no "kind" on any step (the field didn't exist).
        var current = ConfigBundleJson.Canonicalize(bundle);
        current.Should().Contain(",\"kind\":0}");
        var legacyCanonical = current.Replace(",\"kind\":0}", "}");
        byte[] LegacyFile(ConfigBundle b, string signedOver)
        {
            var env = new ConfigBundleEnvelope(ConfigBundleJson.FormatTag, 2, "1.1.0", _clock.UtcNow, "admin", "old-host",
                _signer.Algorithm, _signer.KeyId, _signer.PublicKeyPem, _signer.Sign(signedOver), b);
            var node = System.Text.Json.Nodes.JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(env, ConfigBundleJson.File))!;
            foreach (var t in node["bundle"]!["caseTemplates"]!.AsArray())
                foreach (var s in t!["steps"]!.AsArray())
                    s!.AsObject().Remove("kind").Should().BeTrue();
            return System.Text.Encoding.UTF8.GetBytes(node.ToJsonString(ConfigBundleJson.File));
        }

        var (parsed, ok) = svc.ParseAndVerify(LegacyFile(bundle, legacyCanonical));
        ok.SignatureValid.Should().BeTrue("the payload is exactly what v1.1 signed");
        parsed.Bundle.CaseTemplates.SelectMany(t => t.Steps).Should().OnlyContain(s => s.Kind == TaskKind.General);
        await svc.ImportAsync(parsed);   // the service's own check agrees

        // Altered after export: a step retitled, or a step given a kind, no longer verifies.
        var template = bundle.CaseTemplates.First(t => t.Steps.Count > 0);
        ConfigBundle WithStep(ConfigTemplateStep step) => bundle with
        {
            CaseTemplates = bundle.CaseTemplates.Select(t => t == template
                ? t with { Steps = t.Steps.Skip(1).Prepend(step).ToList() } : t).ToList()
        };
        var retitled = WithStep(template.Steps[0] with { Title = "Exfiltrate the evidence" });
        svc.ParseAndVerify(LegacyFile(retitled, legacyCanonical)).Verification.SignatureValid.Should().BeFalse();

        var kinded = svc.ParseAndVerify(LegacyFile(bundle, legacyCanonical)).Envelope;
        var withKind = kinded with { Bundle = WithStep(template.Steps[0] with { Kind = TaskKind.Contain }) };
        await svc.Invoking(s => s.ImportAsync(withKind)).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*signature doesn't verify*");
    }

    [Fact]
    public async Task Import_itself_refuses_a_bundle_whose_signature_does_not_verify()
    {
        // The page disables Apply for a bad signature; the service must refuse too, for any other caller.
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var signed = Signed(live);
        var tampered = signed with
        {
            Bundle = live with { Roles = live.Roles.Append(new ConfigRole("Shadow Admin", null, false, "ViewCases,Administer")).ToList() }
        };
        var unsigned = signed with { Signature = "" };

        await svc.Invoking(s => s.ImportAsync(tampered)).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*signature doesn't verify*");
        await svc.Invoking(s => s.ImportAsync(unsigned)).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*signature doesn't verify*");
        (await db.Roles.AsNoTracking().AnyAsync(r => r.Name == "Shadow Admin")).Should().BeFalse("nothing is imported");
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
            await svc.ImportAsync(Signed(incoming));
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

        await svc.Invoking(s => s.ImportAsync(Signed(bundle))).Should()
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
        var svc = new ConfigBundleService(NewFactory(), _signer, new AuditWriter(NewFactory(), _hasher, _user, _clock), _user, _clock,
            reloader, directory, sink);
        var live = await svc.BuildBundleAsync();
        var incoming = live with
        {
            Roles = live.Roles.Append(new ConfigRole("Shadow Admin", null, false, "ViewCases,Administer")).ToList(),
            RoleMappings = live.RoleMappings.Append(new ConfigRoleMapping("Some-Group", "Shadow Admin")).ToList(),
            Settings = live.Settings.Append(new ConfigSetting("Security:IdleTimeoutMinutes", "0")).ToList(),
        };

        await svc.ImportAsync(Signed(incoming));

        sink.Events.Select(e => e.Action).Should().Contain(["RoleImported", "AdGroupMappingImported", "SettingChanged"]);
        sink.Events.Should().Contain(e => e.Detail == "Some-Group → Shadow Admin");
        // CAP-06: and one 5405 for the reference data it replaced, with its counts and signing key (not one per row).
        sink.Events.Should().ContainSingle(e => e.EventId == IncidentManager.Application.Security.SecurityEventIds.ReferenceDataChanged)
            .Which.Should().Match<IncidentManager.Application.Security.SecurityEvent>(e =>
                e.TargetType == IncidentManager.Application.Security.ReferenceDataKinds.ConfigurationBundle
                && e.Detail!.EndsWith($"; signed with this server's key {_signer.KeyId}"));
        directory.Invalidations.Should().Be(1);
        reloader.Reloads.Should().Be(1);
    }

    private sealed class FailingAudit : IAuditWriter
    {
        public Task RecordAsync(AuditAction action, string entityType, string? entityId, string? caseNumber, string summary,
            CancellationToken ct = default) => throw new InvalidOperationException("audit store unavailable");
    }

    [Fact]
    public async Task A_step_failing_after_the_import_is_saved_still_applies_and_streams_it(/* BUG-390 */)
    {
        await using var db = NewContext();
        var sink = new CapturingSecurityEventSink();
        var directory = new CountingDirectory();
        var reloader = new CountingReloader();
        var svc = new ConfigBundleService(NewFactory(), _signer, new FailingAudit(), _user, _clock, reloader, directory, sink);
        var live = await svc.BuildBundleAsync();
        var incoming = live with
        {
            Roles = live.Roles.Append(new ConfigRole("Shadow Admin", null, false, "ViewCases,Administer")).ToList(),
            Settings = live.Settings.Append(new ConfigSetting("Security:IdleTimeoutMinutes", "0")).ToList(),
        };

        (await svc.Invoking(s => s.ImportAsync(Signed(incoming))).Should().ThrowAsync<InvalidOperationException>())
            .WithMessage("The bundle was imported and is in effect*");

        (await db.Roles.AsNoTracking().AnyAsync(r => r.Name == "Shadow Admin")).Should().BeTrue("the import was saved");
        sink.Events.Select(e => e.Action).Should().Contain(["RoleImported", "SettingChanged"]);
        directory.Invalidations.Should().Be(1);
        reloader.Reloads.Should().Be(1);
    }

    [Fact]
    public async Task A_data_element_whose_jurisdictions_use_a_semicolon_imports_with_commas(/* BUG-404 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var first = live.DataElements[0];
        var incoming = live with
        {
            DataElements = live.DataElements.Select(d => d == first ? d with { NotificationJurisdictions = "NY;CA" } : d).ToList()
        };

        // An export from before BUG-404 stored ";" as given; refusing it would block restoring that server's own bundle.
        await svc.Invoking(s => s.PreviewAsync(incoming)).Should().NotThrowAsync();
        await svc.ImportAsync(Signed(incoming));
        (await db.DataElements.AsNoTracking().SingleAsync(e => e.Key == first.Key)).NotificationJurisdictions
            .Should().Be("NY,CA");
    }

    [Fact]
    public async Task An_import_waits_for_a_template_file_being_written(/* BUG-403 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var bundle = await svc.BuildBundleAsync();
        Task import;
        using (await IncidentManager.Application.Admin.ReportTemplateService.EnterFileGateAsync())
        {
            import = svc.ImportAsync(Signed(bundle));
            await Task.Delay(200);
            import.IsCompleted.Should().BeFalse("an upload or replace holds the template file gate");
        }
        await import;
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

        await svc.Invoking(s => s.ImportAsync(Signed(incoming))).Should().ThrowAsync<Exception>();
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
        var config = new ConfigBundleService(factory, _signer, new AuditWriter(factory, _hasher, _user, _clock), _user, _clock,
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

    [WindowsFact]
    public async Task A_template_file_that_cant_be_put_in_place_doesnt_stop_the_rest_of_the_import(/* BUG-238 */)
    {
        var source = NewInstance("src-ro");
        var (sourceTemplateId, _) = await SeedTemplateDefaultAsync(source.Factory, source.Store);
        await new IncidentManager.Application.Admin.ReportTemplateService(source.Factory, _user, _clock, _engine, source.Store)
            .ReplaceFileAsync(sourceTemplateId, "examiner-v2.docx", _engine.LessonsStarter());
        var target = NewInstance("dst-ro");
        var (targetTemplateId, _) = await SeedTemplateDefaultAsync(target.Factory, target.Store);
        string before;
        using (var db = target.Factory.CreateDbContext()) before = (await db.ReportTemplates.SingleAsync()).Sha256;

        var bundle = (await source.Config.ExportAsync()).Envelope.Bundle;
        bundle = bundle with { DataElements = bundle.DataElements.Append(new ConfigDataElement("Passport", "Passport", 20, true, false, "US")).ToList() };
        var live = Directory.EnumerateFiles(Path.Combine(_workDir, "dst-ro", "templates"), "*.docx").Single();
        File.SetAttributes(live, FileAttributes.ReadOnly);
        try
        {
            var result = await target.Config.ImportAsync(Signed(bundle));
            result.TemplatesNotPlaced.Should().Equal("Examiner pack");
            result.TemplatesNotPlacedMessage.Should().Contain("couldn't be put in place");
            using var db = target.Factory.CreateDbContext();
            (await db.ReportTemplates.SingleAsync()).Sha256.Should().Be(before, "the row still describes the file that's there");
            (await db.DataElements.AnyAsync(e => e.Key == "Passport")).Should().BeTrue("the rest of the bundle was imported");
            (await db.AuditLog.OrderBy(a => a.Sequence).LastAsync(a => a.EntityType == "ConfigBundle")).Summary
                .Should().Contain("couldn't be put in place");
            Directory.EnumerateFiles(Path.Combine(_workDir, "dst-ro", "templates"), "*.staged").Should().BeEmpty();
        }
        finally { File.SetAttributes(live, FileAttributes.Normal); }
    }

    [Fact]
    public async Task The_preview_counts_profiles_and_rules_as_the_import_applies_them(/* BUG-559 */)
    {
        var inst = NewInstance("bug559");
        var (templateId, profileName) = await SeedTemplateDefaultAsync(inst.Factory, inst.Store);
        using (var db = inst.Factory.CreateDbContext())
        {
            db.NotificationRules.Add(new NotificationRule
                { Code = "NY", Label = "New York", WindowHours = 72, IsActive = true, CreatedBy = "admin1", CreatedAtUtc = _clock.UtcNow });
            await db.SaveChangesAsync();
        }
        var live = (await inst.Config.ExportAsync()).Envelope.Bundle;

        // An older bundle (no template library) leaves defaults alone, and a rule code differing only in case is the same rule.
        var older = live with
        {
            ReportTemplates = null,
            ReportProfiles = live.ReportProfiles.Select(p => p with { Template = null }).ToList(),
            NotificationRules = live.NotificationRules.Select(r => r with { Code = r.Code.ToLowerInvariant() }).ToList(),
        };
        var diff = await inst.Config.PreviewAsync(older);
        diff.Items.Where(i => i.Section is "Report profile" or "Notification rule").Should().OnlyContain(i => i.Change == ConfigChange.Unchanged);
        var result = await inst.Config.ImportAsync(Signed(older));
        result.Updated.Should().Be(diff.Updated).And.Be(0);
        using (var db = inst.Factory.CreateDbContext())
            (await db.ReportProfiles.SingleAsync(p => p.Name == profileName)).TemplateId.Should().Be(templateId);

        // A profile named differently only in case is updated once, to the bundle's name, and then unchanged.
        var upper = profileName.ToUpperInvariant();
        var recased = live with { ReportProfiles = live.ReportProfiles.Select(p => p.Name == profileName ? p with { Name = upper } : p).ToList() };
        diff = await inst.Config.PreviewAsync(recased);
        diff.Items.Should().ContainSingle(i => i.Change == ConfigChange.Update).Which.Section.Should().Be("Report profile");
        (await inst.Config.ImportAsync(Signed(recased))).Updated.Should().Be(diff.Updated);
        using (var db = inst.Factory.CreateDbContext())
            (await db.ReportProfiles.CountAsync(p => p.Name == upper)).Should().Be(1);
        (await inst.Config.PreviewAsync(recased)).Updated.Should().Be(0);
        (await inst.Config.ImportAsync(Signed(recased))).Updated.Should().Be(0);
    }

    [Fact]
    public async Task A_same_server_round_trip_previews_unchanged_and_imports_nothing(/* BUG-559 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        db.Roles.Add(new Role { Name = "Auditor", Description = "Built in", IsSystem = true, PermissionsCsv = "ViewCases",
            UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "system" });
        db.AppSettings.Add(new AppSetting { Key = "Email:Enabled", Value = "true", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
        await db.SaveChangesAsync();
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();

        var diff = await svc.PreviewAsync(live);
        diff.Items.Should().OnlyContain(i => i.Change == ConfigChange.Unchanged);
        var result = await svc.ImportAsync(Signed(live));
        (result.Added, result.Updated).Should().Be((0, 0));

        // What the import writes is the same, so the preview says so too: a setting the page would normalize to the stored
        // value, a role's permissions in another order, and a custom role named like a system one (never changed).
        var equivalent = live with
        {
            Settings = live.Settings.Select(x => x.Key == "Email:Enabled" ? x with { Value = " True " } : x).ToList(),
            Roles = live.Roles.Where(r => !r.IsSystem)
                .Select(r => r.Name == "IR Lead" ? r with { PermissionsCsv = "EditCases, ViewCases" } : r)
                .Append(new ConfigRole("auditor", "Not the built-in one", false, "Administer")).ToList(),
        };
        diff = await svc.PreviewAsync(equivalent);
        diff.Items.Where(i => i.Section is "Setting" or "Role").Should().OnlyContain(i => i.Change == ConfigChange.Unchanged);
        result = await svc.ImportAsync(Signed(equivalent));
        (result.Added, result.Updated).Should().Be((diff.Added, diff.Updated)).And.Be((0, 0));
        (await db.Roles.AsNoTracking().SingleAsync(r => r.Name == "Auditor")).PermissionsCsv.Should().Be("ViewCases");
    }

    [Fact]
    public async Task Word_templates_and_profile_defaults_are_promoted_to_another_instance()
    {
        var source = NewInstance("source");
        var (sourceTemplateId, profileName) = await SeedTemplateDefaultAsync(source.Factory, source.Store);
        var export = await source.Config.ExportAsync();
        export.Envelope.SchemaVersion.Should().Be(ConfigBundleJson.CurrentSchemaVersion);
        var bundle = export.Envelope.Bundle;
        bundle.ReportTemplates.Should().ContainSingle(t => t.Name == "Examiner pack" && t.FileName == "examiner.docx");
        bundle.ReportProfiles.Single(p => p.Name == profileName).Template.Should().Be("Examiner pack");

        var target = NewInstance("target");
        var (parsed, verification) = target.Config.ParseAndVerify(export.Content);
        verification.SignatureValid.Should().BeTrue();
        (await target.Config.PreviewAsync(parsed.Bundle)).Items
            .Should().Contain(i => i.Section == "Word template" && i.Name == "Examiner pack" && i.Change == ConfigChange.Add);

        await target.Config.ImportAsync(parsed);

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
        var again = await target.Config.ImportAsync(parsed);
        again.Added.Should().Be(0);
        again.Updated.Should().Be(0);

        await AssertLessonsDefaultTravels(source, target);
    }

    [Fact]
    public async Task Two_live_templates_with_one_name_stop_an_import_with_their_name_not_a_raw_error(/* BUG-524 */)
    {
        var source = NewInstance("dup-src");
        await SeedTemplateDefaultAsync(source.Factory, source.Store);
        var bundle = (await source.Config.ExportAsync()).Envelope.Bundle;
        var target = NewInstance("dup-dst");
        await SeedTemplateDefaultAsync(target.Factory, target.Store);
        using (var db = target.Factory.CreateDbContext())
        {
            // Stored before the name check ran under the library gate (a double upload).
            var bytes = _engine.Starter();
            var dup = new IncidentManager.Domain.Entities.ReportTemplate { Name = "examiner PACK", FileName = "examiner.docx",
                Sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant(),
                SizeBytes = bytes.LongLength, IsActive = true, CreatedBy = "admin2", CreatedAtUtc = _clock.UtcNow };
            db.ReportTemplates.Add(dup);
            await db.SaveChangesAsync();
            await target.Store.CommitAsync(await target.Store.StageAsync(dup.Id, bytes));
        }

        (await target.Config.Invoking(c => c.PreviewAsync(bundle)).Should().ThrowAsync<InvalidOperationException>())
            .Which.Message.Should().Contain("More than one Word template on this server is named").And.Contain("Rename one");
        (await target.Config.Invoking(c => c.ImportAsync(Signed(bundle))).Should().ThrowAsync<InvalidOperationException>())
            .Which.Message.Should().Contain("More than one Word template on this server is named");

        // A bundle without the library (from before v3) leaves it alone, so the duplicate doesn't stop it.
        var older = bundle with { ReportTemplates = null };
        await target.Config.Invoking(c => c.ImportAsync(Signed(older))).Should().NotThrowAsync();
    }

    [Fact]
    public async Task A_bundle_with_a_template_stored_before_report_tlp_was_required_still_imports(/* BUG-151 */)
    {
        var source = NewInstance("pre152");
        await SeedTemplateDefaultAsync(source.Factory, source.Store);
        var bundle = await source.Config.BuildBundleAsync();
        // As exported by v1.5.1: an archived template with no {{report.tlp}}, which uploads then allowed.
        byte[] unmarked;
        using (var ms = new MemoryStream())
        {
            using (var doc = DocumentFormat.OpenXml.Packaging.WordprocessingDocument.Create(ms, DocumentFormat.OpenXml.WordprocessingDocumentType.Document, true))
            {
                var main = doc.AddMainDocumentPart();
                main.Document = new DocumentFormat.OpenXml.Wordprocessing.Document(new DocumentFormat.OpenXml.Wordprocessing.Body(
                    new DocumentFormat.OpenXml.Wordprocessing.Paragraph(new DocumentFormat.OpenXml.Wordprocessing.Run(
                        new DocumentFormat.OpenXml.Wordprocessing.Text("{{case.title}}")))));
                main.Document.Save();
            }
            unmarked = ms.ToArray();
        }
        var old = bundle.ReportTemplates![0] with
        {
            Name = "Old layout", FileName = "old.docx", IsActive = false, LessonsDefault = false,
            ContentBase64 = Convert.ToBase64String(unmarked),
            Sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(unmarked)),
        };
        bundle = bundle with { ReportTemplates = [.. bundle.ReportTemplates!, old] };

        var target = NewInstance("post152");
        var diff = await target.Config.PreviewAsync(bundle);
        diff.Warnings.Should().ContainSingle(w => w.Contains("Old layout") && w.Contains("{{report.tlp}}"));
        await target.Config.ImportAsync(Signed(bundle));

        using var db = target.Factory.CreateDbContext();
        (await db.ReportTemplates.CountAsync()).Should().Be(2, "the rest of the bundle, and the template, are imported");
    }

    private async Task AssertLessonsDefaultTravels(
        (IAppDbContextFactory Factory, FileReportTemplateStore Store, ConfigBundleService Config) source,
        (IAppDbContextFactory Factory, FileReportTemplateStore Store, ConfigBundleService Config) target)
    {
        var sourceTemplates = new IncidentManager.Application.Admin.ReportTemplateService(source.Factory, _user, _clock, _engine, source.Store);
        await sourceTemplates.SetLessonsDefaultAsync((await sourceTemplates.ListAllAsync()).Single().Id, true);
        var bundle = await source.Config.BuildBundleAsync();
        bundle.ReportTemplates!.Single().LessonsDefault.Should().BeTrue();

        // Two lessons defaults in one bundle are refused.
        var twice = bundle with { ReportTemplates = [.. bundle.ReportTemplates!, bundle.ReportTemplates![0] with { Name = "Copy" }] };
        await target.Config.Invoking(c => c.PreviewAsync(twice)).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*More than one*lessons-learned default*");

        await target.Config.ImportAsync(Signed(bundle));
        using var db = target.Factory.CreateDbContext();
        (await db.ReportTemplates.SingleAsync()).IsLessonsDefault.Should().BeTrue();
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

        await instance.Config.ImportAsync(Signed(v2));

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
        await target.Config.Invoking(c => c.ImportAsync(Signed(tampered))).Should().ThrowAsync<InvalidOperationException>();

        // A profile default that would end up archived.
        var archived = bundle with { ReportTemplates = [template with { IsActive = false }] };
        await target.Config.Invoking(c => c.ImportAsync(Signed(archived))).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*would be archived*");

        // A macro-enabled file isn't a template, whatever the bundle calls it.
        var macro = bundle with { ReportTemplates = [template with { FileName = "examiner.docm" }] };
        await target.Config.Invoking(c => c.ImportAsync(Signed(macro))).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*only .docx*");

        using var check = target.Factory.CreateDbContext();
        (await check.ReportTemplates.CountAsync()).Should().Be(0, "nothing is written when a template fails");
        (await check.ReportProfiles.CountAsync(p => p.TemplateId != null)).Should().Be(0);
    }

    [Theory]
    [InlineData("EscalateToIncident,EscalateToBreach")]   // OR-ed, this was CloseCase
    [InlineData("3")]
    [InlineData("4")]                                     // no such transition, stored as one
    public async Task A_gate_trigger_is_read_by_name_only(string trigger /* BUG-592 */)
    {
        await using var db = NewContext();
        await SeedConfigAsync(db);
        var svc = NewService(db);
        var live = await svc.BuildBundleAsync();
        var bundle = live with { StageGates = [.. live.StageGates, live.StageGates[0] with { Name = "Listed", Trigger = trigger, IsActive = false }] };

        var diff = await svc.PreviewAsync(bundle);
        diff.Items.Should().NotContain(i => i.Name == "Listed");
        diff.Warnings.Should().Contain(w => w.Contains("\"Listed\"") && w.Contains("doesn't have"));
        await svc.ImportAsync(Signed(bundle));
        (await db.StageGates.AsNoTracking().AnyAsync(g => g.Name == "Listed")).Should().BeFalse();
    }

    [Fact]
    public async Task A_rule_code_saved_in_lower_case_is_the_upper_case_code(/* C16 out of class: NotificationRuleService */)
    {
        await using var db = NewContext();
        db.NotificationRules.Add(new NotificationRule { Code = "ny", Label = "New York", WindowHours = 72, IsActive = true, CreatedBy = "admin1", CreatedAtUtc = _clock.UtcNow });
        await db.SaveChangesAsync();
        var rules = new IncidentManager.Application.Admin.NotificationRuleService(NewFactory(), _user, _clock);

        await rules.Invoking(r => r.SaveAsync(null, "NY", "New York", 96)).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*already exists*");
        (await db.NotificationRules.CountAsync()).Should().Be(1, "the rule set reads codes ignoring case, so two would throw");
    }

    public void Dispose()
    {
        _connection.Dispose();
        foreach (var c in _extraConnections) c.Dispose();
    }
}
