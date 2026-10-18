using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Config;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Configuration;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Web.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-28 discovery: while "Your organization's domains" has never been saved, the domains found on the server's network
/// are the ones left out of "possibly related" suggestions, shown as discovered; once an administrator saves a value
/// (the found ones through "Use these", or blank), theirs wins; and a configuration bundle carries only what was saved,
/// never the domains found. Runs on SQLite always and on SQL Server when <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class DiscoveredDomainTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), "im-discovered-domains", Guid.NewGuid().ToString("N"));

    public static TheoryData<string> Providers => TestDatabase.Providers;

    public void Dispose()
    {
        try { Directory.Delete(_workDir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private sealed record Live(CaseService Cases, AdminSettingsService Settings, ConfigurationRelatedExclusions Exclusions,
        ConfigBundleService Bundles);

    // As the app wires it: the settings provider reads the AppSettings table, a save reloads it, and the exclusions and the
    // settings page both see the discovery (here a fake source: this machine may not be on a domain).
    private async Task<Live> LiveAsync(TestDatabase database, IDomainDiscoverySource source)
    {
        var (provider, connection) = database.Connection;
        var config = new ConfigurationBuilder().Add(new DbSettingsConfigurationSource(provider, connection)).Build();
        var domains = new OrganizationDomains(source);
        await domains.DiscoverAsync();
        var exclusions = new ConfigurationRelatedExclusions(config, domains);
        var cases = new CaseService(database.Factory(), _user, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            relatedExclusions: exclusions);
        var settings = new AdminSettingsService(database.Factory(), _user, _clock, new ConfigurationReloader(config),
            server: new ServerSettingValues(config), exclusions: exclusions, domains: domains);
        var signer = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_workDir, "k.pem"), AllowKeyGeneration = true }));
        var bundles = new ConfigBundleService(database.Factory(), signer, new AuditWriter(database.Factory(), _hasher, _user, _clock), _user, _clock);
        return new(cases, settings, exclusions, bundles);
    }

    private static readonly FakeSource Contoso = new(() =>
    [
        new("CORP.contoso.com", DiscoveredDomainSource.ThisDomain),
        new("contoso.com", DiscoveredDomainSource.ForestRoot),
        new("CORP", DiscoveredDomainSource.Trusted),
        new("partner.example", DiscoveredDomainSource.Trusted),
    ]);

    private async Task<EffectiveSetting> DomainsSettingAsync(Live live) =>
        (await live.Settings.GetEffectiveAsync()).Single(e => e.Definition.Key == RelatedExclusionSettings.DomainsKey);

    private async Task CaseWithAsync(CaseService svc)
    {
        var id = (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Other", Title = "Other case", Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection,
        })).Id;
        await svc.AddOrMatchEntitiesAsync(id, new[] { "www.contoso.com", "cdn.partner.example", "cdn.evil.example" }
            .Select(v => new CaseService.EntityToAdd(EntityType.Domain, v, null, EntityDisposition.Malicious, null, null)).ToList());
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Never_saved_the_domains_found_are_in_force_and_shown_as_discovered_but_never_exported(string provider)
    {
        using var database = Open(provider);
        var live = await LiveAsync(database, Contoso);
        await CaseWithAsync(live.Cases);

        var related = await live.Cases.FindRelatedIndicatorsForIocsAsync(["shop.contoso.com", "mail.partner.example", "evil.example"]);
        related.Select(r => r.OtherValue).Should().BeEquivalentTo(["cdn.partner.example", "cdn.evil.example"],
            "the organization's own domains found are left out; a trusted partner's is only offered, so it still relates");
        related.ExcludedBecause("shop.contoso.com").Should().Contain("contoso.com");

        var setting = await DomainsSettingAsync(live);
        setting.IsOverridden.Should().BeFalse();
        setting.Source.Should().Be("Discovered");
        setting.Value.Should().BeEmpty("the field shows what is saved: nothing yet");
        setting.Discovered!.Select(d => (d.Name, d.Source)).Should().Equal(
            ("corp.contoso.com", DiscoveredDomainSource.ThisDomain), ("contoso.com", DiscoveredDomainSource.ForestRoot));
        setting.InForce.Should().Be("corp.contoso.com\ncontoso.com", "a trusted partner's domain is only offered (owner, 2026-10-18)");

        var bundle = await live.Bundles.BuildBundleAsync();
        bundle.Settings.Should().NotContain(s => s.Key == RelatedExclusionSettings.DomainsKey, "a bundle carries what was saved, never what was found");
        using var db = database.NewContext();
        (await db.AppSettings.AnyAsync(s => s.Key == RelatedExclusionSettings.DomainsKey)).Should().BeFalse("nothing found is stored");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Use_these_then_save_keeps_the_found_domains_as_the_administrators_own(string provider)
    {
        using var database = Open(provider);
        var live = await LiveAsync(database, Contoso);

        // "Use these" fills the field with the found names, one per line; the section's save stores them.
        await live.Settings.SetAsync(RelatedExclusionSettings.DomainsKey, "corp.contoso.com\ncontoso.com\npartner.example");   // every name found, partners too

        var setting = await DomainsSettingAsync(live);
        setting.Source.Should().Be("Database");
        setting.Discovered.Should().BeNull();
        setting.Value.Should().Be("corp.contoso.com\ncontoso.com\npartner.example");
        live.Exclusions.DiscoveredInForce.Should().BeNull();
        (await live.Bundles.BuildBundleAsync()).Settings.Should().ContainSingle(s => s.Key == RelatedExclusionSettings.DomainsKey)
            .Which.Value.Should().Be("corp.contoso.com\ncontoso.com\npartner.example", "saved, it's the administrator's and exported");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_saved_list_or_a_saved_blank_wins_and_reset_brings_the_found_domains_back(string provider)
    {
        using var database = Open(provider);
        var live = await LiveAsync(database, Contoso);
        await CaseWithAsync(live.Cases);

        await live.Settings.SetAsync(RelatedExclusionSettings.DomainsKey, "partner.example");
        live.Exclusions.Current.Domains.Should().Equal("partner.example");
        (await live.Cases.FindRelatedIndicatorsForIocsAsync(["shop.contoso.com"])).Select(r => r.OtherValue)
            .Should().Equal(["www.contoso.com"], "the saved list replaced the found one");

        await live.Settings.SetAsync(RelatedExclusionSettings.DomainsKey, "");
        live.Exclusions.Current.Domains.Should().BeEmpty("saved blank means none, not the domains found");
        (await DomainsSettingAsync(live)).Source.Should().Be("Database");
        (await live.Bundles.BuildBundleAsync()).Settings.Should().ContainSingle(s => s.Key == RelatedExclusionSettings.DomainsKey)
            .Which.Value.Should().BeEmpty();

        await live.Settings.ResetAsync(RelatedExclusionSettings.DomainsKey);
        live.Exclusions.Current.Domains.Should().Equal("corp.contoso.com", "contoso.com");
        (await DomainsSettingAsync(live)).Source.Should().Be("Discovered");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Nothing_found_leaves_the_setting_at_its_default(string provider)
    {
        using var database = Open(provider);
        var live = await LiveAsync(database, new FakeSource(() => null));
        var setting = await DomainsSettingAsync(live);
        setting.Source.Should().Be("Default");
        setting.Discovered.Should().BeNull();
        live.Exclusions.Current.Domains.Should().BeEmpty();
    }

    [Fact]
    public async Task Looking_again_is_an_administrators_and_answers_the_new_look()
    {
        using var database = Open(TestDatabase.Sqlite);
        var asked = 0;
        var live = await LiveAsync(database, new FakeSource(() =>
            Interlocked.Increment(ref asked) == 1 ? null : [new("corp.contoso.com", DiscoveredDomainSource.ThisDomain)]));

        (await live.Settings.DiscoverDomainsAsync()).Domains.Select(d => d.Name).Should().Equal("corp.contoso.com");
        (await DomainsSettingAsync(live)).Source.Should().Be("Discovered");

        _user.RoleSet = [AppRole.Analyst];
        await live.Settings.Invoking(s => s.DiscoverDomainsAsync()).Should().ThrowAsync<ForbiddenException>();
        asked.Should().Be(2);
    }

    [Fact]
    public async Task The_directory_source_on_a_computer_not_on_a_domain_finds_nothing()
    {
        // The real Active Directory source can only be exercised on a domain-joined Windows server; elsewhere (Linux CI, a
        // workgroup machine) it says "not joined" rather than failing.
        if (OperatingSystem.IsWindows()
            && !string.IsNullOrEmpty(System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName))
            return;
        var domains = new OrganizationDomains(new AdDomainDiscoverySource());
        (await domains.DiscoverAsync()).State.Should().Be(DomainDiscoveryState.NotDomainJoined);
    }

    private sealed class FakeSource(Func<IReadOnlyList<DiscoveredDomain>?> read) : IDomainDiscoverySource
    {
        public IReadOnlyList<DiscoveredDomain>? Read() => read();
    }
}
