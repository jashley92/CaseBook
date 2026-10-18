using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Infrastructure.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-28: "possibly related" indicators on other cases: the same registrable domain, /24 or email domain, never the
/// identical value; on the cases the user can see (a restricted case outside need-to-know never shows), exercises left out,
/// for the entity panel and at intake. Runs on SQLite always and on SQL Server when <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class RelatedIndicatorTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic2", RoleSet = [AppRole.SysAdmin] };

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private CaseService NewService(TestDatabase database) =>
        new(database.Factory(), _user, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private async Task<Guid> CaseWithAsync(CaseService svc, string name, bool exercise, params (EntityType Type, string Value)[] entities)
    {
        var id = (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = name, Title = name + " case", Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, IsExercise = exercise
        })).Id;
        await svc.AddOrMatchEntitiesAsync(id, entities
            .Select(e => new CaseService.EntityToAdd(e.Type, e.Value, null, EntityDisposition.Malicious, null, null)).ToList());
        _clock.UtcNow = _clock.UtcNow.AddHours(1);
        return id;
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Related_indicators_are_suggested_from_visible_cases_only(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var other = await CaseWithAsync(svc, "Other", false,
            (EntityType.Domain, "cdn.evil.example"), (EntityType.IpAddress, "203.0.113.77"),
            (EntityType.EmailAddress, "billing@evil.example"), (EntityType.Domain, "evil.example"),
            (EntityType.Domain, "unrelated.example"), (EntityType.Domain, "evil_x.example"));
        await CaseWithAsync(svc, "Drill", true, (EntityType.Domain, "drill.evil.example"));
        var secret = await CaseWithAsync(svc, "Secret", false, (EntityType.Domain, "secret.evil.example"));
        await svc.SetRestrictedAsync(secret, true, "Insider matter");
        var mine = await CaseWithAsync(svc, "Mine", false,
            (EntityType.Url, "https://login.evil.example/reset"), (EntityType.IpAddress, "203.0.113.5"),
            (EntityType.EmailAddress, "ceo@evil.example"));

        _user.UserId = "analyst1";
        _user.RoleSet = [AppRole.Analyst];
        var related = await svc.FindRelatedIndicatorsAsync(mine);

        related.Should().OnlyContain(r => r.OtherCaseId == other, "not the drill, not the restricted case, not the case itself");
        related.Select(r => (r.Indicator, r.OtherValue, r.Key.Rule)).Should().BeEquivalentTo(new[]
        {
            ("https://login.evil.example/reset", "cdn.evil.example", RelatedRule.RegistrableDomain),
            ("https://login.evil.example/reset", "evil.example", RelatedRule.RegistrableDomain),
            ("203.0.113.5", "203.0.113.77", RelatedRule.Ipv4Slash24),
            ("ceo@evil.example", "billing@evil.example", RelatedRule.EmailDomain),
        });
        related.Single(r => r.OtherValue == "203.0.113.77").Why.Should().Be("same /24 (203.0.113.0/24)");

        // The entity panel asks for one entity.
        var ipId = (await svc.GetDetailAsync(mine))!.Entities.Single(e => e.Value == "203.0.113.5").Id;
        (await svc.FindRelatedIndicatorsAsync(mine, ipId)).Should().ContainSingle().Which.OtherValue.Should().Be("203.0.113.77");

        // A restricted case the analyst can't see answers nothing, as if missing.
        (await svc.FindRelatedIndicatorsAsync(secret)).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Intake_suggests_related_indicators_for_what_is_being_entered(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var other = await CaseWithAsync(svc, "Other", false, (EntityType.Domain, "mail.evil.example"), (EntityType.Domain, "evil.example"));
        var secret = await CaseWithAsync(svc, "Secret", false, (EntityType.Domain, "vpn.evil.example"));
        await svc.SetRestrictedAsync(secret, true, "Insider matter");
        _user.UserId = "analyst1";
        _user.RoleSet = [AppRole.Analyst];

        var related = await svc.FindRelatedIndicatorsForIocsAsync(["hxxps://portal.evil[.]example/login", "evil.example", "d41d8cd98f00b204e9800998ecf8427e"]);

        related.Should().OnlyContain(r => r.OtherCaseId == other);
        related.Where(r => r.Indicator == "evil.example").Select(r => r.OtherValue).Should().Equal(["mail.evil.example"],
            "the identical value is a match (Seen before), not a suggestion");
        related.Where(r => r.Indicator.StartsWith("https://portal", StringComparison.Ordinal)).Select(r => r.OtherValue)
            .Should().BeEquivalentTo(["mail.evil.example", "evil.example"]);
    }

    // CAP-28 review: the scan reads the newest RelatedScanLimit candidates, and copies of the value being checked (a match,
    // never a suggestion) used to fill it, so an older related indicator was missed and the panel said nothing was related.
    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Copies_of_the_checked_value_do_not_fill_the_scan_and_a_full_scan_is_reported(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var now = _clock.UtcNow;
        await using (var db = database.NewContext())
        {
            Case NewCase(int seq, DateTimeOffset opened, string value)
            {
                var c = Case.Open(2026, seq, $"C{seq}", $"Case {seq}", Classification.Incident, Severity.High,
                    CaseOrigin.InternalDetection, "ic2", opened);
                c.Entities.Add(new CaseEntity { CaseId = c.Id, Type = EntityType.Domain, Value = value });
                return c;
            }
            var older = NewCase(1, now.AddDays(-30), "a.evil.example");
            db.Cases.Add(older);
            db.Cases.AddRange(Enumerable.Range(0, CaseService.RelatedScanLimit + 1)
                .Select(i => NewCase(i + 2, now.AddDays(-20).AddMinutes(i), "evil.example")));
            await db.SaveChangesAsync();
        }

        var related = await svc.FindRelatedIndicatorsForIocsAsync(["evil.example"]);
        related.Should().ContainSingle().Which.OtherValue.Should().Be("a.evil.example",
            "the newer identical copies are left out of the scan, so the older related one is found");
        related.ScanLimitHit.Should().BeFalse();

        // A value the copies are candidates for: the scan fills with them, and the result says only the newest were read.
        var crowded = await svc.FindRelatedIndicatorsForIocsAsync(["b.evil.example"]);
        crowded.ScanLimitHit.Should().BeTrue();
        crowded.Should().OnlyContain(r => r.OtherValue == "evil.example");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Addresses_narrow_by_their_own_prefix(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var other = await CaseWithAsync(svc, "Other", false,
            (EntityType.IpAddress, "203.0.113.77"), (EntityType.IpAddress, "13.0.113.8"),
            (EntityType.Url, "http://203.0.113.9/x"), (EntityType.IpAddress, "2001:db8:0:1::7"),
            (EntityType.IpAddress, "2001:db8:1::7"), (EntityType.Url, "http://[2001:db8::9]/y"));

        var related = await svc.FindRelatedIndicatorsForIocsAsync(["203.0.113.5", "2001:db8::5"]);

        related.Should().OnlyContain(r => r.OtherCaseId == other);
        related.Select(r => (r.Indicator, r.OtherValue)).Should().BeEquivalentTo(new[]
        {
            ("203.0.113.5", "203.0.113.77"),
            ("203.0.113.5", "http://203.0.113.9/x"),
            ("2001:db8::5", "2001:db8:0:1::7"),
            ("2001:db8::5", "http://[2001:db8::9]/y"),
        }, "13.0.113.8 isn't in 203.0.113.0/24, nor 2001:db8:1::7 in 2001:db8::/48");
    }

    // R1: a URL's address is never canonicalised, and an IpAddress stored before v1.5.3 (BUG-176, no backfill) may not be,
    // so the anchored narrowing used to miss them: leading zeros, an IPv4-mapped address, a zero hextet written out.
    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Addresses_not_stored_canonically_still_narrow(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var other = await CaseWithAsync(svc, "Other", false, (EntityType.Url, "http://[2001:0db8:abcd::9]/y"));
        await using (var db = database.NewContext())
        {
            // Written past Normalize, as a legacy row would be.
            db.CaseEntities.Add(new CaseEntity { CaseId = other, Type = EntityType.IpAddress, Value = "::ffff:203.0.113.9" });
            db.CaseEntities.Add(new CaseEntity { CaseId = other, Type = EntityType.IpAddress, Value = "2001:0db8:0:0:0:0:0:1" });
            await db.SaveChangesAsync();
        }

        var related = await svc.FindRelatedIndicatorsForIocsAsync(["2001:db8:abcd::5", "203.0.113.5"]);
        related.Select(r => (r.Indicator, r.OtherValue)).Should().BeEquivalentTo(new[]
        {
            ("2001:db8:abcd::5", "http://[2001:0db8:abcd::9]/y"),
            ("203.0.113.5", "::ffff:203.0.113.9"),
        });

        (await svc.FindRelatedIndicatorsForIocsAsync(["2001:db8::5"])).Should().ContainSingle()
            .Which.OtherValue.Should().Be("2001:0db8:0:0:0:0:0:1");
    }

    // --- CAP-28 exclusions: the organization's own domains and ranges, saved in Administration and read live -------------

    private sealed record Live(CaseService Cases, AdminSettingsService Settings, IConfigurationRoot Config);

    // The service as the app wires it: the exclusions read from the configuration, whose settings provider reads the
    // AppSettings table, and a save that reloads it (no restart).
    private Live LiveSettings(TestDatabase database)
    {
        var (provider, connection) = database.Connection;
        var config = new ConfigurationBuilder().Add(new DbSettingsConfigurationSource(provider, connection)).Build();
        var cases = new CaseService(database.Factory(), _user, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            relatedExclusions: new ConfigurationRelatedExclusions(config));
        return new(cases, new AdminSettingsService(database.Factory(), _user, _clock, new ConfigurationReloader(config)), config);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Excluded_values_are_not_suggested_and_suggest_nothing_and_a_saved_change_applies_at_once(string provider)
    {
        using var database = Open(provider);
        var live = LiveSettings(database);
        var other = await CaseWithAsync(live.Cases, "Other", false,
            (EntityType.Domain, "www.contoso.com"), (EntityType.Domain, "dc1.corp.contoso.com"), (EntityType.EmailAddress, "hr@contoso.com"),
            (EntityType.IpAddress, "10.20.30.40"), (EntityType.Url, "http://10.20.30.41/x"),
            (EntityType.Domain, "cdn.evil.example"), (EntityType.IpAddress, "203.0.113.77"));
        string[] entered = ["shop.contoso.com", "it@contoso.com", "10.20.30.5", "evil.example", "203.0.113.5"];

        // The defaults: no domains yet, the private ranges left out.
        var before = await live.Cases.FindRelatedIndicatorsForIocsAsync(entered);
        before.Select(r => (r.Indicator, r.OtherValue)).Should().BeEquivalentTo(new[]
        {
            ("shop.contoso.com", "www.contoso.com"), ("shop.contoso.com", "dc1.corp.contoso.com"), ("it@contoso.com", "hr@contoso.com"),
            ("evil.example", "cdn.evil.example"), ("203.0.113.5", "203.0.113.77"),
        });
        before.ExcludedBecause("10.20.30.5").Should().Be(
            "10.20.30.5 is in 10.0.0.0/8, one of your organization's excluded address ranges, so it isn't used to suggest relations.");

        // The organization's domain, saved: no restart.
        await live.Settings.SetAsync(RelatedExclusionSettings.DomainsKey, "Contoso.COM");
        var after = await live.Cases.FindRelatedIndicatorsForIocsAsync(entered);
        after.Select(r => (r.Indicator, r.OtherValue)).Should().BeEquivalentTo(new[]
        {
            ("evil.example", "cdn.evil.example"), ("203.0.113.5", "203.0.113.77"),
        }, "what isn't excluded still relates");
        after.ExcludedBecause("shop.contoso.com").Should().Be(
            "shop.contoso.com is under contoso.com, one of your organization's domains, so it isn't used to suggest relations.");
        after.ExcludedBecause("it@contoso.com").Should().NotBeNull();

        // An excluded value on the other case suggests nothing either: the case's own www.contoso.com, asked from the panel.
        var wwwId = (await live.Cases.GetDetailAsync(other))!.Entities.Single(e => e.Value == "www.contoso.com").Id;
        var panel = await live.Cases.FindRelatedIndicatorsAsync(other, wwwId);
        panel.Should().BeEmpty();
        panel.ExcludedBecause("www.contoso.com").Should().StartWith("www.contoso.com is under contoso.com");

        // Narrowed to a sub-domain: contoso.com relates again, but never to the hosts under corp.contoso.com.
        await live.Settings.SetAsync(RelatedExclusionSettings.DomainsKey, "corp.contoso.com");
        (await live.Cases.FindRelatedIndicatorsForIocsAsync(["shop.contoso.com"])).Select(r => r.OtherValue)
            .Should().Equal(["www.contoso.com"]);

        // The ranges cleared: a private /24 relates as before, the URL on it too.
        await live.Settings.SetAsync(RelatedExclusionSettings.RangesKey, "");
        (await live.Cases.FindRelatedIndicatorsForIocsAsync(["10.20.30.5"])).Select(r => r.OtherValue)
            .Should().BeEquivalentTo(["10.20.30.40", "http://10.20.30.41/x"]);

        // A range of the organization's own public addresses.
        await live.Settings.SetAsync(RelatedExclusionSettings.RangesKey, "203.0.113.0/25");
        var own = await live.Cases.FindRelatedIndicatorsForIocsAsync(["203.0.113.200", "203.0.113.5"]);
        own.Select(r => (r.Indicator, r.OtherValue)).Should().BeEmpty("203.0.113.5 and .77 are in the range; .200 relates to neither");
        own.ExcludedBecause("203.0.113.5").Should().Contain("203.0.113.0/25");
        own.ExcludedBecause("203.0.113.200").Should().BeNull();

        // Reset: the defaults again.
        await live.Settings.ResetAsync(RelatedExclusionSettings.RangesKey);
        (await live.Cases.FindRelatedIndicatorsForIocsAsync(["10.20.30.5"])).ExcludedBecause("10.20.30.5").Should().NotBeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_invalid_exclusion_is_refused_with_its_entry_named_and_nothing_changes(string provider)
    {
        using var database = Open(provider);
        var live = LiveSettings(database);
        await live.Settings.SetAsync(RelatedExclusionSettings.DomainsKey, "contoso.com");

        var badRange = () => live.Settings.SetAsync(RelatedExclusionSettings.RangesKey, "10.0.0.0/8, 10.0.0.1/8");
        (await badRange.Should().ThrowAsync<ArgumentException>())
            .WithMessage("Excluded address ranges: \"10.0.0.1/8\" has bits set past its /8. Did you mean 10.0.0.0/8?");
        var badDomain = () => live.Settings.SetAsync(RelatedExclusionSettings.DomainsKey, "fabrikam.com\nco.uk");
        (await badDomain.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().StartWith("Your organization's domains: \"co.uk\"");

        using var db = database.NewContext();
        (await db.AppSettings.Where(s => s.Key.StartsWith("RelatedIndicators:")).Select(s => new { s.Key, s.Value }).ToListAsync())
            .Should().BeEquivalentTo(new[] { new { Key = RelatedExclusionSettings.DomainsKey, Value = (string?)"contoso.com" } });
        live.Config.GetSection(RelatedExclusionSettings.DomainsKey).GetChildren().Select(c => c.Value).Where(v => v != "")
            .Should().Equal(["contoso.com"]);
    }

    // CAP-28 exclusions: an organization's sub-domain under a suggested one (corp.contoso.com under contoso.com) is left out
    // in SQL too, so its hosts, often many and on newer cases, don't fill the scan and hide an older related one.
    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Excluded_hosts_do_not_fill_the_scan(string provider)
    {
        using var database = Open(provider);
        var live = LiveSettings(database);
        await live.Settings.SetAsync(RelatedExclusionSettings.DomainsKey, "corp.contoso.com");
        var now = _clock.UtcNow;
        await using (var db = database.NewContext())
        {
            Case NewCase(int seq, DateTimeOffset opened, string value)
            {
                var c = Case.Open(2026, seq, $"C{seq}", $"Case {seq}", Classification.Incident, Severity.High,
                    CaseOrigin.InternalDetection, "ic2", opened);
                c.Entities.Add(new CaseEntity { CaseId = c.Id, Type = EntityType.Domain, Value = value });
                return c;
            }
            db.Cases.Add(NewCase(1, now.AddDays(-30), "www.contoso.com"));
            db.Cases.AddRange(Enumerable.Range(0, CaseService.RelatedScanLimit + 1)
                .Select(i => NewCase(i + 2, now.AddDays(-20).AddMinutes(i), $"ws{i}.corp.contoso.com")));
            await db.SaveChangesAsync();
        }

        var related = await live.Cases.FindRelatedIndicatorsForIocsAsync(["shop.contoso.com"]);
        related.Should().ContainSingle().Which.OtherValue.Should().Be("www.contoso.com");
        related.ScanLimitHit.Should().BeFalse("the excluded hosts weren't read");
    }
}
