using FluentAssertions;
using IncidentManager.Application.Cases;
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
}
