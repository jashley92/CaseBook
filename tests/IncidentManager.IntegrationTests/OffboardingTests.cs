using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Security;
using IncidentManager.Application.Work;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Agenda;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-30: the offboarding page's service, on both providers. It shows a leaver's roles at last sign-in, the open cases
/// they command or are on (restricted ones only to an administrator cleared for them, otherwise counted), their open tasks,
/// their working personal tokens and whether their calendar link works; it revokes exactly the tokens shown and voids the
/// calendar link (which then stops resolving), each audited; and all of it needs Administer.
/// </summary>
public sealed class OffboardingTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _admin = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly TestCurrentUser _uncleared = new()
    {
        UserId = "admin2",
        PermissionSet = [Permission.Administer, Permission.ViewCases],   // an administrator without restricted clearance
    };
    private readonly CapturingSecurityEventSink _siem = new();
    private readonly AgendaFeedTokenService _feeds = new(new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["Agenda:FeedKey"] = "offboarding-" + Guid.NewGuid().ToString("N") }).Build());

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _admin, _clock, new CaseChangeNotifier()));

    private OffboardingService Service(TestDatabase database, ICurrentUser? user = null)
    {
        user ??= _admin;
        return new OffboardingService(database.Factory(), user, _clock, new AuditWriter(database.Factory(), _hasher, user, _clock), _feeds, _siem);
    }

    private sealed record Seeded(Guid Leaver, Guid Open, Guid Restricted, Guid Token, Guid OtherToken);

    private async Task<Seeded> SeedAsync(TestDatabase database)
    {
        var now = _clock.UtcNow;
        await using var db = database.NewContext();
        await RoleSeeder.SeedAsync(db, _clock, new RoleMappingOptions());
        var leaver = new AppUser
        {
            Sid = "leaver1", DisplayName = "Lee Ver", UserPrincipalName = "lee.ver@contoso.example", Email = "lee.ver@contoso.example",
            RolesCsv = "Analyst,IncidentCommander", LastSeenUtc = now.AddDays(-100), FeedLinkIssuedAtUtc = now.AddDays(-10),
        };
        db.Users.AddRange(leaver,
            new AppUser { Sid = "other1", DisplayName = "Other One", UserPrincipalName = "other1@contoso.example", RolesCsv = "Analyst", LastSeenUtc = now });

        var open = Case.Open(2026, 1, "Open", "Phish at the help desk", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection,
            "admin1", now.AddDays(-5));
        open.Assign("leaver1", "Lee Ver", CaseAssignmentRole.IncidentCommander, "admin1", now.AddDays(-5));
        var restricted = Case.Open(2026, 2, "Restricted", "Insider matter", Classification.Incident, Severity.High, CaseOrigin.InternalDetection,
            "admin1", now.AddDays(-4));
        restricted.IsRestricted = true;
        restricted.Assign("leaver1", "Lee Ver", CaseAssignmentRole.Analyst, "admin1", now.AddDays(-4));
        var closed = Case.Open(2026, 3, "Closed", "Done and dusted", Classification.Incident, Severity.Low, CaseOrigin.InternalDetection,
            "admin1", now.AddDays(-30));
        closed.Assign("leaver1", "Lee Ver", CaseAssignmentRole.IncidentCommander, "admin1", now.AddDays(-30));
        closed.ChangePhase(CasePhase.Closed, "Done", "admin1", now.AddDays(-20));
        var notTheirs = Case.Open(2026, 4, "Theirs not", "Someone else's", Classification.Incident, Severity.Low, CaseOrigin.InternalDetection,
            "admin1", now.AddDays(-3));
        db.Cases.AddRange(open, restricted, closed, notTheirs);

        db.ActionItems.AddRange(
            new ActionItem { CaseId = open.Id, Title = "Collect mailbox logs", Owner = "Lee Ver", DueAtUtc = now.AddDays(2) },
            new ActionItem { CaseId = open.Id, Title = "Done already", Owner = "leaver1", Status = ActionItemStatus.Done },
            new ActionItem { CaseId = open.Id, Title = "Not theirs", Owner = "Other One" },
            new ActionItem { CaseId = restricted.Id, Title = "Interview", Owner = "lee.ver@contoso.example" },
            new ActionItem { CaseId = closed.Id, Title = "On a closed case", Owner = "leaver1" });

        ApiToken Token(string name, string owner, ApiTokenKind kind = ApiTokenKind.Personal, DateTimeOffset? revoked = null) => new()
        {
            Name = name, Kind = kind, OwnerUserId = owner, OwnerDisplayName = owner, RolesCsv = "Analyst",
            TokenHash = Guid.NewGuid().ToString("N"), Prefix = "cb_" + name[..3].ToLowerInvariant(), CreatedBy = owner,
            CreatedAtUtc = now.AddDays(-30), ExpiresAtUtc = now.AddDays(60), RevokedAtUtc = revoked, RevokedBy = revoked is null ? null : "admin1",
        };
        var token = Token("Laptop script", "leaver1");
        var other = Token("Other's", "other1");
        var system = Token("Ingest", "apitoken:ingest", ApiTokenKind.System);
        system.CreatedBy = "leaver1";   // a system token they made: counted, not theirs to lose
        db.ApiTokens.AddRange(token, other, Token("Old", "leaver1", revoked: now.AddDays(-1)), system);
        await db.SaveChangesAsync();
        return new Seeded(leaver.Id, open.Id, restricted.Id, token.Id, other.Id);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_page_shows_what_the_leaver_holds(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);

        var view = (await Service(database).BuildAsync(s.Leaver))!;

        view.DisplayName.Should().Be("Lee Ver");
        view.Roles.Should().BeEquivalentTo(["Analyst", "IncidentCommander"], "the roles at last sign-in, as AD gave them");
        view.IsDormant.Should().BeTrue();
        view.Cases.Select(c => (c.CaseId, c.Commands, c.IsRestricted)).Should().BeEquivalentTo(
            [(s.Open, true, false), (s.Restricted, false, true)], "open cases they command or are on; not the closed one or another's");
        view.HiddenCases.Should().Be(0, "this administrator is cleared for restricted cases");
        view.Tasks.Select(t => t.Title).Should().BeEquivalentTo(["Collect mailbox logs", "Interview"],
            "open tasks owned by their name, id or address, on open cases");
        view.Tokens.Should().ContainSingle().Which.TokenId.Should().Be(s.Token, "working personal tokens only");
        view.SystemTokensCreated.Should().Be(1);
        (view.CalendarFeedOn, view.CalendarLinkLive).Should().Be((true, true));
        view.CalendarLinkExpiresAtUtc.Should().Be(_clock.UtcNow.AddDays(-10) + AgendaFeedService.MaxAge);

        (await Service(database).BuildAsync(Guid.NewGuid())).Should().BeNull("no such person");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Restricted_cases_are_counted_not_named_for_an_administrator_without_clearance(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);

        var view = (await Service(database, _uncleared).BuildAsync(s.Leaver))!;

        view.Cases.Should().ContainSingle().Which.CaseId.Should().Be(s.Open);
        view.HiddenCases.Should().Be(1);
        view.Tasks.Should().ContainSingle().Which.Title.Should().Be("Collect mailbox logs");
        view.HiddenTasks.Should().Be(1, "the restricted case's task is counted, its title not shown");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Revoking_takes_exactly_the_tokens_shown_and_is_audited(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        var service = Service(database);

        (await service.RevokeTokensAsync(s.Leaver, [s.Token, s.OtherToken])).Should().Be(1, "another person's token isn't theirs to lose");

        await using (var db = database.NewContext())
        {
            (await db.ApiTokens.SingleAsync(t => t.Id == s.Token)).Should().Match<ApiToken>(t => t.RevokedAtUtc == _clock.UtcNow && t.RevokedBy == "admin1");
            (await db.ApiTokens.SingleAsync(t => t.Id == s.OtherToken)).RevokedAtUtc.Should().BeNull();
            var entry = await db.AuditLog.Where(a => a.EntityType == OffboardingService.AuditEntityType).SingleAsync();
            (entry.EntityId, entry.Actor).Should().Be((s.Leaver.ToString(), "admin1"));
            entry.Summary.Should().Contain("Lee Ver").And.Contain("revoked 1 API token").And.Contain("cb_lap");
        }
        _siem.Events.Should().ContainSingle(e => e.Action == "ApiTokenRevoked");

        await FluentActions.Awaiting(() => service.RevokeTokensAsync(s.Leaver, [s.Token])).Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*no longer working*", "C9: the page's list is stale; nothing more changes");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Voiding_the_calendar_link_stops_it_and_is_audited(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        var leaver = new TestCurrentUser { UserId = "leaver1", RoleSet = [AppRole.Analyst] };
        var feed = new AgendaFeedService(database.Factory(), _feeds, leaver, _clock);
        var link = (await feed.GetMyLinkAsync())!;   // re-issued at their last sign-in's stamp
        (await feed.ResolveAsync(link.Token)).Should().Be("leaver1");

        await Service(database).VoidCalendarLinkAsync(s.Leaver);

        (await feed.ResolveAsync(link.Token)).Should().BeNull("a subscribed calendar is refused from now on");
        (await Service(database).BuildAsync(s.Leaver))!.CalendarLinkLive.Should().BeFalse();
        await using (var db = database.NewContext())
            (await db.AuditLog.SingleAsync(a => a.EntityType == OffboardingService.AuditEntityType)).Summary
                .Should().Contain("voided their calendar link").And.NotContain(link.Token, "the link is never written down");
        await FluentActions.Awaiting(() => Service(database).VoidCalendarLinkAsync(s.Leaver)).Should().ThrowAsync<InvalidOperationException>();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Everything_needs_Administer(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        var analyst = Service(database, new TestCurrentUser { UserId = "analyst1" });

        await FluentActions.Awaiting(() => analyst.BuildAsync(s.Leaver)).Should().ThrowAsync<ForbiddenException>();
        await FluentActions.Awaiting(() => analyst.RevokeTokensAsync(s.Leaver, [s.Token])).Should().ThrowAsync<ForbiddenException>();
        await FluentActions.Awaiting(() => analyst.VoidCalendarLinkAsync(s.Leaver)).Should().ThrowAsync<ForbiddenException>();
        await using var db = database.NewContext();
        (await db.ApiTokens.SingleAsync(t => t.Id == s.Token)).RevokedAtUtc.Should().BeNull();
        (await db.Users.SingleAsync(u => u.Id == s.Leaver)).FeedLinkIssuedAtUtc.Should().NotBeNull();
    }
}
