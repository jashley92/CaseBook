using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.ApiTokens;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;
using IncidentManager.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// PROD-34: API-token issuance, validation, and revocation. Tokens are opaque + stored hashed; personal
/// tokens can't exceed the creator's roles; authentication rejects unknown/expired/revoked tokens; create
/// and revoke are recorded in the audit chain.
/// </summary>
public sealed class ApiTokenTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 20, 12, 0, 0, TimeSpan.Zero));

    public ApiTokenTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var _ = NewContext();
    }

    private AppDbContext NewContext()
    {
        var user = new TestCurrentUser { RoleSet = [AppRole.SysAdmin] };
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory(ICurrentUser user) =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, user, _clock, new CaseChangeNotifier()))
            .Options);

    private ApiTokenService NewService(AppDbContext db, ICurrentUser user) =>
        new(NewFactory(user), user, _clock, new FakeRoleDirectory());

    private static TestCurrentUser Admin() => new() { UserId = "admin1", DisplayName = "Admin One", RoleSet = [AppRole.SysAdmin] };
    private static TestCurrentUser Analyst() => new() { UserId = "analyst1", DisplayName = "Analyst One", RoleSet = [AppRole.Analyst] };

    /// <summary>Resolves role names to permissions from the code definitions (no DB role rows needed).</summary>
    private sealed class FakeRoleDirectory : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) =>
            RoleDefinitions.PermissionsForRoleNames(roleNames);
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
        public void Invalidate() { }
    }

    [Fact]
    public async Task A_token_is_chained_with_its_hash_in_the_same_save_and_use_isnt_audited(/* REV-05, REV-06 */)
    {
        await using var db = NewContext();
        var svc = NewService(db, Admin());
        var created = await svc.CreateSystemAsync("XSIAM", ["Analyst"], _clock.UtcNow.AddDays(30));
        var row = await db.ApiTokens.AsNoTracking().SingleAsync();

        var entry = await db.AuditLog.AsNoTracking().SingleAsync(a => a.EntityType == nameof(ApiToken) && a.EntityId == row.Id.ToString());
        entry.Action.Should().Be(AuditAction.Create);
        entry.AfterJson.Should().Contain(row.RowHash!, "the chain holds the row's hash, which the record check compares")
            .And.NotContain(row.TokenHash, "the lookup key for the secret isn't copied into the trail");

        var before = await db.AuditLog.CountAsync();
        (await svc.AuthenticateAsync(created.Plaintext)).Should().NotBeNull();
        (await db.AuditLog.CountAsync()).Should().Be(before, "a call's last-used stamp isn't an audited change");
    }

    [Fact]
    public async Task A_system_token_belongs_to_the_admins_not_to_whoever_created_it(/* REV-06 */)
    {
        await using var db = NewContext();
        var admin = Admin();
        var made = await NewService(db, admin).CreateSystemAsync("XSIAM", ["Analyst"], _clock.UtcNow.AddDays(30));

        var demoted = new TestCurrentUser { UserId = admin.UserId, DisplayName = admin.DisplayName, RoleSet = [AppRole.Analyst] };
        var svc = NewService(db, demoted);
        (await svc.ListMineAsync()).Should().BeEmpty();
        var revoke = async () => await svc.RevokeAsync(made.Token.Id);
        await revoke.Should().ThrowAsync<ForbiddenException>();
    }

    [Fact]
    public void A_generated_token_is_opaque_and_its_hash_round_trips()
    {
        var (plaintext, prefix, hash) = ApiTokenService.NewToken();
        plaintext.Should().StartWith("cbk_");
        prefix.Should().Be(plaintext[..12]);
        ApiTokenService.HashToken(plaintext).Should().Be(hash);
        hash.Should().NotContain(plaintext[4..]); // the secret isn't recoverable from the stored hash
        ApiTokenService.NewToken().Plaintext.Should().NotBe(plaintext); // random each time
    }

    [Fact]
    public async Task A_system_token_authenticates_with_its_granted_permissions_and_is_audited()
    {
        await using var db = NewContext();
        var svc = NewService(db, Admin());

        var created = await svc.CreateSystemAsync("XSIAM-Prod", ["IncidentCommander"],
            _clock.UtcNow.AddDays(30));

        var auth = await svc.AuthenticateAsync(created.Plaintext);
        auth.Should().NotBeNull();
        auth!.OwnerUserId.Should().Be("apitoken:xsiam-prod");
        auth.Permissions.Should().Contain(Permission.EditCases);

        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        chain.Should().Contain(a => a.EntityType == nameof(ApiToken) && a.Action == AuditAction.Create);
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Authentication_rejects_unknown_expired_and_revoked_tokens()
    {
        await using var db = NewContext();
        var svc = NewService(db, Admin());

        (await svc.AuthenticateAsync("cbk_not-a-real-token")).Should().BeNull();

        // Revoked
        var revoked = await svc.CreateSystemAsync("ToRevoke", ["Analyst"], _clock.UtcNow.AddDays(30));
        var revokedId = (await svc.ListAllAsync()).Single(t => t.Name == "ToRevoke").Id;
        await svc.RevokeAsync(revokedId);
        (await svc.AuthenticateAsync(revoked.Plaintext)).Should().BeNull();

        // Expired: valid now, but not after the clock passes its expiry.
        var shortLived = await svc.CreateSystemAsync("ShortLived", ["Analyst"], _clock.UtcNow.AddHours(1));
        (await svc.AuthenticateAsync(shortLived.Plaintext)).Should().NotBeNull();
        _clock.UtcNow = _clock.UtcNow.AddHours(2);
        (await svc.AuthenticateAsync(shortLived.Plaintext)).Should().BeNull();
    }

    [Fact]
    public async Task A_personal_token_cannot_grant_roles_the_user_lacks()
    {
        await using var db = NewContext();
        var analyst = Analyst();
        var svc = NewService(db, analyst);

        var tooMuch = async () => await svc.CreatePersonalAsync("mine", ["SysAdmin"], _clock.UtcNow.AddDays(30));
        await tooMuch.Should().ThrowAsync<ArgumentException>();

        var created = await svc.CreatePersonalAsync("mine", ["Analyst"], _clock.UtcNow.AddDays(30));
        var auth = await svc.AuthenticateAsync(created.Plaintext);
        auth!.OwnerUserId.Should().Be("analyst1"); // attributes to the user
        auth.Permissions.Should().Contain(Permission.EditCases);
        auth.Permissions.Should().NotContain(Permission.Administer);
    }

    [Fact]
    public async Task A_personal_token_can_carry_a_custom_role_the_user_holds()
    {
        // S-14: custom roles count as the user's own roles.
        await using var db = NewContext();
        var analyst = Analyst();
        analyst.CustomRoleNames = ["Insider Response"];
        var svc = NewService(db, analyst);

        var created = await svc.CreatePersonalAsync("mine", ["Insider Response"], _clock.UtcNow.AddDays(30));

        created.Token.Roles.Should().Equal("Insider Response");
    }

    [Fact]
    public async Task A_rejected_token_is_streamed_to_the_siem_without_the_secret()
    {
        // S-19: the real auth handler, with a capturing sink.
        await using var db = NewContext();
        var sink = new CapturingSecurityEventSink();
        var sp = new ServiceCollection()
            .AddOptions()
            .AddSingleton<ISecurityEventSink>(sink)
            .AddSingleton(NewService(db, Admin()))
            .BuildServiceProvider();

        var http = new Microsoft.AspNetCore.Http.DefaultHttpContext { RequestServices = sp };
        const string bogus = "cbk_thisIsNotARealTokenAtAll_0123456789";
        http.Request.Headers.Authorization = "Bearer " + bogus;
        http.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.1.2.3");

        var handler = new ApiKeyAuthenticationHandler(
            sp.GetRequiredService<IOptionsMonitor<AuthenticationSchemeOptions>>(),
            NullLoggerFactory.Instance, System.Text.Encodings.Web.UrlEncoder.Default);
        await handler.InitializeAsync(new AuthenticationScheme(
            ApiKeyAuthenticationHandler.SchemeName, null, typeof(ApiKeyAuthenticationHandler)), http);

        var result = await handler.AuthenticateAsync();

        result.Succeeded.Should().BeFalse();
        var e = sink.Events.Should().ContainSingle(x => x.Action == "ApiTokenRejected").Subject;
        e.EventId.Should().Be(SecurityEventIds.AuthenticationFailed);
        e.Detail.Should().Contain(bogus[..12]).And.Contain("10.1.2.3").And.NotContain(bogus[12..]);
    }

    [Fact]
    public async Task Token_lifetimes_are_capped()
    {
        // S-11: personal ≤ 90 days, system ≤ 1 year.
        await using var db = NewContext();
        await NewService(db, Analyst()).Invoking(s => s.CreatePersonalAsync("long", ["Analyst"], _clock.UtcNow.AddDays(120)))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*90 days*");
        await NewService(db, Admin()).Invoking(s => s.CreateSystemAsync("Forever", ["Analyst"], _clock.UtcNow.AddYears(3)))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*365 days*");
        (await NewService(db, Admin()).CreateSystemAsync("Annual", ["Analyst"], _clock.UtcNow.AddDays(365))).Plaintext
            .Should().StartWith("cbk_");
    }

    private sealed class MirrorDirectory : IUserDirectory
    {
        public Dictionary<string, string> Roles { get; } = new();
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => [];
        public UserSummary? Resolve(string userId) =>
            Roles.TryGetValue(userId, out var csv) ? new UserSummary(userId, userId, null, null, csv) : null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }

    [Fact]
    public async Task A_personal_token_only_carries_roles_its_owner_still_holds()
    {
        // S-11: token roles are intersected with the owner's current roles (the user mirror).
        await using var db = NewContext();
        var mirror = new MirrorDirectory();
        mirror.Roles["analyst1"] = "Analyst,IncidentCommander";
        var owner = Analyst();
        owner.RoleSet = [AppRole.Analyst, AppRole.IncidentCommander];
        var svc = new ApiTokenService(NewFactory(owner), owner, _clock, new FakeRoleDirectory(), users: mirror);
        var created = await svc.CreatePersonalAsync("mine", ["Analyst", "IncidentCommander"], _clock.UtcNow.AddDays(30));

        (await svc.AuthenticateAsync(created.Plaintext))!.Permissions.Should().Contain(Permission.ApproveReports);

        mirror.Roles["analyst1"] = "Analyst";   // lost Incident Commander in AD
        var auth = await svc.AuthenticateAsync(created.Plaintext);
        auth!.Permissions.Should().Contain(Permission.EditCases).And.NotContain(Permission.ApproveReports);

        mirror.Roles["analyst1"] = "";          // no CaseBook roles left
        (await svc.AuthenticateAsync(created.Plaintext)).Should().BeNull();

        mirror.Roles.Remove("analyst1");        // unknown to the directory
        (await svc.AuthenticateAsync(created.Plaintext)).Should().BeNull();
    }

    [Fact]
    public async Task Only_an_admin_can_create_a_system_token()
    {
        await using var db = NewContext();
        var svc = NewService(db, Analyst());
        var act = async () => await svc.CreateSystemAsync("Nope", ["Analyst"], _clock.UtcNow.AddDays(30));
        await act.Should().ThrowAsync<ForbiddenException>();
    }

    [Fact]
    public async Task Only_an_admin_can_list_every_token()
    {
        // Administration → API tokens requires Administer; the service asserts it too, for any other caller.
        await using var db = NewContext();
        await NewService(db, Admin()).CreateSystemAsync("Integration", ["Analyst"], _clock.UtcNow.AddDays(30));

        var manager = new TestCurrentUser { UserId = "mgr1", RoleSet = [AppRole.Manager] };
        await NewService(db, manager).Invoking(s => s.ListAllAsync()).Should().ThrowAsync<ForbiddenException>();
        (await NewService(db, Admin()).ListAllAsync()).Should().ContainSingle(t => t.Name == "Integration");
    }

    [Fact]
    public async Task Expiry_must_be_in_the_future()
    {
        await using var db = NewContext();
        var svc = NewService(db, Admin());
        var act = async () => await svc.CreateSystemAsync("Past", ["Analyst"], _clock.UtcNow.AddDays(-1));
        await act.Should().ThrowAsync<ArgumentException>();
    }

    /// <summary>Maps the group "SOC-Commanders" to Analyst + IncidentCommander and "SOC-Analysts" to Analyst.</summary>
    private sealed class GroupRoleDirectory : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) => RoleDefinitions.PermissionsForRoleNames(roleNames);
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var g in adGroups)
            {
                if (g == "S-1-5-21-COMMANDERS") { set.Add("Analyst"); set.Add("IncidentCommander"); }
                if (g == "S-1-5-21-ANALYSTS") set.Add("Analyst");
            }
            return set;
        }
        public void Invalidate() { }
    }

    [Fact]
    public async Task A_personal_token_follows_its_owners_account_in_AD()
    {
        // BUG-20: the mirror only moves when the owner signs in, so a leaver kept their roles on their tokens for up to 90 days.
        await using var db = NewContext();
        AdTokenOwnerCheck.AccountGroups? account = new(true, ["S-1-5-21-COMMANDERS"]);
        var lookups = 0;
        var adDown = false;
        var ad = new AdTokenOwnerCheck(new GroupRoleDirectory(), _clock, lookup: _ =>
        {
            lookups++;
            if (adDown) throw new InvalidOperationException("The server is not operational.");
            return account;
        });
        var owner = Analyst();
        owner.RoleSet = [AppRole.Analyst, AppRole.IncidentCommander];
        var svc = new ApiTokenService(NewFactory(owner), owner, _clock, new FakeRoleDirectory(), users: new MirrorDirectory(), owners: ad);
        var token = (await svc.CreatePersonalAsync("mine", ["Analyst", "IncidentCommander"], _clock.UtcNow.AddDays(30))).Plaintext;

        (await svc.AuthenticateAsync(token))!.Permissions.Should().Contain(Permission.ApproveReports);

        // Removed from the commanders group: once the cached answer is stale, the token keeps Analyst only.
        account = new(true, ["S-1-5-21-ANALYSTS"]);
        (await svc.AuthenticateAsync(token))!.Permissions.Should().Contain(Permission.ApproveReports, "the answer is reused for 15 minutes");
        lookups.Should().Be(1);
        _clock.UtcNow += AdTokenOwnerCheck.Fresh;
        (await svc.AuthenticateAsync(token))!.Permissions.Should().Contain(Permission.EditCases).And.NotContain(Permission.ApproveReports);

        // AD unreachable: the last answer stands for up to a day, then the token is refused rather than trusted.
        adDown = true;
        _clock.UtcNow += AdTokenOwnerCheck.Fresh;
        (await svc.AuthenticateAsync(token)).Should().NotBeNull();
        _clock.UtcNow += AdTokenOwnerCheck.LastKnownLimit;
        (await svc.AuthenticateAsync(token)).Should().BeNull();

        // Disabled in AD: refused.
        adDown = false;
        account = new(false, ["S-1-5-21-ANALYSTS"]);
        (await svc.AuthenticateAsync(token)).Should().BeNull();
    }

    public void Dispose() => _connection.Dispose();
}
