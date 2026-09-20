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
        new(NewFactory(user), user, _clock, new FakeRoleDirectory(),
            new AuditWriter(db, _hasher, user, _clock));

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
    public async Task Only_an_admin_can_create_a_system_token()
    {
        await using var db = NewContext();
        var svc = NewService(db, Analyst());
        var act = async () => await svc.CreateSystemAsync("Nope", ["Analyst"], _clock.UtcNow.AddDays(30));
        await act.Should().ThrowAsync<ForbiddenException>();
    }

    [Fact]
    public async Task Expiry_must_be_in_the_future()
    {
        await using var db = NewContext();
        var svc = NewService(db, Admin());
        var act = async () => await svc.CreateSystemAsync("Past", ["Analyst"], _clock.UtcNow.AddDays(-1));
        await act.Should().ThrowAsync<ArgumentException>();
    }

    public void Dispose() => _connection.Dispose();
}
