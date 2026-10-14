using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Accounts;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Security;
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
/// BUG-416: an account's directory details. Kept when it's added (best effort), looked up again on request, and kept
/// again only when asked; every kept snapshot is append-only and passes the record check.
/// </summary>
public sealed class AccountDirectoryTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };
    private readonly FakeDirectory _directory = new();

    public AccountDirectoryTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    public void Dispose() => _connection.Dispose();

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
        return db;
    }

    private AccountDirectoryService NewService() => new(new TestDbContextFactory(Options()), _user, _clock, _directory);

    private async Task<(Guid CaseId, Guid Account, Guid Email, Guid Ip)> SeedAsync()
    {
        await using var db = NewContext();
        var cases = new CaseService(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
        var c = await cases.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Acct", Title = "Account case", Classification = Classification.Incident,
            Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
        });
        var account = (await cases.AddOrMatchEntityAsync(c.Id, EntityType.Account, "CONTOSO\\jdoe", null, EntityDisposition.Unknown, null, null)).Id;
        var email = (await cases.AddOrMatchEntityAsync(c.Id, EntityType.EmailAddress, "someone@elsewhere.example", null, EntityDisposition.Unknown, null, null)).Id;
        var ip = (await cases.AddOrMatchEntityAsync(c.Id, EntityType.IpAddress, "203.0.113.5", null, EntityDisposition.Unknown, null, null)).Id;
        return (c.Id, account, email, ip);
    }

    private static DirectoryAccount Jdoe(bool enabled = true) => new("jdoe", "CONTOSO", "jdoe@contoso.example", "Jordan Doe", "Analyst",
        "Finance", "Rivera, Sam", "jordan.doe@contoso.example", "CN=Jordan Doe,DC=contoso", enabled, false, null,
        new DateTimeOffset(2026, 10, 13, 9, 0, 0, TimeSpan.Zero), null, null);

    [Fact]
    public async Task Accounts_added_are_kept_as_the_directory_has_them_and_others_are_skipped()
    {
        var (caseId, account, email, ip) = await SeedAsync();
        _directory.Accounts["CONTOSO\\jdoe"] = Jdoe();

        var taken = await NewService().CaptureOnAddAsync(caseId, [account, email, ip]);

        taken.Should().Be(1, "the email address isn't in the directory, and an IP isn't an account");
        var kept = (await NewService().SnapshotsAsync(caseId, account)).Should().ContainSingle().Subject;
        kept.Trigger.Should().Be(DirectorySnapshotTrigger.Added);
        kept.Found.Should().BeTrue();
        kept.DisplayName.Should().Be("Jordan Doe");
        kept.Enabled.Should().BeTrue();
        kept.CreatedBy.Should().Be(_user.UserId);
        (await NewService().SnapshotsAsync(caseId, email)).Should().BeEmpty();
    }

    [Fact]
    public async Task An_account_the_directory_doesnt_have_is_kept_as_not_found_but_an_unreachable_directory_keeps_nothing()
    {
        var (caseId, account, _, _) = await SeedAsync();

        (await NewService().CaptureOnAddAsync(caseId, [account])).Should().Be(1);
        (await NewService().SnapshotsAsync(caseId, account)).Should().ContainSingle().Which.Found.Should().BeFalse();

        _directory.Down = true;
        (await NewService().CaptureOnAddAsync(caseId, [account])).Should().Be(0);
        (await NewService().SnapshotsAsync(caseId, account)).Should().HaveCount(1);
    }

    [Fact]
    public async Task A_fresh_lookup_is_shown_and_kept_only_when_asked_and_every_snapshot_passes_the_record_check()
    {
        var (caseId, account, _, _) = await SeedAsync();
        _directory.Accounts["CONTOSO\\jdoe"] = Jdoe();
        await NewService().CaptureOnAddAsync(caseId, [account]);

        _directory.Accounts["CONTOSO\\jdoe"] = Jdoe(enabled: false);
        _clock.UtcNow = _clock.UtcNow.AddHours(3);
        var live = await NewService().LookupAsync(caseId, account);
        live.Account!.Enabled.Should().BeFalse();
        (await NewService().SnapshotsAsync(caseId, account)).Should().HaveCount(1, "looking up keeps nothing");

        await NewService().SaveAsync(caseId, account, live);

        var all = await NewService().SnapshotsAsync(caseId, account);
        all.Should().HaveCount(2);
        all[0].Trigger.Should().Be(DirectorySnapshotTrigger.Requested);
        all[0].Enabled.Should().BeFalse("the newest first");
        all[1].Enabled.Should().BeTrue("the snapshot taken when it was added is kept as it was");

        await using var db = NewContext();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        (await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain)).Should().BeNull();
    }

    [Fact]
    public async Task Lookups_are_refused_for_non_accounts_and_keeping_needs_edit_rights_and_a_real_answer()
    {
        var (caseId, account, _, ip) = await SeedAsync();

        await NewService().Invoking(s => s.LookupAsync(caseId, ip)).Should().ThrowAsync<InvalidOperationException>();
        await NewService().Invoking(s => s.SaveAsync(caseId, account, DirectoryLookup.Unavailable("down")))
            .Should().ThrowAsync<InvalidOperationException>();

        _user.PermissionSet = [Permission.ViewCases];   // a viewer
        await NewService().Invoking(s => s.SaveAsync(caseId, account, DirectoryLookup.NotFound))
            .Should().ThrowAsync<ForbiddenException>();
        (await NewService().CaptureOnAddAsync(caseId, [account])).Should().Be(0, "a viewer adds nothing");
    }

    [Fact]
    public async Task A_bare_name_is_an_account_only_when_the_directory_knows_it()
    {
        _directory.Accounts["jdoe"] = Jdoe();
        (await NewService().IsKnownAccountAsync("jdoe")).Should().BeTrue();
        (await NewService().IsKnownAccountAsync("wks-hr-14")).Should().BeFalse();
        (await NewService().IsKnownAccountAsync("a name with spaces")).Should().BeFalse();
        _directory.Down = true;
        (await NewService().IsKnownAccountAsync("jdoe")).Should().BeFalse();
    }

    private sealed class FakeDirectory : IAccountDirectory
    {
        public Dictionary<string, DirectoryAccount> Accounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool Down { get; set; }
        public bool IsAvailable => true;

        public Task<DirectoryLookup> LookupAsync(string account, CancellationToken ct = default) => Task.FromResult(
            Down ? DirectoryLookup.Unavailable("down")
            : Accounts.TryGetValue(account, out var a) ? DirectoryLookup.Of(a) : DirectoryLookup.NotFound);
    }
}
