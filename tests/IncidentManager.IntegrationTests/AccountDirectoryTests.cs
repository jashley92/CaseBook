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
    public async Task Adding_an_account_through_the_case_keeps_its_directory_details()
    {
        _directory.Accounts["CONTOSO\\asmith"] = Jdoe() with { SamAccountName = "asmith", DisplayName = "Alex Smith" };
        await using var db = NewContext();
        var cases = new CaseService(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            accounts: NewService());
        var c = await cases.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Acct2", Title = "Account case", Classification = Classification.Incident,
            Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
        });

        var one = (await cases.AddOrMatchEntityAsync(c.Id, EntityType.Account, "CONTOSO\\asmith", null, EntityDisposition.Unknown, null, null)).Id;
        var pasted = await cases.AddOrMatchEntitiesAsync(c.Id,
            [new CaseService.EntityToAdd(EntityType.Account, "CONTOSO\\nobody", null, EntityDisposition.Unknown, null, null),
             new CaseService.EntityToAdd(EntityType.IpAddress, "203.0.113.9", null, EntityDisposition.Unknown, null, null)]);
        await cases.AddOrMatchEntityAsync(c.Id, EntityType.Account, "CONTOSO\\asmith", null, EntityDisposition.Unknown, null, null);

        (await NewService().SnapshotsAsync(c.Id, one)).Should().ContainSingle("adding it again takes no second snapshot")
            .Which.DisplayName.Should().Be("Alex Smith");
        (await NewService().SnapshotsAsync(c.Id, pasted[0].Id)).Should().ContainSingle().Which.Found.Should().BeFalse();
    }

    [Fact]
    public async Task An_account_copied_by_a_supersede_keeps_its_directory_details_on_the_kept_case(/* BUG-493 */)
    {
        _directory.Accounts["CONTOSO\\asmith"] = Jdoe() with { SamAccountName = "asmith", DisplayName = "Alex Smith" };
        await using var db = NewContext();
        var cases = new CaseService(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            accounts: NewService());
        Task<IncidentManager.Domain.Entities.Case> Open(string name) => cases.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = name, Title = "Account case", Classification = Classification.Incident,
            Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
        });
        var dup = await Open("Dup");
        var kept = await Open("Kept");
        await cases.AddOrMatchEntityAsync(dup.Id, EntityType.Account, "CONTOSO\\asmith", null, EntityDisposition.Compromised, null, null);
        await cases.AddOrMatchEntityAsync(dup.Id, EntityType.Account, "CONTOSO\\jdoe", null, EntityDisposition.Unknown, null, null);
        await cases.AddOrMatchEntityAsync(dup.Id, EntityType.IpAddress, "203.0.113.9", null, EntityDisposition.Unknown, null, null);
        var already = (await cases.AddOrMatchEntityAsync(kept.Id, EntityType.Account, "CONTOSO\\jdoe", null, EntityDisposition.Unknown, null, null)).Id;
        _directory.Asked.Clear();

        var result = await cases.SupersedeAsync(dup.Id, kept.Id, copyIndicators: true, "Same sign-ins");

        result.IndicatorsCopied.Should().Be(2);
        var copy = (await cases.GetDetailAsync(kept.Id))!.Entities.Single(e => e.Value == "CONTOSO\\asmith");
        (await NewService().SnapshotsAsync(kept.Id, copy.Id)).Should().ContainSingle()
            .Which.DisplayName.Should().Be("Alex Smith");
        (await NewService().SnapshotsAsync(kept.Id, already)).Should().ContainSingle("one already on the kept case isn't looked up again");
        _directory.Asked.Should().Equal(["CONTOSO\\asmith"]);
    }

    [Fact]
    public async Task A_supersede_is_saved_when_the_directory_is_down(/* BUG-493 */)
    {
        await using var db = NewContext();
        var cases = new CaseService(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            accounts: NewService());
        Task<IncidentManager.Domain.Entities.Case> Open(string name) => cases.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = name, Title = "Account case", Classification = Classification.Incident,
            Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
        });
        var dup = await Open("Dup");
        var kept = await Open("Kept");
        await cases.AddOrMatchEntityAsync(dup.Id, EntityType.Account, "CONTOSO\\asmith", null, EntityDisposition.Unknown, null, null);
        _directory.Down = true;

        (await cases.SupersedeAsync(dup.Id, kept.Id, copyIndicators: true, "Same sign-ins")).IndicatorsCopied.Should().Be(1);

        var copy = (await cases.GetDetailAsync(kept.Id))!.Entities.Single(e => e.Value == "CONTOSO\\asmith");
        (await NewService().SnapshotsAsync(kept.Id, copy.Id)).Should().BeEmpty();
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

    private CaseService Cases(AppDbContext db) => new(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db),
        new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(),
        new TestSlaTargets(), accounts: NewService());

    private static CaseService.EntityToAdd Account(string value) =>
        new(EntityType.Account, value, null, EntityDisposition.Unknown, null, null);

    [Fact]
    public async Task Capture_stops_at_the_first_unavailable_answer_and_skips_accounts_it_doesnt_look_up(/* BUG-419, BUG-420 */)
    {
        var (caseId, _, _, _) = await SeedAsync();
        await using var db = NewContext();
        _directory.Accounts["CONTOSO\\found"] = Jdoe();
        _directory.NotAsked.Add("EVIL\\svc");
        _directory.DownFor.Add("CONTOSO\\broken");

        var added = await Cases(db).AddOrMatchEntitiesAsync(caseId,
            [Account("EVIL\\svc"), Account("CONTOSO\\found"), Account("CONTOSO\\broken"), Account("CONTOSO\\later1"), Account("CONTOSO\\later2")]);

        added.Should().HaveCount(5);
        _directory.Asked.Should().Equal(["EVIL\\svc", "CONTOSO\\found", "CONTOSO\\broken"],
            "a skipped account doesn't stop the capture; an unavailable directory isn't asked again for the rest of the add");
        (await db.AccountDirectorySnapshots.AsNoTracking().Select(s => s.LookedUp).ToListAsync())
            .Should().Equal(["CONTOSO\\found"], "an account that wasn't looked up isn't kept as 'not found'");
    }

    [Fact]
    public async Task Capture_keeps_what_it_took_when_the_add_runs_out_of_time(/* BUG-420 */)
    {
        var (caseId, account, _, _) = await SeedAsync();
        var hang = (await SeedEntityAsync(caseId, "CONTOSO\\hangs")).Id;
        _directory.Hang.Add("CONTOSO\\hangs");

        var started = DateTime.UtcNow;
        var taken = await NewService().CaptureOnAddAsync(caseId, [account, hang],
            new AccountDirectoryService.CaptureAllowance(TimeSpan.FromMilliseconds(300)));

        (DateTime.UtcNow - started).Should().BeLessThan(TimeSpan.FromSeconds(10));
        _directory.Asked.Should().Equal("CONTOSO\\jdoe", "CONTOSO\\hangs");
        taken.Should().Be(1, "what was looked up before the time ran out is kept");
        (await NewService().SnapshotsAsync(caseId, account)).Should().ContainSingle();
    }

    [Fact]
    public async Task Accounts_saved_before_a_later_batch_failed_are_still_captured(/* BUG-429 */)
    {
        var (caseId, _, _, _) = await SeedAsync();
        await using var db = NewContext();
        var first = Enumerable.Range(0, CaseService.EntitiesPerSave - 1)
            .Select(i => new CaseService.EntityToAdd(EntityType.IpAddress, $"198.51.100.{i % 250}", null, EntityDisposition.Unknown, null, $"s{i}"))
            .Prepend(Account("CONTOSO\\firstbatch"));
        var items = first.Append(Account("   ")).ToList();   // the second batch fails

        await Cases(db).Invoking(c => c.AddOrMatchEntitiesAsync(caseId, items)).Should().ThrowAsync<ArgumentException>();

        (await db.AccountDirectorySnapshots.AsNoTracking().CountAsync(s => s.LookedUp == "CONTOSO\\firstbatch")).Should().Be(1);
    }

    [Fact]
    public async Task A_lookup_is_kept_only_for_the_value_it_was_made_for(/* BUG-432 */)
    {
        var (caseId, account, _, _) = await SeedAsync();
        _directory.Accounts["CONTOSO\\jdoe"] = Jdoe();
        var live = await NewService().LookupAsync(caseId, account);
        live.LookedUp.Should().Be("CONTOSO\\jdoe");

        await using (var db = NewContext())
            await db.CaseEntities.Where(e => e.Id == account).ExecuteUpdateAsync(s => s.SetProperty(e => e.Value, "CONTOSO\\asmith"));

        await NewService().Invoking(s => s.SaveAsync(caseId, account, live)).Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*changed since it was looked up*");
        await NewService().Invoking(s => s.SaveAsync(caseId, account, DirectoryLookup.Of(Jdoe())))
            .Should().ThrowAsync<InvalidOperationException>("a lookup that doesn't say what it was for isn't kept");
        (await NewService().SnapshotsAsync(caseId, account)).Should().BeEmpty();

        _directory.NotAsked.Add("CONTOSO\\asmith");
        var notAsked = await NewService().LookupAsync(caseId, account);
        await NewService().Invoking(s => s.SaveAsync(caseId, account, notAsked)).Should().ThrowAsync<InvalidOperationException>();
    }

    private async Task<IncidentManager.Domain.Entities.CaseEntity> SeedEntityAsync(Guid caseId, string value)
    {
        await using var db = NewContext();
        var c = await db.Cases.Include(x => x.Entities).FirstAsync(x => x.Id == caseId);
        var e = c.AddEntity(EntityType.Account, value, null, EntityDisposition.Unknown, null, null, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync();
        return e;
    }

    private sealed class FakeDirectory : IAccountDirectory
    {
        public Dictionary<string, DirectoryAccount> Accounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool Down { get; set; }
        public HashSet<string> DownFor { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> NotAsked { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Hang { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Asked { get; } = [];
        public bool IsAvailable => true;

        public async Task<DirectoryLookup> LookupAsync(string account, CancellationToken ct = default)
        {
            Asked.Add(account);
            if (Hang.Contains(account)) await Task.Delay(Timeout.Infinite, ct);
            return Down || DownFor.Contains(account) ? DirectoryLookup.Unavailable("down")
                : NotAsked.Contains(account) ? DirectoryLookup.NotLookedUp("not ours")
                : Accounts.TryGetValue(account, out var a) ? DirectoryLookup.Of(a) : DirectoryLookup.NotFound;
        }
    }
}
