using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
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

public sealed class AccessReviewTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 11, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };

    public AccessReviewTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
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

    [Fact]
    public async Task Only_an_administrator_can_build_the_review(/* BUG-22 */)
    {
        var analyst = new TestCurrentUser { UserId = "an1", RoleSet = [AppRole.Analyst] };
        await new AccessReviewService(NewFactory(), _clock, analyst).Invoking(s => s.BuildAsync())
            .Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
    }

    [Fact]
    public async Task Reports_broad_access_roles_and_restricted_cases()
    {
        await using (var db = NewContext())
        {
            await RoleSeeder.SeedAsync(db, _clock, new RoleMappingOptions
            {
                Groups = new()
                {
                    ["Manager"] = ["SOC-Leadership"],
                    ["SysAdmin"] = ["SOC-AppAdmins"],
                    ["Analyst"] = ["SOC-Analysts"]
                }
            });

            var restricted = Case.Open(2026, 1, "Restricted Matter", "Sensitive",
                Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "system", _clock.UtcNow);
            restricted.IsRestricted = true;
            restricted.Assign("ic-uid", "Alice IC", CaseAssignmentRole.IncidentCommander, "system", _clock.UtcNow);
            restricted.Assign("an-uid", "Bob Analyst", CaseAssignmentRole.Analyst, "system", _clock.UtcNow);
            db.Cases.Add(restricted);

            var open = Case.Open(2026, 2, "Open Matter", "Public",
                Classification.AdverseEvent, Severity.Low, CaseOrigin.InternalDetection, "system", _clock.UtcNow);
            db.Cases.Add(open);

            // REV-58: archived, but its commander can still open it.
            var archived = Case.Open(2026, 3, "Archived Matter", "Old and sensitive",
                Classification.Incident, Severity.Low, CaseOrigin.InternalDetection, "system", _clock.UtcNow);
            archived.IsRestricted = true;
            archived.Assign("ic-uid", "Alice IC", CaseAssignmentRole.IncidentCommander, "system", _clock.UtcNow);
            archived.Archive("system", _clock.UtcNow);
            db.Cases.Add(archived);

            // PROD-14: the sign-in mirror — one active user, one idle past the dormancy threshold.
            db.Users.Add(new AppUser { Sid = "an-uid", DisplayName = "Bob Analyst", UserPrincipalName = "bob@corp",
                RolesCsv = "Analyst", LastSeenUtc = _clock.UtcNow.AddDays(-2) });
            db.Users.Add(new AppUser { Sid = "old-uid", DisplayName = "Old Manager", RolesCsv = "Manager, IncidentCommander",
                LastSeenUtc = _clock.UtcNow - AccessReviewService.DormantAfter - TimeSpan.FromDays(1) });

            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var review = await new AccessReviewService(NewFactory(), _clock, _user).BuildAsync();

            // Broad access: roles with ViewAllCases / ViewRestricted, with their AD groups.
            review.Broad.Should().Contain(b => b.RoleName == "Manager" && b.ViewAllCases);
            review.Broad.Single(b => b.RoleName == "Manager").Groups.Should().Contain("SOC-Leadership");
            review.Broad.Should().Contain(b => b.RoleName == "IncidentCommander" && b.ViewRestricted && !b.ViewAllCases);
            review.Broad.Should().NotContain(b => b.RoleName == "Analyst"); // neither capability

            // The restricted cases appear with their need-to-know grantees, archived ones too (REV-58), after the rest.
            review.RestrictedCases.Should().HaveCount(2);
            review.RestrictedCases[1].IsArchived.Should().BeTrue();
            review.RestrictedCases[1].IncidentCommander.Should().Be("ic-uid");
            var rc = review.RestrictedCases[0];
            rc.CaseNumber.Should().Contain("Restricted");
            rc.IncidentCommander.Should().Be("ic-uid");
            rc.Assignees.Should().Contain("Bob Analyst");

            // Known users: dormant first, roles split from the sign-in snapshot.
            review.KnownUsers.Select(u => (u.DisplayName, u.IsDormant)).Should().Equal(
                ("Old Manager", true), ("Bob Analyst", false));
            review.KnownUsers[0].Roles.Should().Equal("Manager", "IncidentCommander");
            review.KnownUsers[1].UserPrincipalName.Should().Be("bob@corp");
        }
    }

    // --- CAP-15: API tokens, the CSV, recording the review and its reminder ------------------------------------------

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private AccessReviewService Review(TestDatabase database, ICurrentUser? user = null, int reminderDays = 90)
    {
        user ??= _user;
        return new AccessReviewService(database.Factory(), _clock, user, audit: new AuditWriter(database.Factory(), _hasher, user, _clock),
            options: new TestOptionsMonitor<AccessReviewOptions>(new AccessReviewOptions { ReminderDays = reminderDays }));
    }

    private ApiToken Token(string name, ApiTokenKind kind, DateTimeOffset expires, DateTimeOffset? revoked = null, DateTimeOffset? used = null) => new()
    {
        Name = name, Kind = kind, OwnerUserId = kind == ApiTokenKind.System ? "apitoken:" + name.ToLowerInvariant() : "an-uid",
        OwnerDisplayName = kind == ApiTokenKind.System ? name : "Bob Analyst", RolesCsv = "Analyst", TokenHash = Guid.NewGuid().ToString("N"),
        Prefix = "cb_" + name[..3].ToLowerInvariant(), CreatedBy = "admin1", CreatedAtUtc = _clock.UtcNow.AddDays(-30), ExpiresAtUtc = expires,
        RevokedAtUtc = revoked, RevokedBy = revoked is null ? null : "admin1", LastUsedAtUtc = used,
    };

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_review_lists_the_api_tokens_that_work_now(string provider)
    {
        using var database = Open(provider);
        await using (var db = database.NewContext())
        {
            await RoleSeeder.SeedAsync(db, _clock, new RoleMappingOptions());
            db.ApiTokens.AddRange(
                Token("Xsiam", ApiTokenKind.System, _clock.UtcNow.AddDays(60), used: _clock.UtcNow.AddHours(-1)),
                Token("Laptop", ApiTokenKind.Personal, _clock.UtcNow.AddDays(10)),
                Token("Revoked", ApiTokenKind.System, _clock.UtcNow.AddDays(60), revoked: _clock.UtcNow.AddDays(-1)),
                Token("Expired", ApiTokenKind.System, _clock.UtcNow.AddDays(-1)));
            await db.SaveChangesAsync();
        }

        var review = await Review(database).BuildAsync();

        review.ApiTokens.Select(t => (t.Name, t.Kind)).Should().Equal(("Laptop", ApiTokenKind.Personal), ("Xsiam", ApiTokenKind.System));
        var laptop = review.ApiTokens[0];
        (laptop.Owner, laptop.Prefix, laptop.LastUsedAtUtc).Should().Be(("Bob Analyst", "cb_lap", null));
        laptop.Roles.Should().Equal("Analyst");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Recording_the_review_writes_an_audit_entry_that_reads_back_as_the_last_review(string provider)
    {
        using var database = Open(provider);
        (await Review(database).GetLastReviewAsync()).Should().BeNull();

        var first = await Review(database).RecordReviewAsync("  Checked roles, groups and tokens; removed one leaver.  ");
        _clock.UtcNow = _clock.UtcNow.AddDays(1);
        var second = await Review(database).RecordReviewAsync("Follow-up: the leaver's token is revoked.");

        first.Note.Should().Be("Checked roles, groups and tokens; removed one leaver.", "trimmed");
        (second.AtUtc, second.ReviewerId, second.Note).Should().Be((_clock.UtcNow, "admin1", "Follow-up: the leaver's token is revoked."));
        (await Review(database).GetLastReviewAsync()).Should().Be(second, "the newest is the last review");

        await using var db = database.NewContext();
        var entries = await db.AuditLog.Where(a => a.EntityType == AccessReviewService.AuditEntityType).OrderBy(a => a.Sequence).ToListAsync();
        entries.Should().HaveCount(2);
        entries.Should().OnlyContain(e => e.Action == AuditAction.Create && e.Actor == "admin1" && e.CaseNumber == null);
        entries[0].Summary.Should().Be("Access review recorded: Checked roles, groups and tokens; removed one leaver.");
        _hasher.VerifyChain(await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue("chained like every entry");
        (await db.Cases.CountAsync()).Should().Be(0, "not case data");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_review_needs_a_note_within_the_limit_and_an_administrator(string provider)
    {
        using var database = Open(provider);
        var analyst = new TestCurrentUser { UserId = "an1", RoleSet = [AppRole.Analyst] };

        await Review(database).Invoking(r => r.RecordReviewAsync("   ")).Should().ThrowAsync<ArgumentException>();
        await Review(database).Invoking(r => r.RecordReviewAsync(new string('x', AccessReviewService.MaxNoteLength + 1)))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*1,000*");
        await Review(database, analyst).Invoking(r => r.RecordReviewAsync("I looked"))
            .Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
        await Review(database, analyst).Invoking(r => r.GetLastReviewAsync())
            .Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();

        (await Review(database).RecordReviewAsync(new string('x', AccessReviewService.MaxNoteLength))).Note
            .Should().HaveLength(AccessReviewService.MaxNoteLength, "the longest note is kept whole");
    }

    [Fact]
    public void The_reminder_is_due_after_the_interval_or_when_none_was_recorded_and_off_at_zero()
    {
        var now = _clock.UtcNow;
        var last = new AccessReviewRecord(now.AddDays(-89), "admin1", "Admin One", "done");

        AccessReviewService.ReminderFor(null, 90, now).Should().Be(new AccessReviewReminder(false, true, null), "none recorded: due now");
        AccessReviewService.ReminderFor(last, 90, now).Should().Be(new AccessReviewReminder(false, false, now.AddDays(1)));
        AccessReviewService.ReminderFor(last with { AtUtc = now.AddDays(-90) }, 90, now).Due.Should().BeTrue("due on the day");
        AccessReviewService.ReminderFor(last, 30, now).Due.Should().BeTrue();
        AccessReviewService.ReminderFor(null, 0, now).Should().Be(new AccessReviewReminder(true, false, null), "0 turns it off");
        AccessReviewService.ReminderFor(last with { AtUtc = DateTimeOffset.MaxValue.AddDays(-1) }, 1_000_000, now).Due
            .Should().BeFalse("C12: a huge interval is capped, not an overflow");
        new AccessReviewService(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().Options), _clock, _user,
            options: new TestOptionsMonitor<AccessReviewOptions>(new AccessReviewOptions { ReminderDays = 99_999 })).ReminderDays
            .Should().Be(AccessReviewService.MaxReminderDays);
        new AccessReviewOptions().ReminderDays.Should().Be(90, "the default");
        SettingsCatalog.Editable.Single(d => d.Key == "Governance:AccessReview:ReminderDays").Default.Should().Be("90");
    }

    [Fact]
    public void The_csv_has_a_row_per_role_case_user_and_token_with_formulas_neutralized()
    {
        var review = new AccessReview(
            [new BroadAccessRow("Manager", true, false, ["=HYPERLINK(\"x\")"]), new BroadAccessRow("Legal", false, true, [])],
            [new RestrictedCaseRow("2026-01_Restricted", "Sensitive, \"quoted\"", "ic-uid", ["Bob Analyst", "Ann"], IsArchived: true)],
            [new KnownUserRow("Old Manager", null, ["Manager"], _clock.UtcNow.AddDays(-120), true)],
            [new ApiTokenReviewRow("Xsiam", ApiTokenKind.System, "Xsiam", "cb_xsi", ["Analyst", "Importer"], _clock.UtcNow.AddDays(-30),
                _clock.UtcNow.AddDays(60), null)]);
        var last = new AccessReviewRecord(_clock.UtcNow.AddDays(-3), "admin1", "Admin One", "Checked,\nall of it");

        var lines = AccessReviewService.ToCsv(review, last, _clock.UtcNow).Split("\r\n");

        lines[0].Should().StartWith("# CaseBook access review, generated 2026-08-11 00:00 UTC");
        lines[1].Should().Be("\"# Last recorded review: 2026-08-08 00:00 by Admin One: Checked, all of it\"", "the free-text note is one field");
        lines[2].Should().Be("section,subject,detail,access,via,last_seen_utc,expires_utc,flag");
        lines.Should().Contain("Broad access,Manager,,All cases,\"'=HYPERLINK(\"\"x\"\")\",,,", "C13: an AD group named like a formula stays text");
        lines.Should().Contain("Broad access,Legal,,Restricted cases,,,,No AD group mapped");
        lines.Should().Contain("Restricted case,2026-01_Restricted,\"Sensitive, \"\"quoted\"\"\",Incident commander: ic-uid,Bob Analyst; Ann,,,Archived");
        lines.Should().Contain("Known user,Old Manager,,Manager,,2026-04-13 00:00,,Dormant");
        lines.Should().Contain("API token,Xsiam,\"System token of Xsiam, starting cb_xsi\",Analyst; Importer,,,2026-10-10 00:00,Never used");
        AccessReviewService.ToCsv(review with { ApiTokens = [] }, null, _clock.UtcNow).Should().Contain("# Last recorded review: none");
    }

    public void Dispose() => _connection.Dispose();
}
