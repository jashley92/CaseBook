using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-03: the whole audit trail on <c>/integrity</c>, paged and filtered, and its CSV export. The scoping is
/// <c>ScopedAuditLog</c>'s, unchanged: a user who can't see a restricted case finds its entries in neither the page nor the
/// file. A setting's history follows its key across the rows that held it. Runs on SQLite always and on SQL Server when
/// <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class AuditTrailSearchTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 17, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _seeder = new() { UserId = "seeder", RoleSet = [AppRole.SysAdmin] };

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _seeder, _clock, new CaseChangeNotifier()));

    // Read-only: nothing here signs or exports a seal.
    private IntegrityService NewService(TestDatabase database, ICurrentUser user) =>
        new(new TestDbContextFactory(database.OptionsWithoutInterceptors), _hasher, null!, null!, user, _clock,
            new IntegrityMonitor(), new NoOpIntegrityAlerts());

    private static TestCurrentUser Analyst() => new() { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] };
    private static TestCurrentUser Admin() => new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };

    private async Task<(string Open, string Restricted)> SeedCasesAsync(TestDatabase database)
    {
        await using var db = database.NewContext();
        var open = Case.Open(2026, 1, "Open", "Ordinary matter", Classification.Incident, Severity.Medium,
            CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
        var restricted = Case.Open(2026, 2, "Secret", "Restricted matter", Classification.Breach, Severity.High,
            CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
        restricted.IsRestricted = true;
        restricted.IncidentCommander = "commander1";
        db.Cases.AddRange(open, restricted);
        await db.SaveChangesAsync();
        for (var i = 0; i < 5; i++)
        {
            _clock.UtcNow = _clock.UtcNow.AddMinutes(1);
            open.AddEventStep(_clock.UtcNow, [MitreTactic.Discovery], null, null, null, $"Open step {i}", null, "someone-else", _clock.UtcNow);
            restricted.AddEventStep(_clock.UtcNow, [MitreTactic.Discovery], null, null, null, $"Restricted step {i}", null, "commander1", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        return (open.CaseNumber, restricted.CaseNumber);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Someone_who_cant_see_a_restricted_case_finds_it_in_neither_the_page_nor_the_export(string provider)
    {
        using var database = Open(provider);
        var (open, restricted) = await SeedCasesAsync(database);
        var analyst = NewService(database, Analyst());

        var everything = new List<AuditLogEntry>();
        AuditPage page;
        var index = 0;
        do
        {
            page = await analyst.QueryPageAsync(new AuditQueryFilter(), index++, 3);
            everything.AddRange(page.Entries);
        } while (page.HasOlder);
        everything.Should().NotBeEmpty().And.OnlyContain(a => a.CaseNumber == open);
        (await analyst.QueryPageAsync(new AuditQueryFilter { CaseNumber = restricted }, 0, 100)).Entries.Should().BeEmpty();

        var csv = (await analyst.ExportCsvAsync(new AuditQueryFilter(), 100_000)).Csv;
        csv.Should().Contain(open).And.NotContain(restricted).And.NotContain("Restricted step").And.NotContain("Restricted matter");
        (await analyst.ExportCsvAsync(new AuditQueryFilter { CaseNumber = restricted }, 100_000)).Rows.Should().Be(0);

        var admin = NewService(database, Admin());
        (await admin.ExportCsvAsync(new AuditQueryFilter(), 100_000)).Csv.Should().Contain(restricted);
        var commander = NewService(database, new TestCurrentUser { UserId = "commander1", RoleSet = [AppRole.Analyst] });
        (await commander.QueryPageAsync(new AuditQueryFilter { CaseNumber = restricted }, 0, 100)).Entries.Should().NotBeEmpty();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Pages_follow_each_other_newest_first_without_a_gap_or_a_repeat(string provider)
    {
        using var database = Open(provider);
        await SeedCasesAsync(database);
        var admin = NewService(database, Admin());
        var all = await admin.QueryAsync(new AuditQueryFilter(), 10_000);

        var first = await admin.QueryPageAsync(new AuditQueryFilter(), 0, 4);
        var second = await admin.QueryPageAsync(new AuditQueryFilter(), 1, 4);
        first.HasOlder.Should().BeTrue();
        first.Entries.Concat(second.Entries).Select(a => a.Sequence).Should().Equal(all.Take(8).Select(a => a.Sequence));
        var last = await admin.QueryPageAsync(new AuditQueryFilter(), (all.Count - 1) / 4, 4);
        last.HasOlder.Should().BeFalse();
        last.Entries[^1].Sequence.Should().Be(all[^1].Sequence);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_settings_history_follows_its_key_across_the_rows_that_held_it(string provider)
    {
        using var database = Open(provider);
        await using (var db = database.NewContext())
        {
            db.AppSettings.Add(new AppSetting { Key = "Email:From", Value = "soc@contoso.example", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            db.AppSettings.Add(new AppSetting { Key = "Email:FromName", Value = "SOC", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            await db.SaveChangesAsync();
            var row = await db.AppSettings.SingleAsync(s => s.Key == "Email:From");
            row.Value = "ir@contoso.example";
            await db.SaveChangesAsync();
            db.AppSettings.Remove(row);   // Reset to default removes the row…
            await db.SaveChangesAsync();
            db.AppSettings.Add(new AppSetting { Key = "Email:From", Value = "cirt@contoso.example", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            await db.SaveChangesAsync();   // …and the next change adds a new one
            (await db.AppSettings.SingleAsync(s => s.Key == "Email:FromName")).Value = "CIRT";
            await db.SaveChangesAsync();
        }
        var admin = NewService(database, Admin());

        var history = (await admin.QueryPageAsync(new AuditQueryFilter { EntityType = nameof(AppSetting), SettingKey = "Email:From" }, 0, 100)).Entries;

        history.Select(a => a.Action).Should().Equal(AuditAction.Create, AuditAction.Delete, AuditAction.Update, AuditAction.Create);
        history.Select(a => a.EntityId).Distinct().Should().HaveCount(2, "the reset row and the one after it");
        history.Should().NotContain(a => (a.AfterJson ?? "").Contains("CIRT") || (a.AfterJson ?? "").Contains("\"SOC\""),
            "Email:FromName is another setting, though its key starts the same");
        (await admin.ExportCsvAsync(new AuditQueryFilter { SettingKey = "Email:From" }, 100_000)).Rows.Should().Be(4);
        // Configuration has no case, so only oversight sees it (as before).
        (await NewService(database, Analyst()).QueryPageAsync(new AuditQueryFilter { SettingKey = "Email:From" }, 0, 100)).Entries.Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_export_cut_at_its_limit_keeps_the_newest_and_says_so_at_the_end(string provider)
    {
        using var database = Open(provider);
        await SeedCasesAsync(database);
        var admin = NewService(database, Admin());
        var all = await admin.QueryAsync(new AuditQueryFilter(), 10_000);

        var cut = await admin.ExportCsvAsync(new AuditQueryFilter(), 3);
        cut.Truncated.Should().BeTrue();
        cut.Rows.Should().Be(3);
        var lines = cut.Csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        lines[^1].Should().Be("# Truncated at 3 rows: narrow the range to export the rest.");
        lines[^2].Should().StartWith($"{all[2].Sequence},", "the newest three are kept");

        var whole = await admin.ExportCsvAsync(new AuditQueryFilter(), all.Count);
        whole.Truncated.Should().BeFalse("exactly the limit isn't a cut");
        whole.Csv.Should().NotContain("Truncated");
    }

    private sealed class NoOpIntegrityAlerts : IIntegrityAlertNotifier
    {
        public Task OnChainBrokenAsync(ChainVerificationResult result, CancellationToken ct = default) => Task.CompletedTask;
    }
}
