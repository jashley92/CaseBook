using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// RD-21: open-case tabs. Opening a case makes it a tab (kept per user, so it's there at the next sign-in); pinned cases
/// are tabs that stay, first; at most <see cref="CaseTabsService.MaxOpen"/> others, letting go of the least recently
/// seen; need-to-know scoped at read time.
/// Runs on SQLite and, when a server is configured, on SQL Server (<see cref="TestDatabase"/>).
/// </summary>
public sealed class CaseTabsServiceTests : IDisposable
{
    private TestDatabase? _db;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 5, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _me = new() { UserId = "analyst1", RoleSet = [AppRole.Analyst] };

    private AppDbContext NewContext() => _db!.NewContext();

    private CaseTabsService NewTabs() => new(_db!.Factory(), _me, _clock, new TestSlaTargets());

    private List<Guid> Seed(int n, out Guid restricted)
    {
        using var db = NewContext();
        var ids = new List<Guid>();
        for (var i = 1; i <= n; i++)
        {
            var c = Case.Open(2026, i, $"c{i}", $"Case {i}", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "ivy", _clock.UtcNow);
            db.Cases.Add(c);
            ids.Add(c.Id);
        }
        var r = Case.Open(2026, 99, "secret", "Secret", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ivy", _clock.UtcNow);
        r.IsRestricted = true;
        db.Cases.Add(r);
        restricted = r.Id;
        db.SaveChanges();
        return ids;
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Opened_cases_become_tabs_pinned_ones_stay_first_and_the_least_recent_is_let_go(string provider)
    {
        _db = TestDatabase.Open(provider);
        var ids = Seed(11, out var restricted);
        await using (var db = NewContext())
        {
            db.PinnedCases.Add(new PinnedCase { UserId = "analyst1", CaseId = ids[10], PinnedAtUtc = _clock.UtcNow });
            await db.SaveChangesAsync();
        }

        var tabs = NewTabs();
        for (var i = 0; i < 10; i++)
        {
            _clock.UtcNow = _clock.UtcNow.AddMinutes(1);
            await tabs.OpenAsync(ids[i]);
        }
        _clock.UtcNow = _clock.UtcNow.AddMinutes(1);
        await tabs.OpenAsync(ids[0]);   // looked at again: kept even though it was opened first
        await tabs.OpenAsync(restricted);   // can't see it: ignored

        var list = await tabs.ListAsync();
        list[0].CaseId.Should().Be(ids[10]);
        list[0].IsPinned.Should().BeTrue();
        list.Skip(1).Should().HaveCount(CaseTabsService.MaxOpen);
        list.Select(t => t.CaseId).Should().Contain(ids[0]).And.NotContain([ids[1], ids[2], restricted]);

        await tabs.CloseAsync(ids[0]);
        (await tabs.ListAsync()).Select(t => t.CaseId).Should().NotContain(ids[0]);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_case_that_becomes_restricted_drops_out_of_the_tabs(string provider)
    {
        _db = TestDatabase.Open(provider);
        var ids = Seed(2, out _);
        var tabs = NewTabs();
        await tabs.OpenAsync(ids[0]);
        await tabs.OpenAsync(ids[1]);
        await using (var db = NewContext())
        {
            var c = await db.Cases.FirstAsync(x => x.Id == ids[1]);
            c.IsRestricted = true;
            await db.SaveChangesAsync();
        }
        (await tabs.ListAsync()).Select(t => t.CaseId).Should().Equal(ids[0]);
    }

    public void Dispose() => _db?.Dispose();
}
