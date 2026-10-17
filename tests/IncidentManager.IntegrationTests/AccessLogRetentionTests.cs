using FluentAssertions;
using IncidentManager.Application.Access;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// PROD-52: the access log is kept for Retention:AccessLogYears and older entries are deleted, except those of a case
/// under a legal hold. The deletion is recorded in the audit trail, which stays intact. On both providers, since the
/// prune is a batched bulk delete.
/// </summary>
public sealed class AccessLogRetentionTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 17, 3, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private AccessLogRetention Retention(TestDatabase database) =>
        new(database.Factory(), new AuditWriter(database.Factory(), _hasher, new TestCurrentUser(), _clock), _clock);

    private CaseAccessEvent Access(Guid? caseId, string label, TimeSpan ago) => new()
    {
        ActorUserId = "alice", CaseId = caseId, CaseNumber = caseId is null ? null : "2026-01", AccessType = AccessType.CaseOpen,
        TargetLabel = label, FirstSeenUtc = _clock.UtcNow - ago - TimeSpan.FromMinutes(5), LastSeenUtc = _clock.UtcNow - ago, Count = 1,
    };

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Entries_older_than_the_retention_are_deleted_except_a_held_cases(string provider)
    {
        using var database = Open(provider);
        Guid held, open;
        await using (var db = database.NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            var cases = await db.Cases.OrderBy(c => c.CaseNumber).Take(2).ToListAsync();
            cases[0].LegalHold = true;
            await db.SaveChangesAsync();
            (held, open) = (cases[0].Id, cases[1].Id);
            db.CaseAccessEvents.AddRange(
                Access(open, "old", TimeSpan.FromDays(3 * 366)),
                Access(open, "just inside", TimeSpan.FromDays(3 * 365 - 2)),
                Access(open, "recent", TimeSpan.FromDays(10)),
                Access(held, "old but held", TimeSpan.FromDays(3 * 366)),
                Access(null, "old export", TimeSpan.FromDays(4 * 365)),
                Access(Guid.NewGuid(), "old, case gone", TimeSpan.FromDays(4 * 365)));
            await db.SaveChangesAsync();
        }
        var entriesBefore = await CountAuditAsync(database);

        (await Retention(database).PruneAsync(3)).Should().Be(3);

        await using (var db = database.NewContext())
        {
            (await db.CaseAccessEvents.Select(e => e.TargetLabel).ToListAsync())
                .Should().BeEquivalentTo("just inside", "recent", "old but held");
            var entry = await db.AuditLog.OrderByDescending(a => a.Sequence).FirstAsync();
            entry.Action.Should().Be(AuditAction.Delete);
            entry.EntityType.Should().Be(AccessLogRetention.AuditEntityType);
            entry.Actor.Should().Be(new TestCurrentUser().UserId, "whoever the job runs as (\"system\" in the background)");
            entry.Summary.Should().Contain("deleted 3 entries").And.Contain("2023-10-17").And.Contain("legal hold");
            (await db.AuditLog.CountAsync()).Should().Be(entriesBefore + 1);
            _hasher.VerifyChain(await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
        }

        (await Retention(database).PruneAsync(3)).Should().Be(0);
        (await CountAuditAsync(database)).Should().Be(entriesBefore + 1, "a prune that deletes nothing records nothing");

        await using (var db = database.NewContext())
        {
            var c = await db.Cases.SingleAsync(x => x.Id == held);
            c.LegalHold = false;
            await db.SaveChangesAsync();
        }
        (await Retention(database).PruneAsync(3)).Should().Be(1, "once the hold is lifted its old entries go too");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Zero_years_keeps_everything_and_a_large_backlog_is_deleted_in_batches(string provider)
    {
        using var database = Open(provider);
        await using (var db = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            db.ChangeTracker.AutoDetectChangesEnabled = false;
            db.CaseAccessEvents.AddRange(Enumerable.Range(0, AccessLogRetention.Batch * 2 + 7)
                .Select(i => Access(null, $"e{i}", TimeSpan.FromDays(4 * 365 + i % 30))));
            db.CaseAccessEvents.Add(Access(null, "recent", TimeSpan.FromDays(1)));
            await db.SaveChangesAsync();
        }

        (await Retention(database).PruneAsync(0)).Should().Be(0);
        (await Retention(database).PruneAsync(-1)).Should().Be(0);
        await using (var db = database.NewContext()) (await db.CaseAccessEvents.CountAsync()).Should().Be(AccessLogRetention.Batch * 2 + 8);

        (await Retention(database).PruneAsync(3)).Should().Be(AccessLogRetention.Batch * 2 + 7);
        await using (var db = database.NewContext())
            (await db.CaseAccessEvents.Select(e => e.TargetLabel).ToListAsync()).Should().Equal("recent");
    }

    private static async Task<int> CountAuditAsync(TestDatabase database)
    {
        await using var db = database.NewContext();
        return await db.AuditLog.CountAsync();
    }
}
