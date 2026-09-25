using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
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
/// REL-05: the audit-chain append (head-read → chained append → commit) is serialised by a process-wide
/// gate so two concurrent writers can't read the same chain head and fork it, and the gate is released on
/// every save outcome — success, failure, or cancellation — so a failed save never strands it and
/// deadlocks the next append.
/// </summary>
public sealed class AuditChainIntegrityTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public AuditChainIntegrityTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin];
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

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());


    [Fact]
    public async Task A_failed_save_releases_the_audit_gate_so_the_next_append_is_not_deadlocked()
    {
        // Two new cases with the SAME case number → the unique index rejects the batch. Both are auditable,
        // so the interceptor takes the audit-chain gate, appends the chained lines, and then the save fails
        // inside SaveChanges (the failure path must release the gate).
        await using (var db = NewContext())
        {
            var now = _clock.UtcNow;
            var a = Case.Open(2026, 1, "dup", "Dup A", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, _user.UserId, now);
            var b = Case.Open(2026, 1, "dup", "Dup B", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, _user.UserId, now);
            a.CaseNumber.Should().Be(b.CaseNumber); // same year+sequence+slug → collides on the unique index

            db.Cases.AddRange(a, b);
            var bad = async () => await db.SaveChangesAsync();
            await bad.Should().ThrowAsync<DbUpdateException>();
        }

        // If the gate had leaked on that failure, this next append would block forever — bound it so a
        // regression surfaces as a clean timeout rather than a hung test run.
        await using var db2 = NewContext();
        var svc = NewService(db2);
        var created = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "ok",
            Title = "Recovered",
            Classification = Classification.Incident,
            Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        }).WaitAsync(TimeSpan.FromSeconds(5));

        created.Should().NotBeNull();

        // The failed attempt left nothing behind: the chain is contiguous (1..N) and verifies.
        var entries = await db2.AuditLog.AsNoTracking().OrderBy(e => e.Sequence).ToListAsync();
        entries.Should().NotBeEmpty();
        entries.Select(e => e.Sequence).Should().Equal(Enumerable.Range(1, entries.Count).Select(i => (long)i));
        _hasher.VerifyChain(entries).IsValid.Should().BeTrue();
    }

    public void Dispose() => _connection.Dispose();
}
