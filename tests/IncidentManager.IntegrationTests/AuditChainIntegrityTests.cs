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
using Microsoft.EntityFrameworkCore.Diagnostics;
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

    [Fact]
    public async Task A_concurrency_conflict_releases_the_audit_gate()
    {
        // BUG-01: EF reports a concurrency conflict through ThrowingConcurrencyException, not SaveChangesFailed.
        // Two people remove the same assignment: the second DELETE matches no row.
        var now = _clock.UtcNow;
        Guid id;
        await using (var db = NewContext())
        {
            var c = Case.Open(2026, 1, "conflict", "Conflict", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, _user.UserId, now);
            c.Assign("someone", "Someone", CaseAssignmentRole.Analyst, _user.UserId, now);
            db.Cases.Add(c);
            await db.SaveChangesAsync();
            id = c.Id;
        }

        await using var first = NewContext();
        await using var second = NewContext();
        var a = await first.Cases.Include(x => x.Assignments).Include(x => x.AssignmentChanges).SingleAsync(x => x.Id == id);
        var b = await second.Cases.Include(x => x.Assignments).Include(x => x.AssignmentChanges).SingleAsync(x => x.Id == id);
        a.Unassign("someone", _user.UserId, now);
        await first.SaveChangesAsync();
        b.Unassign("someone", _user.UserId, now);
        var conflict = async () => await second.SaveChangesAsync();
        await conflict.Should().ThrowAsync<IncidentManager.Application.Cases.ConcurrentEditException>();

        // A leaked gate would block this forever.
        await using var db3 = NewContext();
        var created = await NewService(db3).CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "after",
            Title = "After the conflict",
            Classification = Classification.Incident,
            Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        }).WaitAsync(TimeSpan.FromSeconds(5));
        created.Should().NotBeNull();
    }

    [Fact]
    public async Task A_long_audit_label_is_cut_to_its_column_and_the_chain_still_verifies()
    {
        // BUG-02: the label column is nvarchar(300); an IOC's "{Label} ({Value})" can run to thousands of characters.
        await using var db = NewContext();
        var now = _clock.UtcNow;
        var c = Case.Open(2026, 1, "long", "Long label", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, _user.UserId, now);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        c.AddEntity(EntityType.Url, "https://example.test/" + new string('a', 1900), new string('L', 380), EntityDisposition.Unknown, null, null, _user.UserId, now);
        await db.SaveChangesAsync();

        var entries = await db.AuditLog.AsNoTracking().OrderBy(e => e.Sequence).ToListAsync();
        entries.Should().OnlyContain(e => e.EntityLabel == null || e.EntityLabel.Length <= 300);
        entries.Should().Contain(e => e.EntityLabel != null && e.EntityLabel.EndsWith('…'));
        _hasher.VerifyChain(entries).IsValid.Should().BeTrue();
    }

    private sealed class CapturingNotifier : ICaseChangeNotifier
    {
        public List<Guid> Published { get; } = [];
        public void Publish(Guid caseId, string actorId) => Published.Add(caseId);
        public IDisposable Subscribe(Guid caseId, Func<string, Task> onChanged) => new CaseChangeNotifier().Subscribe(caseId, onChanged);
        public IDisposable SubscribeAll(Func<Guid, string, Task> onAnyChanged) => new CaseChangeNotifier().SubscribeAll(onAnyChanged);
    }

    /// <summary>Runs another context's save in the middle of this one's, as interleaved saves in a circuit do.</summary>
    private sealed class MidSave(Func<Task> during) : SaveChangesInterceptor
    {
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken ct = default)
        {
            await during();
            return result;
        }
    }

    [Fact]
    public async Task An_interleaved_save_on_another_context_doesnt_take_this_saves_broadcast_or_gate()
    {
        // BUG-27: the circuit's factory hands every context one interceptor; its per-save state was a single field.
        var notifier = new CapturingNotifier();
        var shared = new AuditChainInterceptor(_hasher, _user, _clock, notifier);
        var now = _clock.UtcNow;
        Guid caseId;
        await using (var db = NewContext())
        {
            var seeded = Case.Open(2026, 1, "interleave", "Interleave", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, _user.UserId, now);
            db.Cases.Add(seeded);
            await db.SaveChangesAsync();
            caseId = seeded.Id;
        }

        await using var other = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).AddInterceptors(shared).Options);
        await using var main = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection)
            .AddInterceptors(shared, new MidSave(async () =>
            {
                other.PinnedCases.Add(new PinnedCase { UserId = _user.UserId, CaseId = caseId, PinnedAtUtc = now });   // not audited
                await other.SaveChangesAsync();
            })).Options);

        var c = await main.Cases.SingleAsync(x => x.Id == caseId);
        c.Title = "Renamed";
        await main.SaveChangesAsync().WaitAsync(TimeSpan.FromSeconds(5));

        notifier.Published.Should().Contain(caseId, "the audited save's change is still broadcast");
        // And the gate is free for the next save (an early release would have let this one race, not hang; a leak would hang).
        await using var next = NewContext();
        (await next.Cases.SingleAsync(x => x.Id == caseId)).Title = "Again";
        await next.SaveChangesAsync().WaitAsync(TimeSpan.FromSeconds(5));
    }

    public void Dispose() => _connection.Dispose();
}
