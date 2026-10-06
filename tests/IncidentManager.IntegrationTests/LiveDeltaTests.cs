using System.Collections.Concurrent;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
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
/// RD-22: delta live updates. A committed save's change event says what changed (type, id, added/modified/deleted); the
/// workspace maps it to the parts of the case to re-read, and re-reads only those, in place, need-to-know scoped.
/// Runs on SQLite and, when a server is configured, on SQL Server (<see cref="TestDatabase"/>).
/// </summary>
public sealed class LiveDeltaTests : IDisposable
{
    private TestDatabase? _db;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 5, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };
    private readonly CaseChangeNotifier _notifier = new();

    // The audit interceptor publishes the change events, as in production.
    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>(_db!.Options)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, _notifier))
        .Options;

    private AppDbContext NewContext() => new(Options());

    private CaseService NewService(AppDbContext db) =>
        new(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private static async Task<CaseChange> Next(BlockingCollection<CaseChange> seen)
    {
        for (var i = 0; i < 100; i++)
        {
            if (seen.TryTake(out var c)) return c;
            await Task.Delay(20);
        }
        throw new TimeoutException("No change event arrived.");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_change_says_what_changed_and_the_workspace_re_reads_only_that_part(string provider)
    {
        _db = TestDatabase.Open(provider);
        await using var db = NewContext();
        var svc = NewService(db);
        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "delta", Title = "Delta", Classification = Classification.Incident,
            Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
        });
        var snapshot = (await svc.GetDetailAsync(c.Id))!;

        var seen = new BlockingCollection<CaseChange>();
        using var sub = _notifier.SubscribeChanges(c.Id, ch => { seen.Add(ch); return Task.CompletedTask; });

        // A timeline entry: the event names it, and it maps to the record alone.
        await svc.AddTimelineEntryAsync(c.Id, TimelineKind.Investigation, TimelineEntryType.Analysis, _clock.UtcNow, "Checked the proxy logs", null);
        var change = await Next(seen);
        change.ActorId.Should().Be(_user.UserId);
        change.Items.Should().Contain(i => i.Type == nameof(TimelineEntry) && i.Op == CaseChangeOp.Added);
        var regions = CaseRegionMap.Of(change);
        regions.Should().Be(CaseRegions.Record);

        snapshot.TimelineEntries.Should().BeEmpty();
        (await svc.RefreshPartsAsync(snapshot, regions)).Should().BeTrue();
        snapshot.TimelineEntries.Should().ContainSingle(e => e.Description.Contains("proxy logs"));

        // A task maps to tasks; a severity change touches the case itself, so the whole case is re-read.
        await svc.AddActionItemAsync(c.Id, "Pull the mailbox audit log", null, null);
        CaseRegionMap.Of(await Next(seen)).Should().Be(CaseRegions.Tasks);
        await svc.ChangeSeverityAsync(c.Id, Severity.High, "Scope grew");
        var sev = await Next(seen);
        CaseRegionMap.Of(sev).HasFlag(CaseRegions.Whole).Should().BeTrue();
        (await svc.RefreshPartsAsync(snapshot, CaseRegionMap.Of(sev))).Should().BeFalse();
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_case_the_viewer_can_no_longer_see_is_not_re_read_in_parts(string provider)
    {
        _db = TestDatabase.Open(provider);
        await using var db = NewContext();
        var svc = NewService(db);
        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "gone", Title = "Gone", Classification = Classification.Incident,
            Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
        });
        var snapshot = (await svc.GetDetailAsync(c.Id))!;
        await using (var raw = _db!.NewContext())
        {
            var row = await raw.Cases.FirstAsync(x => x.Id == c.Id);
            row.IsRestricted = true;
            await raw.SaveChangesAsync();
        }
        _user.RoleSet = [AppRole.Analyst];   // not on the case, so a restricted case is out of sight

        (await svc.RefreshPartsAsync(snapshot, CaseRegions.Record)).Should().BeFalse();
    }

    [Fact]
    public void A_change_without_detail_or_of_another_kind_means_the_whole_case()
    {
        var id = Guid.NewGuid();
        CaseRegionMap.Of(new CaseChange(id, "x", [])).Should().Be(CaseRegions.Whole);
        CaseRegionMap.Of(new CaseChange(id, "x", [new(nameof(StatusChange), Guid.NewGuid(), CaseChangeOp.Added)]))
            .HasFlag(CaseRegions.Whole).Should().BeTrue();
        CaseRegionMap.Of(new CaseChange(id, "x",
        [
            new(nameof(CaseEntity), Guid.NewGuid(), CaseChangeOp.Modified),
            new(nameof(EntityVerdictChange), Guid.NewGuid(), CaseChangeOp.Added),
            new(nameof(AnalystNote), Guid.NewGuid(), CaseChangeOp.Added),
        ])).Should().Be(CaseRegions.Things | CaseRegions.Notes);
    }

    public void Dispose() => _db?.Dispose();
}
