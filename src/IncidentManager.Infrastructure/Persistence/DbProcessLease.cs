using System.Diagnostics;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Common;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// The background jobs' lease and each process's heartbeat, kept in <c>ProcessLeases</c>.
/// <para>Taking and renewing the lease is one conditional UPDATE: it sets this holder and a new expiry where the row is
/// this holder's or has lapsed. That's atomic on SQLite and SQL Server alike: whoever's statement lands first wins, and
/// the other's matches no row. The first process to find no row inserts it, and the key stops a second insert. The lease
/// lapses <see cref="Expiry"/> after its last renewal, so a process that dies is taken over within minutes. It's let go
/// at shutdown, so the next process takes over at its next renewal.</para>
/// <para>A holder on this machine whose process has ended (a crash, or a kill) is taken over at once, rather than after
/// the expiry, so a restart doesn't stand by behind its own dead predecessor. Expiries are compared on each process's own
/// clock: servers on a domain keep theirs within seconds of each other, well inside the margins.</para>
/// <para>Each process also renews a heartbeat row. One seen within <see cref="SeenWithin"/> is another live process, and
/// that's shown to administrators. Singleton: it opens a context for each renewal.</para>
/// </summary>
public sealed class DbProcessLease(IServiceScopeFactory scopes, IClock clock, ILogger<DbProcessLease> log, string? holder = null)
    : IProcessLease
{
    /// <summary>How long the lease and a heartbeat last after a renewal.</summary>
    public static readonly TimeSpan Expiry = TimeSpan.FromMinutes(3);

    /// <summary>How often the hosted service renews them.</summary>
    public static readonly TimeSpan RenewEvery = TimeSpan.FromSeconds(30);

    /// <summary>A holder stops running jobs this long before the expiry it last wrote, if it hasn't renewed since.</summary>
    public static readonly TimeSpan Margin = TimeSpan.FromSeconds(30);

    /// <summary>A heartbeat renewed within this long is a live process. Long enough to cover a missed renewal.</summary>
    public static readonly TimeSpan SeenWithin = TimeSpan.FromSeconds(90);

    /// <summary>Heartbeats lapsed longer than this are removed.</summary>
    public static readonly TimeSpan PruneAfter = TimeSpan.FromDays(1);

    // Never disposed: it's used at shutdown, which can come after the container that built this is disposed, and a
    // SemaphoreSlim whose wait handle is never asked for holds nothing to free.
    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile ProcessLeaseStatus _status = ProcessLeaseStatus.NotChecked;
    private readonly DateTimeOffset _startedAt = clock.UtcNow;

    public string Holder { get; } = Clip(holder ?? $"{Environment.MachineName}/{Environment.ProcessId}/{Guid.NewGuid():N}");

    public ProcessLeaseStatus Status => _status;

    public bool RunsJobs => _status is { State: LeaseState.Held, ExpiresAtUtc: { } until } && clock.UtcNow < until - Margin;

    public event Action? Changed;

    /// <summary>Whether a process on this machine with this id is running. Replaceable in tests.</summary>
    public Func<int, bool> IsRunning { get; init; } = ProcessIsRunning;

    public async Task<bool> HoldAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var before = _status;
            var now = clock.UtcNow;
            try
            {
                _status = await TakeAsync(before, now, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                // The database didn't answer. A holder keeps going until shortly before the expiry it last wrote (nobody
                // else can take the lease before then). After that, or if it didn't hold it, it runs nothing.
                var stillHeld = before is { State: LeaseState.Held, ExpiresAtUtc: { } until } && now < until - Margin;
                var problem = ex.GetType().Name;
                _status = stillHeld
                    ? before with { CheckedAtUtc = now, Problem = problem }
                    : new ProcessLeaseStatus(LeaseState.Unreachable, before.Holder, before.ExpiresAtUtc, null, now, problem, before.Others);
                log.LogWarning(ex, "Couldn't take or renew the background jobs' lease{Still}.",
                    stillHeld ? "; still holding it until it nears its expiry" : "; no background job runs here until it can");
            }
            Report(before, _status);
            return _status.State == LeaseState.Held;
        }
        finally { _gate.Release(); }
    }

    private async Task<ProcessLeaseStatus> TakeAsync(ProcessLeaseStatus before, DateTimeOffset now, CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
        var me = Holder;
        var until = now + Expiry;

        await BeatAsync(db, me, now, until, ct);

        var row = await db.ProcessLeases.AsNoTracking().FirstOrDefaultAsync(l => l.Name == ProcessLease.BackgroundJobs, ct);
        // A holder on this machine whose process has ended: its lease is as good as lapsed.
        var dead = row is not null && row.Holder != me && row.ExpiresAtUtc > now && IsDeadHere(row.Holder) ? row.Holder : null;
        // One statement: whoever's renewal or takeover lands first wins, and the other's matches no row.
        var taken = await db.ProcessLeases
            .Where(l => l.Name == ProcessLease.BackgroundJobs && (l.Holder == me || l.ExpiresAtUtc <= now || l.Holder == dead))
            .ExecuteUpdateAsync(u => u
                .SetProperty(l => l.AcquiredAtUtc, l => l.Holder == me ? l.AcquiredAtUtc : now)
                .SetProperty(l => l.Holder, me)
                .SetProperty(l => l.ExpiresAtUtc, until), ct) == 1;
        if (!taken && row is null)
        {
            db.ProcessLeases.Add(new ProcessLease { Name = ProcessLease.BackgroundJobs, Holder = me, AcquiredAtUtc = now, ExpiresAtUtc = until });
            try
            {
                await db.SaveChangesAsync(ct);
                taken = true;
            }
            catch (DbUpdateException)
            {
                // Another process inserted it first: it holds it.
                db.ChangeTracker.Clear();
            }
        }
        if (dead is not null && taken)
        {
            await db.ProcessLeases.Where(l => l.Name == ProcessLease.ProcessPrefix + dead).ExecuteDeleteAsync(ct);
            log.LogInformation("Took over the background jobs from {Dead}, whose process has ended.", ProcessLeaseStatus.Describe(dead));
        }

        var others = await OthersAsync(db, me, now, ct);
        if (taken)
        {
            var since = before.State == LeaseState.Held && before.HeldSinceUtc is { } held ? held : now;
            return new ProcessLeaseStatus(LeaseState.Held, me, until, since, now, null, others);
        }
        row = await db.ProcessLeases.AsNoTracking().FirstOrDefaultAsync(l => l.Name == ProcessLease.BackgroundJobs, ct);
        return new ProcessLeaseStatus(LeaseState.StandingBy, row?.Holder, row?.ExpiresAtUtc, null, now, null, others);
    }

    // This process's heartbeat: renewed, or inserted on the first renewal. Lapsed heartbeats are pruned on the way.
    private async Task BeatAsync(AppDbContext db, string me, DateTimeOffset now, DateTimeOffset until, CancellationToken ct)
    {
        var name = ProcessLease.ProcessPrefix + me;
        var renewed = await db.ProcessLeases.Where(l => l.Name == name)
            .ExecuteUpdateAsync(u => u.SetProperty(l => l.ExpiresAtUtc, until), ct) == 1;
        if (renewed) return;
        db.ProcessLeases.Add(new ProcessLease { Name = name, Holder = me, AcquiredAtUtc = _startedAt, ExpiresAtUtc = until });
        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
        var old = now - PruneAfter;
        await db.ProcessLeases.Where(l => l.Name.StartsWith(ProcessLease.ProcessPrefix) && l.ExpiresAtUtc < old).ExecuteDeleteAsync(ct);
    }

    // Other processes whose heartbeat was renewed within SeenWithin, but not one on this machine that has ended.
    private async Task<IReadOnlyList<OtherProcess>> OthersAsync(AppDbContext db, string me, DateTimeOffset now, CancellationToken ct)
    {
        var freshAfter = now - SeenWithin + Expiry;   // renewed at (expiry - Expiry) after now - SeenWithin
        var rows = await db.ProcessLeases.AsNoTracking()
            .Where(l => l.Name.StartsWith(ProcessLease.ProcessPrefix) && l.Holder != me && l.ExpiresAtUtc > freshAfter)
            .ToListAsync(ct);
        return rows.Where(r => !IsDeadHere(r.Holder))
            .Select(r => new OtherProcess(r.Holder, r.AcquiredAtUtc, r.ExpiresAtUtc - Expiry))
            .OrderBy(o => o.StartedAtUtc)
            .ToList();
    }

    private bool IsDeadHere(string other)
    {
        var parts = other.Split('/');
        return parts.Length >= 2
               && string.Equals(parts[0], Environment.MachineName, StringComparison.OrdinalIgnoreCase)
               && int.TryParse(parts[1], System.Globalization.CultureInfo.InvariantCulture, out var pid)
               && !IsRunning(pid);
    }

    private static bool ProcessIsRunning(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch (ArgumentException) { return false; }   // no such process
        catch (InvalidOperationException) { return false; }
        catch (System.ComponentModel.Win32Exception) { return true; }   // can't be asked: assume it's there
    }

    // Logs what changed, and tells the banner and Diagnostics.
    private void Report(ProcessLeaseStatus before, ProcessLeaseStatus after)
    {
        var stateChanged = before.State != after.State;
        if (stateChanged)
        {
            if (after.State == LeaseState.Held) log.LogInformation("This process ({Holder}) now runs the background jobs.", Holder);
            else if (after.State == LeaseState.StandingBy)
                log.LogWarning("Standing by: {Other} runs the background jobs, so this process ({Holder}) runs none until it stops.",
                    after.HolderName, Holder);
        }
        var othersChanged = !before.Others.Select(o => o.Holder).Order(StringComparer.Ordinal)
            .SequenceEqual(after.Others.Select(o => o.Holder).Order(StringComparer.Ordinal), StringComparer.Ordinal);
        if (othersChanged && after.Others.Count > 0)
            log.LogError("Another CaseBook process is using this database: {Others}. CaseBook supports one process; the audit trail's " +
                         "lock covers one process only. Stop the other one (a web garden, or a second server pointed at this database).",
                string.Join("; ", after.Others.Select(o => o.Name)));
        else if (othersChanged)
            log.LogInformation("No other CaseBook process is using this database now.");
        if (stateChanged || othersChanged)
        {
            try { Changed?.Invoke(); }
            catch (Exception ex) { log.LogWarning(ex, "A listener on the background jobs' lease failed."); }
        }
    }

    public async Task ReleaseAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
            var me = Holder;
            var now = clock.UtcNow;
            if (_status.State == LeaseState.Held)
            {
                await db.ProcessLeases.Where(l => l.Name == ProcessLease.BackgroundJobs && l.Holder == me)
                    .ExecuteUpdateAsync(u => u.SetProperty(l => l.ExpiresAtUtc, now), ct);
                Quietly(() => log.LogInformation("Let go of the background jobs' lease ({Holder}) at shutdown.", Holder));
            }
            await db.ProcessLeases.Where(l => l.Name == ProcessLease.ProcessPrefix + me).ExecuteDeleteAsync(ct);
            _status = ProcessLeaseStatus.NotChecked;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Quietly(() => log.LogWarning(ex, "Couldn't let go of the background jobs' lease at shutdown; another process takes it when it lapses."));
        }
        finally { _gate.Release(); }
    }

    // At shutdown the loggers can already be gone (a host disposed while it stops): a log line there never fails the stop.
    private static void Quietly(Action write)
    {
        try { write(); }
        catch (Exception ex) when (ex is ObjectDisposedException or AggregateException) { /* the logger has gone */ }
    }

    private static string Clip(string s) => TextFit.Cap(s, ProcessLease.MaxHolder, "")!;
}
