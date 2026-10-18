using Microsoft.Extensions.Logging;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// Verifies and seals the audit chain. Verification recomputes the whole chain and reports the
/// first break; sealing records a signed chain-head snapshot for independent later comparison.
/// </summary>
public sealed class IntegrityService
{
    private readonly IAppDbContextFactory _factory;
    private readonly IHashChainService _hasher;
    private readonly ISealSigner _signer;
    private readonly ISealStore _sealStore;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IIntegrityMonitor _monitor;
    private readonly IIntegrityAlertNotifier _alerts;
    private readonly OnDemandVerificationGate _gate;
    private readonly Security.ISecurityEventSink? _siem;
    private readonly SealCopyStatus? _copies;
    private readonly Microsoft.Extensions.Logging.ILogger? _logger;
    private readonly IReadOnlyList<ISealCopier> _copiers;

    /// <summary>The destination name the export folder's results are recorded under in <see cref="SealCopyStatus"/>.</summary>
    public const string FolderCopy = "Export folder";

    public IntegrityService(IAppDbContextFactory factory, IHashChainService hasher, ISealSigner signer,
        ISealStore sealStore, ICurrentUser user, IClock clock, IIntegrityMonitor monitor,
        IIntegrityAlertNotifier alerts, OnDemandVerificationGate? gate = null,
        Security.ISecurityEventSink? siem = null, SealCopyStatus? copies = null,
        Microsoft.Extensions.Logging.ILogger<IntegrityService>? logger = null, IEnumerable<ISealCopier>? copiers = null,
        IChainKeyring? chainKeys = null, IntegrityCheckState? state = null)
    {
        _state = state;
        _chainKeys = chainKeys;
        _copiers = copiers?.ToList() ?? [];
        _siem = siem;
        _copies = copies;
        _logger = logger;
        _gate = gate ?? new OnDemandVerificationGate();
        _factory = factory;
        _hasher = hasher;
        _signer = signer;
        _sealStore = sealStore;
        _user = user;
        _clock = clock;
        _monitor = monitor;
        _alerts = alerts;
    }

    private readonly IChainKeyring? _chainKeys;   // BUG-142
    private readonly IntegrityCheckState? _state;   // BUG-257: none (tests, tools) means every check is a full one

    public async Task<ChainVerificationResult> VerifyAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await StreamChainAsync(db, null, ct);
    }

    /// <summary>
    /// BUG-195: the chain checked as it's read, one entry at a time (as the compliance bundle does, BUG-78), instead of
    /// loading the whole audit log, its JSON snapshots included, every cycle. <paramref name="records"/>, when given,
    /// collects what the record check needs from each entry.
    /// </summary>
    private async Task<ChainVerificationResult> StreamChainAsync(IAppDbContext db, RowIntegrityVerifier.ChainRecords? records,
        CancellationToken ct)
    {
        var verifier = _hasher.BeginVerify(await KeyedFromAsync(db, ct));
        await ReadOnAsync(db, verifier, records, after: null, ct);
        return verifier.Result;
    }

    // The chain's entries after a sequence (all of them for null), checked and collected as they're read.
    private static async Task ReadOnAsync(IAppDbContext db, IChainVerifier verifier, RowIntegrityVerifier.ChainRecords? records,
        long? after, CancellationToken ct, IntegrityCycleCounts? counts = null)
    {
        var q = db.AuditLog.AsNoTracking();
        if (after is { } from) q = q.Where(a => a.Sequence > from);
        await foreach (var e in q.OrderBy(a => a.Sequence).AsAsyncEnumerable().WithCancellation(ct))
        {
            if (counts is not null) counts.EntriesHashed++;
            if (!verifier.Add(e)) break;
            records?.Add(e);
        }
    }

    /// <summary>BUG-142: where the latest seal says the chain is keyed from (its signature is checked with the seal).
    /// BUG-401: two seals over the same head (the chain key turned on with nothing written since) are told apart by when
    /// they were made, so the older plain seal isn't read in place of the newer keyed one.</summary>
    internal static Task<long?> KeyedFromAsync(IAppDbContext db, CancellationToken ct) =>
        db.IntegritySeals.AsNoTracking().OrderByDescending(s => s.UpToSequence).ThenByDescending(s => s.SealedAtUtc)
            .Select(s => s.KeyedFromSequence).FirstOrDefaultAsync(ct);

    /// <summary>
    /// BUG-06: the chain check, then the records themselves (<see cref="RowIntegrityVerifier"/>): each record's
    /// content against its hash, and that hash against the one the chain last recorded for it.
    /// </summary>
    public Task<ChainVerificationResult> VerifyChainAndRecordsAsync(CancellationToken ct = default) =>
        CheckAsync(full: true, ct);

    // BUG-257: with full false, and a check kept from a recent cycle, only the entries written since are read and hashed
    // (on from where the kept verifier stopped); every record is still checked against the kept map. Otherwise the
    // whole chain is read from the start. Either way, what's checked is kept for the next cycle.
    private Task<ChainVerificationResult> CheckAsync(bool full, CancellationToken ct) =>
        GatedAsync(() => CheckCoreAsync(full: _state is null || full, ct), ct);

    // BUG-257: one check at a time (the kept state is the gate's); a failed one forgets what it kept.
    private async Task<T> GatedAsync<T>(Func<Task<T>> run, CancellationToken ct)
    {
        if (_state is null) return await run();
        await _state.Gate.WaitAsync(ct);
        try { return await run(); }
        catch
        {
            _state.Forget();
            throw;
        }
        finally { _state.Gate.Release(); }
    }

    // What the check cost: kept for Diagnostics and logged, as a warning when it's slow (see IntegrityCycleStats).
    private async Task<ChainVerificationResult> CheckCoreAsync(bool full, CancellationToken ct)
    {
        var counts = new IntegrityCycleCounts();
        var timer = System.Diagnostics.Stopwatch.StartNew();
        var (result, ranFull, chainTime, kept) = await CheckCoreAsync(full, counts, timer, ct);
        var stats = new IntegrityCycleStats(_clock.UtcNow, ranFull, result.IsValid, chainTime, timer.Elapsed - chainTime,
            counts.EntriesHashed, counts.RecordsByTable.Values.Sum(), kept, counts.RecordsByTable);
        if (_state is null) return result;
        _state.LastCycle = stats;
        _logger?.Log(stats.Total >= IntegrityCheckState.SlowCycle ? LogLevel.Warning : LogLevel.Information,
            "Integrity check ({Kind}) took {Seconds:N1} s: {Entries:N0} audit entries hashed in {ChainSeconds:N1} s, " +
            "{Records:N0} records checked in {RecordSeconds:N1} s, {Kept:N0} records held in memory.{Slow}",
            ranFull ? "full" : "incremental", stats.Total.TotalSeconds, stats.EntriesHashed, stats.Chain.TotalSeconds,
            stats.RecordsChecked, stats.Records.TotalSeconds, stats.RecordsKept,
            stats.Total >= IntegrityCheckState.SlowCycle
                ? $" That's over {IntegrityCheckState.SlowCycle.TotalSeconds:N0} s of every 10-minute cycle; see docs/architecture/integrity.md (Check cost)."
                : "");
        return result;
    }

    private async Task<(ChainVerificationResult Result, bool Full, TimeSpan Chain, int Kept)> CheckCoreAsync(bool full,
        IntegrityCycleCounts counts, System.Diagnostics.Stopwatch timer, CancellationToken ct)
    {
        // BUG-66/BUG-194: the chain is read before the tables, so a save landing in between makes a record look added,
        // changed or removed outside CaseBook. A record that fails is checked again after reading the entries written
        // since (their links checked too), and reported only if it still fails: a real edit stays, a save in progress
        // doesn't, however many saves land during the check.
        using var db = _factory.CreateDbContext();
        var keyedFrom = await KeyedFromAsync(db, ct);
        var now = _clock.UtcNow;
        var carryOn = !full && _state is not null && _state.CanContinue(keyedFrom, now);
        // The chain must still run through the last entry checked, unchanged: entries removed from the end (or that
        // entry rewritten) would otherwise go unseen until the next full check. Anything else and it starts over.
        if (carryOn && _state!.Records!.Head is { } head)
            carryOn = await db.AuditLog.AsNoTracking().Where(a => a.Sequence == head).Select(a => a.EntryHash).FirstOrDefaultAsync(ct)
                is { } stillThere && string.Equals(stillThere, _state.Records.HeadHash, StringComparison.Ordinal);
        var records = carryOn ? _state!.Records! : new RowIntegrityVerifier.ChainRecords();
        var verifier = carryOn ? _state!.Verifier! : _hasher.BeginVerify(keyedFrom);
        await ReadOnAsync(db, verifier, records, after: carryOn ? records.Head ?? 0 : null, ct, counts);
        var chainTime = timer.Elapsed;
        if (!verifier.Result.IsValid) { _state?.Forget(); return (verifier.Result, !carryOn, chainTime, records.Count); }

        var bad = await RowIntegrityVerifier.VerifyAsync(db, _hasher, records,
            new RowIntegrityVerifier.Recheck(t => ReadOnAsync(db, verifier, records, records.Head ?? 0, t, counts)), counts, ct);
        if (!verifier.Result.IsValid)   // an entry written since broke the chain
        {
            _state?.Forget();
            return (verifier.Result, !carryOn, chainTime, records.Count);
        }
        if (bad is not null)
        {
            _state?.Forget();
            return (ChainVerificationResult.Broken(bad.LastSequence ?? 0, bad.Detail), !carryOn, chainTime, records.Count);
        }
        _state?.Keep(verifier, records, keyedFrom, carryOn ? null : now);
        return (verifier.Result, !carryOn, chainTime, records.Count);
    }

    /// <summary>
    /// Verifies the chain, records the outcome for the app-wide integrity banner, and — on the first
    /// detection of a break — fires the alarm (SIEM/critical log + email). Used by the background monitor
    /// and by the manual "Verify now" action, so any detection path raises the same alert exactly once
    /// per broken episode. The notifier never throws, so a notification failure can't hide the break.
    /// </summary>
    /// <summary>
    /// S-20: the page's "Verify now" — a full <see cref="VerifyAndTrackAsync"/>, but single-flight and reusing a result
    /// under a minute old (<see cref="OnDemandVerificationGate"/>), since any case viewer can press it.
    /// </summary>
    public Task<OnDemandVerification> VerifyOnDemandAsync(CancellationToken ct = default) =>
        _gate.RunAsync(VerifyAndTrackAsync, _clock.UtcNow, ct);   // a person asked: the whole chain, re-hashed

    /// <summary>
    /// BUG-257: the background monitor's check. Between full checks (every <see cref="IntegrityCheckState.FullEvery"/>) it
    /// hashes only the entries written since the last cycle, and checks every record; otherwise as
    /// <see cref="VerifyAndTrackAsync"/>.
    /// </summary>
    public Task<ChainVerificationResult> MonitorAndTrackAsync(CancellationToken ct = default) => TrackAsync(full: false, ct);

    public Task<ChainVerificationResult> VerifyAndTrackAsync(CancellationToken ct = default) => TrackAsync(full: true, ct);

    private async Task<ChainVerificationResult> TrackAsync(bool full, CancellationToken ct)
    {
        // C18 (minor, from C21's sweep): the check, the seal check and recording the outcome happen under the check's
        // gate, so of two checks (the monitor and "Verify now") the one that ran last is the one recorded: an older
        // result landing after a newer one flipped the banner and could raise the alarm twice. The alarm itself goes
        // out after the gate is released, so a slow mail relay doesn't hold up the next check.
        var (result, raise) = await GatedAsync(async () =>
        {
            var checkedNow = await CheckCoreAsync(full: _state is null || full, ct);
            checkedNow = await WithSealAsync(checkedNow, ct);
            return (checkedNow, _monitor.RecordResult(checkedNow, _clock.UtcNow));
        }, ct);
        if (raise) await _alerts.OnChainBrokenAsync(result, ct);
        return result;
    }

    private async Task<ChainVerificationResult> WithSealAsync(ChainVerificationResult result, CancellationToken ct)
    {
        // VerifyAsync is the unkeyed self-consistency check — a tamperer who recomputes every hash would
        // pass it. The signed seals are the independent anchor, but they were only ever checked on demand
        // (a manual "verify seal" / a compliance export). Verify the most-covering seal here too, so a
        // competent rewrite of sealed history (or an altered/re-signed seal) trips the same F-16 alarm
        // automatically on the monitor's cadence, not only when someone happens to run a manual check (S-05).
        if (result.IsValid && await VerifyLatestSealAsync(ct) is { } sc && !sc.Result.IsValid)
            result = ChainVerificationResult.Broken(sc.Sequence, "Seal check failed: " + sc.Result.Detail);
        return result;
    }

    /// <summary>
    /// Verifies the seal covering the most history (highest <see cref="IntegritySeal.UpToSequence"/>)
    /// against the live chain — signature authentic AND the sealed head hash still matches the audit entry
    /// at that sequence. Because the chain is linear, a match proves all history up to that sequence is
    /// unchanged since sealing. Returns null when no seal exists yet.
    /// </summary>
    public async Task<(long Sequence, SealVerificationResult Result)?> VerifyLatestSealAsync(CancellationToken ct = default)
    {
        Guid sealId;
        long upTo;
        using (var db = _factory.CreateDbContext())
        {
            var latest = await db.IntegritySeals.AsNoTracking()
                .OrderByDescending(s => s.UpToSequence).ThenByDescending(s => s.SealedAtUtc).FirstOrDefaultAsync(ct);   // BUG-401
            if (latest is null) return null;
            sealId = latest.Id;
            upTo = latest.UpToSequence;
        }
        return (upTo, await VerifySealAsync(sealId, ct));
    }

    /// <summary>The timestamp of the most recent seal, or null if none exists — for cadence decisions.</summary>
    public async Task<DateTimeOffset?> LatestSealAtUtc(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var latest = await db.IntegritySeals.AsNoTracking()
            .OrderByDescending(s => s.SealedAtUtc).FirstOrDefaultAsync(ct);
        return latest?.SealedAtUtc;
    }

    /// <summary>
    /// Records a seal only when at least <paramref name="minInterval"/> has elapsed since the most recent
    /// one (or none exists yet), so the monitor can verify frequently while seals stay on a slower cadence.
    /// Returns the new seal, or null if none was due (or the chain is empty).
    /// </summary>
    public async Task<IntegritySeal?> SealIfDueAsync(TimeSpan minInterval, CancellationToken ct = default)
    {
        if (await LatestSealAtUtc(ct) is { } last && _clock.UtcNow - last < minInterval && !await KeyedButUnsealedAsync(ct))
            return null;
        // The background job's system path: the scheduled cadence isn't an admin action, so it bypasses the
        // F-23 assertion that guards the on-demand SealAsync.
        return await SealCoreAsync(ct);
    }

    // BUG-67: the chain's keyed entries are only anchored once a seal covers one (after that, a plain entry after a keyed
    // one is a break). Until then, someone with database access could rewrite them all with the plain hash. So the first
    // keyed entry after a seal over a plain head is sealed at the next run, not at the next interval.
    private async Task<bool> KeyedButUnsealedAsync(CancellationToken ct)
    {
        using var db = _factory.CreateDbContext();
        var sealedUpTo = await db.IntegritySeals.AsNoTracking().OrderByDescending(s => s.UpToSequence)
            .Select(s => (long?)s.UpToSequence).FirstOrDefaultAsync(ct) ?? 0;
        var keyedUnderSeal = await db.AuditLog.AsNoTracking().AnyAsync(a => a.Sequence <= sealedUpTo && a.HashKeyId != null, ct);
        return !keyedUnderSeal && await db.AuditLog.AsNoTracking().AnyAsync(a => a.Sequence > sealedUpTo && a.HashKeyId != null, ct);
    }

    public async Task<int> AuditCountAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.AuditLog.CountAsync(ct);
    }

    /// <summary>
    /// The newest audit entries, need-to-know scoped (<see cref="ScopedAuditLog"/>): the cross-case trail on
    /// <c>/integrity</c> must not reveal a restricted case's number or who is working it.
    /// </summary>
    public async Task<List<AuditLogEntry>> RecentAsync(string? caseNumber, int take = 100, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var q = string.IsNullOrWhiteSpace(caseNumber) ? ScopedAuditLog(db) : await ForCaseAsync(db, caseNumber, ct);
        return await q.OrderByDescending(a => a.Sequence).Take(take).ToListAsync(ct);
    }

    /// <summary>
    /// Filtered read over the hash-chained audit trail (E-24). Fields on <paramref name="filter"/>
    /// AND together; blank fields are ignored. Server-side filtering (rather than trimming a client-side
    /// top-N) so an actor/date-range question answers over the whole history. Newest first.
    /// </summary>
    public async Task<List<AuditLogEntry>> QueryAsync(AuditQueryFilter filter, int take = 500, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await (await FilteredAsync(db, filter, ct)).OrderByDescending(a => a.Sequence).Take(take).ToListAsync(ct);
    }

    /// <summary>
    /// CAP-03: one page of <see cref="QueryAsync"/>'s result for the cross-case trail on <c>/integrity</c>, newest first,
    /// scoped the same way. CAP-03 review: paged by sequence, not by offset. An offset (Skip(page * size)) moved under
    /// the reader as entries were written, so "Older" repeated entries just shown and "Newer" skipped some; each page now
    /// starts from the sequence the page shown ended at. A "Newer" page that reaches the newest entries is the newest
    /// page (full, with nothing newer).
    /// </summary>
    public async Task<AuditPage> QueryPageAsync(AuditQueryFilter filter, AuditPageAt at, int pageSize, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(pageSize, 1);
        using var db = _factory.CreateDbContext();
        var q = await FilteredAsync(db, filter, ct);

        if (at.NewerThan is { } first)
        {
            var newer = await q.Where(a => a.Sequence > first).OrderBy(a => a.Sequence)
                .Take(pageSize + 1).ToListAsync(ct);   // one more, to know there's a newer page still
            if (newer.Count > pageSize)
            {
                var kept = newer.Take(pageSize).ToList();
                kept.Reverse();
                return new AuditPage(kept, HasOlder: true, HasNewer: true);
            }
            at = AuditPageAt.Newest;   // reached the top: the newest page, full
        }

        var older = at.OlderThan is { } last ? q.Where(a => a.Sequence < last) : q;
        var rows = await older.OrderByDescending(a => a.Sequence)
            .Take(pageSize + 1).ToListAsync(ct);   // one more, to know there's an older page
        var page = rows.Take(pageSize).ToList();
        var top = page.Count > 0 ? page[0].Sequence : at.OlderThan.GetValueOrDefault() - 1;
        var hasNewer = at.OlderThan is not null && await q.AnyAsync(a => a.Sequence > top, ct);
        return new AuditPage(page, rows.Count > pageSize, hasNewer);
    }

    /// <summary>
    /// CAP-03: the filtered trail as the examiner's CSV (<see cref="AuditCsv"/>), at most <paramref name="rowLimit"/>
    /// entries, newest first; one cut at the limit says so at the top and at the end (REV-65, CAP-32). The same scoping as
    /// <see cref="QueryAsync"/>, so a case the caller can't see is in neither the page nor the file.
    /// </summary>
    public async Task<AuditExport> ExportCsvAsync(AuditQueryFilter filter, int rowLimit, CancellationToken ct = default)
    {
        var rows = await QueryAsync(filter, rowLimit + 1, ct);   // REV-65: one more, to know it was cut
        var truncated = rows.Count > rowLimit;
        var kept = truncated ? rows.Take(rowLimit).ToList() : rows;
        return new AuditExport(AuditCsv.Build(kept, _clock.UtcNow, filter.CaseNumber, truncated ? rowLimit : null), kept.Count, truncated);
    }

    // E-24: the filter's fields AND together over the caller's scoped trail.
    private async Task<IQueryable<AuditLogEntry>> FilteredAsync(IAppDbContext db, AuditQueryFilter filter, CancellationToken ct)
    {
        var q = string.IsNullOrWhiteSpace(filter.CaseNumber) ? ScopedAuditLog(db) : await ForCaseAsync(db, filter.CaseNumber, ct);

        if (!string.IsNullOrWhiteSpace(filter.Actor))
            q = q.Where(a => a.Actor == filter.Actor);
        if (filter.Action is { } action)
            q = q.Where(a => a.Action == action);
        if (!string.IsNullOrWhiteSpace(filter.EntityType))
            q = q.Where(a => a.EntityType == filter.EntityType);
        if (filter.FromUtc is { } from)
            q = q.Where(a => a.AtUtc >= from);
        if (filter.ToUtc is { } to)
            q = q.Where(a => a.AtUtc <= to);
        if (!string.IsNullOrWhiteSpace(filter.SettingKey))
        {
            // CAP-03: an update's snapshot holds only what moved, so the key is found in the row's create and delete
            // snapshots, and its updates by the row's id. Serialized as the audit interceptor serializes it, so the token
            // matches exactly ("Key":"Email:From", not "Email:FromName").
            var token = "\"Key\":" + System.Text.Json.JsonSerializer.Serialize(filter.SettingKey.Trim());
            var rowsForKey = db.AuditLog.AsNoTracking()
                .Where(a => a.EntityType == nameof(AppSetting)
                    && ((a.AfterJson != null && a.AfterJson.Contains(token)) || (a.BeforeJson != null && a.BeforeJson.Contains(token))))
                .Select(a => a.EntityId);
            q = q.Where(a => a.EntityType == nameof(AppSetting) && rowsForKey.Contains(a.EntityId));
        }
        return q;
    }

    /// <summary>
    /// Distinct actors and entity types present in the audit trail (optionally scoped to one case),
    /// to populate the E-24 filter dropdowns so the choices always reflect the real history.
    /// </summary>
    public async Task<(List<string> Actors, List<string> EntityTypes)> AuditFacetsAsync(string? caseNumber, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var q = string.IsNullOrWhiteSpace(caseNumber) ? ScopedAuditLog(db) : await ForCaseAsync(db, caseNumber, ct);
        var actors = await q.Select(a => a.Actor).Distinct().OrderBy(x => x).ToListAsync(ct);
        var types = await q.Select(a => a.EntityType).Distinct().OrderBy(x => x).ToListAsync(ct);
        return (actors, types);
    }

    /// <summary>
    /// The audit entries the caller may read. Oversight (<c>ViewAllCases</c>) and administrators see the whole
    /// trail, including entries with no case (configuration, roles). Everyone else sees only entries for cases
    /// <see cref="CaseQueryExtensions.ForUser"/> lets them see, so a restricted case's number, actors and entity
    /// labels never reach an unassigned, uncleared user. Fails closed: an entry under a case's former number
    /// (before a renumber) no longer matches a visible case and is left out.
    /// </summary>
    private IQueryable<AuditLogEntry> ScopedAuditLog(IAppDbContext db)
    {
        var all = db.AuditLog.AsNoTracking();
        if (_user.Has(Permission.ViewAllCases) || _user.Has(Permission.Administer)) return all;
        var visible = db.Cases.AsNoTracking().ForUser(_user).Select(c => c.CaseNumber);
        return all.Where(a => a.CaseNumber != null && visible.Contains(a.CaseNumber));
    }

    /// <summary>
    /// REV-01: one case's audit entries, under every number it has held. An entry carries the number the case had
    /// when it was saved, so a promotion out of Complex Event (or a renumber) would otherwise cut the trail at that
    /// point. The case's own rows record each number it has had; numbers are never reused while still in the trail.
    /// A number that isn't a case the caller can see now (a former number typed in) matches exactly, as before.
    /// </summary>
    private async Task<IQueryable<AuditLogEntry>> ForCaseAsync(IAppDbContext db, string caseNumber, CancellationToken ct)
    {
        // BUG-465: whoever sees the whole trail (ScopedAuditLog) finds the case without ForUser, which now shows nothing to
        // an Administer-only role, so its former numbers still join in.
        var cases = _user.Has(Permission.ViewAllCases) || _user.Has(Permission.Administer)
            ? db.Cases.AsNoTracking() : db.Cases.AsNoTracking().ForUser(_user);
        var caseId = await cases.Where(c => c.CaseNumber == caseNumber)
            .Select(c => (Guid?)c.Id).FirstOrDefaultAsync(ct);
        if (caseId is null) return ScopedAuditLog(db).Where(a => a.CaseNumber == caseNumber);

        var id = caseId.Value.ToString();
        var numbers = await db.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == nameof(Case) && a.EntityId == id && a.CaseNumber != null)
            .Select(a => a.CaseNumber!).Distinct().ToListAsync(ct);
        if (!numbers.Contains(caseNumber)) numbers.Add(caseNumber);
        return db.AuditLog.AsNoTracking().Where(a => a.CaseNumber != null && numbers.Contains(a.CaseNumber));
    }

    /// <summary>
    /// Records a signed seal over the current chain head and exports a copy out of band. The seal is
    /// signed with an asymmetric key (<see cref="ISealSigner"/>) so its authenticity can be verified
    /// independently of the database later.
    /// </summary>
    public async Task<IntegritySeal?> SealAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<IntegrityService>(_user);
        // REV-04: as the background job does, never sign over a chain that doesn't verify. A seal over a rewritten head
        // would make the rewrite read as authentic. The full check also raises the alarm and the banner if it's broken.
        var check = await VerifyAndTrackAsync(ct);
        if (!check.IsValid)
            throw new InvalidOperationException(
                $"No seal was recorded: the audit chain doesn't verify{(check.FirstBrokenSequence is { } at ? $" at entry #{at}" : "")}. " +
                "A seal would sign over the break, so investigate it first.");
        return await SealCoreAsync(ct);
    }

    private async Task<IntegritySeal?> SealCoreAsync(CancellationToken ct)
    {
        using var db = _factory.CreateDbContext();
        var head = await db.AuditLog.AsNoTracking().OrderByDescending(a => a.Sequence).FirstOrDefaultAsync(ct);
        if (head is null) return null;

        // BUG-142: record, under the signature, where the chain is keyed from.
        var firstKeyed = await db.AuditLog.AsNoTracking().Where(a => a.HashKeyId != null)
            .OrderBy(a => a.Sequence).Select(a => (long?)a.Sequence).FirstOrDefaultAsync(ct);
        var keyedFrom = firstKeyed ?? (_chainKeys?.CurrentKeyId is not null ? head.Sequence + 1 : null);
        var seal = new IntegritySeal
        {
            SealedAtUtc = _clock.UtcNow,
            UpToSequence = head.Sequence,
            ChainHeadHash = head.EntryHash,
            SealedBy = _user.UserId,
            Algorithm = _signer.Algorithm,
            KeyId = _signer.KeyId,
            KeyedFromSequence = keyedFrom,
        };
        seal.Signature = _signer.Sign(seal.BuildCanonicalContent());

        db.IntegritySeals.Add(seal);
        await db.SaveChangesAsync(ct);

        // F-26: the SIEM's copy, kept apart from CaseBook's database and servers. Emit never blocks or throws.
        _siem?.Emit(Security.SecurityEvents.IntegritySealRecorded(seal.UpToSequence, seal.ChainHeadHash, seal.KeyId,
            seal.SealedAtUtc, seal.SealedBy, seal.KeyedFromSequence));

        // Every other copy is best-effort: a failure must not roll back a persisted seal, but it must be seen.
        await CopyAsync(FolderCopy, () => _sealStore.ExportAsync(seal, ct), seal, ct);
        foreach (var copier in _copiers)
            await CopyAsync(copier.Name, () => copier.CopyAsync(seal, ct), seal, ct);

        return seal;
    }

    private async Task CopyAsync(string destination, Func<Task> copy, IntegritySeal seal, CancellationToken ct)
    {
        try
        {
            await copy();
            _copies?.Record(destination, _clock.UtcNow, null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _copies?.Record(destination, _clock.UtcNow, ex.Message);
            _logger?.LogWarning(new Microsoft.Extensions.Logging.EventId(Security.SecurityEventIds.SealExportFailed, "SealExportFailed"), ex,
                "Integrity seal #{UpToSequence} was recorded, but its copy to {Destination} failed: {Reason}",
                seal.UpToSequence, destination, ex.Message);
            _siem?.Emit(Security.SecurityEvents.SealExportFailed(seal.UpToSequence, $"{destination}: {ex.Message}"));
        }
    }

    /// <summary>
    /// Verifies a stored seal: its signature must be authentic (proving the sealed values are
    /// unaltered and signed by our key), and its recorded chain-head hash must still match the live
    /// audit entry at that sequence (proving history has not been rewritten since it was sealed).
    /// </summary>
    public async Task<SealVerificationResult> VerifySealAsync(Guid sealId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var seal = await db.IntegritySeals.AsNoTracking().FirstOrDefaultAsync(s => s.Id == sealId, ct);
        if (seal is null) return new SealVerificationResult(false, false, "Seal not found.");

        var signatureValid = _signer.Verify(seal.BuildCanonicalContent(), seal.Signature, seal.Algorithm, seal.KeyId);

        var entry = await db.AuditLog.AsNoTracking()
            .FirstOrDefaultAsync(a => a.Sequence == seal.UpToSequence, ct);
        var chainMatches = entry is not null && entry.EntryHash == seal.ChainHeadHash;

        var detail = (signatureValid, chainMatches) switch
        {
            (true, true) => "Signature authentic and the chain head is unchanged since sealing.",
            (false, _) when !_signer.VerificationKeys.Any(k => string.Equals(k.KeyId, seal.KeyId, StringComparison.OrdinalIgnoreCase))
                => $"Signed by key {seal.KeyId}, which this server doesn't hold. Add that key's public key to the retired seal keys folder.",
            (false, _) => "Signature invalid. The seal record was altered or signed by a different key.",
            (true, false) when entry is null => $"No audit entry at sealed sequence {seal.UpToSequence}. History was truncated.",
            (true, false) => $"Chain head at sequence {seal.UpToSequence} differs from the seal. History was rewritten after sealing.",
        };
        return new SealVerificationResult(signatureValid, chainMatches, detail);
    }

    public async Task<List<IntegritySeal>> RecentSealsAsync(int take = 20, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.IntegritySeals.AsNoTracking().OrderByDescending(s => s.SealedAtUtc).Take(take).ToListAsync(ct);
    }
}

/// <summary>Outcome of verifying a single integrity seal.</summary>
public sealed record SealVerificationResult(bool SignatureValid, bool ChainMatches, string Detail)
{
    public bool IsValid => SignatureValid && ChainMatches;
}
