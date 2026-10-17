using System.Security.Cryptography;
using IncidentManager.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// Re-verifies evidence at rest (F-17). The audit chain protects each evidence row's recorded
/// <c>Sha256</c> (it is part of the row's canonical content); this service closes the other half by
/// re-hashing the <b>stored bytes</b> and reporting any that no longer match — bit-rot, silent
/// substitution, or a missing/unreadable file under the evidence store.
///
/// It only reads (rows and files) and writes nothing to the database: the outcome is ops telemetry held
/// in the in-memory <see cref="IEvidenceIntegrityMonitor"/> and alarmed out-of-band, never a case
/// mutation — so a tamper that targets the store or the DB cannot also suppress the signal. Modeled on
/// the F-16 chain-break path (<see cref="IntegrityService.VerifyAndTrackAsync"/>).
/// </summary>
public sealed class EvidenceIntegrityVerifier
{
    private readonly IAppDbContextFactory _factory;
    private readonly IEvidenceStore _store;
    private readonly IClock _clock;
    private readonly IEvidenceIntegrityMonitor _monitor;
    private readonly IEvidenceIntegrityAlertNotifier _alerts;

    public EvidenceIntegrityVerifier(IAppDbContextFactory factory, IEvidenceStore store, IClock clock,
        IEvidenceIntegrityMonitor monitor, IEvidenceIntegrityAlertNotifier alerts)
    {
        _factory = factory;
        _store = store;
        _clock = clock;
        _monitor = monitor;
        _alerts = alerts;
    }

    private sealed record Row(Guid Id, Guid CaseId, string? CaseNumber, string OriginalFileName,
        string Sha256, string StoragePath);

    /// <summary>
    /// Re-hashes every stored evidence file and reports the ones whose bytes drifted from their recorded
    /// SHA-256. Pure: records nothing and raises no alarm (see <see cref="VerifyAndTrackAsync"/> for that).
    /// </summary>
    public Task<EvidenceVerificationResult> VerifyAllAsync(CancellationToken ct = default) => VerifyShareAsync(0, 1, ct);

    /// <summary>
    /// PROD-53: how many shares the files are split into so that every one is re-hashed at least once in
    /// <paramref name="passDays"/> days with a run every <paramref name="interval"/>: each run reads one share, not the
    /// whole store.
    /// </summary>
    public static int Shares(int passDays, TimeSpan interval) =>
        interval <= TimeSpan.Zero ? 1 : (int)Math.Clamp(Math.Floor(TimeSpan.FromDays(Math.Max(1, passDays)) / interval), 1, 10_000);

    /// <summary>The share a file is in: fixed by its id (random for evidence), so the shares are even and never move.</summary>
    public static int ShareOf(Guid id, int shares)
    {
        Span<byte> bytes = stackalloc byte[16];
        id.TryWriteBytes(bytes);
        return (int)(System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes) % (uint)Math.Max(1, shares));
    }

    /// <summary>
    /// The share the run in the interval holding <paramref name="now"/> checks. Intervals are counted from 1 January 2000 UTC,
    /// so the order holds across restarts without anything stored (this check writes nothing).
    /// </summary>
    public static int ShareDue(DateTimeOffset now, TimeSpan interval, int shares) =>
        (int)(Slot(now, interval) % Math.Max(1, shares));

    /// <summary>Which interval <paramref name="now"/> falls in, counted from 1 January 2000 UTC.</summary>
    public static long Slot(DateTimeOffset now, TimeSpan interval) =>
        (now.UtcTicks - Epoch.UtcTicks) / Math.Max(1, interval.Ticks);

    private static readonly DateTimeOffset Epoch = new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// PROD-53: re-hashes the files in share <paramref name="share"/> of <paramref name="shares"/> (every file when
    /// <paramref name="shares"/> is 1) and reports the ones whose bytes drifted. Pure, as <see cref="VerifyAllAsync"/>.
    /// </summary>
    public async Task<EvidenceVerificationResult> VerifyShareAsync(int share, int shares, CancellationToken ct = default)
    {
        // Read the metadata once, then release the DbContext before the (potentially slow) file IO — the
        // re-hash pass must not hold a database connection open while it streams bytes off disk. A left
        // join so an orphaned evidence row (no parent case) is still verified.
        List<Row> rows;
        using (var db = _factory.CreateDbContext())
        {
            rows = await (
                from e in db.Evidence.AsNoTracking()
                join c in db.Cases.AsNoTracking() on e.CaseId equals c.Id into cj
                from c in cj.DefaultIfEmpty()
                select new Row(e.Id, e.CaseId, c != null ? c.CaseNumber : null, e.OriginalFileName,
                    e.Sha256, e.StoragePath)).ToListAsync(ct);
        }

        var all = shares <= 1;
        var known = all ? null : rows.Select(r => r.Id).ToHashSet();
        if (!all) rows = rows.Where(r => ShareOf(r.Id, shares) == share).ToList();

        var drifts = new List<EvidenceDrift>();
        foreach (var r in rows)
        {
            ct.ThrowIfCancellationRequested();
            var (kind, actual, detail) = await ReHashAsync(r, ct);
            if (kind is { } k)
                drifts.Add(new EvidenceDrift(r.Id, r.CaseId, r.CaseNumber, r.OriginalFileName, r.Sha256, actual, k, detail!));
        }

        return new EvidenceVerificationResult(rows.Count, drifts, _clock.UtcNow,
            all ? null : rows.Select(r => r.Id).ToHashSet(), known);
    }

    /// <summary>
    /// Runs a verification pass, records the outcome for the app-wide banner/panel, and — on the first
    /// detection of a drift episode — fires the alarm (SIEM/critical log + email). The de-duplicating
    /// latch lives in the monitor, so the alarm fires once per episode regardless of how often this runs.
    /// The notifier never throws, so a notification failure can't hide the drift.
    /// </summary>
    public Task<EvidenceVerificationResult> VerifyAndTrackAsync(CancellationToken ct = default) => VerifyAndTrackAsync(0, 1, ct);

    /// <summary>PROD-53: as <see cref="VerifyAndTrackAsync(CancellationToken)"/>, over one share of the files.</summary>
    public async Task<EvidenceVerificationResult> VerifyAndTrackAsync(int share, int shares, CancellationToken ct = default)
    {
        var result = await VerifyShareAsync(share, shares, ct);
        if (_monitor.RecordResult(result, _clock.UtcNow))
            await _alerts.OnDriftDetectedAsync(result, ct);
        return result;
    }

    private async Task<(EvidenceDriftKind? Kind, string? Actual, string? Detail)> ReHashAsync(Row r, CancellationToken ct)
    {
        try
        {
            await using var stream = await _store.OpenReadAsync(r.StoragePath, ct);
            var actual = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant();
            if (string.Equals(actual, r.Sha256, StringComparison.OrdinalIgnoreCase))
                return (null, actual, null);
            return (EvidenceDriftKind.HashMismatch, actual,
                $"stored bytes hash {Prefix(actual)} ≠ recorded {Prefix(r.Sha256)}");
        }
        catch (OperationCanceledException)
        {
            throw; // shutdown / caller cancellation — not a drift
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return (EvidenceDriftKind.Missing, null, "file not found in the evidence store");
        }
        catch (Exception ex)
        {
            // Permission denied, IO error, path rejected by the store's traversal guard, etc.
            return (EvidenceDriftKind.Unreadable, null, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static string Prefix(string hex) => hex.Length <= 12 ? hex : hex[..12] + "…";
}
