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
    public async Task<EvidenceVerificationResult> VerifyAllAsync(CancellationToken ct = default)
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

        var drifts = new List<EvidenceDrift>();
        foreach (var r in rows)
        {
            ct.ThrowIfCancellationRequested();
            var (kind, actual, detail) = await ReHashAsync(r, ct);
            if (kind is { } k)
                drifts.Add(new EvidenceDrift(r.Id, r.CaseId, r.CaseNumber, r.OriginalFileName, r.Sha256, actual, k, detail!));
        }

        return new EvidenceVerificationResult(rows.Count, drifts, _clock.UtcNow);
    }

    /// <summary>
    /// Runs a verification pass, records the outcome for the app-wide banner/panel, and — on the first
    /// detection of a drift episode — fires the alarm (SIEM/critical log + email). The de-duplicating
    /// latch lives in the monitor, so the alarm fires once per episode regardless of how often this runs.
    /// The notifier never throws, so a notification failure can't hide the drift.
    /// </summary>
    public async Task<EvidenceVerificationResult> VerifyAndTrackAsync(CancellationToken ct = default)
    {
        var result = await VerifyAllAsync(ct);
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
