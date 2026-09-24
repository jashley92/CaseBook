using IncidentManager.Application.Abstractions;

namespace IncidentManager.Application.Integrity;

/// <summary>The outcome of an on-demand chain verification, and whether it was a fresh run or a recent shared one.</summary>
public sealed record OnDemandVerification(ChainVerificationResult Result, DateTimeOffset VerifiedAtUtc, bool Shared);

/// <summary>
/// S-20: "Verify now" recomputes the whole audit chain, and every case viewer can press it. This process-wide gate
/// runs at most one verification at a time and reuses a result younger than <see cref="Freshness"/>, so repeated or
/// concurrent presses can't turn the button into a load generator. The scheduled monitor (every 10 minutes) is
/// unaffected.
/// </summary>
public sealed class OnDemandVerificationGate
{
    /// <summary>How long a verification result is reused before a press runs a new one.</summary>
    public static readonly TimeSpan Freshness = TimeSpan.FromMinutes(1);

    private readonly SemaphoreSlim _single = new(1, 1);
    private OnDemandVerification? _last;

    public async Task<OnDemandVerification> RunAsync(Func<CancellationToken, Task<ChainVerificationResult>> verify,
        DateTimeOffset nowUtc, CancellationToken ct = default)
    {
        if (Fresh(nowUtc) is { } recent) return recent;
        await _single.WaitAsync(ct);
        try
        {
            // Someone else may have finished a run while this caller waited.
            if (Fresh(nowUtc) is { } justRun) return justRun;
            var result = await verify(ct);
            _last = new OnDemandVerification(result, nowUtc, Shared: false);
            return _last;
        }
        finally { _single.Release(); }
    }

    private OnDemandVerification? Fresh(DateTimeOffset nowUtc) =>
        _last is { } l && nowUtc - l.VerifiedAtUtc < Freshness ? l with { Shared = true } : null;
}
