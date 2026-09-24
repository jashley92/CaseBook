using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>S-20: "Verify now" recomputes the chain at most once a minute, and concurrent presses share one run.</summary>
public class OnDemandVerificationGateTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly ChainVerificationResult Ok = new(true, null, "ok");

    [Fact]
    public async Task A_recent_result_is_reused_then_refreshed_after_a_minute()
    {
        var gate = new OnDemandVerificationGate();
        var runs = 0;
        Task<ChainVerificationResult> Verify(CancellationToken _) { runs++; return Task.FromResult(Ok); }

        (await gate.RunAsync(Verify, T0)).Shared.Should().BeFalse();
        var again = await gate.RunAsync(Verify, T0.AddSeconds(30));
        again.Shared.Should().BeTrue();
        again.VerifiedAtUtc.Should().Be(T0);
        runs.Should().Be(1);

        (await gate.RunAsync(Verify, T0 + OnDemandVerificationGate.Freshness)).Shared.Should().BeFalse();
        runs.Should().Be(2);
    }

    [Fact]
    public async Task Concurrent_presses_share_one_run()
    {
        var gate = new OnDemandVerificationGate();
        var runs = 0;
        var release = new TaskCompletionSource<ChainVerificationResult>();
        Task<ChainVerificationResult> Verify(CancellationToken _) { Interlocked.Increment(ref runs); return release.Task; }

        var presses = Enumerable.Range(0, 5).Select(_ => gate.RunAsync(Verify, T0)).ToList();
        release.SetResult(Ok);
        await Task.WhenAll(presses);

        runs.Should().Be(1);
    }
}
