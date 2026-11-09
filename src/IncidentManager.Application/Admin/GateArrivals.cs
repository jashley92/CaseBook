using System.Collections.Concurrent;

namespace IncidentManager.Application.Admin;

/// <summary>
/// Test hook for the process-wide gates (<see cref="GuardGate"/>, the template file gate): counts the callers that have
/// reached each gate from one flow of work. A test that holds a gate and checks that its own calls wait behind it first
/// waits for them to arrive, so the check can't pass just because they hadn't got there yet. Other tests running at the
/// same time share the gates, so the count is per flow (an <see cref="AsyncLocal{T}"/>, which a <c>Task.Run</c> started
/// from the test inherits), not the gate's whole queue. Outside a test nothing is watching and arriving costs one read.
/// </summary>
internal sealed class GateArrivals : IDisposable
{
    /// <summary>The gate names <see cref="Arrive"/> is called with.</summary>
    public const string Guard = "guard", TemplateFiles = "template-files";

    private static readonly AsyncLocal<GateArrivals?> Current = new();
    private readonly GateArrivals? _outer;
    private readonly ConcurrentDictionary<string, int> _counts = new(StringComparer.Ordinal);

    private GateArrivals(GateArrivals? outer) => _outer = outer;

    /// <summary>Starts counting arrivals from this flow (and the tasks it starts) until disposed. Start it after taking
    /// the gate the test holds, so the test's own entry isn't counted.</summary>
    public static GateArrivals Watch()
    {
        var watch = new GateArrivals(Current.Value);
        Current.Value = watch;
        return watch;
    }

    /// <summary>How many calls from the watched flow have reached <paramref name="gate"/>.</summary>
    public int At(string gate) => _counts.GetValueOrDefault(gate);

    /// <summary>Called by a gate as a caller starts to wait for it.</summary>
    public static void Arrive(string gate)
    {
        for (var w = Current.Value; w is not null; w = w._outer) w._counts.AddOrUpdate(gate, 1, (_, n) => n + 1);
    }

    public void Dispose() => Current.Value = _outer;
}
