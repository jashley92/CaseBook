namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// BUG-576: a per-target back-off for sends to other hosts (the mail relay, a chat webhook). Sends are made inline in
/// user actions (assign, reclassify, each mention, handoff), so a relay that stalls held every one of them for its full
/// timeout. A send that finds its target not answering backs that target off for <see cref="FirstBackOff"/>, doubling
/// on each further failure up to <see cref="MaxBackOff"/>; meanwhile <see cref="TryEnter"/> says no and the caller fails
/// fast (reporting the failure, so a scan retries and a critical alert goes to its outbox). When the back-off ends one
/// send goes through as a probe while the others still fail fast; a success ends the back-off.
/// </summary>
public sealed class OutboundCircuit
{
    public static readonly TimeSpan FirstBackOff = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan MaxBackOff = TimeSpan.FromMinutes(10);

    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly Dictionary<string, State> _targets = new(StringComparer.OrdinalIgnoreCase);

    public OutboundCircuit(TimeProvider? time = null) => _time = time ?? TimeProvider.System;

    /// <summary>Whether a send to <paramref name="target"/> may go now; false while it's backed off.</summary>
    public bool TryEnter(string target)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            if (!_targets.TryGetValue(target, out var state)) return true;
            if (now < state.OpenUntil) return false;
            // One probe at a time; a probe that never reports holds the turn for at most MaxBackOff.
            if (state.ProbeUntil is { } probing && now < probing) return false;
            state.ProbeUntil = now + MaxBackOff;
            return true;
        }
    }

    /// <summary>The target answered: any back-off ends.</summary>
    public void Succeeded(string target)
    {
        lock (_gate) _targets.Remove(target);
    }

    /// <summary>The target didn't answer (timed out, couldn't be reached, or a server error): it's backed off.</summary>
    public void Failed(string target)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            if (!_targets.TryGetValue(target, out var state)) _targets[target] = state = new State();
            else if (now < state.OpenUntil) return;   // a send started before the back-off: it doesn't lengthen it
            state.Failures = Math.Min(state.Failures + 1, 16);
            var backOff = TimeSpan.FromTicks(Math.Min(FirstBackOff.Ticks << (state.Failures - 1), MaxBackOff.Ticks));
            state.OpenUntil = now + backOff;
            state.ProbeUntil = null;
        }
    }

    private sealed class State
    {
        public int Failures;
        public DateTimeOffset OpenUntil;
        public DateTimeOffset? ProbeUntil;
    }
}
