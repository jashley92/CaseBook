namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// BUG-576: a per-target back-off for sends to other hosts (the mail relay, a chat webhook). Sends are made inline in
/// user actions (assign, reclassify, each mention, handoff), so a relay that stalls held every one of them for its full
/// timeout. A target that didn't answer <see cref="FailuresToOpen"/> sends in a row within <see cref="FailureWindow"/>
/// (BUG-608: one dropped connection isn't a relay that's down) is backed off for <see cref="FirstBackOff"/>, doubling on
/// each further failure up to <see cref="MaxBackOff"/>; meanwhile <see cref="TryEnter"/> says no and the caller fails
/// fast (a scan retries, a critical alert waits in its outbox, a user action's email is held). When the back-off ends
/// one send goes through as a probe while the others still fail fast; a success ends the back-off.
/// </summary>
public sealed class OutboundCircuit
{
    public static readonly TimeSpan FirstBackOff = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan MaxBackOff = TimeSpan.FromMinutes(10);

    /// <summary>BUG-608: failures in a row, within <see cref="FailureWindow"/>, that back a target off.</summary>
    public const int FailuresToOpen = 3;
    public static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(2);

    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly Dictionary<string, State> _targets = new(StringComparer.OrdinalIgnoreCase);

    public OutboundCircuit(TimeProvider? time = null) => _time = time ?? TimeProvider.System;

    /// <summary>The clock the back-offs run on (BUG-608: the email sender times its held mail by it).</summary>
    public TimeProvider Time => _time;

    /// <summary>Whether a send to <paramref name="target"/> may go now; false while it's backed off.</summary>
    public bool TryEnter(string target)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            if (!_targets.TryGetValue(target, out var state) || state.BackOffs == 0) return true;   // not backed off
            if (now < state.OpenUntil) return false;
            // One probe at a time; a probe that never reports holds the turn for at most MaxBackOff.
            if (state.ProbeUntil is { } probing && now < probing) return false;
            state.ProbeUntil = now + MaxBackOff;
            return true;
        }
    }

    /// <summary>BUG-608: how long until the target's back-off ends (zero when it isn't backed off, or it's over).</summary>
    public TimeSpan RetryIn(string target)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
            return _targets.TryGetValue(target, out var state) && state.BackOffs > 0 && now < state.OpenUntil
                ? state.OpenUntil - now : TimeSpan.Zero;
    }

    /// <summary>The target answered: any back-off ends.</summary>
    public void Succeeded(string target)
    {
        lock (_gate) _targets.Remove(target);
    }

    /// <summary>
    /// BUG-607: a send that was let in ended without learning whether the target answers (the caller cancelled, or it
    /// failed before anything was sent): the probe's turn is handed back and the back-off stays as it was.
    /// </summary>
    public void Release(string target)
    {
        lock (_gate) if (_targets.TryGetValue(target, out var state)) state.ProbeUntil = null;
    }

    /// <summary>The target didn't answer (timed out, couldn't be reached, or a server error): it's backed off.</summary>
    public void Failed(string target)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            if (!_targets.TryGetValue(target, out var state)) _targets[target] = state = new State();
            if (state.BackOffs == 0)
            {
                // BUG-608: not backed off yet: counted, and backed off on the third within the window.
                state.Recent.Enqueue(now);
                while (state.Recent.Count > 0 && now - state.Recent.Peek() > FailureWindow) state.Recent.Dequeue();
                if (state.Recent.Count < FailuresToOpen) return;
                state.Recent.Clear();
            }
            else if (now < state.OpenUntil) return;   // a send started before the back-off: it doesn't lengthen it
            state.BackOffs = Math.Min(state.BackOffs + 1, 16);
            var backOff = TimeSpan.FromTicks(Math.Min(FirstBackOff.Ticks << (state.BackOffs - 1), MaxBackOff.Ticks));
            state.OpenUntil = now + backOff;
            state.ProbeUntil = null;
        }
    }

    private sealed class State
    {
        public int BackOffs;   // 0 while it's only counting failures
        public readonly Queue<DateTimeOffset> Recent = new();
        public DateTimeOffset OpenUntil;
        public DateTimeOffset? ProbeUntil;
    }
}
