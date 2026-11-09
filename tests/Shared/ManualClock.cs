namespace IncidentManager.TestSupport;

/// <summary>
/// A clock whose timers fire only when the test moves it on (<see cref="Advance"/>), for code that waits with
/// <c>Task.Delay(delay, timeProvider)</c>: the test needn't sleep through the delay, and a slow machine can't make a timer
/// fire before the test meant it to. Its time of day starts at the system's. Safe to hand to code that makes and drops
/// timers on its own threads.
/// </summary>
public sealed class ManualClock : TimeProvider
{
    private readonly List<Timer> _timers = [];
    private readonly DateTimeOffset _start = System.GetUtcNow();
    private TimeSpan _now;

    public override DateTimeOffset GetUtcNow()
    {
        lock (_timers) return _start + _now;
    }

    /// <summary>How many timers are waiting to fire: one, say, once the code under test is in its delay.</summary>
    public int Pending
    {
        get { lock (_timers) return _timers.Count(t => t.Due is not null); }
    }

    /// <summary>Moves the clock on by <paramref name="by"/>, firing each timer that falls due on the way.</summary>
    public void Advance(TimeSpan by)
    {
        List<Timer> due;
        lock (_timers)
        {
            _now += by;
            due = _timers.Where(t => t.Due <= _now).ToList();
            foreach (var t in due) t.Due = null;
        }
        foreach (var t in due) t.Callback(t.State);
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new Timer(this, callback, state);
        lock (_timers) _timers.Add(timer);
        timer.Change(dueTime, period);
        return timer;
    }

    private sealed class Timer(ManualClock owner, TimerCallback callback, object? state) : ITimer
    {
        public TimerCallback Callback => callback;
        public object? State => state;
        public TimeSpan? Due { get; set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (owner._timers) Due = dueTime == Timeout.InfiniteTimeSpan ? null : owner._now + dueTime;
            return true;
        }

        public void Dispose()
        {
            lock (owner._timers) owner._timers.Remove(this);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
