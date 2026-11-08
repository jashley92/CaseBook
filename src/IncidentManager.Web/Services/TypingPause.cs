namespace IncidentManager.Web.Services;

/// <summary>
/// A pause before acting on what's typed: a word typed is one search, not one a letter. Each keystroke awaits
/// <see cref="Settled"/>; only the last one before typing stops for <see cref="DelayMs"/> gets true. <see cref="Now"/>
/// drops a pending one, for what applies at once (Clear, Enter, closing), and hands back a mark that
/// <see cref="IsLatest"/> checks, so a slower answer to an earlier search can be dropped when a later one started.
/// </summary>
/// <param name="delayMs">How long typing must stop; <see cref="SearchMs"/> unless the caller says otherwise.</param>
/// <param name="time">The clock the pause runs on (a test moves its own on).</param>
public sealed class TypingPause(int delayMs = TypingPause.SearchMs, TimeProvider? time = null)
{
    /// <summary>How long a picker waits after a keystroke before it filters.</summary>
    public const int SearchMs = 200;

    private int _latest;

    /// <summary>How long typing must stop before the work runs.</summary>
    public int DelayMs => delayMs;

    /// <summary>Waits out the pause after a keystroke: true when nothing came after it in the meantime.</summary>
    public async Task<bool> Settled()
    {
        var mine = ++_latest;
        await Task.Delay(TimeSpan.FromMilliseconds(delayMs), time ?? TimeProvider.System);
        return mine == _latest;
    }

    /// <summary>Supersedes any pending keystroke (its <see cref="Settled"/> answers false), and marks the work starting
    /// now: <see cref="IsLatest"/> says whether anything has superseded it since.</summary>
    public int Now() => ++_latest;

    /// <summary>Whether nothing has come since <paramref name="mark"/> (from <see cref="Now"/>): no keystroke, and no other work.</summary>
    public bool IsLatest(int mark) => mark == _latest;
}
