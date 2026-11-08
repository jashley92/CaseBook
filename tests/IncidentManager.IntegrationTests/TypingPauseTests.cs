using IncidentManager.Web.Services;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>The pause before the ATT&amp;CK picker's filter acts on what's typed: once per pause, the last keystroke wins,
/// what applies at once drops the pending one, and a later piece of work supersedes an earlier one's answer.</summary>
public class TypingPauseTests
{
    [Fact]
    public void A_picker_waits_200ms_by_default()
    {
        Assert.Equal(200, TypingPause.SearchMs);
        Assert.Equal(TypingPause.SearchMs, new TypingPause().DelayMs);
    }

    // The pauses run on a clock the test moves on, so a busy machine's slow timers can't put a keystroke after the pause
    // it was meant to fall within.
    private readonly ManualClock _clock = new();

    [Fact]
    public async Task A_pause_after_one_keystroke_applies_it_once()
    {
        var pause = new TypingPause(20, _clock);
        var settled = pause.Settled();
        _clock.Advance(TimeSpan.FromMilliseconds(19));
        Assert.False(settled.IsCompleted, "the pause hasn't passed");
        _clock.Advance(TimeSpan.FromMilliseconds(1));
        Assert.True(await settled);
    }

    [Fact]
    public async Task A_keystroke_within_the_pause_supersedes_the_one_before()
    {
        var pause = new TypingPause(150, _clock);
        var first = pause.Settled();
        _clock.Advance(TimeSpan.FromMilliseconds(30));
        var second = pause.Settled();
        var third = pause.Settled();
        _clock.Advance(TimeSpan.FromMilliseconds(150));
        bool[] settled = await Task.WhenAll(first, second, third);
        Assert.Equal(new[] { false, false, true }, settled);
    }

    [Fact]
    public async Task Applying_at_once_drops_the_pending_keystroke()
    {
        var pause = new TypingPause(100, _clock);
        var pending = pause.Settled();
        pause.Now(); // Clear, Enter or closing the picker
        _clock.Advance(TimeSpan.FromMilliseconds(100));
        Assert.False(await pending);
        // The next keystroke pauses again as usual.
        var next = pause.Settled();
        _clock.Advance(TimeSpan.FromMilliseconds(100));
        Assert.True(await next);
    }

    [Fact]
    public async Task Work_started_later_supersedes_an_earlier_answer()
    {
        var pause = new TypingPause(50, _clock);
        var earlier = pause.Now();
        Assert.True(pause.IsLatest(earlier));
        var later = pause.Now();
        Assert.False(pause.IsLatest(earlier), "its answer is dropped");
        Assert.True(pause.IsLatest(later));
        var typing = pause.Settled(); // a keystroke supersedes it too
        Assert.False(pause.IsLatest(later));
        _clock.Advance(TimeSpan.FromMilliseconds(50));
        Assert.True(await typing);
    }
}
