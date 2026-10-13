using FluentAssertions;
using IncidentManager.Web.Components.Pages.Workspace;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>REV-25: a transition's time left alone means "now"; only a time someone set is stored as when it happened.</summary>
public sealed class TransitionDraftTests
{
    private static readonly DateTime Opened = new(2026, 10, 12, 9, 0, 0);

    [Fact]
    public void A_time_left_alone_is_now_however_long_the_draft_was_kept()
    {
        var d = new TransitionDraft();
        d.Reset(Opened);

        d.EffectiveUtc(TimeZoneInfo.Utc).Should().BeNull("untouched, it's stored as happening when it's applied");
        d.Backdated(TimeZoneInfo.Utc, new DateTimeOffset(Opened.AddHours(3), TimeSpan.Zero)).Should().BeFalse();
    }

    [Fact]
    public void A_time_someone_set_is_kept_even_if_it_is_the_one_shown_at_the_start()
    {
        var d = new TransitionDraft();
        d.Reset(Opened);
        d.When = Opened;   // kept deliberately, then the sheet sat open for three hours
        d.Edited = true;

        d.EffectiveUtc(TimeZoneInfo.Utc).Should().Be(new DateTimeOffset(Opened, TimeSpan.Zero));
        d.Backdated(TimeZoneInfo.Utc, new DateTimeOffset(Opened.AddHours(3), TimeSpan.Zero)).Should().BeTrue("so it asks for a reason");

        d.Reset(Opened.AddHours(3));
        d.Edited.Should().BeFalse();
    }
}
