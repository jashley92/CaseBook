using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-721: the composer's preview of a pasted screenshot is base64-encoded once per staged file, not on every render
/// (the composer re-renders on each keystroke). No bUnit, so this checks the source.
/// </summary>
public sealed class TimelineShotPreviewTests
{
    [Fact]
    public void The_pasted_screenshots_data_uri_is_kept_for_the_bytes_it_was_made_from()
    {
        var code = File.ReadAllText(Path.Combine(ComponentsRoot(), "Pages", "CaseTabs", "CaseTimelineTab.razor"));
        var body = Methods(code).Single(m => m.Name == "TlShotDataUri").Body;
        body.Should().Contain("ReferenceEquals(kept.Bytes, _tlShotBytes)", "it's made again only for other bytes");
        Methods(code).Where(m => m.Name == "ClearTimelineShot").Select(m => m.Body)
            .Should().Contain(b => b.Contains("_tlShotUri = null"), "a removed file's string isn't held");
        code.Split("Convert.ToBase64String(_tlShotBytes)").Should().HaveCount(2, "encoded in one place");
    }
}
