using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-721: the composer's preview of a pasted screenshot is base64-encoded once per staged file, not on every render
/// (the composer re-renders on each keystroke). BUG-722: the composer stages several, each with its own Remove, and an
/// edit sends the screenshots it keeps and the files added to it. No bUnit, so this checks the source.
/// </summary>
public sealed class TimelineShotPreviewTests
{
    private static string Code() => File.ReadAllText(Path.Combine(ComponentsRoot(), "Pages", "CaseTabs", "CaseTimelineTab.razor"));

    private static string MarkupOf(string code) => code[..code.IndexOf("@code", StringComparison.Ordinal)];

    [Fact]
    public void The_pasted_screenshots_data_uri_is_kept_for_the_bytes_it_was_made_from()
    {
        var code = Code();
        code.Should().Contain("public string DataUri() => _uri ??= ", "it's made once for each staged file, and dropped with it");
        code.Split("Convert.ToBase64String(").Should().HaveCount(2, "encoded in one place");
        MarkupOf(code).Should().Contain("src=\"@shot.DataUri()\"").And.NotContain("ToBase64String");
    }

    [Fact]
    public void The_composer_stages_several_files_each_removable_and_an_edit_sends_what_it_keeps()
    {
        var code = Code();
        code.Should().Contain("<InputFile id=\"timeline-file-paste\" class=\"d-none\" OnChange=\"OnTimelinePasted\" multiple");
        code.Should().Contain("@foreach (var shot in _tlShots)").And.Contain("@onclick=\"() => RemoveStagedShot(shot)\"");
        code.Should().NotContain("can't take a file", "an entry being edited takes more files");
        Methods(code).Single(m => m.Name == "OnTimelinePasted").Body.Should().Contain("ShotRoom", "no more than ten an entry");
        foreach (var save in new[] { "SaveEventEditCore", "SaveInvestigationEditCore" })
            Methods(code).Single(m => m.Name == save).Body.Should().Contain("keepScreenshots: kept").And.Contain("screenshots: Screenshots(shots)");
        foreach (var add in new[] { "AddTimelineCore", "AddEventStepCore" })
            Methods(code).Single(m => m.Name == add).Body.Should().Contain("ClearSavedShots(shots)", "only what was saved is cleared");
        // Every place an entry shows its screenshot shows them all.
        code.Should().NotContain("e.EvidenceId is { } shotId");
        code.Split("@EntryScreenshots(").Should().HaveCount(4, "attack steps, investigation entries and their earlier versions");
    }
}
