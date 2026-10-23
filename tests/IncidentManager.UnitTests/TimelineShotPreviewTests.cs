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
        Methods(code).Single(m => m.Name == "StageFile").Body.Should().Contain("ShotRoom", "no more than ten an entry");
        foreach (var save in new[] { "SaveEventEditCore", "SaveInvestigationEditCore" })
            Methods(code).Single(m => m.Name == save).Body.Should().Contain("keepScreenshots: kept").And.Contain("screenshots: Screenshots(shots)");
        foreach (var add in new[] { "AddTimelineCore", "AddEventStepCore" })
            Methods(code).Single(m => m.Name == add).Body.Should().Contain("ClearSavedShots(shots)", "only what was saved is cleared");
        // Every place an entry shows its screenshot shows them all.
        code.Should().NotContain("e.EvidenceId is { } shotId");
        code.Split("@EntryScreenshots(").Should().HaveCount(4, "attack steps, investigation entries and their earlier versions");
    }

    [Fact]
    public void Only_images_count_against_the_ten_and_one_other_file_is_cited(/* BUG-722 follow-up */)
    {
        var code = Code();
        code.Should().Contain("private int ShotRoom => TimelineEntry.MaxScreenshots - _tlShots.Count(x => x.IsRaster) -",
            "the server counts images only");
        var stage = Methods(code).Single(m => m.Name == "StageFile").Body;
        stage.Should().Contain("if (raster is not null && ShotRoom <= 0) return StageRefusal.NoRoom;")
            .And.Contain("if (raster is null && _tlShots.Any(x => !x.IsRaster)) return StageRefusal.OneFile;");
        Methods(code).Single(m => m.Name == "OnTimelinePasted").Body.Should().NotContain("Take(room)", "a file is staged or refused by what it is");
    }

    [Fact]
    public void The_full_size_view_steps_through_the_entrys_screenshots(/* BUG-722 follow-up */)
    {
        var code = Code();
        code.Should().Contain("@onclick=\"() => OnPreviewSet.InvokeAsync((shots, at))\"", "a thumbnail opens with its entry's others");
        var root = ComponentsRoot();
        var dialogs = File.ReadAllText(Path.Combine(root, "Pages", "Workspace", "WorkspaceDialogs.razor"));
        var lightbox = dialogs[dialogs.IndexOf("@if (ShotId is { } previewId)", StringComparison.Ordinal)..dialogs.IndexOf("@code", StringComparison.Ordinal)];
        lightbox.Should().Contain("var many = ShotSet.Count > 1").And.Contain("@if (many)", "buttons only for more than one")
            .And.Contain("OnStepShot.InvokeAsync(-1)").And.Contain("OnStepShot.InvokeAsync(1)")
            .And.Contain("@(at + 1) of @ShotSet.Count").And.Contain("@onkeydown=\"ShotKey\"");
        // The arrows can't come from a text box: there is none in the dialog, and its trap (im-trap) keeps the focus in it.
        lightbox.Should().Contain("im-trap").And.NotContain("<input").And.NotContain("<textarea").And.NotContain("contenteditable");
        Methods(dialogs).Single(m => m.Name == "ShotKey").Body.Should().Contain("ShotSet.Count > 1")
            .And.Contain("\"ArrowLeft\" or \"ArrowRight\"").And.Contain("return Escape(e);", "Esc still closes it");
        var ws = File.ReadAllText(Path.Combine(root, "Pages", "CaseWorkspace.razor"));
        ws.Should().Contain("ShotSet=\"_previewShots\" OnStepShot=\"StepShot\"").And.Contain("OnPreviewSet=\"OpenShots\"");
        var acts = File.ReadAllText(Path.Combine(root, "Pages", "CaseWorkspace.Acts.cs"));
        Methods(acts).Single(m => m.Name == "StepShot").Body.Should().Contain("ShowShot(", "each one stepped to is recorded as viewed");
    }
}
