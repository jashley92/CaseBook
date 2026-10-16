using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-578 (C7): anything that hides, replaces or re-seeds an editor first reads back and keeps (or asks before losing)
/// the unsaved text. Owner decisions: a tab switch, leaving the case or the time-display redraw with unsaved text asks
/// Stay / Discard; starting an edit on a second row while one is open is refused with the standard toast. The checks:
/// the workspace asks UnsavedEdits before each of those; every case component with plain text fields registers them
/// with UnsavedEdits (markdown editors are asked through the browser); and a second row's edit opens through an
/// EditSlot (or refuses on its own).
/// </summary>
/// <remarks>What it can't see: whether a registered check covers every field (it reads the component's own state);
/// an editor re-seeded by a parameter change (a panel moving to another item re-seeds in OnParametersSet, which the
/// panel itself must guard); a viewport resize that hides the Now/Next pane (nothing to ask: the browser already moved).</remarks>
public partial class EditPreservationTests
{
    // Wave 2b: components with plain text fields that don't register them yet (a tab switch, leaving the case or the
    // time-display redraw then loses them without asking).
    private static readonly Dictionary<string, int> Untracked = new(StringComparer.Ordinal)
    {
        // wave 2b, U1 (timeline, notes)
        ["Pages/CaseTabs/CaseTimelineTab.razor"] = 1,   // 15 text field(s), no Edits.Track
        // wave 2b, U3 (entities, overview, panels, evidence)
        ["Pages/CaseTabs/CaseEntitiesTab.razor"] = 1,   // 8 text field(s), no Edits.Track
        ["Pages/CaseTabs/CaseOverviewTab.razor"] = 1,   // 8 text field(s), no Edits.Track
        // wave 2b, U4 (pages, admin, other shared)
        ["Pages/CaseTabs/CaseReviewTab.razor"] = 1,   // 4 text field(s), no Edits.Track
        ["Shared/PromoteToTimeline.razor"] = 1,   // 1 text field(s), no Edits.Track
    };

    // Wave 2b: "Edit" / "Done" on a row that replaces another row's open edit instead of refusing (EditSlot.TryOpen).
    private static readonly Dictionary<string, int> Replacing = new(StringComparer.Ordinal)
    {
        // wave 2b, U1 (timeline, notes)
        ["Pages/CaseTabs/CaseNotesTab.razor"] = 1,   // StartNoteEdit
        ["Pages/CaseTabs/CaseTimelineTab.razor"] = 2,   // StartEventEdit; StartInvestigationEdit
        // wave 2b, U3 (entities, overview, panels, evidence)
        ["Pages/CaseTabs/CaseEntitiesTab.razor"] = 2,   // StartEntityEdit; BeginEditRelationship
        // wave 2b, U4 (pages, admin, other shared)
        ["Pages/CaseTabs/CaseReviewTab.razor"] = 1,   // BeginEdit
        ["Shared/RegulatoryDeadlineRules.razor"] = 1,   // BeginEdit
    };

    // The case workspace's own forms: their text is the workspace's (CaseActionDraft, CloseOutDraft, the header's
    // number), tracked by CaseWorkspace (ActionDirty, CloseOutDirty) and CaseHeader.
    private static readonly HashSet<string> HeldByTheWorkspace = new(StringComparer.Ordinal)
    {
        "Pages/Workspace/CaseActionForm.razor", "Pages/Workspace/CaseCloseOut.razor", "Pages/Workspace/GateSection.razor",
        "Pages/Workspace/WhenItHappened.razor",
    };

    [Fact]
    public void Every_case_component_with_plain_text_fields_registers_them()
    {
        var found = new List<(string File, string What)>();
        foreach (var (file, parts) in Components().Where(c => InTheCase(c.File) && !HeldByTheWorkspace.Contains(c.File)))
        {
            var fields = parts.Sum(p => PlainField().Count(Markup(p)));
            if (fields == 0) continue;
            var code = string.Concat(parts.Select(p => p.Code));
            var tracks = Track().Matches(code).ToList();
            if (tracks.Count == 0) found.Add((file, $"{fields} text field(s), no Edits.Track"));
            else if (file.StartsWith("Pages/CaseTabs/", StringComparison.Ordinal) && tracks.Any(t => t.Groups["args"].Value.Split(',').Length < 4))
                found.Add((file, "Edits.Track without its Region (a tab switch wouldn't ask)"));
        }
        var (offenders, stale) = Against(Untracked, found);
        offenders.Should().BeEmpty("a component's typed-but-unsaved text is registered with UnsavedEdits, with the region it's in");
        stale.Should().BeEmpty("a fixed component comes off the wave-2b list");
    }

    [Fact]
    public void A_second_rows_edit_is_refused_not_replaced()
    {
        var found = new List<(string File, string What)>();
        foreach (var (file, parts) in Components())
        {
            foreach (var m in parts.SelectMany(p => Methods(p.Code)).Where(m => Opener().IsMatch(m.Name)))
            {
                if (!RowKey().IsMatch(m.Body)) continue;   // opens nothing for a row
                if (Refuses().IsMatch(m.Body)) continue;
                found.Add((file, m.Name));
            }
        }
        var (offenders, stale) = Against(Replacing, found);
        offenders.Should().BeEmpty("Edit on a second row while one is open says \"Save or cancel the X you're editing\" (EditSlot.TryOpen)");
        stale.Should().BeEmpty("a fixed site comes off the wave-2b list");
    }

    [Fact]
    public void The_workspace_asks_before_it_hides_unsaved_text()
    {
        var ws = Components().Single(c => c.File == "Pages/CaseWorkspace.razor").Parts;
        var methods = ws.SelectMany(p => Methods(p.Code)).GroupBy(m => m.Name).ToDictionary(g => g.Key, g => g.First().Body);
        // A switch of part, a phone view, the pane, a panel moving or closing, a dialog over a dialog with input in it.
        foreach (var name in new[] { "SetTab", "PhoneGo", "LeavePhonePane", "ToggleRail" })
            methods[name].Should().Contain("HoldForUnsavedAsync", $"{name} hides an editor");
        foreach (var name in new[] { "OpenEntity", "OpenEvidence", "CloseEntityPanel", "CloseEvidencePanel", "ShowCitation", "ShowEntityOnTimeline", "EntityPanelGoTo" })
            methods[name].Should().Contain("HoldPanelAsync", $"{name} moves or closes a panel");
        methods["HoldPanelAsync"].Should().Contain("HoldForUnsavedAsync");
        methods["TryOpenModal"].Should().Contain("HoldOpenAction");
        methods["FixGateItem"].Should().Contain("HoldOpenAction");
        methods["OnBeforeInternalNav"].Should().Contain("Edits.PendingAsync");
        // ShowTab is the unguarded switch; only the workspace's own moves use it (a load, a live refresh, a case it has
        // just moved to, a Discard).
        var showTabCallers = methods.Where(m => m.Key != "SetTab" && m.Value.Contains("ShowTab(", StringComparison.Ordinal)).Select(m => m.Key);
        showTabCallers.Should().BeSubsetOf(["OnParametersSetAsync", "ReloadWith", "ApplyChangeAsync", "PhoneGo"]);

        var profile = Sources().Single(s => s.File == "Shared/ProfileMenu.razor").Code;
        Methods(profile).Single(m => m.Name == "HoldForUnsavedAsync").Body.Should().Contain("Edits.PendingAsync", "the time-display redraw asks too");
    }

    [Fact]
    public void The_stashed_composer_the_workspace_lets_a_tab_switch_keep_is_the_timelines()
    {
        // CaseWorkspace.StashedComposerId mirrors CaseTimelineTab.InvEditorId (FR-02's stash, kept across a tab switch).
        var timeline = Sources().Single(s => s.File == "Pages/CaseTabs/CaseTimelineTab.razor").Raw;
        timeline.Should().Contain("InvEditorId => $\"inv-md-{CaseId}\"");
        var dialogs = Sources().Single(s => s.File == "Pages/CaseWorkspace.Dialogs.cs").Raw;
        dialogs.Should().Contain("StashedComposerId => $\"inv-md-{_case?.Id}\"");
        var js = File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "wwwroot", "js", "markdown-editor.js"));
        js.Should().Contain("dirtyIds: function (within, except)");
        var program = File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "Program.cs"));
        program.Should().Contain("AddScoped<IncidentManager.Web.Services.UnsavedEdits>()");
    }

    [Theory]
    [InlineData("private void BeginEdit(ActionItem t) { _editingTaskId = t.Id; _editTitle = t.Title; }", true)]
    [InlineData("private void BeginEdit(ActionItem t) { if (!_edit.TryOpen(t.Id, Toasts, \"task\")) return; _editTitle = t.Title; }", false)]
    [InlineData("private void StartNoteEdit(Note n) { if (_editId is not null) { Toasts.Info(EditSlot.Refusal(\"note\")); return; } _editId = n.Id; }", false)]
    public void The_opener_scan_tells_a_refusal_from_a_replacement(string snippet, bool flagged)
    {
        var m = Methods(Strip(snippet)).Single();
        (Opener().IsMatch(m.Name) && RowKey().IsMatch(m.Body) && !Refuses().IsMatch(m.Body)).Should().Be(flagged);
    }

    // The components the case workspace shows (its tabs, panels and pane, its own forms, and the shared ones used in them).
    private static bool InTheCase(string file) =>
        file.StartsWith("Pages/CaseTabs/", StringComparison.Ordinal) || file.StartsWith("Pages/Workspace/", StringComparison.Ordinal)
        || file is "Shared/QuickTask.razor" or "Shared/PromoteToTimeline.razor";

    // A text box bound to the component's state: <input> of a text kind or <textarea>, with @bind or a value/oninput pair.
    [GeneratedRegex(@"<(?:input(?![^>]*type=""(?:checkbox|radio|file|hidden|range|color|button|submit)"")|textarea)\b[^>]*(?:@bind(?!-Value)|@oninput)[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline, matchTimeoutMilliseconds: 1000)]
    private static partial Regex PlainField();

    [GeneratedRegex(@"\bEdits\.Track\((?<args>(?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Track();

    [GeneratedRegex(@"^(?:Start|Begin)\w*$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Opener();

    // The row the edit is for, put in a field: `_editingTaskId = t.Id`, `_editId = id` (not the case itself: one per page).
    [GeneratedRegex(@"\b_\w*(?:Id|For|Key)\s*=\s*(?:(?!Case\.)\w+\.Id\b|id\b|key\b)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex RowKey();

    [GeneratedRegex(@"\.TryOpen\(|EditSlot\.Refusal\(|you're editing", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Refuses();
}
