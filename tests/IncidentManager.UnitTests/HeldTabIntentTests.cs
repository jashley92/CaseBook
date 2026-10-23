using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-703, BUG-719: a one-shot intent set for the tab being opened (the fix to hand over, the Unknown entities to select,
/// the composer to focus, the entry to jump to, the filter or playbook to apply) must be dropped when the switch is held
/// for unsaved text. Left set, it fired on a later, unrelated visit to that tab (and the Briefing still showing was handed
/// the impact fix, passed it back, and the Stay / Discard prompt came back after every Stay). (No bUnit, so this checks
/// the source.)
/// </summary>
public sealed partial class HeldTabIntentTests
{
    private static IEnumerable<(string File, string Code)> Workspace() =>
        Directory.GetFiles(Path.Combine(ComponentSourceScanner.ComponentsRoot(), "Pages"), "CaseWorkspace*")
            .Select(f => (Path.GetFileName(f), ComponentSourceScanner.StripComments(File.ReadAllText(f))));

    [Fact]
    public void An_intent_set_before_a_tab_switch_is_dropped_when_the_switch_is_held()
    {
        var found = 0;
        foreach (var (file, code) in Workspace())
            foreach (Match m in IntentThenSwitch().Matches(code))
            {
                found++;
                var (field, tab, after) = (m.Groups["f"].Value, m.Groups["t"].Value, m.Groups["after"].Value);
                var shown = tab == "Notes" ? "Timeline" : tab;
                (after.Contains($"if (_activeTab != \"{shown}\") {field} = ") || after.Contains($"if (!Showing(\"{tab}\")) {field} = "))
                    .Should().BeTrue($"{file}: {field} must be dropped when the switch to {tab} is held");
            }
        found.Should().BeGreaterThan(5, "the gate Fix, the shortcuts and the panels set intents before switching");
    }

    [Fact]
    public void An_intent_set_after_a_tab_switch_is_set_only_when_it_happened()
    {
        foreach (var (file, code) in Workspace())
            SwitchThenIntent().Matches(code).Should().BeEmpty($"{file}: set after a switch, it must first check the switch happened");
    }

    // A field set, then a switch to a tab (possibly through the phone pane), then the statement after it.
    [GeneratedRegex(@"(?<f>_\w+) = [^;]+;\s*(?:if \(PhoneNowNext\)[^;]+;\s*else )?await SetTab\(""(?<t>\w+)""\);(?<after>[^;]*;)")]
    private static partial Regex IntentThenSwitch();

    // A switch to a tab, then a field set straight after it.
    [GeneratedRegex(@"await SetTab\(""\w+""\);\s*_\w+ = ")]
    private static partial Regex SwitchThenIntent();
}
