using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-703: a one-shot intent set for the tab being opened (the fix to hand over, the Unknown entities to select) must be
/// dropped when the switch is held for unsaved text. Left set, the Briefing still showing was handed the impact fix,
/// passed it back, and the Stay / Discard prompt came back after every Stay. (No bUnit, so this checks the source.)
/// </summary>
public sealed partial class HeldTabIntentTests
{
    [Fact]
    public void An_intent_set_before_a_tab_switch_is_dropped_when_the_switch_is_held()
    {
        var code = ComponentSourceScanner.StripComments(File.ReadAllText(Path.Combine(ComponentSourceScanner.ComponentsRoot(),
            "Pages", "CaseWorkspace.Dialogs.cs")));
        var sets = IntentThenSwitch().Matches(code);
        sets.Should().NotBeEmpty("the gate Fix sets intents before switching");
        foreach (Match m in sets)
        {
            var (field, tab) = (m.Groups["f"].Value, m.Groups["t"].Value);
            m.Groups["after"].Value.Should().Contain($"if (_activeTab != \"{tab}\") {field} = ",
                $"{field} must be dropped when the switch to {tab} is held");
        }
    }

    // A field set, then a switch to a tab, then the statement after it.
    [GeneratedRegex(@"(?<f>_\w+) = [^;]+;\s*await SetTab\(""(?<t>\w+)""\);(?<after>[^;]*;)")]
    private static partial Regex IntentThenSwitch();
}
