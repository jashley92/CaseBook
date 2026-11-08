using IncidentManager.Domain.Enums;
using IncidentManager.Web.Components.Shared;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// The ATT&amp;CK matrix picker's filter box: a keystroke waits out the typing pause before the matrix changes, and until
/// then the picker doesn't render at all (the box already shows what's typed), so the matrix isn't diffed per letter.
/// When it does render, what was typed isn't written back to the box, so newer keystrokes aren't lost; a clear is.
/// </summary>
public class AttackMatrixPickerTypingTests
{
    private static Dictionary<string, object?> NoTags() =>
        new() { ["Current"] = (IReadOnlyDictionary<string, MitreTactic>)new Dictionary<string, MitreTactic>() };

    [Fact]
    public async Task A_keystroke_does_not_render_the_matrix_until_typing_pauses_and_is_never_written_back()
    {
        await using var r = RecordingRenderer.Create();
        await r.Mount<AttackMatrixPicker>(NoTags());
        Assert.False(r.Shows("atkm-col-hidden"), "with nothing typed every tactic shows");

        // The first letter brings the Clear button, so it draws at once; the matrix filters once typing pauses.
        var first = await r.Type("phish");
        Assert.True(r.Shows("Clear"));
        Assert.False(r.Shows("atkm-filterline"));
        await first;
        Assert.True(r.Shows("atkm-filterline"));
        Assert.True(r.Shows("atkm-col-hidden"));
        Assert.Empty(r.ValuesSent); // what's typed isn't written back to the box
        Assert.Equal("phish", r.Drawn); // Blazor's copy of the box follows the typing

        // A later keystroke: nothing renders while it pauses, not the box's value and not the matrix.
        var redraws = r.Redraws;
        var second = await r.Type("phishing");
        Assert.Equal(redraws, r.Redraws);
        await second;

        // Two quick keystrokes: the first is superseded and draws nothing; the second filters.
        var a = await r.Type("T1566");
        var b = await r.Type("T1566.001");
        await Task.WhenAll(a, b);
        Assert.True(r.Shows("T1566.001"));
        Assert.Empty(r.ValuesSent);

        // Clear empties the box: a change Blazor sends.
        await r.Click("Clear");
        Assert.Equal([""], r.ValuesSent);
        Assert.False(r.Shows("atkm-filterline"));

        // Typed again and cleared again: the second clear reaches the box too.
        await await r.Type("lure");
        await r.Click("Clear");
        Assert.Equal(["", ""], r.ValuesSent);
    }

    [Fact]
    public async Task Enter_filters_at_once_and_nothing_matching_says_so()
    {
        await using var r = RecordingRenderer.Create();
        await r.Mount<AttackMatrixPicker>(NoTags());
        var pending = await r.Type("qqzzxv");
        await r.Key("Enter");
        Assert.True(r.Shows("No techniques match 'qqzzxv'"));
        await pending; // the pause it started is superseded: still the same view
        Assert.True(r.Shows("No techniques match 'qqzzxv'"));
    }

    [Fact]
    public async Task A_retired_id_in_the_filter_says_where_it_went_and_shows_the_replacement()
    {
        await using var r = RecordingRenderer.Create();
        await r.Mount<AttackMatrixPicker>(NoTags());
        await await r.Type("T1574.002");
        Assert.True(r.Shows("is no longer in ATT&CK v19.1: it was replaced by T1574.001 DLL."));
        await r.Click("Show T1574.001");
        Assert.Equal(["T1574.001"], r.ValuesSent); // the box now holds the replacement
        Assert.False(r.Shows("is no longer in ATT&CK"));
        Assert.True(r.Shows("Showing "));
    }

    [Fact]
    public async Task A_retired_tag_is_replaced_under_a_tactic_the_replacement_has()
    {
        IReadOnlyDictionary<string, MitreTactic>? applied = null;
        await using var r = RecordingRenderer.Create();
        await r.Mount<AttackMatrixPicker>(new()
        {
            ["Current"] = (IReadOnlyDictionary<string, MitreTactic>)new Dictionary<string, MitreTactic>
            {
                ["T1574.002"] = MitreTactic.Persistence, // T1574.001 isn't under Persistence: it takes its primary tactic
                ["T1999.123"] = MitreTactic.Execution,   // custom: never in ATT&CK, stays in its own strip
            },
            ["OnApply"] = Microsoft.AspNetCore.Components.EventCallback.Factory.Create<IReadOnlyDictionary<string, MitreTactic>>(this, d => applied = d),
        });
        Assert.True(r.Shows("No longer in ATT"));
        Assert.True(r.Shows("Custom:"));

        await r.Click("Replace with T1574.001");
        Assert.False(r.Shows("No longer in ATT"));
        await r.Click("Apply");

        Assert.NotNull(applied);
        var primary = IncidentManager.Application.Mitre.AttackCatalog.Find("T1574.001")!.PrimaryTactic;
        Assert.Equal(primary, applied["T1574.001"]);
        Assert.False(applied.ContainsKey("T1574.002"));
        Assert.Equal(MitreTactic.Execution, applied["T1999.123"]);
    }

    [Fact]
    public async Task Expand_buttons_and_column_heads_say_what_they_are()
    {
        await using var r = RecordingRenderer.Create();
        await r.Mount<AttackMatrixPicker>(NoTags());
        Assert.True(r.Shows("Expand the sub-techniques of T1059"));
        Assert.True(r.Shows("TA0002: "), "a column head names its tactic id");
        await await r.Type("powershell");
        Assert.True(r.Shows("Collapse the sub-techniques of T1059"), "a sub-technique match opens its parent");
        Assert.True(r.Shows("Showing "));
    }
}
