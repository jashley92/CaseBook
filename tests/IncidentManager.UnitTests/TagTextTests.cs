using FluentAssertions;
using IncidentManager.Application.Content;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Entity tags and evidence citations edit as [[name]] in plain text boxes and save back as links.</summary>
public class TagTextTests
{
    private static readonly Guid Jane = Guid.Parse("fba4c04a-ba0a-4d2f-ade5-302541694bf7");
    private static readonly Guid File = Guid.Parse("0eb8d243-df1c-4a9a-9a2e-49a2c2bde88c");
    private static readonly Guid Tor = Guid.Parse("9f0c6455-b3aa-4e57-9013-f437e8c56026");
    private static readonly (Guid, string?, string)[] Entities = [(Jane, "Jane Doe (Finance)", "jdoe@contoso.example"), (Tor, null, "185.220.101.4")];

    [Fact]
    public void Links_show_as_tags_and_an_unchanged_text_round_trips_exactly()
    {
        var md = $"[Jane Doe (Finance)](entity:{Jane}) entered credentials; see [audit.csv](evidence:{File}). [a site](https://example.com)";
        var refs = new Dictionary<string, string>();

        var editable = TagText.ToEditable(md, refs);

        editable.Should().Be("[[Jane Doe (Finance)]] entered credentials; see [[audit.csv]]. [a site](https://example.com)");
        TagText.FromEditable(editable, refs, Entities).Should().Be(md);
    }

    [Fact]
    public void Two_links_that_share_a_label_each_keep_their_target(/* BUG-121 */)
    {
        var md = $"Opened [invoice.docm](evidence:{File}); the file [invoice.docm](entity:{Jane}) beaconed out.";
        var refs = new Dictionary<string, string>();

        var editable = TagText.ToEditable(md, refs);

        editable.Should().Be("Opened [[invoice.docm]]; the file [[invoice.docm]] beaconed out.");
        TagText.FromEditable(editable, refs, Entities).Should().Be(md);
    }

    [Fact]
    public void A_typed_tag_links_to_the_entity_of_that_label_or_value_and_an_unknown_one_stays_as_typed()
    {
        var refs = new Dictionary<string, string>();

        TagText.FromEditable("[[jane doe (finance)]] from [[185.220.101.4]] and [[nobody]]", refs, Entities)
            .Should().Be($"[jane doe (finance)](entity:{Jane}) from [185.220.101.4](entity:{Tor}) and [[nobody]]");
        TagText.ToEditable(null, refs).Should().BeNull();
    }

    [Fact]
    public void A_typed_tag_prefers_a_label_to_another_entitys_value_and_ignores_spaces_round_the_label(/* BUG-423 */)
    {
        var host = Guid.Parse("3b1f0b3e-6a40-4a43-9d5f-0f1ad3b5c201");
        var user = Guid.Parse("7c2e1d4f-8b51-4c64-ae60-1f2be4c6d302");
        (Guid, string?, string)[] entities = [(host, null, "Jane"), (user, " Jane ", "jane@contoso.example")];

        TagText.FromEditable("[[Jane]] logged in", new Dictionary<string, string>(), entities)
            .Should().Be($"[Jane](entity:{user}) logged in");
    }

    [Fact]
    public void The_picker_never_offers_a_tag_that_names_two_entities(/* BUG-423 */)
    {
        var a = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var b = Guid.Parse("22222222-2222-4222-8222-222222222222");
        var c = Guid.Parse("33333333-3333-4333-8333-333333333333");
        var d = Guid.Parse("44444444-4444-4444-8444-444444444444");
        (Guid, string?, string)[] entities =
        [
            (a, "Web server", "10.0.0.5"),
            (b, null, "10.0.0.5"),             // shares a's value
            (c, "Payroll ", "payroll.exe"),
            (d, "payroll", "PAYROLL.EXE"),     // shares c's label and value
        ];

        var tags = TagText.PickerTags(entities).ToDictionary(t => t.Id);

        tags[a].Insert.Should().Be("[[Web server]]");
        tags[b].Insert.Should().Be($"[10.0.0.5](entity:{b})");
        tags[c].Insert.Should().Be($"[Payroll](entity:{c})");
        tags[d].Insert.Should().Be($"[payroll](entity:{d})");
        // Whatever the picker inserts saves as a link to that entity.
        foreach (var (id, _, insert) in tags.Values)
            TagText.FromEditable(insert, new Dictionary<string, string>(), entities).Should().Contain($"(entity:{id})");
    }
}
