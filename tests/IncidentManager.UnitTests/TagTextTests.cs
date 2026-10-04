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
    public void A_typed_tag_links_to_the_entity_of_that_label_or_value_and_an_unknown_one_stays_as_typed()
    {
        var refs = new Dictionary<string, string>();

        TagText.FromEditable("[[jane doe (finance)]] from [[185.220.101.4]] and [[nobody]]", refs, Entities)
            .Should().Be($"[jane doe (finance)](entity:{Jane}) from [185.220.101.4](entity:{Tor}) and [[nobody]]");
        TagText.ToEditable(null, refs).Should().BeNull();
    }
}
