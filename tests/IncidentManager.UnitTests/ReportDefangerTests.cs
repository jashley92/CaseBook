using FluentAssertions;
using IncidentManager.Application.Content;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-44: report indicators are defanged so a forwarded report can't be clicked through.</summary>
public class ReportDefangerTests
{
    private static ReportDefanger With(params (EntityType Type, string Value)[] entities) =>
        ReportDefanger.For(entities.Select(e => new CaseEntity { Type = e.Type, Value = e.Value }), enabled: true);

    [Theory]
    [InlineData(EntityType.Url, "https://evil.example/login", "hxxps://evil[.]example/login")]
    [InlineData(EntityType.Domain, "evil.example", "evil[.]example")]
    [InlineData(EntityType.IpAddress, "203.0.113.7", "203[.]0[.]113[.]7")]
    [InlineData(EntityType.EmailAddress, "ceo@evil.example", "ceo[at]evil[.]example")]
    [InlineData(EntityType.FileHash, "d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e")]
    [InlineData(EntityType.Host, "ws-042.corp.example", "ws-042.corp.example")]
    public void Structured_values_are_defanged_only_when_linkable(EntityType type, string value, string expected) =>
        With().Value(type, value).Should().Be(expected);

    [Fact]
    public void Prose_has_known_indicators_urls_and_ips_defanged()
    {
        var d = With((EntityType.Domain, "evil.example"), (EntityType.EmailAddress, "ceo@evil.example"));

        d.Text("User clicked a link to evil.example from ceo@evil.example, then http://other.test/x; beacon to 198.51.100.4.")
            .Should().Be("User clicked a link to evil[.]example from ceo[at]evil[.]example, then hxxp://other[.]test/x; beacon to 198[.]51[.]100[.]4.");
    }

    [Fact]
    public void A_url_wins_over_the_domain_inside_it_and_nothing_is_defanged_twice()
    {
        var d = With((EntityType.Domain, "evil.example"), (EntityType.Url, "https://evil.example/a"));

        d.Text("See https://evil.example/a and evil.example").Should().Be("See hxxps://evil[.]example/a and evil[.]example");
        d.Text("Already hxxp://evil[.]example").Should().Be("Already hxxp://evil[.]example");
    }

    [Fact]
    public void Formatting_is_kept_in_rich_text()
    {
        var d = With((EntityType.Domain, "evil.example"));
        var blocks = RichText.Parse("**Blocked** evil.example at the proxy");

        var text = string.Concat(d.Blocks(blocks).SelectMany(b => b.Runs).Select(r => r.Text));

        text.Should().Contain("evil[.]example");
        d.Blocks(blocks)[0].Runs[0].Bold.Should().BeTrue();
    }

    [Fact]
    public void Off_changes_nothing()
    {
        ReportDefanger.Off.Value(EntityType.Url, "http://x.test").Should().Be("http://x.test");
        ReportDefanger.Off.Text("go to http://x.test").Should().Be("go to http://x.test");
        ReportDefanger.Off.Enabled.Should().BeFalse();
    }
}
