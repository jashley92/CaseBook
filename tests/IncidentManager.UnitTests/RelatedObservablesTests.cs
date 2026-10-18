using FluentAssertions;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>CAP-28: the fixed rules for "possibly related" indicators.</summary>
public sealed class RelatedObservablesTests
{
    [Theory]
    [InlineData("evil.example", "evil.example")]
    [InlineData("login.evil.example", "evil.example")]
    [InlineData("a.b.Evil.Example.", "evil.example")]
    [InlineData("portal.contoso.co.uk", "contoso.co.uk")]
    [InlineData("contoso.com.au", "contoso.com.au")]
    [InlineData("x.y.gov.in", "y.gov.in")]
    [InlineData("phish.azurewebsites.net", "phish.azurewebsites.net")]
    [InlineData("a.phish.github.io", "phish.github.io")]
    [InlineData("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com")]
    public void The_registrable_domain_is_approximated_without_a_suffix_list(string host, string expected) =>
        RelatedObservables.RegistrableDomain(host).Should().Be(expected);

    [Theory]
    [InlineData("localhost")]
    [InlineData("co.uk")]
    [InlineData("azurewebsites.net")]
    [InlineData("203.0.113.5")]
    [InlineData("bad..name")]
    [InlineData("1.2.3")]
    public void A_name_with_no_registrable_domain_has_none(string host) =>
        RelatedObservables.RegistrableDomain(host).Should().BeNull();

    [Fact]
    public void A_parent_a_child_and_a_sibling_domain_are_related_and_a_url_on_one_too()
    {
        RelatedObservables.AreRelated(EntityType.Domain, "evil.example", EntityType.Domain, "cdn.evil.example").Should().BeTrue();
        RelatedObservables.AreRelated(EntityType.Domain, "a.evil.example", EntityType.Domain, "b.evil.example").Should().BeTrue();
        RelatedObservables.AreRelated(EntityType.Domain, "evil.example", EntityType.Url, "https://login.evil.example/x").Should().BeTrue();
        RelatedObservables.AreRelated(EntityType.Domain, "evil.example", EntityType.Domain, "notevil.example").Should().BeFalse();
        RelatedObservables.AreRelated(EntityType.Domain, "a.azurewebsites.net", EntityType.Domain, "b.azurewebsites.net").Should()
            .BeFalse("everyone is hosted on a shared suffix");
    }

    [Fact]
    public void The_identical_value_is_a_match_not_a_suggestion()
    {
        RelatedObservables.AreRelated(EntityType.Domain, "evil.example", EntityType.Domain, "EVIL.example").Should().BeFalse();
        RelatedObservables.AreRelated(EntityType.Account, "a@evil.example", EntityType.EmailAddress, "a@evil.example").Should().BeFalse();
    }

    [Fact]
    public void Addresses_in_one_slash_24_or_slash_48_are_related()
    {
        RelatedObservables.AreRelated(EntityType.IpAddress, "203.0.113.5", EntityType.IpAddress, "203.0.113.200").Should().BeTrue();
        RelatedObservables.AreRelated(EntityType.IpAddress, "203.0.113.5", EntityType.IpAddress, "203.0.114.5").Should().BeFalse();
        RelatedObservables.AreRelated(EntityType.IpAddress, "203.0.113.5", EntityType.Url, "http://203.0.113.9:8080/a").Should().BeTrue();
        RelatedObservables.KeyOf(EntityType.IpAddress, "203.0.113.5")!.Value.Describe().Should().Be("same /24 (203.0.113.0/24)");
        RelatedObservables.AreRelated(EntityType.IpAddress, "2001:db8:1::5", EntityType.IpAddress, "2001:db8:1:ff::9").Should().BeTrue();
        RelatedObservables.AreRelated(EntityType.IpAddress, "2001:db8::5", EntityType.IpAddress, "2001:db8:0:1::5").Should().BeTrue();
        RelatedObservables.AreRelated(EntityType.IpAddress, "2001:db8:1::5", EntityType.IpAddress, "2001:db8:2::5").Should().BeFalse();
        RelatedObservables.KeyOf(EntityType.IpAddress, "127.0.0.1").Should().BeNull();
        RelatedObservables.KeyOf(EntityType.IpAddress, "1.2.3").Should().BeNull();
    }

    [Fact]
    public void Addresses_at_one_email_domain_are_related_but_not_at_free_mail()
    {
        RelatedObservables.AreRelated(EntityType.EmailAddress, "ceo@evil.example", EntityType.Account, "billing@evil.example").Should().BeTrue();
        RelatedObservables.AreRelated(EntityType.EmailAddress, "a@mail.evil.example", EntityType.EmailAddress, "b@evil.example").Should()
            .BeFalse("the email domain matches exactly");
        RelatedObservables.KeyOf(EntityType.EmailAddress, "someone@gmail.com").Should().BeNull();
        RelatedObservables.AreRelated(EntityType.EmailAddress, "a@evil.example", EntityType.Domain, "evil.example").Should()
            .BeFalse("an email domain is its own rule");
    }

    [Theory]
    [InlineData(EntityType.FileHash, "d41d8cd98f00b204e9800998ecf8427e")]
    [InlineData(EntityType.Host, "ws01.corp.example")]
    [InlineData(EntityType.FileName, "invoice.pdf")]
    [InlineData(EntityType.Account, "CORP\\jdoe")]
    public void Other_types_have_no_rule(EntityType type, string value) =>
        RelatedObservables.KeyOf(type, value).Should().BeNull();
}
