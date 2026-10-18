using System.Net;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-28 exclusions: the organization's own domains and address ranges (and free mail, by default) are never used to
/// suggest "possibly related" indicators, and nothing is suggested because of them; invalid entries are refused on save.
/// </summary>
public sealed class RelatedExclusionsTests
{
    private static RelatedExclusions Org(string[]? domains = null, string[]? ranges = null, bool freeMail = true) =>
        RelatedExclusions.From(domains ?? ["contoso.com", "corp.fabrikam.local"], ranges ?? RelatedExclusions.DefaultRanges, freeMail);

    [Theory]
    [InlineData("contoso.com", "contoso.com")]
    [InlineData("mail.contoso.com", "contoso.com")]
    [InlineData("A.B.Contoso.COM.", "contoso.com")]
    [InlineData("corp.fabrikam.local", "corp.fabrikam.local")]
    [InlineData("x.corp.fabrikam.local", "corp.fabrikam.local")]
    [InlineData("notcontoso.com", null)]
    [InlineData("contoso.com.evil.example", null)]
    [InlineData("fabrikam.local", null)]
    [InlineData("www.fabrikam.local", null)]
    public void A_domain_covers_itself_and_every_name_under_it(string host, string? listed) =>
        Org().DomainOf(host).Should().Be(listed);

    [Theory]
    [InlineData("10.0.0.0", "10.0.0.0/8")]
    [InlineData("10.255.255.255", "10.0.0.0/8")]
    [InlineData("11.0.0.0", null)]
    [InlineData("172.16.0.1", "172.16.0.0/12")]
    [InlineData("172.31.255.255", "172.16.0.0/12")]
    [InlineData("172.32.0.0", null)]
    [InlineData("172.15.255.255", null)]
    [InlineData("192.168.4.20", "192.168.0.0/16")]
    [InlineData("169.254.1.1", "169.254.0.0/16")]
    [InlineData("203.0.113.5", null)]
    [InlineData("::ffff:10.1.2.3", "10.0.0.0/8")]
    [InlineData("::ffff:203.0.113.5", null)]
    [InlineData("fd12:3456::1", "fc00::/7")]
    [InlineData("fc00::", "fc00::/7")]
    [InlineData("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fc00::/7")]
    [InlineData("fe00::1", null)]
    [InlineData("2001:db8::1", null)]
    public void A_range_covers_the_addresses_inside_it_to_its_edges(string address, string? range) =>
        (Org().RangeOf(IPAddress.Parse(address))?.ToString()).Should().Be(range);

    [Fact]
    public void A_listed_v6_range_and_a_narrow_v4_one_match_exactly()
    {
        var ex = Org(ranges: ["2001:db8:aa::/48", "198.51.100.128/25"]);
        ex.RangeOf(IPAddress.Parse("2001:db8:aa:ffff::1")).Should().NotBeNull();
        ex.RangeOf(IPAddress.Parse("2001:db8:ab::1")).Should().BeNull();
        ex.RangeOf(IPAddress.Parse("198.51.100.128")).Should().NotBeNull();
        ex.RangeOf(IPAddress.Parse("198.51.100.127")).Should().BeNull();
        ex.RangeOf(IPAddress.Parse("10.1.1.1")).Should().BeNull("the defaults are replaced, not added to");
    }

    [Fact]
    public void An_excluded_indicator_has_no_key_and_says_why()
    {
        var ex = Org();
        RelatedObservables.KeyOf(EntityType.Domain, "vpn.contoso.com", ex).Should().BeNull();
        RelatedObservables.ExcludedBecause(EntityType.Domain, "contoso.com", ex)
            .Should().Be("contoso.com is one of your organization's domains, so it isn't used to suggest relations.");
        RelatedObservables.ExcludedBecause(EntityType.Domain, "vpn.contoso.com", ex)
            .Should().Be("vpn.contoso.com is under contoso.com, one of your organization's domains, so it isn't used to suggest relations.");
        RelatedObservables.ExcludedBecause(EntityType.IpAddress, "10.4.5.6", ex)
            .Should().Be("10.4.5.6 is in 10.0.0.0/8, one of your organization's excluded address ranges, so it isn't used to suggest relations.");
        RelatedObservables.ExcludedBecause(EntityType.EmailAddress, "someone@gmail.com", ex)
            .Should().Be("gmail.com is a free mail provider, so an address there isn't used to suggest relations.");
        RelatedObservables.ExcludedBecause(EntityType.Domain, "evil.example", ex).Should().BeNull();
        RelatedObservables.ExcludedBecause(EntityType.FileHash, "d41d8cd98f00b204e9800998ecf8427e", ex).Should().BeNull("no rule applies at all");
    }

    [Theory]
    [InlineData(EntityType.Url, "https://intranet.contoso.com/login")]
    [InlineData(EntityType.Url, "http://10.1.2.3:8080/admin")]
    [InlineData(EntityType.Url, "http://[fd00::5]/x")]
    [InlineData(EntityType.Url, "http://[::ffff:192.168.1.1]/x")]
    [InlineData(EntityType.EmailAddress, "ceo@contoso.com")]
    [InlineData(EntityType.EmailAddress, "a@mail.contoso.com")]
    [InlineData(EntityType.Account, "svc@corp.fabrikam.local")]
    [InlineData(EntityType.IpAddress, "::ffff:10.0.0.9")]
    public void Urls_emails_and_accounts_on_an_excluded_host_are_excluded(EntityType type, string value)
    {
        RelatedObservables.HasRule(type, value).Should().BeTrue();
        RelatedObservables.KeyOf(type, value, Org()).Should().BeNull();
        RelatedObservables.ExcludedBecause(type, value, Org()).Should().NotBeNull();
    }

    [Fact]
    public void An_excluded_indicator_suggests_nothing_and_is_suggested_by_nothing()
    {
        var ex = Org(domains: ["corp.contoso.com"]);
        RelatedObservables.AreRelated(EntityType.Domain, "www.contoso.com", EntityType.Domain, "shop.contoso.com", ex).Should().BeTrue();
        RelatedObservables.AreRelated(EntityType.Domain, "www.contoso.com", EntityType.Domain, "dc1.corp.contoso.com", ex).Should()
            .BeFalse("an excluded one is never suggested");
        RelatedObservables.AreRelated(EntityType.Domain, "dc1.corp.contoso.com", EntityType.Domain, "www.contoso.com", ex).Should()
            .BeFalse("and suggests nothing");
        RelatedObservables.AreRelated(EntityType.IpAddress, "10.0.0.5", EntityType.IpAddress, "10.0.0.6", ex).Should().BeFalse();
        RelatedObservables.AreRelated(EntityType.IpAddress, "10.0.0.5", EntityType.IpAddress, "10.0.0.6", RelatedExclusions.None)
            .Should().BeTrue("with no ranges, a private /24 relates as before");
    }

    [Fact]
    public void Free_mail_is_related_when_the_switch_is_off()
    {
        RelatedObservables.AreRelated(EntityType.EmailAddress, "a@gmail.com", EntityType.EmailAddress, "b@gmail.com", Org(freeMail: false))
            .Should().BeTrue();
        RelatedObservables.AreRelated(EntityType.EmailAddress, "a@gmail.com", EntityType.EmailAddress, "b@gmail.com", Org())
            .Should().BeFalse();
    }

    // --- the settings: validated and stored as the rule reads them --------------------------------------------------

    private static readonly SettingDefinition Domains = SettingsCatalog.ByKey[RelatedExclusionSettings.DomainsKey];
    private static readonly SettingDefinition Ranges = SettingsCatalog.ByKey[RelatedExclusionSettings.RangesKey];

    [Fact]
    public void Domains_are_split_lowercased_and_stored_once()
    {
        SettingsCatalog.Normalize(Domains, "Contoso.COM., corp.contoso.local; *.fabrikam.com\ncontoso.com").Should()
            .Be("contoso.com\ncorp.contoso.local\nfabrikam.com");
        SettingsCatalog.Normalize(Domains, "  ").Should().Be("");
    }

    [Theory]
    [InlineData("ceo@contoso.com", "is an email address")]
    [InlineData("10.0.0.1", "isn't a domain name")]
    [InlineData("contoso", "is a single label")]
    [InlineData("co.uk", "is a public suffix")]
    [InlineData("bad_name.com", "isn't a domain name")]
    [InlineData("-x.com", "isn't a domain name")]
    [InlineData("bücher.example", "xn-- form")]
    public void An_entry_that_isnt_a_domain_is_refused_with_its_name(string entry, string why) =>
        SettingsCatalog.Problem(Domains, $"contoso.com\n{entry}").Should()
            .StartWith($"Your organization's domains: \"{entry}\"").And.Contain(why);

    [Fact]
    public void Ranges_are_split_and_stored_canonically()
    {
        SettingsCatalog.Normalize(Ranges, "10.0.0.0/8, 172.16.0.0/12 192.168.0.0/16\nFD00::/8; 198.51.100.7; 2001:DB8::1").Should()
            .Be("10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\nfd00::/8\n198.51.100.7/32\n2001:db8::1/128");
        SettingsCatalog.Normalize(Ranges, SettingsCatalog.ByKey[RelatedExclusionSettings.RangesKey].Default).Should()
            .Be(string.Join("\n", RelatedExclusions.DefaultRanges), "the default is valid as it stands");
    }

    [Theory]
    [InlineData("10.0.0.1/8", "Did you mean 10.0.0.0/8?")]
    [InlineData("10.0.0.0/33", "0 to 32")]
    [InlineData("fd00::/129", "0 to 128")]
    [InlineData("10.0/8", "isn't an address range")]
    [InlineData("contoso.com", "isn't an address range")]
    [InlineData("fe80::1%3/64", "isn't an address range")]
    [InlineData("10.0.0.0/-1", "0 to 32")]
    public void An_entry_that_isnt_a_range_is_refused_with_its_name(string entry, string why) =>
        SettingsCatalog.Problem(Ranges, entry).Should().StartWith($"Excluded address ranges: \"{entry}\"").And.Contain(why);

    // --- CAP-28 review (F3): IPv4 parts are decimal, never octal or hex ---

    [Theory]
    [InlineData("010.0.0.0/8", "10.0.0.0/8")]
    [InlineData("192.168.010.000/24", "192.168.10.0/24")]
    [InlineData("010.000.000.001", "10.0.0.1/32")]
    [InlineData("::ffff:10.0.0.0/104", "10.0.0.0/8")]
    [InlineData("::ffff:192.168.010.000/120", "192.168.10.0/24")]
    [InlineData("::ffff:0:0/96", "0.0.0.0/0")]
    public void A_zero_padded_or_mapped_range_is_read_as_the_decimal_IPv4_range(string entry, string stored) =>
        SettingsCatalog.Normalize(Ranges, entry).Should().Be(stored);

    [Theory]
    [InlineData("0x0A.0.0.0/8")]
    [InlineData("0xC0.168.0.0/16")]
    [InlineData("10.0.0.0x0/32")]
    [InlineData("0010.0.0.0/8")]
    [InlineData("256.0.0.0/8")]
    [InlineData("::ffff:0x0A.0.0.0/104")]
    public void A_hex_or_out_of_range_part_is_refused(string entry) =>
        SettingsCatalog.Problem(Ranges, entry).Should().StartWith($"Excluded address ranges: \"{entry}\"").And.Contain("isn't an address range");

    [Fact]
    public void A_mapped_range_matches_a_plain_IPv4_indicator_and_a_zero_padded_one_its_decimal_addresses()
    {
        var ex = Org(ranges: ["::ffff:198.51.100.0/120", "010.0.0.0/8"]);
        ex.Ranges.Select(r => r.ToString()).Should().Equal("198.51.100.0/24", "10.0.0.0/8");
        RelatedObservables.KeyOf(EntityType.IpAddress, "198.51.100.7", ex).Should().BeNull("inside the mapped range");
        RelatedObservables.KeyOf(EntityType.IpAddress, "10.1.2.3", ex).Should().BeNull("inside 10/8, not 8/8");
        RelatedObservables.KeyOf(EntityType.IpAddress, "8.1.2.3", ex).Should().NotBeNull("8.0.0.0/8 was never meant");
    }

    [Fact]
    public void A_zero_padded_indicator_is_its_decimal_address_and_a_hex_one_is_no_address()
    {
        IocObservable.DetectType("010.000.000.001").Should().Be(EntityType.IpAddress);
        RelatedObservables.KeyOf(EntityType.IpAddress, "010.000.000.001", RelatedExclusions.None)!.Value.Shared.Should().Be("10.0.0", "not 8.0.0");
        RelatedObservables.KeyOf(EntityType.IpAddress, "192.168.010.005", RelatedExclusions.None)!.Value.Shared.Should().Be("192.168.10");
        RelatedObservables.ExcludedBecause(EntityType.IpAddress, "010.4.5.6", Org()).Should().Contain("10.0.0.0/8");
        IocObservable.DetectType("0x0A.0.0.1").Should().NotBe(EntityType.IpAddress);
        RelatedObservables.KeyOf(EntityType.IpAddress, "0x0A.0.0.1", RelatedExclusions.None).Should().BeNull();
        IocObservable.Normalize(EntityType.IpAddress, "::ffff:010.0.0.1").Should().Be("10.0.0.1", "BUG-176's mapped form, read decimally");
    }

    // --- CAP-28 review (R1): a URL's IPv4 host is read as written; System.Uri reads 010.0.0.5 as 8.0.0.5 ---

    [Fact]
    public void A_zero_padded_URL_host_is_its_decimal_address_and_a_hex_one_is_no_address()
    {
        RelatedObservables.AreRelated(EntityType.IpAddress, "010.0.0.5", EntityType.Url, "http://010.0.0.5/x", RelatedExclusions.None)
            .Should().BeTrue("both are 10.0.0.5");
        RelatedObservables.KeyOf(EntityType.Url, "http://user@010.0.0.5:8080/x?q#f", RelatedExclusions.None)!.Value
            .Should().Be(new RelatedKey(RelatedRule.Ipv4Slash24, "10.0.0"));
        RelatedObservables.ExcludedBecause(EntityType.Url, "http://010.0.0.5/x", Org(ranges: ["10.0.0.0/8"])).Should().Contain("10.0.0.0/8");
        RelatedObservables.KeyOf(EntityType.Url, "http://010.0.0.5/x", Org(ranges: ["10.0.0.0/8"])).Should().BeNull();
        RelatedObservables.KeyOf(EntityType.Url, "http://010.0.0.5/x", Org(ranges: ["8.0.0.0/8"])).Should().NotBeNull("not 8.0.0.5");
        RelatedObservables.KeyOf(EntityType.Url, "http://0x0a.0.0.5/", RelatedExclusions.None).Should().BeNull("no Ipv4Slash24 key, nor any other");
        RelatedObservables.KeyOf(EntityType.Url, "http://[2001:db8::9]/y", RelatedExclusions.None)!.Value
            .Should().Be(new RelatedKey(RelatedRule.Ipv6Slash48, "2001:db8:0"), "a bracketed IPv6 host as before");
        RelatedObservables.KeyOf(EntityType.Url, "https://203.0.113.9/x", RelatedExclusions.None)!.Value.Shared.Should().Be("203.0.113");
    }

    // --- CAP-28 review: IpText changed only zero-padded and hex IPv4; everything else reads as IPAddress.TryParse read it ---

    // Expected: whether DetectType took it as an IP, and Normalize's IpAddress form, both as before IpText (27182076^).
    [Theory]
    [InlineData("1.2.3.4", true, "1.2.3.4")]
    [InlineData("203.0.113.5", true, "203.0.113.5")]
    [InlineData("fe80::1%eth0.5", true, "fe80::1")]
    [InlineData("fe80::1%3", true, "fe80::1%3")]
    [InlineData("fe80::1%eth0", true, "fe80::1")]
    [InlineData("FE80::ABCD%ETH0", true, "fe80::abcd")]
    [InlineData("fe80::1%25eth0", true, "fe80::1")]
    [InlineData("::ffff:1.2.3.4%3", true, "1.2.3.4")]
    [InlineData("::ffff:1.2.3.4%eth0", true, "1.2.3.4")]
    [InlineData("::ffff:1.2.3.4", true, "1.2.3.4")]
    [InlineData("::FFFF:203.0.113.5", true, "203.0.113.5")]
    [InlineData("::ffff:0a00:0001", true, "10.0.0.1")]
    [InlineData("2001:0db8:0:0:0:0:0:1", true, "2001:db8::1")]
    [InlineData("2001:DB8::ABCD", true, "2001:db8::abcd")]
    [InlineData("2001:DB8:0:0:1:0:0:1", true, "2001:db8::1:0:0:1")]
    [InlineData("2001:db8::1.2.3.4", true, "2001:db8::102:304")]
    [InlineData("64:ff9b::192.0.2.33", true, "64:ff9b::c000:221")]
    [InlineData("::1.2.3.4", true, "::1.2.3.4")]
    [InlineData("::1", true, "::1")]
    [InlineData("::", true, "::")]
    [InlineData("FE80::1", true, "fe80::1")]
    [InlineData("[2001:db8::1]", true, "2001:db8::1")]
    [InlineData("[::1]:80", true, "::1")]
    [InlineData("2001:db8::1/64", false, "2001:db8::1/64")]
    [InlineData("1.2.3", false, "1.2.3")]
    [InlineData("1.2.3.4/24", false, "1.2.3.4/24")]
    [InlineData("1.2.3.4:80", false, "1.2.3.4:80")]
    [InlineData("1.2.3.4.5", false, "1.2.3.4.5")]
    [InlineData("256.1.1.1", false, "256.1.1.1")]
    public void Every_address_but_a_padded_or_hex_IPv4_one_reads_as_before(string value, bool ip, string canonical)
    {
        (IocObservable.DetectType(value) == EntityType.IpAddress).Should().Be(ip);
        IocObservable.Normalize(EntityType.IpAddress, value).Should().Be(canonical);
    }

    // The ones IpText changed on purpose: a padded part is decimal, a hex one isn't an address.
    [Theory]
    [InlineData("010.0.0.1", true, "010.0.0.1")]
    [InlineData("::ffff:010.0.0.1", true, "10.0.0.1")]
    [InlineData("::ffff:010.0.0.1%3", true, "10.0.0.1")]
    [InlineData("0x0a.0.0.1", false, "0x0a.0.0.1")]
    [InlineData("::ffff:0x0a.0.0.1", false, "::ffff:0x0a.0.0.1")]
    public void A_padded_IPv4_part_is_decimal_and_a_hex_one_no_address(string value, bool ip, string canonical)
    {
        (IocObservable.DetectType(value) == EntityType.IpAddress).Should().Be(ip);
        IocObservable.Normalize(EntityType.IpAddress, value).Should().Be(canonical);
    }
}
