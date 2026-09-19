using FluentAssertions;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using Xunit;

namespace IncidentManager.UnitTests;

public class IocObservableTests
{
    [Theory]
    // Bracketed / parenthesized / braced dots, with and without the spelled-out word and padding.
    [InlineData("1.1.1[.]1", "1.1.1.1")]
    [InlineData("1.1.1(.)1", "1.1.1.1")]
    [InlineData("1.1.1{.}1", "1.1.1.1")]
    [InlineData("evil[dot]com", "evil.com")]
    [InlineData("evil(dot)com", "evil.com")]
    [InlineData("evil[ . ]com", "evil.com")]
    // Defanged scheme.
    [InlineData("hxxp://evil[.]com", "http://evil.com")]
    [InlineData("hxxps://evil[.]com/path", "https://evil.com/path")]
    [InlineData("hXXp://evil[.]com", "http://evil.com")]
    [InlineData("hxxp[:]//evil[.]com", "http://evil.com")]
    [InlineData("fxp://evil[.]com", "ftp://evil.com")]
    // Email refang.
    [InlineData("user[at]evil[.]com", "user@evil.com")]
    [InlineData("user(at)evil(dot)com", "user@evil.com")]
    // Whitespace + idempotency (already-live values pass through).
    [InlineData("  1.1.1.1  ", "1.1.1.1")]
    [InlineData("https://evil.com", "https://evil.com")]
    public void Refang_normalizes_defanged_notation(string input, string expected)
    {
        IocObservable.Refang(input).Should().Be(expected);
    }

    [Fact]
    public void Refang_is_idempotent()
    {
        var once = IocObservable.Refang("hxxps://a[.]b[.]com");
        IocObservable.Refang(once).Should().Be(once).And.Be("https://a.b.com");
    }

    [Theory]
    [InlineData(EntityType.IpAddress, true)]
    [InlineData(EntityType.Domain, true)]
    [InlineData(EntityType.Url, true)]
    [InlineData(EntityType.EmailAddress, true)]
    [InlineData(EntityType.FileHash, false)]
    [InlineData(EntityType.FileName, false)]
    [InlineData(EntityType.Account, false)]
    [InlineData(EntityType.Host, false)]
    [InlineData(EntityType.RegistryKey, false)]
    [InlineData(EntityType.Process, false)]
    public void Only_network_indicator_types_are_refangable(EntityType type, bool expected)
    {
        IocObservable.IsRefangable(type).Should().Be(expected);
    }

    [Fact]
    public void Normalize_leaves_non_network_types_byte_for_byte()
    {
        // A registry key legitimately containing a literal "[.]" must not be rewritten — only trimmed.
        const string key = @"HKLM\Software\Vendor[.]Suite";
        IocObservable.Normalize(EntityType.RegistryKey, "  " + key + "  ").Should().Be(key);

        // A filename with the word "dot" or brackets is left intact.
        IocObservable.Normalize(EntityType.FileName, "report[dot]final.docx")
            .Should().Be("report[dot]final.docx");
    }

    [Fact]
    public void Normalize_refangs_network_types()
    {
        IocObservable.Normalize(EntityType.Url, "hxxp://evil[.]com").Should().Be("http://evil.com");
        IocObservable.Normalize(EntityType.IpAddress, "203.0.113[.]5").Should().Be("203.0.113.5");
    }

    [Theory]
    [InlineData("http://evil.com", "hxxp://evil[.]com")]
    [InlineData("https://a.evil.com/x", "hxxps://a[.]evil[.]com/x")]
    [InlineData("1.1.1.1", "1[.]1[.]1[.]1")]
    [InlineData("user@evil.com", "user[at]evil[.]com")]
    public void Defang_produces_safe_display_form(string input, string expected)
    {
        IocObservable.Defang(input).Should().Be(expected);
    }

    [Fact]
    public void Defang_then_refang_round_trips_to_the_live_value()
    {
        const string live = "https://login.evil.com/portal";
        IocObservable.Refang(IocObservable.Defang(live)).Should().Be(live);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_input_is_handled(string? input)
    {
        IocObservable.Refang(input).Should().BeEmpty();
        IocObservable.Defang(input).Should().BeEmpty();
        IocObservable.Normalize(EntityType.Domain, input).Should().BeEmpty();
    }

    [Theory]
    // URL (any scheme with ://) wins first.
    [InlineData("http://evil.com/x", EntityType.Url)]
    [InlineData("ftp://host/file", EntityType.Url)]
    // Email before domain (has @).
    [InlineData("user@evil.com", EntityType.EmailAddress)]
    // IPv4 and IPv6 via IPAddress.TryParse.
    [InlineData("203.0.113.5", EntityType.IpAddress)]
    [InlineData("2001:db8::1", EntityType.IpAddress)]
    // Fixed-length hex hashes (MD5/SHA-1/SHA-256).
    [InlineData("44d88612fea8a8f36de82e1278abb02f", EntityType.FileHash)]                                 // MD5 (32)
    [InlineData("da39a3ee5e6b4b0d3255bfef95601890afd80709", EntityType.FileHash)]                         // SHA-1 (40)
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", EntityType.FileHash)] // SHA-256 (64)
    // Domain (dotted labels, alpha TLD).
    [InlineData("evil.example.com", EntityType.Domain)]
    // Fallbacks: bare hostname, account, partial IP, odd-length hex.
    [InlineData("WKS-HR-14", EntityType.Other)]
    [InlineData("CONTOSO\\jdoe", EntityType.Other)]
    [InlineData("1.2.3", EntityType.Other)]
    [InlineData("abc123", EntityType.Other)]
    public void DetectType_classifies_common_indicators(string value, EntityType expected)
    {
        IocObservable.DetectType(value).Should().Be(expected);
    }

    [Fact]
    public void DetectType_refangs_before_classifying()
    {
        // A defanged paste classifies as its live type.
        IocObservable.DetectType("1.1.1[.]1").Should().Be(EntityType.IpAddress);
        IocObservable.DetectType("hxxp://evil[.]com").Should().Be(EntityType.Url);
        IocObservable.DetectType("user[at]evil[.]com").Should().Be(EntityType.EmailAddress);
        IocObservable.DetectType("evil[.]com").Should().Be(EntityType.Domain);
        IocObservable.DetectType("   ").Should().Be(EntityType.Other);
    }

    // --- PROD-22: ParseIndicators (bulk paste) ---

    [Fact]
    public void ParseIndicators_splits_refangs_and_auto_types_a_mixed_block()
    {
        const string block = "1.2.3.4, evil.example[.]com\nhxxp://bad[.]site/x\n44d88612fea8a8f36de82e1278abb02f\nuser[at]phish.example";
        var parsed = IocObservable.ParseIndicators(block);

        parsed.Should().Equal(
            new IocObservable.ParsedIndicator("1.2.3.4", EntityType.IpAddress),
            new IocObservable.ParsedIndicator("evil.example.com", EntityType.Domain),
            new IocObservable.ParsedIndicator("http://bad.site/x", EntityType.Url),
            new IocObservable.ParsedIndicator("44d88612fea8a8f36de82e1278abb02f", EntityType.FileHash),
            new IocObservable.ParsedIndicator("user@phish.example", EntityType.EmailAddress));
    }

    [Fact]
    public void ParseIndicators_drops_blanks_and_collapses_duplicates_in_first_seen_order()
    {
        // Same value defanged and live, plus a blank line and different separators — one entry, canonical.
        const string block = "1.1.1[.]1\n\n , ;\n1.1.1.1\tevil.com;evil.com";
        var parsed = IocObservable.ParseIndicators(block);

        parsed.Should().Equal(
            new IocObservable.ParsedIndicator("1.1.1.1", EntityType.IpAddress),
            new IocObservable.ParsedIndicator("evil.com", EntityType.Domain));
    }

    [Fact]
    public void ParseIndicators_does_not_split_on_spaces()
    {
        // A single URL token stays one indicator even though it contains no separator we split on.
        IocObservable.ParseIndicators("https://evil.com/a b")
            .Should().ContainSingle().Which.Value.Should().Be("https://evil.com/a b");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \n  , ; \t")]
    public void ParseIndicators_returns_empty_for_no_indicators(string? block)
    {
        IocObservable.ParseIndicators(block).Should().BeEmpty();
    }
}
