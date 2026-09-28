using FluentAssertions;
using IncidentManager.Application.Admin;
using Xunit;

namespace IncidentManager.UnitTests;

public class SettingsCatalogTests
{
    private static SettingDefinition Def(SettingKind kind) =>
        new("Test:Key", "Test", "Group", kind, "desc");

    [Theory]
    [InlineData("true", "true")]
    [InlineData("  TRUE ", "true")]
    [InlineData("false", "false")]
    public void Normalize_bool_canonicalizes(string input, string expected) =>
        SettingsCatalog.Normalize(Def(SettingKind.Bool), input).Should().Be(expected);

    [Fact]
    public void Normalize_bool_rejects_garbage()
    {
        var act = () => SettingsCatalog.Normalize(Def(SettingKind.Bool), "yes");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Normalize_int_accepts_non_negative_and_rejects_the_rest()
    {
        SettingsCatalog.Normalize(Def(SettingKind.Int), " 7 ").Should().Be("7");
        SettingsCatalog.Normalize(Def(SettingKind.Int), "").Should().BeNull();

        var negative = () => SettingsCatalog.Normalize(Def(SettingKind.Int), "-1");
        negative.Should().Throw<ArgumentException>();
        var words = () => SettingsCatalog.Normalize(Def(SettingKind.Int), "lots");
        words.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("Sla:Containment:Critical")]
    [InlineData("Sla:Detection:Low")]
    [InlineData("Sla:Breach:Resolution:High")]
    public void Sla_targets_are_capped_at_one_year(string key)
    {
        var def = SettingsCatalog.ByKey[key];
        SettingsCatalog.Normalize(def, "8760").Should().Be("8760");
        SettingsCatalog.Normalize(def, "").Should().BeNull("blank disables the target");
        var tooLong = () => SettingsCatalog.Normalize(def, "8761");
        tooLong.Should().Throw<ArgumentException>().WithMessage("*from 0 to 8,760*");
    }

    [Fact]
    public void Every_sla_hours_setting_has_the_cap() =>
        SettingsCatalog.Editable.Where(d => d.Key.StartsWith("Sla:") && d.Key != "Sla:AtRiskThresholdPercent")
            .Should().NotBeEmpty().And.OnlyContain(d => d.Max == IncidentManager.Application.Sla.SlaPolicy.MaxTargetHours);

    [Theory]
    [InlineData("Sla:AtRiskThresholdPercent")]
    [InlineData("Compliance:NotificationDeadlines:AtRiskThresholdPercent")]
    public void At_risk_thresholds_must_be_1_to_100(string key)
    {
        var def = SettingsCatalog.ByKey[key];
        SettingsCatalog.Normalize(def, "1").Should().Be("1");
        SettingsCatalog.Normalize(def, "100").Should().Be("100");
        foreach (var bad in new[] { "0", "101" })
        {
            var act = () => SettingsCatalog.Normalize(def, bad);
            act.Should().Throw<ArgumentException>(bad);
        }
    }

    [Fact]
    public void A_fixed_choice_setting_takes_only_a_listed_value()
    {
        var zone = SettingsCatalog.ByKey["Organization:TimeZone"];
        SettingsCatalog.Normalize(zone, "america/chicago").Should().Be("America/Chicago");
        SettingsCatalog.Normalize(zone, "").Should().Be("", "blank uses the default");
        var unknown = () => SettingsCatalog.Normalize(zone, "Mars/Olympus_Mons");
        unknown.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Every_listed_time_zone_resolves_on_this_host() =>
        SettingsCatalog.ByKey["Organization:TimeZone"].Options!
            .Where(o => !TimeZoneInfo.TryFindSystemTimeZoneById(o.Value, out _)).Should().BeEmpty();

    [Fact]
    public void Normalize_multitext_trims_lines_and_drops_blanks()
    {
        var input = "  a@x.com \r\n\r\n b@x.com  \n";
        SettingsCatalog.Normalize(Def(SettingKind.MultiText), input)
            .Should().Be("a@x.com\nb@x.com");
    }

    [Fact]
    public void Catalog_excludes_security_and_infrastructure_keys()
    {
        // The editable whitelist must never expose secrets or infra plumbing.
        SettingsCatalog.IsEditable("ConnectionStrings:Default").Should().BeFalse();
        SettingsCatalog.IsEditable("Auth:Mode").Should().BeFalse();
        SettingsCatalog.IsEditable("Integrity:SigningKeyPath").Should().BeFalse();

        SettingsCatalog.IsEditable("Email:From").Should().BeTrue();
    }
}
