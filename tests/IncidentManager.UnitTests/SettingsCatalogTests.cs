using FluentAssertions;
using IncidentManager.Application.Admin;
using Xunit;

namespace IncidentManager.UnitTests;

public class SettingsCatalogTests
{
    [Fact]
    public void A_distribution_list_holds_addresses_only_and_a_pasted_list_is_split(/* BUG-241 */)
    {
        var legal = SettingsCatalog.ByKey["Email:LegalDistribution"];
        SettingsCatalog.Normalize(legal, "legal@corp.com; privacy@corp.com\nciso@corp.com")
            .Should().Be("legal@corp.com\nprivacy@corp.com\nciso@corp.com");
        SettingsCatalog.Problem(legal, "legal").Should().Contain("isn't an email address");
        SettingsCatalog.Problem(legal, "Legal Team <legal@corp.com>").Should().Contain("isn't an email address");
        SettingsCatalog.Problem(SettingsCatalog.ByKey["Email:IntegrityAlertDistribution"], "soc@corp.com").Should().BeNull();
    }

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
        SettingsCatalog.Editable.Where(d => d.Key.StartsWith("Sla:", StringComparison.Ordinal) && d.Key != "Sla:AtRiskThresholdPercent")
            .Should().NotBeEmpty().And.OnlyContain(d => d.Max == IncidentManager.Application.Sla.SlaPolicy.MaxTargetHours);

    [Theory]
    [InlineData("Compliance:NotificationDeadlines:DefaultWindowHours", "1", "8760", "0", "8761")]   // REV-48
    [InlineData("Security:IdleTimeoutMinutes", "0", "1440", "-1", "1441")]                         // REV-46
    // BUG-354: 0 read as the default (30 minutes; the scan's own default), so it isn't offered.
    [InlineData("Access:CoalesceWindowMinutes", "1", "1440", "0", "1441")]
    [InlineData("Notifications:OverdueScan:IntervalHours", "1", "744", "0", "745")]
    [InlineData("Notifications:DueSoonScan:IntervalHours", "1", "744", "0", "745")]
    [InlineData("Notifications:DeadlineScan:IntervalHours", "1", "744", "0", "745")]
    [InlineData("Notifications:StaleScan:IntervalHours", "1", "744", "0", "745")]
    [InlineData("Notifications:DigestScan:IntervalHours", "1", "744", "0", "745")]
    [InlineData("Integrity:AutoSeal:IntervalHours", "1", "744", "0", "745")]
    [InlineData("Integrity:EvidenceVerify:IntervalHours", "1", "744", "0", "745")]
    public void Bounded_settings_refuse_values_outside_their_range(string key, string low, string high, string under, string over)
    {
        var def = SettingsCatalog.ByKey[key];
        SettingsCatalog.Normalize(def, low).Should().Be(low);
        SettingsCatalog.Normalize(def, high).Should().Be(high);
        foreach (var bad in new[] { under, over, "100000000" })
            ((Action)(() => SettingsCatalog.Normalize(def, bad))).Should().Throw<ArgumentException>(bad);
    }

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
    public void FindInvalid_reports_values_that_break_todays_rules_and_skips_blanks()
    {
        var values = new Dictionary<string, string?>
        {
            ["Sla:Containment:High"] = "9000",          // over the one-year cap
            ["Sla:Containment:Low"] = "72",             // fine
            ["Sla:AtRiskThresholdPercent"] = "0",       // below 1
            ["Organization:TimeZone"] = "Mars/Base",    // not a listed choice
            ["Sla:Resolution:Low"] = "",                // blank: the default applies
        };

        var invalid = SettingsCatalog.FindInvalid(k => values.GetValueOrDefault(k));

        invalid.Select(i => i.Definition.Key).Should().BeEquivalentTo(
            ["Sla:Containment:High", "Sla:AtRiskThresholdPercent", "Organization:TimeZone"]);
        invalid.Single(i => i.Definition.Key == "Sla:Containment:High").Problem.Should().Contain("8,760");
    }

    [Fact]
    public void A_stored_zero_interval_is_reported_not_thrown(/* BUG-354 */)
    {
        // A 0 saved before the limit is listed (the health check and the section's save say so), never thrown at start.
        var invalid = SettingsCatalog.FindInvalid(k => k == "Access:CoalesceWindowMinutes" ? "0" : null);
        invalid.Should().ContainSingle().Which.Problem.Should().Contain("from 1 to 1,440");
    }

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
