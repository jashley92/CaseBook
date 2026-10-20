using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Services;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// How Administration reads and labels settings. A list in the server's settings file binds as key:0, key:1, so the
/// "Settings within limits" check read it as unset and never found a bad address there. Every per-severity label shows
/// the organization's name for the level, the stale-case rows included, but not the rows that do the renaming.
/// </summary>
public sealed class AdminSettingsDisplayTests
{
    private sealed class Renamed : ISeverityLabels
    {
        public string For(Severity severity) => severity == Severity.Critical ? "SEV-1" : severity.ToString();
    }

    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();

    [Fact]
    public void A_bad_address_in_a_list_in_the_settings_file_is_found()
    {
        var config = Config(("Email:LegalDistribution:0", "legal@example.test"), ("Email:LegalDistribution:1", "not an address"));

        SettingsCatalog.FindInvalid(key => config[key]).Should().BeEmpty("the list's own key holds nothing, which is what the check used to read");
        SettingsCatalog.FindInvalid(key => AdminSettingsDisplay.ConfiguredValue(config, key))
            .Should().ContainSingle(i => i.Definition.Key == "Email:LegalDistribution");
    }

    [Fact]
    public void A_list_reads_one_entry_per_line_and_a_scalar_as_written()
    {
        var config = Config(("Email:LegalDistribution:0", "a@example.test"), ("Email:LegalDistribution:1", "b@example.test"),
            ("Retention:CaseYears", "7"));
        AdminSettingsDisplay.ConfiguredValue(config, "Email:LegalDistribution").Should().Be("a@example.test\nb@example.test");
        AdminSettingsDisplay.ConfiguredValue(config, "Retention:CaseYears").Should().Be("7");
        AdminSettingsDisplay.ConfiguredValue(config, "Email:IntegrityAlertDistribution").Should().BeNull();
    }

    [Fact]
    public void Every_per_severity_label_uses_the_organizations_name_but_the_renaming_rows_keep_theirs()
    {
        var labels = new Renamed();
        AdminSettingsDisplay.Label(SettingsCatalog.ByKey["Sla:Containment:Critical"], labels).Should().Contain("SEV-1");
        AdminSettingsDisplay.Label(SettingsCatalog.ByKey["Sla:Breach:Resolution:Critical"], labels).Should().Contain("SEV-1");
        AdminSettingsDisplay.Label(SettingsCatalog.ByKey["Notifications:StaleScan:Days:Critical"], labels).Should().Contain("SEV-1");
        AdminSettingsDisplay.Label(SettingsCatalog.ByKey["Severity:Label:Critical"], labels).Should().Be("Critical label");
        AdminSettingsDisplay.Label(SettingsCatalog.ByKey["Retention:CaseYears"], labels).Should().Be(SettingsCatalog.ByKey["Retention:CaseYears"].Label);
    }

    [Fact]
    public void No_setting_description_repeats_a_word()
    {
        // "for Critical cases Breach cases" ran through all eight breach overrides.
        SettingsCatalog.Editable.Where(d => System.Text.RegularExpressions.Regex.IsMatch(d.Description, @"\b(\w+) \w+ \1 \w+ ?\1\b|cases Breach cases",
                System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1)))
            .Select(d => d.Key).Should().BeEmpty();
    }
}
