using FluentAssertions;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Sla;
using IncidentManager.Infrastructure.Time;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Configuration-backed providers: values from appsettings bypass the admin validation, so they guard too.</summary>
public class ConfigurationProvidersTests
{
    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();

    [Fact]
    public void Sla_targets_over_a_year_are_ignored_rather_than_breaking_date_arithmetic()
    {
        var targets = new ConfigurationSlaTargetsProvider(Config(
            ("Sla:Containment:Critical", "8760"), ("Sla:Containment:High", "8761"),
            ("Sla:Breach:Containment:Critical", "2147483647"))).Current;

        targets.HoursFor(SlaClock.Containment, Severity.Critical).Should().Be(8760);
        targets.HoursFor(SlaClock.Containment, Severity.High).Should().BeNull();
        targets.HoursFor(SlaClock.Containment, Severity.Critical, Classification.Breach).Should().Be(8760, "the base target applies");
    }

    [Fact]
    public void Reporting_time_zone_defaults_to_eastern_and_follows_the_setting()
    {
        new ConfigurationOrganizationTimeZone(Config()).Current.BaseUtcOffset.Should().Be(TimeSpan.FromHours(-5));
        new ConfigurationOrganizationTimeZone(Config(("Organization:TimeZone", "America/Los_Angeles"))).Current
            .BaseUtcOffset.Should().Be(TimeSpan.FromHours(-8));
        new ConfigurationOrganizationTimeZone(Config(("Organization:TimeZone", "UTC"))).Current
            .BaseUtcOffset.Should().Be(TimeSpan.Zero);
        new ConfigurationOrganizationTimeZone(Config(("Organization:TimeZone", "Not/AZone"))).Current
            .BaseUtcOffset.Should().Be(TimeSpan.FromHours(-5), "an unknown id falls back to the default");
    }
}
