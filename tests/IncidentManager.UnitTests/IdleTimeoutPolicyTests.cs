using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Security;
using Xunit;

namespace IncidentManager.UnitTests;

public class IdleTimeoutPolicyTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-999)]
    public void Zero_or_negative_disables_the_timeout(int minutes)
    {
        var plan = IdleTimeoutPolicy.Compute(minutes);
        plan.Enabled.Should().BeFalse();
        plan.IdleMs.Should().Be(0);
        plan.WarnMs.Should().Be(0);
    }

    [Fact]
    public void A_normal_timeout_gives_a_60_second_warning()
    {
        var plan = IdleTimeoutPolicy.Compute(15);
        plan.Enabled.Should().BeTrue();
        plan.IdleMs.Should().Be(15 * 60_000);
        plan.WarnMs.Should().Be(60_000); // full 60s warning
    }

    [Fact]
    public void A_short_timeout_caps_the_warning_at_half_the_total()
    {
        // 1 minute total: a 60s warning would consume the whole window, so it's capped at 30s.
        var plan = IdleTimeoutPolicy.Compute(1);
        plan.Enabled.Should().BeTrue();
        plan.IdleMs.Should().Be(60_000);
        plan.WarnMs.Should().Be(30_000);
        plan.WarnMs.Should().BeLessThan(plan.IdleMs);
    }

    [Fact]
    public void The_administered_setting_exists_and_is_an_integer()
    {
        SettingsCatalog.IsEditable("Security:IdleTimeoutMinutes").Should().BeTrue();
        var def = SettingsCatalog.ByKey["Security:IdleTimeoutMinutes"];
        def.Kind.Should().Be(SettingKind.Int);
        def.Group.Should().Be("Security");
        def.Default.Should().Be("15");
    }
}
