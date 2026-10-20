using FluentAssertions;
using IncidentManager.Application.Integrity;
using Xunit;

namespace IncidentManager.UnitTests;

public class SigningKeyRotationTests
{
    private static readonly DateTimeOffset First = new(2025, 10, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Due_a_year_after_the_keys_first_seal_by_default()
    {
        SigningKeyRotation.DueAt(First, SigningKeyRotation.DefaultDays).Should().Be(First.AddDays(365));
    }

    [Fact]
    public void Off_at_zero_and_not_due_before_the_key_has_signed_anything()
    {
        SigningKeyRotation.DueAt(First, 0).Should().BeNull();
        SigningKeyRotation.DueAt(null, 365).Should().BeNull();
    }

    [Fact]
    public void The_interval_is_kept_within_its_limits()
    {
        SigningKeyRotation.Clamp(-5).Should().Be(0);
        SigningKeyRotation.Clamp(100_000).Should().Be(SigningKeyRotation.MaxDays);
    }
}
