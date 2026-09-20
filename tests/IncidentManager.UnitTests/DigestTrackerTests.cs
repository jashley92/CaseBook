using FluentAssertions;
using IncidentManager.Application.Notifications;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-39: the digest tracker sends once per (user, cadence, period) — a new period or a cadence
/// change is a fresh send.</summary>
public class DigestTrackerTests
{
    [Fact]
    public void First_send_in_a_period_is_new_thereafter_it_is_not()
    {
        var t = new DigestTracker();
        t.TryMarkSent("u1", DigestCadence.Daily, "2026-09-10").Should().BeTrue();
        t.TryMarkSent("u1", DigestCadence.Daily, "2026-09-10").Should().BeFalse();
    }

    [Fact]
    public void A_new_period_is_a_fresh_send()
    {
        var t = new DigestTracker();
        t.TryMarkSent("u1", DigestCadence.Daily, "2026-09-10").Should().BeTrue();
        t.TryMarkSent("u1", DigestCadence.Daily, "2026-09-11").Should().BeTrue();
    }

    [Fact]
    public void Cadence_and_user_are_part_of_the_key()
    {
        var t = new DigestTracker();
        t.TryMarkSent("u1", DigestCadence.Daily, "2026-W37").Should().BeTrue();
        t.TryMarkSent("u1", DigestCadence.Weekly, "2026-W37").Should().BeTrue();  // different cadence
        t.TryMarkSent("u2", DigestCadence.Daily, "2026-W37").Should().BeTrue();   // different user
    }
}
