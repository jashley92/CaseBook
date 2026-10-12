using FluentAssertions;
using IncidentManager.Application.Abstractions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>BUG-94: a failed send is put down to the items it carried, so only those are retried.</summary>
public sealed class DeliveryWatchTests
{
    private static void Send(bool fails, params string[] items)
    {
        int failures;
        using (var send = DeliveryWatch.Begin())
        {
            if (fails) DeliveryWatch.ReportFailure();
            failures = send.Failures;
        }
        if (failures > 0) DeliveryWatch.Attribute(items, failures);
    }

    [Fact]
    public void Only_the_items_on_a_failed_send_are_retried()
    {
        using var scan = DeliveryWatch.Begin();
        Send(false, "a", "b");
        Send(true, "c");

        scan.ShouldRetry("a").Should().BeFalse();
        scan.ShouldRetry("c").Should().BeTrue();
    }

    [Fact]
    public void A_failure_nobody_attributed_retries_everything()
    {
        using var scan = DeliveryWatch.Begin();
        Send(true, "c");
        DeliveryWatch.ReportFailure();   // e.g. a send outside SendFor

        scan.ShouldRetry("a").Should().BeTrue();
    }

    [Fact]
    public void Nothing_failed_nothing_is_retried()
    {
        using var scan = DeliveryWatch.Begin();
        Send(false, "a");
        scan.ShouldRetry("a").Should().BeFalse();
    }
}
