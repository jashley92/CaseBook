using FluentAssertions;
using IncidentManager.Infrastructure.Realtime;
using Xunit;

namespace IncidentManager.UnitTests;

public class CaseChangeNotifierTests
{
    [Fact]
    public async Task Publish_notifies_only_subscribers_of_that_case()
    {
        var notifier = new CaseChangeNotifier();
        var caseA = Guid.NewGuid();
        var caseB = Guid.NewGuid();
        var aHits = 0;
        var bHits = 0;
        string? seenActor = null;

        using var subA = notifier.Subscribe(caseA, actor => { seenActor = actor; Interlocked.Increment(ref aHits); return Task.CompletedTask; });
        using var subB = notifier.Subscribe(caseB, _ => { Interlocked.Increment(ref bHits); return Task.CompletedTask; });

        notifier.Publish(caseA, "S-1-5-21-ACTOR");
        await WaitFor(() => Volatile.Read(ref aHits) == 1);

        aHits.Should().Be(1);
        bHits.Should().Be(0);
        seenActor.Should().Be("S-1-5-21-ACTOR"); // the acting user is delivered to subscribers (U-30)
    }

    [Fact]
    public async Task Disposed_subscription_stops_receiving()
    {
        var notifier = new CaseChangeNotifier();
        var caseId = Guid.NewGuid();
        var hits = 0;

        var sub = notifier.Subscribe(caseId, _ => { Interlocked.Increment(ref hits); return Task.CompletedTask; });
        sub.Dispose();

        notifier.Publish(caseId, "actor");
        await Task.Delay(50); // give any (erroneously live) handler a chance to run

        hits.Should().Be(0);
    }

    private static async Task WaitFor(Func<bool> condition)
    {
        for (var i = 0; i < 50 && !condition(); i++) await Task.Delay(10);
    }
}
