using FluentAssertions;
using IncidentManager.Infrastructure.Realtime;
using Xunit;

namespace IncidentManager.UnitTests;

public class CasePresenceServiceTests
{
    [Fact]
    public void Viewers_lists_distinct_people_on_that_case()
    {
        var presence = new CasePresenceService();
        var caseA = Guid.NewGuid();
        var caseB = Guid.NewGuid();

        using var a1 = presence.Join(caseA, "sid-alice", "Alice", "circuit-1");
        using var b1 = presence.Join(caseA, "sid-bob", "Bob", "circuit-2");
        using var other = presence.Join(caseB, "sid-carol", "Carol", "circuit-3");

        presence.Viewers(caseA).Select(v => v.DisplayName).Should().BeEquivalentTo(new[] { "Alice", "Bob" });
        presence.Viewers(caseB).Select(v => v.DisplayName).Should().ContainSingle().Which.Should().Be("Carol");
    }

    [Fact]
    public void Same_user_in_multiple_tabs_counts_once()
    {
        var presence = new CasePresenceService();
        var caseId = Guid.NewGuid();

        using var tab1 = presence.Join(caseId, "sid-alice", "Alice", "circuit-1");
        using var tab2 = presence.Join(caseId, "sid-alice", "Alice", "circuit-2");

        presence.Viewers(caseId).Should().ContainSingle().Which.UserId.Should().Be("sid-alice");
    }

    [Fact]
    public void Leaving_removes_the_viewer()
    {
        var presence = new CasePresenceService();
        var caseId = Guid.NewGuid();

        var reg = presence.Join(caseId, "sid-alice", "Alice", "circuit-1");
        presence.Viewers(caseId).Should().ContainSingle();

        reg.Dispose();
        presence.Viewers(caseId).Should().BeEmpty();
    }

    [Fact]
    public void RemoveCircuit_purges_every_registration_from_that_circuit()
    {
        var presence = new CasePresenceService();
        var caseA = Guid.NewGuid();
        var caseB = Guid.NewGuid();

        // A crashed tab (circuit-1) had two cases open; a different circuit stays.
        presence.Join(caseA, "sid-alice", "Alice", "circuit-1");
        presence.Join(caseB, "sid-alice", "Alice", "circuit-1");
        using var survivor = presence.Join(caseA, "sid-bob", "Bob", "circuit-2");

        presence.RemoveCircuit("circuit-1");

        presence.Viewers(caseA).Select(v => v.DisplayName).Should().BeEquivalentTo(new[] { "Bob" });
        presence.Viewers(caseB).Should().BeEmpty();
    }

    [Fact]
    public async Task Subscribers_are_notified_on_join_and_leave()
    {
        var presence = new CasePresenceService();
        var caseId = Guid.NewGuid();
        var hits = 0;

        using var sub = presence.Subscribe(caseId, () => { Interlocked.Increment(ref hits); return Task.CompletedTask; });

        var reg = presence.Join(caseId, "sid-alice", "Alice", "circuit-1");
        await WaitFor(() => Volatile.Read(ref hits) >= 1);

        reg.Dispose();
        await WaitFor(() => Volatile.Read(ref hits) >= 2);

        hits.Should().BeGreaterThanOrEqualTo(2);
    }

    private static async Task WaitFor(Func<bool> condition)
    {
        for (var i = 0; i < 50 && !condition(); i++) await Task.Delay(10);
    }
}
