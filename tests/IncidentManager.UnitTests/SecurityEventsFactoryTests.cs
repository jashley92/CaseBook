using FluentAssertions;
using IncidentManager.Application.Security;
using Xunit;

namespace IncidentManager.UnitTests;

public class SecurityEventsFactoryTests
{
    [Fact]
    public void DownloadRateLimited_carries_actor_and_path_as_a_warning_deny_on_5306()
    {
        var e = SecurityEvents.DownloadRateLimited("analyst1", "analyst1@example.test", "/export/iocs.csv");

        e.EventId.Should().Be(SecurityEventIds.DownloadRateLimited).And.Be(5306);
        e.Category.Should().Be("DataAccess");
        e.Action.Should().Be("DownloadRateLimited");
        e.Outcome.Should().Be(SecurityOutcome.Deny);
        e.Severity.Should().Be(SecuritySeverity.Warning);
        e.Actor.Should().Be("analyst1");
        e.ActorUpn.Should().Be("analyst1@example.test");
        e.Detail.Should().Be("/export/iocs.csv"); // path only — never the payload
    }
}
