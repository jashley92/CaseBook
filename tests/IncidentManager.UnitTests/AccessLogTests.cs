using FluentAssertions;
using IncidentManager.Application.Access;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class AccessLogRulesTests
{
    [Fact]
    public void Off_logs_nothing()
    {
        foreach (var type in Enum.GetValues<AccessType>())
        {
            AccessLogRules.ShouldLog(AccessLogScope.Off, type, wasRestricted: false).Should().BeFalse();
            AccessLogRules.ShouldLog(AccessLogScope.Off, type, wasRestricted: true).Should().BeFalse();
        }
    }

    [Fact]
    public void All_logs_everything()
    {
        foreach (var type in Enum.GetValues<AccessType>())
        {
            AccessLogRules.ShouldLog(AccessLogScope.All, type, wasRestricted: false).Should().BeTrue();
            AccessLogRules.ShouldLog(AccessLogScope.All, type, wasRestricted: true).Should().BeTrue();
        }
    }

    [Fact]
    public void RestrictedOnly_logs_case_opens_only_when_restricted()
    {
        AccessLogRules.ShouldLog(AccessLogScope.RestrictedOnly, AccessType.CaseOpen, wasRestricted: false).Should().BeFalse();
        AccessLogRules.ShouldLog(AccessLogScope.RestrictedOnly, AccessType.CaseOpen, wasRestricted: true).Should().BeTrue();
    }

    [Theory]
    [InlineData(AccessType.EvidenceDownload)]
    [InlineData(AccessType.ReportDownload)]
    [InlineData(AccessType.Export)]
    public void RestrictedOnly_always_logs_artifacts_and_exports(AccessType type)
    {
        // Artifacts/exports are inherently sensitive, so RestrictedOnly still captures them.
        AccessLogRules.ShouldLog(AccessLogScope.RestrictedOnly, type, wasRestricted: false).Should().BeTrue();
        AccessLogRules.ShouldLog(AccessLogScope.RestrictedOnly, type, wasRestricted: true).Should().BeTrue();
    }
}

public class AccessCoalescerTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(30);

    [Fact]
    public void Within_the_window_coalesces()
    {
        AccessCoalescer.ShouldCoalesce(Now.AddMinutes(-10), Now, Window).Should().BeTrue();
    }

    [Fact]
    public void At_the_exact_window_edge_still_coalesces()
    {
        AccessCoalescer.ShouldCoalesce(Now.AddMinutes(-30), Now, Window).Should().BeTrue();
    }

    [Fact]
    public void Past_the_window_starts_a_new_session()
    {
        AccessCoalescer.ShouldCoalesce(Now.AddMinutes(-31), Now, Window).Should().BeFalse();
    }

    [Fact]
    public void A_future_last_seen_does_not_coalesce()
    {
        // Clock skew / a bad row: never fold into a session that claims to be ahead of now.
        AccessCoalescer.ShouldCoalesce(Now.AddMinutes(1), Now, Window).Should().BeFalse();
    }
}
