using FluentAssertions;
using IncidentManager.Application.Work;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Agenda (and digest) banding: calendar days in the viewer's or organization's zone.</summary>
public class AgendaBucketTests
{
    private static readonly TimeZoneInfo Eastern = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");
    private static readonly DateTimeOffset Now = new(2026, 9, 10, 23, 30, 0, TimeSpan.Zero);   // 19:30 EDT on the 10th

    [Fact]
    public void Today_ends_at_local_midnight()
    {
        var tonight = new DateTimeOffset(2026, 9, 11, 2, 0, 0, TimeSpan.Zero);          // 22:00 EDT on the 10th
        AgendaService.Bucket(tonight, Now, Eastern).Should().Be(AgendaBucketKind.Today);
        AgendaService.Bucket(tonight, Now, TimeZoneInfo.Utc).Should().Be(AgendaBucketKind.ThisWeek);

        var justAfterMidnight = new DateTimeOffset(2026, 9, 11, 4, 0, 0, TimeSpan.Zero); // 00:00 EDT on the 11th
        AgendaService.Bucket(justAfterMidnight, Now, Eastern).Should().Be(AgendaBucketKind.ThisWeek);
    }

    [Fact]
    public void This_week_runs_through_the_six_days_after_today()
    {
        var lastOfWeek = new DateTimeOffset(2026, 9, 17, 3, 59, 0, TimeSpan.Zero);      // 23:59 EDT on the 16th
        var firstLater = new DateTimeOffset(2026, 9, 17, 4, 0, 0, TimeSpan.Zero);       // 00:00 EDT on the 17th
        AgendaService.Bucket(lastOfWeek, Now, Eastern).Should().Be(AgendaBucketKind.ThisWeek);
        AgendaService.Bucket(firstLater, Now, Eastern).Should().Be(AgendaBucketKind.Later);
    }

    [Fact]
    public void Overdue_and_undated_are_unaffected_by_the_zone()
    {
        AgendaService.Bucket(Now.AddMinutes(-1), Now, Eastern).Should().Be(AgendaBucketKind.Overdue);
        AgendaService.Bucket(null, Now, Eastern).Should().Be(AgendaBucketKind.NoDueDate);
    }
}
