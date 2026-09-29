using FluentAssertions;
using IncidentManager.Application.Access;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Access;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>INV-04: "when did I last have this case open", allowing for the page's two-pass load.</summary>
public sealed class LastViewedTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 20, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "me" };
    private readonly Guid _caseId = Guid.NewGuid();

    public LastViewedTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options;

    private sealed class Policy : IAccessLogPolicy
    {
        public AccessLogScope Scope => AccessLogScope.All;
        public TimeSpan CoalesceWindow => TimeSpan.FromMinutes(30);
        public bool ShouldLog(AccessType type, bool wasRestricted) => true;
    }

    private AccessLogService Service() => new(new TestDbContextFactory(Options()), new Policy(), _user, _clock,
        new CapturingSecurityEventSink(), NullLogger<AccessLogService>.Instance);

    private void Session(DateTimeOffset first, DateTimeOffset last)
    {
        using var db = new AppDbContext(Options());
        var e = CaseAccessEvent.Start("me", _caseId, "2026-01_X", AccessType.CaseOpen, null, null, false, first);
        e.LastSeenUtc = last;
        db.CaseAccessEvents.Add(e);
        db.SaveChanges();
    }

    [Fact]
    public async Task Never_viewed_means_no_last_view()
        => (await Service().LastViewedAsync(_caseId)).Should().BeNull();

    [Fact]
    public async Task A_session_started_moments_ago_is_this_visit_so_the_one_before_is_the_last_view()
    {
        var earlier = _clock.UtcNow.AddDays(-3);
        Session(earlier.AddMinutes(-10), earlier);
        Session(_clock.UtcNow.AddSeconds(-5), _clock.UtcNow.AddSeconds(-5)); // recorded by the prerender pass

        (await Service().LastViewedAsync(_caseId)).Should().Be(earlier);
    }

    [Fact]
    public async Task A_session_still_being_extended_means_the_viewer_never_left()
    {
        Session(_clock.UtcNow.AddMinutes(-20), _clock.UtcNow.AddSeconds(-5));

        (await Service().LastViewedAsync(_caseId)).Should().BeNull();
    }

    [Fact]
    public async Task Before_this_visit_is_recorded_the_latest_session_is_the_last_view()
    {
        var earlier = _clock.UtcNow.AddHours(-6);
        Session(earlier.AddMinutes(-15), earlier);

        (await Service().LastViewedAsync(_caseId)).Should().Be(earlier);
    }

    public void Dispose() => _connection.Dispose();
}
