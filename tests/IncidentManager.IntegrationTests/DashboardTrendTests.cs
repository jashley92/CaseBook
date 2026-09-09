using FluentAssertions;
using IncidentManager.Application.Dashboards;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

public sealed class DashboardTrendTests : IDisposable
{
    private readonly SqliteConnection _connection;

    public DashboardTrendTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    // No audit interceptor: this test controls CreatedAtUtc/ClosedAtUtc directly.
    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    [Fact]
    public async Task Trend_reconstructs_opened_closed_and_open_at_month_end_from_timestamps()
    {
        var now = new DateTimeOffset(2026, 3, 15, 0, 0, 0, TimeSpan.Zero);

        Case Open(int seq, DateTimeOffset created) =>
            Case.Open(2026, seq, $"Case {seq}", $"Case {seq}",
                Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "system", created);

        await using (var db = NewContext())
        {
            // Opened Jan, still open.
            db.Cases.Add(Open(1, new DateTimeOffset(2026, 1, 10, 0, 0, 0, TimeSpan.Zero)));

            // Opened Jan, closed Feb.
            var c2 = Open(2, new DateTimeOffset(2026, 1, 20, 0, 0, 0, TimeSpan.Zero));
            c2.ClosedAtUtc = new DateTimeOffset(2026, 2, 5, 0, 0, 0, TimeSpan.Zero);
            db.Cases.Add(c2);

            // Opened Mar, still open.
            db.Cases.Add(Open(3, new DateTimeOffset(2026, 3, 2, 0, 0, 0, TimeSpan.Zero)));

            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var trend = await DashboardService.BuildTrendAsync(db.Cases.AsNoTracking(), now, months: 3);

            trend.Should().HaveCount(3);
            var jan = trend.Single(t => t.Month == 1);
            var feb = trend.Single(t => t.Month == 2);
            var mar = trend.Single(t => t.Month == 3);

            jan.Opened.Should().Be(2);
            jan.Closed.Should().Be(0);
            jan.OpenAtEnd.Should().Be(2); // both opened in Jan, neither closed by end of Jan

            feb.Opened.Should().Be(0);
            feb.Closed.Should().Be(1);
            feb.OpenAtEnd.Should().Be(1); // case 2 closed in Feb, case 1 still open

            mar.Opened.Should().Be(1);
            mar.OpenAtEnd.Should().Be(2); // case 1 + case 3 open at end of March
        }
    }

    public void Dispose() => _connection.Dispose();
}
