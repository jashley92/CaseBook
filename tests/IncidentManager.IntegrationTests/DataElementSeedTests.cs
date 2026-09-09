using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>X-03: the built-in data-element reference set is seeded on first run and is idempotent.</summary>
public sealed class DataElementSeedTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 8, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public DataElementSeedTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    [Fact]
    public async Task Seeds_the_thirteen_system_elements_with_catalog_codes()
    {
        await using var db = NewContext();

        await DevDataSeeder.SeedDataElementsAsync(db, _clock);

        var elements = await db.DataElements.AsNoTracking().OrderBy(e => e.SortOrder).ToListAsync();
        elements.Should().HaveCount(13);
        elements.Should().OnlyContain(e => e.IsSystem && e.IsActive);
        elements.Select(e => e.Key).Should().Equal(DataElementCatalog.Defaults.Select(d => d.Key));
        elements.Select(e => e.Label).Should().Equal(DataElementCatalog.Defaults.Select(d => d.Label));
        // Reference rows are audited/hash-chained like other reference data.
        elements.Should().OnlyContain(e => e.RowHash != null && e.RowHash != "");
    }

    [Fact]
    public async Task Seeding_is_idempotent()
    {
        await using var db = NewContext();

        await DevDataSeeder.SeedDataElementsAsync(db, _clock);
        await DevDataSeeder.SeedDataElementsAsync(db, _clock);

        (await db.DataElements.CountAsync()).Should().Be(13);
    }

    public void Dispose() => _connection.Dispose();
}
