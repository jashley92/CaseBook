using FluentAssertions;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>E-06 / U-47c: the built-in starter playbooks seed on first run and include a vendor-breach template.</summary>
public sealed class StarterTemplateSeedTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 11, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public StarterTemplateSeedTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);
        db.Database.EnsureCreated();
        return db;
    }

    [Fact]
    public async Task Seeds_a_third_party_vendor_breach_template_with_disclosure_steps()
    {
        await using var db = NewContext();

        await DevDataSeeder.SeedStarterTemplatesAsync(db, _clock);

        var vendor = await db.CaseTemplates.Include(t => t.Steps)
            .SingleOrDefaultAsync(t => t.Name == "Third-party / vendor breach");
        vendor.Should().NotBeNull();
        vendor!.IsActive.Should().BeTrue();
        vendor.Steps.Should().NotBeEmpty();
        // The playbook follows a vendor-disclosure narrative, not a first-party kill-chain.
        vendor.Steps.Select(s => s.Title).Should().Contain(t => t.Contains("disclosure"));
        vendor.RowHash.Should().NotBeNullOrEmpty();   // audited/hash-chained like other reference data
    }

    [Fact]
    public async Task Seeding_is_idempotent()
    {
        await using var db = NewContext();

        await DevDataSeeder.SeedStarterTemplatesAsync(db, _clock);
        var count = await db.CaseTemplates.CountAsync();
        await DevDataSeeder.SeedStarterTemplatesAsync(db, _clock);

        (await db.CaseTemplates.CountAsync()).Should().Be(count);
    }

    public void Dispose() => _connection.Dispose();
}
