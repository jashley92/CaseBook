using FluentAssertions;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-546: the default gates, templates and report profiles seed on a true first run only.</summary>
public sealed class FirstRunSeedTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public FirstRunSeedTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private AppDbContext NewContext() => new(new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options);

    [Fact]
    public async Task A_fresh_database_gets_the_default_gates_templates_and_profiles()
    {
        await using var db = NewContext();

        await DevDataSeeder.InitializeAsync(db, _clock, seedDemoData: false);

        (await db.StageGates.AnyAsync()).Should().BeTrue();
        (await db.CaseTemplates.AnyAsync()).Should().BeTrue();
        (await db.ReportProfiles.AnyAsync()).Should().BeTrue();
    }

    [Fact]
    public async Task Deleting_them_all_keeps_them_deleted_after_a_restart()
    {
        await using (var db = NewContext())
        {
            await DevDataSeeder.InitializeAsync(db, _clock, seedDemoData: false);

            db.StageGates.RemoveRange(await db.StageGates.Include(g => g.Requirements).ToListAsync());
            db.CaseTemplates.RemoveRange(await db.CaseTemplates.Include(t => t.Steps).ToListAsync());
            db.ReportProfiles.RemoveRange(await db.ReportProfiles.ToListAsync());
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            await DevDataSeeder.InitializeAsync(db, _clock, seedDemoData: false);

            (await db.StageGates.AnyAsync()).Should().BeFalse("the admin deleted every gate");
            (await db.CaseTemplates.AnyAsync()).Should().BeFalse();
            (await db.ReportProfiles.AnyAsync()).Should().BeFalse();
            // The reference data that can't be emptied still seeds as before.
            (await db.DataElements.AnyAsync()).Should().BeTrue();
        }
    }

    public void Dispose() => _connection.Dispose();
}
