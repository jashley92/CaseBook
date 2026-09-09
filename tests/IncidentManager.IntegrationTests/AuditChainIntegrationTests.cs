using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Exercises the real EF Core context + audit-chain interceptor against an in-memory SQLite
/// database: full case workflow, chain verification, and direct-tamper detection.
/// </summary>
public sealed class AuditChainIntegrationTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IHashChainService _hasher = new HashChainService();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public AuditChainIntegrationTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    [Fact]
    public async Task Full_case_workflow_writes_a_valid_audit_chain()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);

        // Data landed.
        (await db.Cases.CountAsync()).Should().Be(3);
        var breach = await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave");
        breach.Classification.Should().Be(Classification.Breach);

        // Every changed case got a row hash.
        (await db.Cases.AllAsync(c => c.RowHash != null && c.RowHash != "")).Should().BeTrue();

        // The audit chain is populated and internally valid.
        var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
        chain.Should().NotBeEmpty();
        chain.Should().Contain(a => a.Action == AuditAction.Create && a.EntityType == "Case");
        chain.Should().Contain(a => a.Action == AuditAction.Update && a.CaseNumber == "2026-01_Phishing_Wave");

        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Verification_detects_a_row_edited_directly_in_the_database()
    {
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
        }

        // Tamper: rewrite an audit row's payload directly via SQL, bypassing the application.
        await using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText =
                "UPDATE AuditLog SET Summary = 'covered up' WHERE Sequence = (SELECT MIN(Sequence) + 2 FROM AuditLog)";
            await cmd.ExecuteNonQueryAsync();
        }

        await using var verifyDb = NewContext();
        var chain = await verifyDb.AuditLog.OrderBy(a => a.Sequence).ToListAsync();

        var result = _hasher.VerifyChain(chain);
        result.IsValid.Should().BeFalse();
        result.FirstBrokenSequence.Should().NotBeNull();
        result.Detail.Should().Contain("altered");
    }

    [Fact]
    public async Task Case_number_uses_the_year_sequence_descriptive_convention()
    {
        await using var db = NewContext();
        var c = Case.Open(2026, 7, "Ransomware at HQ", "Ransomware",
            Classification.Incident, Severity.Critical, CaseOrigin.InternalDetection, _user.UserId, _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();

        (await db.Cases.FirstAsync(x => x.Id == c.Id)).CaseNumber.Should().Be("2026-07_Ransomware_at_HQ");
    }

    public void Dispose() => _connection.Dispose();
}
