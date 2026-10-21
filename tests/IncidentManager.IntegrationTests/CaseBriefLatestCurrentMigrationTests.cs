using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-185: where the v1.5.2 clean-up kept the earlier of two racing briefs as current, the upgrade makes the later
/// one current; other cases are left as they are.
/// </summary>
public sealed class CaseBriefLatestCurrentMigrationTests : IDisposable
{
    private const string Before = "20261012183339_AuditEntryFormat";
    private static readonly DateTimeOffset T = new(2026, 10, 1, 9, 0, 0, TimeSpan.Zero);
    private readonly SqliteConnection _connection = new("Data Source=:memory:");

    public CaseBriefLatestCurrentMigrationTests() => _connection.Open();

    private AppDbContext NewContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);

    private static CaseBrief Brief(Guid caseId, int version, bool current, DateTimeOffset at, string summary) => new()
    {
        CaseId = caseId, Version = version, IsCurrent = current, Summary = summary, CreatedBy = "a1", CreatedAtUtc = at,
    };

    [Fact]
    public async Task The_later_of_two_same_version_briefs_becomes_current()
    {
        Guid raced, normal;
        await using (var db = NewContext())
        {
            await db.GetService<IMigrator>().MigrateAsync(Before);
            // Columns added by later migrations (WF-11, WF-30, CAP-36, FR-51), so today's model can write the old rows; dropped below.
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE Cases ADD COLUMN ReportedJurisdictions TEXT NULL");
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE Cases ADD COLUMN TeamId TEXT NULL");
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE Cases ADD COLUMN ContainedBy TEXT NULL");
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE Cases ADD COLUMN ContainedRecordedAtUtc TEXT NULL");
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE CaseBriefs ADD COLUMN Appended INTEGER NOT NULL DEFAULT 0");
            var a = Case.Open(2026, 1, "Raced", "Two saves", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "a1", T);
            var b = Case.Open(2026, 2, "Normal", "One save", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "a1", T);
            db.Cases.AddRange(a, b);
            await db.SaveChangesAsync();
            (raced, normal) = (a.Id, b.Id);
            db.CaseBriefs.AddRange(
                Brief(raced, 1, false, T, "first"),
                Brief(raced, 2, true, T.AddMinutes(1), "earlier save"),    // kept by the clean-up's Id tie-break
                Brief(raced, 2, false, T.AddMinutes(2), "later save"),
                Brief(normal, 1, false, T, "first"),
                Brief(normal, 2, true, T.AddMinutes(1), "current"));
            await db.SaveChangesAsync();
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE Cases DROP COLUMN ReportedJurisdictions");
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE Cases DROP COLUMN TeamId");
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE Cases DROP COLUMN ContainedBy");
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE Cases DROP COLUMN ContainedRecordedAtUtc");
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE CaseBriefs DROP COLUMN Appended");
        }

        await using (var db = NewContext())
            await db.Database.MigrateAsync();

        await using (var db = NewContext())
        {
            var current = await db.CaseBriefs.AsNoTracking().Where(x => x.IsCurrent).ToListAsync();
            current.Should().HaveCount(2);
            current.Single(x => x.CaseId == raced).Summary.Should().Be("later save");
            current.Single(x => x.CaseId == normal).Summary.Should().Be("current");
        }
    }

    public void Dispose() => _connection.Dispose();
}
