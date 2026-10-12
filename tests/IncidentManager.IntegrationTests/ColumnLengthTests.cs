using FluentAssertions;
using IncidentManager.Application.Import;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-02: SQL Server enforces column lengths and SQLite doesn't, so values the app allows must fit the columns.
/// Runs on SQLite always and on SQL Server when <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class ColumnLengthTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_IOC_at_its_longest_saves_and_its_audit_label_fits(string provider)
    {
        using var database = Open(provider);
        await using var db = database.NewContext();
        var now = _clock.UtcNow;
        var c = Case.Open(2026, 1, "long", "Long values", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, _user.UserId, now);
        db.Cases.Add(c);
        await db.SaveChangesAsync();

        c.AddEntity(EntityType.Url, "https://example.test/" + new string('a', 1970), new string('L', 400),
            EntityDisposition.Unknown, null, null, _user.UserId, now);
        await db.SaveChangesAsync();

        var entries = await db.AuditLog.AsNoTracking().OrderBy(e => e.Sequence).ToListAsync();
        entries.Should().OnlyContain(e => e.EntityLabel == null || e.EntityLabel.Length <= 300);
        _hasher.VerifyChain(entries).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Imported_values_clamped_by_the_preview_fit_their_columns(string provider)
    {
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Origin = new string('o', 500),
            Timeline = new() { new() { OccurredAtUtc = _clock.UtcNow.AddHours(-1), Description = "x", Source = new string('s', 500) } },
            Entities = new() { new() { Value = "10.0.0.5", Description = new string('d', 9000), Source = new string('s', 500) } }
        };
        var p = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow);
        var row = p.Entities.Single();
        var step = p.Timeline.Single();

        using var database = Open(provider);
        await using var db = database.NewContext();
        var now = _clock.UtcNow;
        var c = Case.Open(2026, 1, "import", "Imported", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, _user.UserId, now);
        c.AddEntity(row.Type, row.Value, row.Label, row.Disposition, row.Description, row.Source, _user.UserId, now);
        c.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c.Id, Kind = TimelineKind.Investigation, Type = step.Type, OccurredAtUtc = step.OccurredAtUtc,
            Description = step.Description, Source = step.Source, CreatedBy = _user.UserId, CreatedAtUtc = now
        });
        db.Cases.Add(c);
        db.PendingImports.Add(new PendingImport
        {
            SubmittedBy = _user.UserId, SubmittedAtUtc = now, Origin = p.Origin, Summary = "s", RawJson = "{}",
            Status = PendingImportStatus.Pending
        });

        var save = async () => await db.SaveChangesAsync();
        await save.Should().NotThrowAsync();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_value_longer_than_its_column_is_refused_by_name_before_the_database(string provider /* BUG-105 */)
    {
        using var database = Open(provider);
        await using var db = database.NewContext();
        var now = _clock.UtcNow;
        var c = Case.Open(2026, 1, "long", "Long values", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, _user.UserId, now);
        db.Cases.Add(c);
        await db.SaveChangesAsync();

        var entries = await database.NewContext().AuditLog.CountAsync();
        c.UpdateDetails(c.Title, c.Summary, new string('x', 101), null, null, c.DetectedAtUtc ?? now, null, _user.UserId, now);
        var save = async () => await db.SaveChangesAsync();

        await save.Should().ThrowAsync<ArgumentException>().WithMessage("*case detection case id to 100 characters*Nothing was saved*");
        (await database.NewContext().AuditLog.CountAsync()).Should().Be(entries,
            "nothing reaches the audit chain");
    }
}
