using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// C4 / BUG-589: every format <see cref="Case.ReportedJurisdictions"/> has ever been written in reads back as the codes and
/// elements it meant, once the start-up backfill has run, and the backfill leaves a sound value alone.
/// </summary>
public sealed class KeptJurisdictionsFormatTests : IDisposable
{
    private static readonly HashSet<string> Known = new(StringComparer.OrdinalIgnoreCase) { "SSN", "DL" };

    // Stored value, the codes and the elements it means (null: elements not recorded).
    public static TheoryData<string, string[], string[]?> Formats => new()
    {
        { "", [], null },                                  // WF-11: reported with nothing in play
        { "NJ,NY", ["NJ", "NY"], null },                  // WF-11: codes only (before BUG-284)
        { "NJ,NY;SSN,DL", ["NJ", "NY"], ["SSN", "DL"] },  // BUG-284: codes and elements
        { "NJ,NY;", ["NJ", "NY"], [] },                   // BUG-284: no elements then
        { ";SSN", [], ["SSN"] },                          // BUG-284: no codes, an element
        { "NY;CA", ["CA", "NY"], null },                  // BUG-589: a code holding ";" (before BUG-404), codes only
        { "NY;CA;SSN", ["CA", "NY"], ["SSN"] },           // BUG-589: the same, with the elements after it
        { "NY;CA;", ["CA", "NY"], [] },                   // BUG-589: the same, with no elements
        { "NY;CA,TX;SSN,DL", ["CA", "NY", "TX"], ["DL", "SSN"] },
    };

    [Theory]
    [MemberData(nameof(Formats))]
    public void Every_written_format_reads_as_what_it_meant(string stored, string[] codes, string[]? elements)
    {
        var value = ReportedJurisdictionsBackfill.Repaired(stored, Known) ?? stored;
        Case.KeptJurisdictions(value).Should().BeEquivalentTo(codes, stored);
        if (elements is null) Case.KeptElementKeys(value).Should().BeNull(stored);
        else Case.KeptElementKeys(value).Should().BeEquivalentTo(elements, stored);
        ReportedJurisdictionsBackfill.Repaired(value, Known).Should().BeNull("a repaired value is sound: " + stored);
    }

    private readonly SqliteConnection _connection = new("Data Source=:memory:");

    public KeptJurisdictionsFormatTests() => _connection.Open();

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);
        db.Database.EnsureCreated();
        return db;
    }

    [Fact]
    public async Task The_start_up_backfill_repairs_damaged_values_and_gives_them_their_elements()
    {
        var now = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
        var ids = new Dictionary<string, Guid>();
        await using (var db = NewContext())
        {
            db.DataElements.Add(new DataElement { Key = "SSN", Label = "SSN", NotificationJurisdictions = "NY", IsActive = true,
                CreatedBy = "system", CreatedAtUtc = now });
            var seq = 0;
            foreach (var stored in new[] { "NY;CA", "NY;CA;SSN", "NJ,NY;SSN", "NJ,NY;" })
            {
                var c = Case.Open(2026, ++seq, $"C{seq}", stored, Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "ic", now);
                c.SetImpactAssessment(10, ["SSN"], "NY", "ic", now);
                c.ReportedAtUtc = now;
                c.ReportedJurisdictions = stored;
                db.Cases.Add(c);
                ids[stored] = c.Id;
            }
            await db.SaveChangesAsync();
        }

        (await ReportedJurisdictionsBackfill.RunAsync(NewContext())).Should().Be(3, "two repaired, and the codes-only one given its elements");

        await using var check = NewContext();
        var kept = await check.Cases.AsNoTracking().ToDictionaryAsync(c => c.Id, c => c.ReportedJurisdictions);
        kept[ids["NY;CA"]].Should().Be("CA,NY;SSN");
        kept[ids["NY;CA;SSN"]].Should().Be("CA,NY;SSN");
        kept[ids["NJ,NY;SSN"]].Should().Be("NJ,NY;SSN", "a sound value is left alone");
        kept[ids["NJ,NY;"]].Should().Be("NJ,NY;");
        (await ReportedJurisdictionsBackfill.RunAsync(check)).Should().Be(0);
    }

    public void Dispose() => _connection.Dispose();
}
