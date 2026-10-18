using System.Diagnostics;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Search;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Xunit;
using Xunit.Abstractions;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-22: what Find and the case-list search cost on a large database on SQL Server, for docs/architecture/performance.md
/// (Search). Synthetic cases, each with record entries and working notes. Times each keystroke of a word typed into the
/// command bar, and one case-list search, by substring; where the server has Full-Text Search, again by word with the
/// indexes, and checks both find the same for the whole word. Writes the figures to the test output.
/// <c>CASEBOOK_FIND_ROWS</c> sets the number of records (default 50,000). Skipped without <c>CASEBOOK_TEST_SQL</c>.
/// </summary>
public sealed class FindThroughputTests(ITestOutputHelper output)
{
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };

    private static int Rows =>
        int.TryParse(Environment.GetEnvironmentVariable("CASEBOOK_FIND_ROWS"), out var n) && n > 0 ? n : 50_000;

    private const string Word = "credential";

    [SqlServerFact]
    public async Task Find_reads_a_large_database_at_a_measured_rate()
    {
        using var database = TestDatabase.Open(TestDatabase.SqlServer);
        var seed = Stopwatch.StartNew();
        var cases = await SeedAsync(database, Rows);
        output.WriteLine($"Seeded {cases:N0} cases with {Rows:N0} records (entries and notes) in {seed.Elapsed.TotalSeconds:N0} s.");

        var substring = await TimeAsync(database, null, "substring");
        if (!SqlServerFullTextFactAttribute.Installed)
        {
            output.WriteLine("This server doesn't have Full-Text Search (IsFullTextInstalled = 0): the full-text figures need one that has it.");
            return;
        }

        await using (var db = database.NewContext()) await db.Database.ExecuteSqlRawAsync(FullTextSchema.Script);
        var search = new SqlFullTextSearch(database.Factory(), new FullTextStatusCache(), _clock);
        var fill = Stopwatch.StartNew();
        while ((await search.RefreshAsync()).Mode != FullTextMode.Ready)
        {
            fill.Elapsed.Should().BeLessThan(TimeSpan.FromMinutes(10), "the indexes fill");
            await Task.Delay(1000);
        }
        output.WriteLine($"Full-text indexes filled in {fill.Elapsed.TotalSeconds:N0} s.");
        var fullText = await TimeAsync(database, search, "full-text");
        fullText.Should().Be(substring, $"\"{Word}\" starts a word wherever it appears, so both find the same");
        (await search.StatusAsync()).Fallbacks.Should().Be(0);
    }

    // Each keystroke of the word as the command bar sends it, then the list's search; the whole word's entry and case counts.
    private async Task<(int Entries, int Notes, int Cases)> TimeAsync(TestDatabase database, IFullTextSearch? fullText, string how)
    {
        var find = new FindService(database.Factory(), _user, new ListedUserDirectory(), fullText: fullText);
        await find.FindAsync("warm");   // the first query pays for the connection and the model
        FindResult? last = null;
        for (var i = 2; i <= Word.Length; i++)
        {
            var typed = Word[..i];
            var watch = Stopwatch.StartNew();
            last = await find.FindAsync(typed + " in:notes");
            output.WriteLine($"{how}: Find \"{typed}\" in {watch.Elapsed.TotalMilliseconds:N0} ms "
                             + $"({last.Counts.GetValueOrDefault(FindKind.Entries):N0} entries, {last.Counts.GetValueOrDefault(FindKind.Notes):N0} notes).");
        }
        var factory = database.Factory();
        var list = new CaseService(factory, _user, _clock, new CaseNumberGenerator(factory.CreateAppDbContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(), fullText: fullText);
        var w = Stopwatch.StartNew();
        var page = await list.ListAsync(new CaseFilter { Search = Word, IncludeClosed = true });
        output.WriteLine($"{how}: case list search \"{Word}\" in {w.Elapsed.TotalMilliseconds:N0} ms ({page.Total:N0} cases).");
        return (last!.Counts.GetValueOrDefault(FindKind.Entries), last.Counts.GetValueOrDefault(FindKind.Notes), page.Total);
    }

    // Cases of 100 records each, half entries naming the word, half notes that don't, written outside the interceptor.
    private async Task<int> SeedAsync(TestDatabase database, int count)
    {
        await using var db = new AppDbContext(database.OptionsWithoutInterceptors);
        db.ChangeTracker.AutoDetectChangesEnabled = false;
        var perCase = 100;
        var caseCount = Math.Max(1, count / perCase);
        for (var c = 0; c < caseCount; c++)
        {
            var at = _clock.UtcNow.AddMinutes(-count + c * perCase);
            var k = Case.Open(2026, c + 1, $"Synthetic_{c}", $"Synthetic case {c}", Classification.Incident, Severity.Medium,
                CaseOrigin.InternalDetection, "alice", at);
            for (var i = 0; i < perCase; i++)
            {
                var when = at.AddMinutes(i);
                if (i % 2 == 0)
                    k.TimelineEntries.Add(new TimelineEntry
                    {
                        Kind = TimelineKind.Event, OccurredAtUtc = when, CreatedBy = "alice", CreatedAtUtc = when, Source = "EDR",
                        Description = $"Credential dumping on WS-{c:D4}{i:D2}: lsass memory read by an unsigned binary from a user temp folder.",
                    });
                else
                    k.Notes.Add(new AnalystNote
                    {
                        CreatedBy = "alice", CreatedAtUtc = when,
                        Body = $"Observed beaconing from host WS-{c:D4}{i:D2} to 203.0.113.{i % 250}; isolated it and pulled the EDR timeline.",
                    });
            }
            db.Cases.Add(k);
            if (c % 20 == 19)
            {
                await db.SaveChangesAsync();
                db.ChangeTracker.Clear();
            }
        }
        await db.SaveChangesAsync();
        return caseCount;
    }
}
