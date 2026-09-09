using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>X-03 slice B: admin CRUD over the data-element reference set — add/relabel/reorder, archive/restore,
/// delete-when-unused, keyed by a stable Key, audited and hash-chained.</summary>
public sealed class DataElementServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 8, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public DataElementServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
        DevDataSeeder.SeedDataElementsAsync(db, _clock).GetAwaiter().GetResult();
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

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private DataElementService NewService() => new(NewFactory(), _user, _clock);

    // Active views → editor rows (order preserved).
    private static List<DataElementRow> RowsFrom(IEnumerable<DataElementView> views) =>
        views.Where(v => v.IsActive).Select(v => new DataElementRow(v.Id, v.Label, v.NotificationJurisdictions)).ToList();

    [Fact]
    public async Task Adding_generates_a_derived_key()
    {
        var svc = NewService();
        var rows = RowsFrom(await svc.ListAllAsync());
        rows.Add(new DataElementRow(null, "Health record", "US, NY"));

        await svc.SaveAsync(rows);

        var added = (await svc.ListAllAsync()).Single(e => e.Label == "Health record");
        added.Key.Should().Be("HealthRecord");
        added.IsSystem.Should().BeFalse();
        added.IsActive.Should().BeTrue();
        added.NotificationJurisdictions.Should().Be("US,NY");
    }

    [Fact]
    public async Task Reorder_and_relabel_persist_without_changing_keys()
    {
        var svc = NewService();
        var views = await svc.ListAllAsync();
        var beforeKeys = views.Select(v => v.Key).ToList();
        var rows = RowsFrom(views);

        // Move the last element to the front and rename the first.
        var last = rows[^1];
        rows.RemoveAt(rows.Count - 1);
        rows.Insert(0, last);
        rows[1] = rows[1] with { Label = "Full name" };

        await svc.SaveAsync(rows);

        var after = await svc.ListAllAsync();
        after[0].Key.Should().Be(views[^1].Key, "the moved element keeps its key but sorts first");
        after[1].Label.Should().Be("Full name");
        after.Select(v => v.Key).Should().BeEquivalentTo(beforeKeys, "reorder/relabel never changes the identity");
    }

    [Fact]
    public async Task Archiving_a_builtin_removes_it_from_the_active_set_but_keeps_it()
    {
        var svc = NewService();
        var ssn = (await svc.ListAllAsync()).Single(e => e.Key == "SocialSecurityNumber");
        ssn.IsSystem.Should().BeTrue();

        await svc.SetArchivedAsync(ssn.Id, archived: true);

        (await svc.ListActiveAsync()).Should().NotContain(e => e.Key == "SocialSecurityNumber");
        var all = await svc.ListAllAsync();
        all.Single(e => e.Key == "SocialSecurityNumber").IsActive.Should().BeFalse("archived, not deleted");

        // And it can be restored.
        await svc.SetArchivedAsync(ssn.Id, archived: false);
        (await svc.ListActiveAsync()).Should().Contain(e => e.Key == "SocialSecurityNumber");
    }

    [Fact]
    public async Task An_unused_custom_element_can_be_deleted_but_a_builtin_cannot()
    {
        var svc = NewService();
        var rows = RowsFrom(await svc.ListAllAsync());
        rows.Add(new DataElementRow(null, "Passport number", null));
        await svc.SaveAsync(rows);

        var custom = (await svc.ListAllAsync()).Single(e => e.Label == "Passport number");
        custom.IsDeletable.Should().BeTrue();
        await svc.DeleteAsync(custom.Id);
        (await svc.ListAllAsync()).Should().NotContain(e => e.Label == "Passport number");

        var builtin = (await svc.ListAllAsync()).First(e => e.IsSystem);
        var act = () => svc.DeleteAsync(builtin.Id);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*archive it instead*");
    }

    [Fact]
    public async Task A_referenced_element_cannot_be_deleted()
    {
        var svc = NewService();
        var rows = RowsFrom(await svc.ListAllAsync());
        rows.Add(new DataElementRow(null, "Passport number", null));
        await svc.SaveAsync(rows);
        var custom = (await svc.ListAllAsync()).Single(e => e.Label == "Passport number");

        // A case records the element (join row references its key).
        await using (var db = NewContext())
        {
            var c = Case.Open(2026, 1, "Ref", "Ref", Classification.Incident, Severity.Low, CaseOrigin.InternalDetection, "a", _clock.UtcNow);
            c.SetImpactAssessment(1, new[] { custom.Key }, null, "a", _clock.UtcNow);
            db.Cases.Add(c);
            await db.SaveChangesAsync();
        }

        (await svc.ListAllAsync()).Single(e => e.Key == custom.Key).IsDeletable.Should().BeFalse();
        var act = () => svc.DeleteAsync(custom.Id);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*case(s)*archive*");
    }

    [Fact]
    public async Task Duplicate_labels_are_rejected()
    {
        var svc = NewService();
        var rows = RowsFrom(await svc.ListAllAsync());
        rows.Add(new DataElementRow(null, rows[0].Label.ToUpperInvariant(), null));

        var act = () => svc.SaveAsync(rows);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*unique*");
    }

    [Fact]
    public async Task A_blank_label_is_rejected()
    {
        var svc = NewService();
        var rows = RowsFrom(await svc.ListAllAsync());
        rows.Add(new DataElementRow(null, "   ", null));

        var act = () => svc.SaveAsync(rows);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Changes_are_audited_and_the_chain_stays_valid()
    {
        var svc = NewService();
        var rows = RowsFrom(await svc.ListAllAsync());
        rows[0] = rows[0] with { Label = "Renamed" };
        rows.Add(new DataElementRow(null, "Passport number", null));
        await svc.SaveAsync(rows);

        await using var db = NewContext();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        chain.Should().Contain(a => a.EntityType == nameof(DataElement));
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    public void Dispose() => _connection.Dispose();
}
