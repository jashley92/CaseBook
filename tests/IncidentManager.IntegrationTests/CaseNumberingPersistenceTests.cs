using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

public sealed class CaseNumberingPersistenceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseNumberingPersistenceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin]; // can view all + change classification
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

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private sealed class NoOpCaseNotifications : ICaseNotifications
    {
        public System.Threading.Tasks.Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string assigneeUserId, string assigneeDisplayName, IncidentManager.Domain.Enums.CaseAssignmentRole role, string assignedByUserId, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsOverdueAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.OverdueActionItem> items, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
    }

    private static CreateCaseRequest Req(string name, Classification? cls) => new()
    {
        DescriptiveName = name,
        Title = $"{name} case",
        Classification = cls,
        Severity = Severity.Medium,
        Origin = CaseOrigin.InternalDetection
    };

    [Fact]
    public async Task Complex_events_are_date_numbered_and_irp_cases_are_sequence_numbered()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var irp1 = await svc.CreateAsync(Req("Alpha", Classification.Incident));
        var ce1 = await svc.CreateAsync(Req("Beta", null));
        var irp2 = await svc.CreateAsync(Req("Gamma", Classification.AdverseEvent));
        var ce2 = await svc.CreateAsync(Req("Delta", null));

        irp1.CaseNumber.Should().Be("2026-01_Alpha");
        irp2.CaseNumber.Should().Be("2026-02_Gamma");        // IRP sequence unaffected by the CEs in between
        ce1.CaseNumber.Should().Be("CE-2026-08-08_Beta");    // clock is 2026-08-08; no sequence consumed
        ce2.CaseNumber.Should().Be("CE-2026-08-08_Delta");
    }

    [Fact]
    public async Task Promoting_a_complex_event_renumbers_it_into_the_irp_scheme()
    {
        Guid id;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            var ce = await svc.CreateAsync(Req("Odd Beaconing", null));
            ce.CaseNumber.Should().StartWith("CE-");
            id = ce.Id;

            await svc.ReclassifyAsync(id, Classification.AdverseEvent, "Confirmed adverse event");
        }

        await using (var db = NewContext())
        {
            var promoted = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id);
            promoted.CaseNumber.Should().Be("2026-01_Odd_Beaconing");
            promoted.Classification.Should().Be(Classification.AdverseEvent);
        }
    }

    [Fact]
    public async Task A_custom_number_is_honoured_and_duplicates_are_rejected()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var custom = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Special", Title = "Special case",
            Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, CaseNumber = "IR-2026-CUSTOM"
        });
        custom.CaseNumber.Should().Be("IR-2026-CUSTOM");
        custom.HasCustomNumber.Should().BeTrue();

        var dup = async () => await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Another", Title = "Another case",
            Classification = Classification.Incident, Severity = Severity.Low,
            Origin = CaseOrigin.InternalDetection, CaseNumber = "IR-2026-CUSTOM"
        });
        await dup.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task A_custom_number_does_not_consume_the_auto_sequence()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Special", Title = "Special", Classification = Classification.Incident,
            Severity = Severity.High, Origin = CaseOrigin.InternalDetection, CaseNumber = "WEIRD-1"
        });
        var auto = await svc.CreateAsync(Req("Normal", Classification.Incident));

        auto.CaseNumber.Should().Be("2026-01_Normal"); // the custom case didn't take sequence 01
    }

    [Fact]
    public async Task Renaming_a_case_number_enforces_uniqueness()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var a = await svc.CreateAsync(Req("Alpha", Classification.Incident));
        var b = await svc.CreateAsync(Req("Beta", Classification.Incident));

        // Collide with A's number → rejected.
        var clash = async () => await svc.RenumberAsync(b.Id, a.CaseNumber);
        await clash.Should().ThrowAsync<InvalidOperationException>();

        // A free number → applied and flagged custom.
        await svc.RenumberAsync(b.Id, "2026-99_Renamed");
        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == b.Id);
        reloaded.CaseNumber.Should().Be("2026-99_Renamed");
        reloaded.HasCustomNumber.Should().BeTrue();
    }

    [Fact]
    public async Task Two_auto_irp_cases_cannot_share_a_sequence()
    {
        await using var db = NewContext();

        db.Cases.Add(IncidentManager.Domain.Entities.Case.Open(2026, 1, "Alpha", "Alpha",
            Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "sys", _clock.UtcNow));
        await db.SaveChangesAsync();

        // A second IRP case forced onto the same (year, sequence) violates the partial unique index.
        db.Cases.Add(IncidentManager.Domain.Entities.Case.Open(2026, 1, "Beta", "Beta",
            Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "sys", _clock.UtcNow));

        var act = async () => await db.SaveChangesAsync();
        await act.Should().ThrowAsync<DbUpdateException>();
    }

    [Fact]
    public async Task A_promoted_complex_event_does_not_block_an_irp_case_on_the_same_sequence()
    {
        await using var db = NewContext();

        // A Complex Event carries a sequence value but no IRP number, so it never occupies the IRP index.
        db.Cases.Add(IncidentManager.Domain.Entities.Case.Open(2026, 1, "CE", "CE",
            classification: null, Severity.Medium, CaseOrigin.InternalDetection, "sys", _clock.UtcNow));
        db.Cases.Add(IncidentManager.Domain.Entities.Case.Open(2026, 1, "IRP", "IRP",
            Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "sys", _clock.UtcNow));

        var act = async () => await db.SaveChangesAsync();
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task A_second_same_day_complex_event_with_the_same_descriptor_gets_a_suffix()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var first = await svc.CreateAsync(Req("Odd Beaconing", null));
        var second = await svc.CreateAsync(Req("Odd Beaconing", null));

        first.CaseNumber.Should().Be("CE-2026-08-08_Odd_Beaconing");
        second.CaseNumber.Should().Be("CE-2026-08-08_Odd_Beaconing-2"); // disambiguated, not a reused number
    }

    public void Dispose() => _connection.Dispose();
}
