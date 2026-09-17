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

/// <summary>
/// FR-06: single-field edits (case details, impact assessment) use an expected-value optimistic-concurrency
/// check so two authors editing the same case during a live incident can't silently clobber each other. A
/// save whose baseline no longer matches the persisted fields is refused; a matching (or opted-out null)
/// baseline saves; and the check is scoped per editor, so an unrelated change never false-conflicts.
/// </summary>
public sealed class CaseConcurrencyTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseConcurrencyTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin];
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
        public Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(System.Collections.Generic.IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(System.Collections.Generic.IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
    }

    private async Task<Guid> NewCaseAsync(CaseService svc)
    {
        var created = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Concurrency",
            Title = "Concurrency case",
            Classification = Classification.Incident,
            Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });
        return created.Id;
    }

    private async Task<string> DetailsStampAsync(Guid id)
    {
        await using var db = NewContext();
        return (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).DetailsConcurrencyStamp();
    }

    private async Task<string> ImpactStampAsync(Guid id)
    {
        await using var db = NewContext();
        return (await db.Cases.AsNoTracking().Include(c => c.DataElements)
            .FirstAsync(c => c.Id == id)).ImpactConcurrencyStamp();
    }

    [Fact]
    public async Task A_stale_details_save_is_rejected_and_the_other_authors_value_survives()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);

        var authorA = await DetailsStampAsync(id); // A opens the editor

        // B edits and saves first, against the same baseline.
        await svc.UpdateDetailsAsync(id, "B's title", "B summary", null, null, null,
            _clock.UtcNow, null, expectedStamp: authorA);

        // A now saves against the stale baseline — refused.
        var act = async () => await svc.UpdateDetailsAsync(id, "A's title", "A summary", null, null, null,
            _clock.UtcNow, null, expectedStamp: authorA);

        await act.Should().ThrowAsync<StaleEditException>();

        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id);
        reloaded.Title.Should().Be("B's title"); // B's write was not clobbered
    }

    [Fact]
    public async Task A_stale_save_carries_the_current_stamp_so_a_deliberate_resave_succeeds()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var stale = await DetailsStampAsync(id);

        await svc.UpdateDetailsAsync(id, "B's title", null, null, null, null, _clock.UtcNow, null, expectedStamp: stale);

        var ex = await Assert.ThrowsAsync<StaleEditException>(() =>
            svc.UpdateDetailsAsync(id, "A's title", null, null, null, null, _clock.UtcNow, null, expectedStamp: stale));

        // Re-baseline to the current stamp the exception carries → the intentional overwrite goes through.
        await svc.UpdateDetailsAsync(id, "A's title", null, null, null, null, _clock.UtcNow, null, expectedStamp: ex.CurrentStamp);

        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id);
        reloaded.Title.Should().Be("A's title");
    }

    [Fact]
    public async Task A_matching_baseline_saves_and_a_null_baseline_opts_out_of_the_check()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);

        // Matching baseline → saves.
        await svc.UpdateDetailsAsync(id, "First", null, null, null, null, _clock.UtcNow, null,
            expectedStamp: await DetailsStampAsync(id));
        (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).Title.Should().Be("First");

        // Null baseline → legacy last-write-wins path (no check), still writes.
        await svc.UpdateDetailsAsync(id, "Second", null, null, null, null, _clock.UtcNow, null, expectedStamp: null);
        (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).Title.Should().Be("Second");
    }

    [Fact]
    public async Task An_unrelated_change_does_not_false_conflict_with_a_details_save()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var detailsBaseline = await DetailsStampAsync(id);

        // A concurrent, unrelated edit to the same row (severity) touches ModifiedAtUtc but not the details fields.
        await svc.ChangeSeverityAsync(id, Severity.High);

        // The details save still succeeds — the stamp is scoped to the details fields only.
        var act = async () => await svc.UpdateDetailsAsync(id, "Retitled", null, null, null, null,
            _clock.UtcNow, null, expectedStamp: detailsBaseline);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task A_stale_impact_assessment_save_is_rejected()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var baseline = await ImpactStampAsync(id);

        await svc.UpdateImpactAssessmentAsync(id, 500, new[] { "Name" }, "NY", expectedStamp: baseline);

        var act = async () => await svc.UpdateImpactAssessmentAsync(id, 999, new[] { "SSN" }, "NJ", expectedStamp: baseline);

        await act.Should().ThrowAsync<StaleEditException>();

        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id);
        reloaded.AffectedIndividualsCount.Should().Be(500); // first author's assessment survives
    }

    public void Dispose() => _connection.Dispose();
}
