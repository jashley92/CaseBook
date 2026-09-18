using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Integrity;
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
/// End-to-end proof that the audit trail says <em>what</em> changed, not just that "something" did: a case
/// mutation is written through the real <see cref="AuditChainInterceptor"/>, then the resulting audit entry
/// is read back and its enriched summary + parsed field diff are asserted. Covers the "setting a legal hold
/// only logged 'update case'" gap.
/// </summary>
public sealed class AuditChangeVerbosityTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };

    public AuditChangeVerbosityTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
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

    [Fact]
    public async Task Placing_a_legal_hold_records_what_changed()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Hold", Title = "Hold case",
            Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });

        await svc.SetLegalHoldAsync(c.Id, held: true);

        // The audit line for the hold: the most recent in-place update to the Case row.
        await using var read = NewContext();
        var entry = await read.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == "Case" && a.Action == AuditAction.Update)
            .OrderByDescending(a => a.Sequence)
            .FirstAsync();

        // (3) The stored summary now names the field, instead of a bare "Update Case".
        entry.Summary.Should().Be("Update Case — Legal hold");

        // (1) The captured before/after parses into a readable field diff.
        var changes = AuditChangeDetail.Changes(entry);
        changes.Should().ContainSingle();
        changes[0].Should().Be(new AuditChangeDetail.FieldChange("Legal hold", "No", "Yes"));
    }

    [Fact]
    public async Task A_pure_touch_is_not_audited_as_a_case_update()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Touch", Title = "Touch case",
            Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });

        // Assigning adds a CaseAssignment and only "touches" the case (bumps ModifiedAtUtc/ModifiedBy).
        await svc.AssignAsync(c.Id, "analyst-2", "Second Analyst", CaseAssignmentRole.Analyst);

        await using var read = NewContext();

        // The substantive action is audited...
        (await read.AuditLog.AsNoTracking()
            .AnyAsync(a => a.EntityType == "CaseAssignment" && a.Action == AuditAction.Create))
            .Should().BeTrue();

        // ...but the parent-case touch it triggered is not logged as a no-op "Update Case".
        (await read.AuditLog.AsNoTracking()
            .CountAsync(a => a.EntityType == "Case" && a.Action == AuditAction.Update))
            .Should().Be(0);
    }

    [Fact]
    public async Task Referring_to_legal_shows_the_change_on_the_case_line()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Referral", Title = "Referral case",
            Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });

        // A referral changes an owned value object (LegalReferral), which shares the case row.
        await svc.ReferToLegalAsync(c.Id, "General Counsel", "NY NPI involved");

        await using var read = NewContext();
        var entry = await read.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == "Case" && a.Action == AuditAction.Update)
            .OrderByDescending(a => a.Sequence)
            .FirstAsync();

        // The owned-VO change is folded into the case entry's diff (previously this was an empty "Update Case").
        entry.Summary.Should().Be("Update Case — Legal referral");
        AuditChangeDetail.Changes(entry).Should()
            .Contain(x => x.Label == "Referred to Legal" && x.Before == "No" && x.After == "Yes");
    }

    public void Dispose() => _connection.Dispose();
}
