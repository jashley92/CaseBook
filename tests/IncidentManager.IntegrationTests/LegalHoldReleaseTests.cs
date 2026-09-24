using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
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

/// <summary>F-12: optional two-person control for releasing a legal hold.</summary>
public sealed class LegalHoldReleaseTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "legal1", RoleSet = [AppRole.LegalPrivacy, AppRole.IncidentCommander] };
    private readonly TestOptionsMonitor<LegalHoldOptions> _options = new(new LegalHoldOptions { RequireSecondApprover = true });

    public LegalHoldReleaseTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;

    private CaseService Service(AppDbContext db) =>
        new(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            siem: null, legalHold: _options);

    private sealed class NoOpNotifications : ICaseNotifications
    {
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole r, string d, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
    }

    private async Task<(AppDbContext Db, CaseService Svc, Guid Id)> HeldCaseAsync()
    {
        var db = new AppDbContext(Options());
        await db.Database.EnsureCreatedAsync();
        var c = Case.Open(2026, 1, "Held", "Case under hold", Classification.Breach, Severity.High,
            CaseOrigin.InternalDetection, "legal1", _clock.UtcNow);
        c.PlaceLegalHold("legal1", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return (db, Service(db), c.Id);
    }

    private async Task<Case> Reload(Guid id)
    {
        await using var db = new AppDbContext(Options());
        return await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id);
    }

    [Fact]
    public async Task With_the_setting_on_a_release_needs_a_request_and_a_different_approver()
    {
        var (db, svc, id) = await HeldCaseAsync();
        await using var _ = db;

        await svc.Invoking(s => s.SetLegalHoldAsync(id, false)).Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*second approver*");

        await svc.RequestLegalHoldReleaseAsync(id, "Litigation settled");
        (await Reload(id)).Should().Match<Case>(c => c.LegalHold && c.LegalHoldReleaseRequestedBy == "legal1"
            && c.LegalHoldReleaseReason == "Litigation settled");

        // The requester can't approve their own request.
        await svc.Invoking(s => s.ApproveLegalHoldReleaseAsync(id)).Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("Two-person control*");

        _user.UserId = "legal2";
        await svc.ApproveLegalHoldReleaseAsync(id);
        var released = await Reload(id);
        released.LegalHold.Should().BeFalse();
        released.LegalHoldReleasePending.Should().BeFalse();

        // Every step is in the tamper-evident audit trail, and the chain still verifies.
        var audit = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        audit.Count(a => a.EntityType == nameof(Case) && a.Action == AuditAction.Update).Should().BeGreaterThanOrEqualTo(2);
        _hasher.VerifyChain(audit).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task A_request_can_be_withdrawn_and_the_hold_stays()
    {
        var (db, svc, id) = await HeldCaseAsync();
        await using var _ = db;

        await svc.RequestLegalHoldReleaseAsync(id, "No longer needed");
        await svc.CancelLegalHoldReleaseAsync(id);

        var c = await Reload(id);
        c.LegalHold.Should().BeTrue();
        c.LegalHoldReleasePending.Should().BeFalse();
        await svc.Invoking(s => s.RequestLegalHoldReleaseAsync(id, " ")).Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task With_the_setting_off_one_person_releases_as_before()
    {
        _options.CurrentValue = new LegalHoldOptions { RequireSecondApprover = false };
        var (db, svc, id) = await HeldCaseAsync();
        await using var _ = db;

        await svc.SetLegalHoldAsync(id, false);

        (await Reload(id)).LegalHold.Should().BeFalse();
    }

    [Fact]
    public async Task Only_Manage_Legal_may_request_or_approve()
    {
        var (db, svc, id) = await HeldCaseAsync();
        await using var _ = db;
        _user.RoleSet = [AppRole.Analyst];

        await svc.Invoking(s => s.RequestLegalHoldReleaseAsync(id, "why"))
            .Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
        await svc.Invoking(s => s.ApproveLegalHoldReleaseAsync(id))
            .Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
    }

    public void Dispose() => _connection.Dispose();
}
