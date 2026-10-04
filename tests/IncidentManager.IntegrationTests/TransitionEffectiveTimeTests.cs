using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>INV-05: a transition recorded after the fact keeps both times and dates the milestones by when it happened.</summary>
public sealed class TransitionEffectiveTimeTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 16, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public TransitionEffectiveTimeTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin];
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    private CaseService NewService()
    {
        var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
        return new(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
    }

    private static CreateCaseRequest Req() => new()
    {
        DescriptiveName = "Phish",
        Title = "Credential phishing",
        Classification = Classification.AdverseEvent,
        Severity = Severity.Medium,
        Origin = CaseOrigin.InternalDetection
    };

    [Fact]
    public async Task A_phase_change_recorded_later_is_dated_when_it_happened()
    {
        var svc = NewService();
        var created = await svc.CreateAsync(Req());
        var detected = _clock.UtcNow;
        _clock.UtcNow = detected.AddHours(6);
        var happened = detected.AddHours(2);

        await svc.ChangePhaseAsync(created.Id, CasePhase.Containment, "Sessions revoked for all three users",
            effectiveAtUtc: happened);

        var c = (await svc.GetDetailAsync(created.Id))!;
        c.ContainedAtUtc.Should().Be(happened);
        var change = c.StatusChanges.Single(x => x.To == CasePhase.Containment);
        change.EffectiveAtUtc.Should().Be(happened);
        change.ChangedAtUtc.Should().Be(detected.AddHours(6));   // the recorded time never moves
    }

    [Fact]
    public async Task Recording_more_than_an_hour_late_needs_a_reason()
    {
        var svc = NewService();
        var created = await svc.CreateAsync(Req());
        _clock.UtcNow = _clock.UtcNow.AddHours(6);

        var act = () => svc.ChangeSeverityAsync(created.Id, Severity.High, null, _clock.UtcNow.AddHours(-3));

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*reason*");
    }

    [Fact]
    public async Task Raising_severity_needs_a_reason_and_lowering_it_does_not()
    {
        // HR-11
        var svc = NewService();
        var created = await svc.CreateAsync(Req());
        var start = (await svc.GetDetailAsync(created.Id))!.Severity;

        var up = () => svc.ChangeSeverityAsync(created.Id, start + 1, "  ");
        await up.Should().ThrowAsync<ArgumentException>().WithMessage(CaseService.SeverityRaiseNeedsReason);

        await svc.ChangeSeverityAsync(created.Id, start + 1, "Second mailbox confirmed");
        await svc.ChangeSeverityAsync(created.Id, start);
        var c = (await svc.GetDetailAsync(created.Id))!;
        c.Severity.Should().Be(start);
    }

    [Fact]
    public async Task A_reclassification_can_be_dated_before_the_case_was_filed_but_not_before_detection()
    {
        var svc = NewService();
        var created = await svc.CreateAsync(Req());
        var c0 = (await svc.GetDetailAsync(created.Id))!;
        // The case was filed after detection: detection was 4h before the case was opened in CaseBook.
        await svc.UpdateDetailsAsync(created.Id, c0.Title, c0.Summary, null, null, null,
            _clock.UtcNow.AddHours(-4), null);
        _clock.UtcNow = _clock.UtcNow.AddHours(1);

        await svc.ReclassifyAsync(created.Id, Classification.Incident, "Agreed on the containment call",
            effectiveAtUtc: _clock.UtcNow.AddHours(-3));
        var early = () => svc.ReclassifyAsync(created.Id, Classification.Breach, "NPI confirmed",
            effectiveAtUtc: _clock.UtcNow.AddHours(-10));

        (await svc.GetDetailAsync(created.Id))!.ClassificationChanges
            .Single(x => x.To == Classification.Incident).EffectiveAt.Should().Be(_clock.UtcNow.AddHours(-3));
        await early.Should().ThrowAsync<ArgumentException>().WithMessage("*before the case was detected*");
    }

    [Fact]
    public async Task A_correction_is_saved_with_its_reason_and_moves_contained()
    {
        var svc = NewService();
        var created = await svc.CreateAsync(Req());
        var detected = _clock.UtcNow;
        _clock.UtcNow = detected.AddHours(6);
        await svc.ChangePhaseAsync(created.Id, CasePhase.Containment, "Isolated");
        var changeId = (await svc.GetDetailAsync(created.Id))!.StatusChanges.Single(x => x.To == CasePhase.Containment).Id;
        _clock.UtcNow = detected.AddHours(8);

        await svc.CorrectTransitionTimeAsync(created.Id, TransitionKind.Phase, changeId, detected.AddHours(2), "Isolated on the call; entered later");

        var c = (await svc.GetDetailAsync(created.Id))!;
        c.ContainedAtUtc.Should().Be(detected.AddHours(2));
        c.TimeCorrections.Should().ContainSingle().Which.Reason.Should().Be("Isolated on the call; entered later");
        await using var db = new AppDbContext(Options());
        (await db.AuditLog.AnyAsync(a => a.Reason == "Isolated on the call; entered later")).Should().BeTrue();
    }

    [Fact]
    public async Task Correcting_a_classification_change_needs_the_classification_permission()
    {
        var svc = NewService();
        var created = await svc.CreateAsync(Req());
        _clock.UtcNow = _clock.UtcNow.AddHours(2);
        await svc.ReclassifyAsync(created.Id, Classification.Incident, "Confirmed");
        var changeId = (await svc.GetDetailAsync(created.Id))!.ClassificationChanges.Single(x => x.To == Classification.Incident).Id;
        // A custom role that may edit cases but not change their classification.
        _user.PermissionSet = [Permission.ViewCases, Permission.EditCases];

        var act = () => svc.CorrectTransitionTimeAsync(created.Id, TransitionKind.Classification, changeId, _clock.UtcNow.AddHours(-1), "x");

        await act.Should().ThrowAsync<ForbiddenException>();
    }

    public void Dispose() => _connection.Dispose();
}
