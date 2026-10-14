using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-101: a breach-escalation or integrity-alarm email whose send fails is retried, and shown if it never goes.</summary>
public sealed class CriticalAlertOutboxTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 12, 9, 0, 0, TimeSpan.Zero));
    private readonly ServiceProvider _services;
    private readonly FlakySender _sender = new();
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };

    public CriticalAlertOutboxTests()
    {
        _connection.Open();
        _services = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite(_connection))
            .BuildServiceProvider();
        using var db = Factory().CreateAppDbContext();
        db.Database.EnsureCreated();
    }

    private TestDbContextFactory Factory() =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);

    private CriticalAlertOutbox Outbox() =>
        new(_sender, _services.GetRequiredService<IServiceScopeFactory>(), _clock, NullLogger<CriticalAlertOutbox>.Instance);

    private static EmailMessage Message() => new(["legal@insurer.example"], "Case escalated to Breach: 2026-04_Vendor", "<p>x</p>", "x");

    [Fact]
    public async Task A_failed_send_is_retried_and_goes_once_the_relay_is_back()
    {
        var outbox = Outbox();
        _sender.Failing = true;
        await outbox.SendAsync(AlertDelivery.BreachEscalation, Guid.NewGuid(), "2026-04_Vendor", Message());

        (await outbox.RetryDueAsync()).Should().Be(0, "the first retry isn't due yet");
        _sender.Attempts.Should().Be(1);

        _sender.Failing = false;
        _clock.UtcNow = _clock.UtcNow.AddMinutes(3);
        (await outbox.RetryDueAsync()).Should().Be(1);
        (await outbox.RetryDueAsync()).Should().Be(0, "a delivered email isn't sent again");
        _sender.Attempts.Should().Be(2);
    }

    [Fact]
    public async Task A_retry_pass_that_stops_part_way_keeps_what_it_delivered(/* BUG-159 */)
    {
        var outbox = Outbox();
        _sender.Failing = true;
        await outbox.SendAsync(AlertDelivery.BreachEscalation, Guid.NewGuid(), "2026-04_Vendor", Message());
        await outbox.SendAsync(AlertDelivery.IntegrityAlarm, null, null, Message());

        _sender.Failing = false;
        _sender.ThrowOnAttempt = 4;   // the pass delivers the first, then stops on the second
        _clock.UtcNow = _clock.UtcNow.AddMinutes(3);
        await outbox.Invoking(o => o.RetryDueAsync()).Should().ThrowAsync<OperationCanceledException>();

        using var db = Factory().CreateAppDbContext();
        (await db.AlertDeliveries.CountAsync(a => a.DeliveredAtUtc != null)).Should().Be(1, "the one that went isn't sent again");
    }

    [Fact]
    public async Task One_that_never_goes_is_shown_on_its_case_and_to_administrators_until_marked_handled()
    {
        var outbox = Outbox();
        _sender.Failing = true;
        var caseId = await SeedCaseAsync();
        await outbox.SendAsync(AlertDelivery.BreachEscalation, caseId, "2026-04_Vendor", Message());
        var service = new UndeliveredAlertService(Factory(), _user, _clock);

        foreach (var wait in AlertDelivery.RetryAfter)
        {
            (await service.ForCaseAsync(caseId)).Should().BeEmpty("it's still being retried");
            _clock.UtcNow = _clock.UtcNow.Add(wait);
            await outbox.RetryDueAsync();
        }

        _sender.Attempts.Should().Be(AlertDelivery.RetryAfter.Length + 1);
        var shown = (await service.ForCaseAsync(caseId)).Should().ContainSingle().Subject;
        shown.Recipients.Should().Equal("legal@insurer.example");
        (await service.ListAsync()).Should().ContainSingle();

        var analyst = new UndeliveredAlertService(Factory(), new TestCurrentUser { UserId = "a1", RoleSet = [AppRole.Analyst] }, _clock);
        (await analyst.ListAsync()).Should().BeEmpty("the banner is for administrators");
        await analyst.Invoking(s => s.DismissAsync(shown.Id)).Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();

        await service.DismissAsync(shown.Id);
        (await service.ForCaseAsync(caseId)).Should().BeEmpty();
        (await service.ListAsync()).Should().BeEmpty();
    }

    [Fact]
    public void Retries_after_a_hold_keep_their_spacing(/* BUG-291 */)
    {
        var t0 = _clock.UtcNow;
        var a = new AlertDelivery { FirstFailedAtUtc = t0 };
        a.Failed(t0);
        a.NextAttemptAtUtc.Should().Be(t0 + AlertDelivery.RetryAfter[0]);

        // Email was off for three hours (WF-92 holds the alert); the first retry fails, and the next isn't due a minute later.
        var back = t0.AddHours(3);
        a.Retries = 1;
        a.Failed(back);
        a.NextAttemptAtUtc.Should().Be(back + (AlertDelivery.RetryAfter[1] - AlertDelivery.RetryAfter[0]));
        a.GaveUpAtUtc.Should().BeNull();
    }

    private async Task<Guid> SeedCaseAsync()
    {
        await using var db = Factory().CreateAppDbContext();
        var c = Case.Open(2026, 4, "Vendor", "Vendor breach", Classification.Breach, Severity.High, CaseOrigin.ThirdParty, "ic1", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    /// <summary>An email sender that fails like the real one does: it never throws, and reports the failure to a watch.</summary>
    private sealed class FlakySender : IEmailSender
    {
        public bool Failing { get; set; }
        public int Attempts { get; private set; }
        public int? ThrowOnAttempt { get; set; }

        public Task SendAsync(EmailMessage message, CancellationToken ct = default)
        {
            Attempts++;
            if (Attempts == ThrowOnAttempt) throw new OperationCanceledException("the app is shutting down");
            if (Failing) DeliveryWatch.ReportFailure();
            return Task.CompletedTask;
        }

        public Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default) =>
            SendAsync(new EmailMessage(to, subject, body, body), ct);
    }

    public void Dispose()
    {
        _services.Dispose();
        _connection.Dispose();
    }
}
