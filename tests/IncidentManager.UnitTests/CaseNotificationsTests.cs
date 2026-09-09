using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Notifications;
using Xunit;

namespace IncidentManager.UnitTests;

public class CaseNotificationsTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 12, 0, 0, TimeSpan.Zero);

    private static Case NewCase() => Case.Open(
        2026, 1, "Vendor Breach", "Vendor data breach",
        Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", Now);

    private sealed class CapturingEmailSender : IEmailSender
    {
        public List<(IReadOnlyCollection<string> To, string Subject)> Sent { get; } = new();
        public Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default)
        {
            Sent.Add((to, subject));
            return Task.CompletedTask;
        }
    }

    private static CaseNotifications Build(CapturingEmailSender sender, params string[] distribution) =>
        new(sender, new TestOptionsMonitor<EmailOptions>(new EmailOptions { LegalDistribution = distribution }));

    [Fact]
    public async Task Escalating_to_breach_emails_the_legal_distribution()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, "legal@insurer.example");

        await notifications.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().Contain("legal@insurer.example");
        sender.Sent[0].Subject.Should().Contain("Breach");
    }

    [Fact]
    public async Task A_non_breach_reclassification_sends_nothing()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, "legal@insurer.example");

        await notifications.OnReclassifiedAsync(NewCase(), Classification.AdverseEvent, Classification.Incident);

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task No_email_when_the_distribution_is_empty()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender); // no recipients configured

        await notifications.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task An_administered_distribution_change_takes_effect_at_runtime()
    {
        var sender = new CapturingEmailSender();
        var monitor = new TestOptionsMonitor<EmailOptions>(
            new EmailOptions { LegalDistribution = ["old@insurer.example"] });
        var notifications = new CaseNotifications(sender, monitor);

        // Admin edits the Legal distribution after the service is already constructed.
        monitor.CurrentValue = new EmailOptions { LegalDistribution = ["new@insurer.example"] };

        await notifications.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().Contain("new@insurer.example").And.NotContain("old@insurer.example");
    }
}
