using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// Composes and dispatches case-lifecycle notifications. Today it alerts the configured Legal/Privacy
/// distribution when a case is escalated to a Breach — the moment regulatory relevance must be assessed.
/// </summary>
public sealed class CaseNotifications : ICaseNotifications
{
    private readonly IEmailSender _email;
    private readonly IOptionsMonitor<EmailOptions> _options;

    public CaseNotifications(IEmailSender email, IOptionsMonitor<EmailOptions> options)
    {
        _email = email;
        _options = options;
    }

    public async Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default)
    {
        // Only on a genuine escalation into Breach, and only if a distribution is configured.
        // Read the current value so an administered change to the distribution takes effect at runtime.
        var options = _options.CurrentValue;
        if (to != Classification.Breach || from == Classification.Breach) return;
        if (options.LegalDistribution.Length == 0) return;

        var subject = $"[CaseBook] Case escalated to Breach: {c.CaseNumber}";
        var body =
            $"Case {c.CaseNumber} — {c.Title} — has been classified as a Breach.\n" +
            $"Severity: {c.Severity}. Phase: {c.Phase}.\n" +
            (c.LegalReferral.IsReferred ? "A Legal/Privacy referral is already recorded.\n" : "") +
            "Review in IncidentManager for regulatory-relevance assessment (NYDFS Part 500 / GLBA).";

        await _email.SendAsync(options.LegalDistribution, subject, body, ct);
    }
}
