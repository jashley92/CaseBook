using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// Composes and dispatches case-lifecycle notifications: alerting Legal/Privacy on a Breach escalation
/// (E-03), the assignee on a case assignment, and item owners on overdue after-action items (E-03b).
/// Recipient resolution uses the <see cref="IUserDirectory"/> mirror. Never throws into the caller — a
/// notification failure must not fail the action (or background scan) that triggered it.
/// </summary>
public sealed class CaseNotifications : ICaseNotifications
{
    private readonly IEmailSender _email;
    private readonly IUserDirectory _users;
    private readonly IOptionsMonitor<EmailOptions> _options;

    public CaseNotifications(IEmailSender email, IUserDirectory users, IOptionsMonitor<EmailOptions> options)
    {
        _email = email;
        _users = users;
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
            "Review in CaseBook for regulatory-relevance assessment (NYDFS Part 500 / GLBA).";

        await _email.SendAsync(options.LegalDistribution, subject, body, ct);
    }

    public async Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName,
        CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default)
    {
        var options = _options.CurrentValue;
        if (!options.AssignmentNotifications) return;
        // Don't email someone for assigning themselves — they already know.
        if (string.Equals(assigneeUserId, assignedByUserId, StringComparison.OrdinalIgnoreCase)) return;

        var to = _users.EmailFor(assigneeUserId);
        if (string.IsNullOrWhiteSpace(to)) return;   // no address on file — nothing to send

        var assignedBy = _users.DisplayFor(assignedByUserId);
        var subject = $"[CaseBook] You've been assigned to {c.CaseNumber} ({Ui(role)})";
        var body =
            $"{assigneeDisplayName},\n\n" +
            $"You have been assigned to case {c.CaseNumber} — {c.Title} — as {Ui(role)} by {assignedBy}.\n" +
            $"Severity: {c.Severity}. Phase: {c.Phase}.\n\n" +
            "Open it in CaseBook to review.";

        await _email.SendAsync([to], subject, body, ct);
    }

    public async Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default)
    {
        if (items.Count == 0) return;

        // Resolve a recipient per item (its owner, else the case's incident commander) and group so each
        // person gets one reminder listing all of their newly-overdue items.
        var byRecipient = new Dictionary<string, List<OverdueActionItem>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items)
        {
            var to = ResolveRecipient(item);
            if (string.IsNullOrWhiteSpace(to)) continue;   // can't reach anyone for this item — skip it
            if (!byRecipient.TryGetValue(to, out var list))
                byRecipient[to] = list = [];
            list.Add(item);
        }

        foreach (var (to, list) in byRecipient)
        {
            var lines = list
                .OrderBy(i => i.DueAtUtc)
                .Select(i => $"  • {i.CaseNumber} — {i.Title} (due {i.DueAtUtc:u})");
            var subject = list.Count == 1
                ? $"[CaseBook] Overdue after-action item: {list[0].CaseNumber}"
                : $"[CaseBook] {list.Count} overdue after-action items";
            var body =
                "The following after-action follow-up item(s) are past their due date:\n\n" +
                string.Join('\n', lines) +
                "\n\nOpen the case(s) in CaseBook to update or close them.";

            await _email.SendAsync([to], subject, body, ct);
        }
    }

    // Owner is a directory user id (the after-action picker stores an id); resolve to an address, or fall
    // back to the case's incident commander so an unowned/unresolvable item still reaches someone.
    private string? ResolveRecipient(OverdueActionItem item)
    {
        var ownerEmail = string.IsNullOrWhiteSpace(item.OwnerUserId) ? null : _users.EmailFor(item.OwnerUserId);
        if (!string.IsNullOrWhiteSpace(ownerEmail)) return ownerEmail;
        return string.IsNullOrWhiteSpace(item.IncidentCommanderUserId)
            ? null
            : _users.EmailFor(item.IncidentCommanderUserId);
    }

    private static string Ui(CaseAssignmentRole role) => role switch
    {
        CaseAssignmentRole.IncidentCommander => "Incident Commander",
        _ => role.ToString(),
    };
}