using System.Globalization;
using System.Net;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// Composes and dispatches case-lifecycle notifications as branded HTML (E-03b): alerting Legal/Privacy on
/// a Breach escalation (E-03), the assignee on a case assignment, and item owners on overdue after-action
/// items. Bodies are rendered from admin-editable templates via <see cref="IEmailComposer"/>; recipients are
/// resolved through the <see cref="IUserDirectory"/> mirror. Never throws into the caller — a notification
/// failure must not fail the action (or background scan) that triggered it.
/// </summary>
public sealed class CaseNotifications : ICaseNotifications
{
    private readonly IEmailSender _email;
    private readonly IEmailComposer _composer;
    private readonly IUserDirectory _users;
    private readonly IConfiguration _config;
    private readonly IOptionsMonitor<EmailOptions> _options;

    public CaseNotifications(IEmailSender email, IEmailComposer composer, IUserDirectory users,
        IConfiguration config, IOptionsMonitor<EmailOptions> options)
    {
        _email = email;
        _composer = composer;
        _users = users;
        _config = config;
        _options = options;
    }

    private string BaseUrl => (_config["App:BaseUrl"] ?? "").TrimEnd('/');
    private string? CaseUrl(Guid id) => BaseUrl.Length == 0 ? null : $"{BaseUrl}/cases/{id}";
    private string? OverdueUrl() => BaseUrl.Length == 0 ? null : $"{BaseUrl}/cases?overdue=true&closed=true";
    private string? AgendaUrl() => BaseUrl.Length == 0 ? null : $"{BaseUrl}/work";

    public async Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default)
    {
        var options = _options.CurrentValue;
        if (to != Classification.Breach || from == Classification.Breach) return;
        if (options.LegalDistribution.Length == 0) return;

        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["CaseNumber"] = c.CaseNumber,
            ["CaseTitle"] = c.Title,
            ["Severity"] = c.Severity.ToString(),
            ["Phase"] = c.Phase.ToString(),
            ["CaseUrl"] = CaseUrl(c.Id) ?? "",
        };
        var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ReferralNote"] = c.LegalReferral.IsReferred
                ? "<p>A Legal/Privacy referral is already recorded.</p>" : "",
        };

        var message = await _composer.ComposeAsync("breach", options.LegalDistribution, tokens, CaseUrl(c.Id), htmlTokens, ct);
        await _email.SendAsync(message, ct);
    }

    public async Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName,
        CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default)
    {
        var options = _options.CurrentValue;
        if (!options.AssignmentNotifications) return;
        if (string.Equals(assigneeUserId, assignedByUserId, StringComparison.OrdinalIgnoreCase)) return; // self-assign
        var to = _users.EmailFor(assigneeUserId);
        if (string.IsNullOrWhiteSpace(to)) return;

        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Assignee"] = assigneeDisplayName,
            ["Role"] = Ui(role),
            ["AssignedBy"] = _users.DisplayFor(assignedByUserId),
            ["CaseNumber"] = c.CaseNumber,
            ["CaseTitle"] = c.Title,
            ["Severity"] = c.Severity.ToString(),
            ["Phase"] = c.Phase.ToString(),
            ["CaseUrl"] = CaseUrl(c.Id) ?? "",
        };

        var message = await _composer.ComposeAsync("assignment", [to], tokens, CaseUrl(c.Id), null, ct);
        await _email.SendAsync(message, ct);
    }

    public async Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default)
    {
        if (items.Count == 0) return;

        var byRecipient = new Dictionary<string, List<OverdueActionItem>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items)
        {
            var to = ResolveRecipient(item);
            if (string.IsNullOrWhiteSpace(to)) continue;
            if (!byRecipient.TryGetValue(to, out var list)) byRecipient[to] = list = [];
            list.Add(item);
        }

        var overdueUrl = OverdueUrl();
        foreach (var (to, list) in byRecipient)
        {
            var ordered = list.OrderBy(i => i.DueAtUtc).ToList();
            var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemCount"] = ordered.Count.ToString(CultureInfo.InvariantCulture),
                ["OverdueUrl"] = overdueUrl ?? "",
            };
            var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemsList"] = RenderItemList(ordered),
            };

            var message = await _composer.ComposeAsync("overdue", [to], tokens, overdueUrl, htmlTokens, ct);
            await _email.SendAsync(message, ct);
        }
    }

    public async Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default)
    {
        if (items.Count == 0) return;

        var byRecipient = new Dictionary<string, List<DueSoonActionItem>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items)
        {
            var to = ResolveRecipient(item.OwnerUserId, item.IncidentCommanderUserId);
            if (string.IsNullOrWhiteSpace(to)) continue;
            if (!byRecipient.TryGetValue(to, out var list)) byRecipient[to] = list = [];
            list.Add(item);
        }

        var agendaUrl = AgendaUrl();
        foreach (var (to, list) in byRecipient)
        {
            var ordered = list.OrderBy(i => i.DueAtUtc).ToList();
            var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemCount"] = ordered.Count.ToString(CultureInfo.InvariantCulture),
                ["LeadHours"] = leadHours.ToString(CultureInfo.InvariantCulture),
                ["AgendaUrl"] = agendaUrl ?? "",
            };
            var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemsList"] = RenderItemList(ordered.Select(i => (i.CaseNumber, i.Title, i.DueAtUtc))),
            };

            var message = await _composer.ComposeAsync("action-item-due-soon", [to], tokens, agendaUrl, htmlTokens, ct);
            await _email.SendAsync(message, ct);
        }
    }

    // Composer-rendered safe HTML: every case-supplied field is HTML-encoded here.
    private static string RenderItemList(IReadOnlyList<OverdueActionItem> items) =>
        RenderItemList(items.Select(i => (i.CaseNumber, i.Title, i.DueAtUtc)));

    private static string RenderItemList(IEnumerable<(string CaseNumber, string Title, DateTimeOffset DueAtUtc)> items)
    {
        var lis = items.Select(i =>
            $"<li>{WebUtility.HtmlEncode(i.CaseNumber)} — {WebUtility.HtmlEncode(i.Title)} " +
            $"(due {WebUtility.HtmlEncode(i.DueAtUtc.ToString("u"))})</li>");
        return "<ul>" + string.Join("", lis) + "</ul>";
    }

    private string? ResolveRecipient(OverdueActionItem item) =>
        ResolveRecipient(item.OwnerUserId, item.IncidentCommanderUserId);

    private string? ResolveRecipient(string? ownerUserId, string? incidentCommanderUserId)
    {
        var ownerEmail = string.IsNullOrWhiteSpace(ownerUserId) ? null : _users.EmailFor(ownerUserId);
        if (!string.IsNullOrWhiteSpace(ownerEmail)) return ownerEmail;
        return string.IsNullOrWhiteSpace(incidentCommanderUserId)
            ? null
            : _users.EmailFor(incidentCommanderUserId);
    }

    private static string Ui(CaseAssignmentRole role) => role switch
    {
        CaseAssignmentRole.IncidentCommander => "Incident Commander",
        _ => role.ToString(),
    };
}
