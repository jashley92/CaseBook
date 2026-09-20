using System.Globalization;
using System.Net;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Sla;
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
    private readonly IChatNotifier _chat;

    public CaseNotifications(IEmailSender email, IEmailComposer composer, IUserDirectory users,
        IConfiguration config, IOptionsMonitor<EmailOptions> options, IChatNotifier chat)
    {
        _email = email;
        _composer = composer;
        _users = users;
        _config = config;
        _options = options;
        _chat = chat;
    }

    private string BaseUrl => (_config["App:BaseUrl"] ?? "").TrimEnd('/');
    private string? CaseUrl(Guid id) => BaseUrl.Length == 0 ? null : $"{BaseUrl}/cases/{id}";
    private string? OverdueUrl() => BaseUrl.Length == 0 ? null : $"{BaseUrl}/cases?overdue=true&closed=true";
    private string? AgendaUrl() => BaseUrl.Length == 0 ? null : $"{BaseUrl}/work";
    private string? CasesUrl() => BaseUrl.Length == 0 ? null : $"{BaseUrl}/cases";

    // PROD-02: is a given notification type routed to the team chat channel? Requires both a configured
    // chat transport and the per-type in-app toggle (Notifications:Chat:*, layered from DB + appsettings).
    private bool ChatOn(string type) => _chat.Enabled && _config.GetValue<bool>($"Notifications:Chat:{type}");

    public async Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default)
    {
        if (to != Classification.Breach || from == Classification.Breach) return;

        // Chat broadcast (PROD-02): independent of the Legal email distribution — the SOC channel should
        // learn of a breach escalation even when no Legal recipients are configured.
        if (ChatOn("BreachEscalations"))
            await _chat.SendAsync(new ChatNotification(
                $"Breach escalation — {c.CaseNumber}",
                $"{c.Title} · severity {c.Severity}, phase {c.Phase}.",
                CaseUrl(c.Id), ChatUrgency.Alert), ct);

        var options = _options.CurrentValue;
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

    public async Task OnMentionedAsync(Case c, string byUserId, IReadOnlyCollection<string> mentionedUserIds,
        string commentExcerpt, CancellationToken ct = default)
    {
        // Distinct recipients, never the author.
        var recipients = mentionedUserIds
            .Where(id => !string.IsNullOrWhiteSpace(id) && !string.Equals(id, byUserId, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (recipients.Count == 0) return;

        var excerpt = commentExcerpt.Length > 280 ? commentExcerpt[..280] + "…" : commentExcerpt;
        var byName = _users.DisplayFor(byUserId);

        // Chat broadcast (PROD-02/04): one summary to the shared channel when enabled.
        if (ChatOn("Mentions"))
        {
            var who = string.Join(", ", recipients.Select(_users.DisplayFor));
            await _chat.SendAsync(new ChatNotification(
                $"Mention — {c.CaseNumber}",
                $"{byName} mentioned {who}: {excerpt}",
                CaseUrl(c.Id)), ct);
        }

        foreach (var id in recipients)
        {
            var to = _users.EmailFor(id);
            if (string.IsNullOrWhiteSpace(to)) continue;

            var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["MentionedBy"] = byName,
                ["Mentioned"] = _users.DisplayFor(id),
                ["CaseNumber"] = c.CaseNumber,
                ["CaseTitle"] = c.Title,
                ["Comment"] = excerpt,
                ["CaseUrl"] = CaseUrl(c.Id) ?? "",
            };

            var message = await _composer.ComposeAsync("mention", [to], tokens, CaseUrl(c.Id), null, ct);
            await _email.SendAsync(message, ct);
        }
    }

    public async Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName,
        CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default)
    {
        if (string.Equals(assigneeUserId, assignedByUserId, StringComparison.OrdinalIgnoreCase)) return; // self-assign — neither channel

        // Chat broadcast (PROD-02): posts to the shared channel independent of the per-assignee email
        // toggle and of whether the assignee has an address on file.
        if (ChatOn("Assignments"))
            await _chat.SendAsync(new ChatNotification(
                $"Case assigned — {c.CaseNumber}",
                $"{assigneeDisplayName} assigned as {Ui(role)} by {_users.DisplayFor(assignedByUserId)} · {c.Title}.",
                CaseUrl(c.Id)), ct);

        var options = _options.CurrentValue;
        if (!options.AssignmentNotifications) return;
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

        // Chat broadcast (PROD-02): one summary to the shared channel, in addition to the per-owner emails.
        if (ChatOn("OverdueReminders"))
        {
            var caseCount = items.Select(i => i.CaseId).Distinct().Count();
            await _chat.SendAsync(new ChatNotification(
                $"{items.Count} after-action item(s) overdue",
                $"Across {caseCount} case(s). Owners have been emailed where reachable.",
                OverdueUrl(), ChatUrgency.Alert), ct);
        }

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

        // Chat broadcast (PROD-02): one summary to the shared channel, in addition to the per-owner emails.
        if (ChatOn("DueSoonReminders"))
        {
            var caseCount = items.Select(i => i.CaseId).Distinct().Count();
            await _chat.SendAsync(new ChatNotification(
                $"{items.Count} after-action item(s) due within {leadHours}h",
                $"Across {caseCount} case(s). Owners have been emailed where reachable.",
                AgendaUrl()), ct);
        }

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

    public async Task OnDeadlineApproachingAsync(IReadOnlyList<DeadlineReminder> reminders, CancellationToken ct = default)
    {
        if (reminders.Count == 0) return;

        // Chat broadcast (PROD-02): one urgent summary to the shared channel, alongside the per-recipient emails.
        if (ChatOn("DeadlineReminders"))
        {
            var caseCount = reminders.Select(r => r.CaseId).Distinct().Count();
            var breached = reminders.Count(r => r.State == SlaState.Breached);
            var detail = breached > 0
                ? $"{breached} past deadline, {reminders.Count - breached} at risk, across {caseCount} case(s). IC/owners emailed where reachable."
                : $"{reminders.Count} case(s) approaching a deadline. IC/owners emailed where reachable.";
            await _chat.SendAsync(new ChatNotification(
                "Regulatory notification deadline", detail,
                CasesUrl(), ChatUrgency.Alert), ct);
        }

        // Group by recipient email, so a person on several at-risk cases gets one reminder listing them all.
        var byRecipient = new Dictionary<string, List<DeadlineReminder>>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in reminders)
        {
            foreach (var uid in r.RecipientUserIds)
            {
                var to = _users.EmailFor(uid);
                if (string.IsNullOrWhiteSpace(to)) continue;
                if (!byRecipient.TryGetValue(to, out var list)) byRecipient[to] = list = [];
                list.Add(r);
            }
        }

        foreach (var (to, list) in byRecipient)
        {
            // A recipient who is both IC and an assignee on the same case would otherwise see it twice.
            var ordered = list
                .DistinctBy(r => r.CaseId)
                .OrderBy(r => r.DueAtUtc ?? DateTimeOffset.MaxValue)
                .ThenBy(r => r.CaseNumber, StringComparer.OrdinalIgnoreCase)
                .ToList();

            // The CTA points at the one case when this recipient's list is a single case, else the case list.
            var cta = ordered.Count == 1 ? CaseUrl(ordered[0].CaseId) : CasesUrl();

            var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemCount"] = ordered.Count.ToString(CultureInfo.InvariantCulture),
                ["DeadlinesUrl"] = cta ?? "",
            };
            var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemsList"] = RenderDeadlineList(ordered),
            };

            var message = await _composer.ComposeAsync("notification-deadline", [to], tokens, cta, htmlTokens, ct);
            await _email.SendAsync(message, ct);
        }
    }

    public async Task OnCasesStaleAsync(IReadOnlyList<StaleCaseReminder> reminders, CancellationToken ct = default)
    {
        if (reminders.Count == 0) return;

        // Chat broadcast (PROD-02): one summary to the shared channel, alongside the per-recipient emails.
        if (ChatOn("StaleReminders"))
        {
            var caseCount = reminders.Select(r => r.CaseId).Distinct().Count();
            await _chat.SendAsync(new ChatNotification(
                $"{caseCount} case(s) with no recent activity",
                "Open cases have gone quiet past their severity threshold. IC/owners emailed where reachable.",
                CasesUrl()), ct);
        }

        // Group by recipient, so a person on several quiet cases gets one nudge listing them all.
        var byRecipient = new Dictionary<string, List<StaleCaseReminder>>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in reminders)
        {
            foreach (var uid in r.RecipientUserIds)
            {
                var to = _users.EmailFor(uid);
                if (string.IsNullOrWhiteSpace(to)) continue;
                if (!byRecipient.TryGetValue(to, out var list)) byRecipient[to] = list = [];
                list.Add(r);
            }
        }

        foreach (var (to, list) in byRecipient)
        {
            var ordered = list
                .DistinctBy(r => r.CaseId)                          // IC who is also an assignee → list once
                .OrderByDescending(r => r.DaysInactive)
                .ThenBy(r => r.CaseNumber, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var cta = ordered.Count == 1 ? CaseUrl(ordered[0].CaseId) : CasesUrl();

            var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemCount"] = ordered.Count.ToString(CultureInfo.InvariantCulture),
                ["StaleUrl"] = cta ?? "",
            };
            var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemsList"] = RenderStaleList(ordered),
            };

            var message = await _composer.ComposeAsync("stale-case", [to], tokens, cta, htmlTokens, ct);
            await _email.SendAsync(message, ct);
        }
    }

    public async Task OnDigestAsync(UserDigest digest, CancellationToken ct = default)
    {
        if (digest.TotalItems == 0) return;
        var to = _users.EmailFor(digest.UserId);
        if (string.IsNullOrWhiteSpace(to)) return; // no address on file → nothing to send

        var agendaUrl = AgendaUrl();
        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ItemCount"] = digest.TotalItems.ToString(CultureInfo.InvariantCulture),
            ["Cadence"] = digest.Cadence == DigestCadence.Weekly ? "weekly" : "daily",
            ["AgendaUrl"] = agendaUrl ?? "",
        };
        var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ItemsList"] = RenderDigest(digest),
        };

        var message = await _composer.ComposeAsync("digest", [to], tokens, agendaUrl, htmlTokens, ct);
        await _email.SendAsync(message, ct);
    }

    // Composer-rendered safe HTML: every user-supplied field is HTML-encoded here.
    private static string RenderDigest(UserDigest digest)
    {
        var sb = new System.Text.StringBuilder();
        Section(sb, "Overdue", digest.Overdue);
        Section(sb, "Due today", digest.DueToday);
        Section(sb, "Due this week", digest.DueThisWeek);
        return sb.ToString();

        static void Section(System.Text.StringBuilder sb, string heading, IReadOnlyList<DigestItem> items)
        {
            if (items.Count == 0) return;
            sb.Append("<p class=\"meta\"><strong>").Append(WebUtility.HtmlEncode(heading))
              .Append(" (").Append(items.Count).Append(")</strong></p><ul>");
            foreach (var i in items)
                sb.Append("<li>").Append(WebUtility.HtmlEncode(i.CaseNumber)).Append(" — ")
                  .Append(WebUtility.HtmlEncode(i.TaskTitle))
                  .Append(" (due ").Append(WebUtility.HtmlEncode(i.DueAtUtc.ToString("u"))).Append(")</li>");
            sb.Append("</ul>");
        }
    }

    // Composer-rendered safe HTML: every case-supplied field is HTML-encoded here.
    private static string RenderStaleList(IEnumerable<StaleCaseReminder> reminders)
    {
        var lis = reminders.Select(r =>
            $"<li>{WebUtility.HtmlEncode(r.CaseNumber)} — {WebUtility.HtmlEncode(r.CaseTitle)} " +
            $"({WebUtility.HtmlEncode(r.Severity.ToString())}: no activity for {r.DaysInactive} day(s))</li>");
        return "<ul>" + string.Join("", lis) + "</ul>";
    }

    // Composer-rendered safe HTML: every case-supplied field is HTML-encoded here.
    private static string RenderDeadlineList(IEnumerable<DeadlineReminder> reminders)
    {
        var lis = reminders.Select(r =>
        {
            var standing = r.State == SlaState.Breached ? "past deadline" : "at risk";
            var due = r.DueAtUtc is { } d ? $", due {d.ToString("u")}" : "";
            return $"<li>{WebUtility.HtmlEncode(r.CaseNumber)} — {WebUtility.HtmlEncode(r.CaseTitle)} " +
                   $"({WebUtility.HtmlEncode(r.JurisdictionLabel)}: {standing}{WebUtility.HtmlEncode(due)})</li>";
        });
        return "<ul>" + string.Join("", lis) + "</ul>";
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
