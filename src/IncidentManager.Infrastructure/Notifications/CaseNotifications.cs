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
    private readonly INotificationPreferenceProvider _prefs;

    public CaseNotifications(IEmailSender email, IEmailComposer composer, IUserDirectory users,
        IConfiguration config, IOptionsMonitor<EmailOptions> options, IChatNotifier chat,
        INotificationPreferenceProvider prefs)
    {
        _email = email;
        _composer = composer;
        _users = users;
        _config = config;
        _options = options;
        _chat = chat;
        _prefs = prefs;
    }

    // PROD-16: has this user opted out of a personal notification type — unless the org marks it mandatory?
    // Applies to the per-user EMAIL path only (never the compliance breach→Legal distribution, never chat).
    private bool Mandatory(string type) => _config.GetValue<bool>($"Notifications:Mandatory:{type}");

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
        // PROD-16: honour the assignee's opt-out unless the org marks assignment notifications mandatory.
        if (!Mandatory("Assignment") && (await _prefs.GetAsync(assigneeUserId, ct)).Assignment) return;
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

        // Group by recipient user (owner, else the case's incident commander), so opt-outs and address
        // resolution are per person (PROD-16).
        var byRecipient = new Dictionary<string, List<OverdueActionItem>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items)
        {
            var uid = ResolveRecipientUserId(item.OwnerUserId, item.IncidentCommanderUserId);
            if (uid is null) continue;
            if (!byRecipient.TryGetValue(uid, out var list)) byRecipient[uid] = list = [];
            list.Add(item);
        }

        var overdueUrl = OverdueUrl();
        var overdueMandatory = Mandatory("Overdue");
        foreach (var (uid, list) in byRecipient)
        {
            if (!overdueMandatory && (await _prefs.GetAsync(uid, ct)).Overdue) continue; // opted out / on digest
            var to = _users.EmailFor(uid);
            if (string.IsNullOrWhiteSpace(to)) continue;
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

    public async Task OnActionItemsEscalatedAsync(IReadOnlyList<EscalatedActionItem> items, CancellationToken ct = default)
    {
        if (items.Count == 0) return;

        if (ChatOn("OverdueReminders"))
        {
            var caseCount = items.Select(i => i.Item.CaseId).Distinct().Count();
            await _chat.SendAsync(new ChatNotification(
                $"{items.Count} overdue after-action escalation(s)",
                $"Across {caseCount} case(s). Incident commanders / managers have been emailed where reachable.",
                OverdueUrl(), ChatUrgency.Alert), ct);
        }

        // Managers = everyone the directory holds with the Manager role (a sign-in snapshot of AD groups).
        var managers = _users.All()
            .Where(u => u.RolesCsv.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Contains(nameof(AppRole.Manager), StringComparer.OrdinalIgnoreCase))
            .Select(u => u.UserId)
            .ToList();

        // (recipient, audience) → items. The IC step skips an IC who was already the first reminder's recipient.
        var byRecipient = new Dictionary<(string Uid, string Audience), List<EscalatedActionItem>>();
        void Add(string uid, string audience, EscalatedActionItem e)
        {
            if (!byRecipient.TryGetValue((uid, audience), out var list)) byRecipient[(uid, audience)] = list = [];
            list.Add(e);
        }
        foreach (var e in items)
        {
            if (e.Tier == OverdueEscalationTier.IncidentCommander)
            {
                var ic = e.Item.IncidentCommanderUserId;
                var first = ResolveRecipientUserId(e.Item.OwnerUserId, ic);
                if (!string.IsNullOrWhiteSpace(ic) && !string.Equals(ic, first, StringComparison.OrdinalIgnoreCase))
                    Add(ic, "the incident commander", e);
            }
            else
            {
                foreach (var m in managers) Add(m, "a manager", e);
            }
        }

        var overdueUrl = OverdueUrl();
        var mandatory = Mandatory("Overdue");
        foreach (var ((uid, audience), list) in byRecipient)
        {
            if (!mandatory && (await _prefs.GetAsync(uid, ct)).Overdue) continue; // same opt-out as overdue reminders
            var to = _users.EmailFor(uid);
            if (string.IsNullOrWhiteSpace(to)) continue;
            var ordered = list.OrderBy(i => i.Item.DueAtUtc).ToList();
            var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemCount"] = ordered.Count.ToString(CultureInfo.InvariantCulture),
                ["Audience"] = audience,
                ["OverdueUrl"] = overdueUrl ?? "",
            };
            var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemsList"] = "<ul>" + string.Join("", ordered.Select(i =>
                    $"<li>{WebUtility.HtmlEncode(i.Item.CaseNumber)} — {WebUtility.HtmlEncode(i.Item.Title)} " +
                    $"(owner {WebUtility.HtmlEncode(_users.DisplayFor(i.Item.OwnerUserId ?? i.Item.IncidentCommanderUserId))}; " +
                    $"due {WebUtility.HtmlEncode(i.Item.DueAtUtc.ToString("u"))}, {OverdueSpan(i.HoursOverdue)} overdue)</li>")) + "</ul>",
            };
            var message = await _composer.ComposeAsync("overdue-escalated", [to], tokens, overdueUrl, htmlTokens, ct);
            await _email.SendAsync(message, ct);
        }
    }

    public async Task OnExecutiveReportAsync(IncidentManager.Application.Dashboards.ProgramReport report, CancellationToken ct = default)
    {
        var to = _users.All()
            .Where(u => u.RolesCsv.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Contains(nameof(AppRole.Manager), StringComparer.OrdinalIgnoreCase))
            .Select(u => _users.EmailFor(u.UserId))
            .Where(e => !string.IsNullOrWhiteSpace(e))
            .Select(e => e!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (to.Count == 0) return;

        var c = report.Current;
        var p = report.Previous;
        static string H(double? h) => h is { } v ? $"{v:0.#} h" : "—";
        static string P(IncidentManager.Application.Dashboards.SlaAttainment s) => s.Percent is { } v ? $"{v}%" : "—";
        var rows = new (string Label, string Cur, string Prev)[]
        {
            ("Cases opened", c.Opened.ToString(CultureInfo.InvariantCulture), p.Opened.ToString(CultureInfo.InvariantCulture)),
            ("Cases closed", c.Closed.ToString(CultureInfo.InvariantCulture), p.Closed.ToString(CultureInfo.InvariantCulture)),
            ("Open at quarter end", c.OpenAtEnd.ToString(CultureInfo.InvariantCulture), p.OpenAtEnd.ToString(CultureInfo.InvariantCulture)),
            ("Classified as breach", c.BreachesOpened.ToString(CultureInfo.InvariantCulture), p.BreachesOpened.ToString(CultureInfo.InvariantCulture)),
            ("Reported to regulators", c.ReportedToRegulators.ToString(CultureInfo.InvariantCulture), p.ReportedToRegulators.ToString(CultureInfo.InvariantCulture)),
            ("Median time to contain", H(c.TimeToContain.MedianHours), H(p.TimeToContain.MedianHours)),
            ("Containment within target", P(c.Sla.First(s => s.Clock == SlaClock.Containment)), P(p.Sla.First(s => s.Clock == SlaClock.Containment))),
            ("Improvement actions open at quarter end", c.ActionsOpenAtEnd.ToString(CultureInfo.InvariantCulture), p.ActionsOpenAtEnd.ToString(CultureInfo.InvariantCulture)),
            ("… of which past target", c.ActionsPastTargetAtEnd.ToString(CultureInfo.InvariantCulture), p.ActionsPastTargetAtEnd.ToString(CultureInfo.InvariantCulture)),
        };
        var table = "<table cellpadding=\"4\" style=\"border-collapse:collapse\"><tr><th align=\"left\"></th>" +
                    $"<th align=\"right\">{WebUtility.HtmlEncode(report.Period.Label)}</th><th align=\"right\">{WebUtility.HtmlEncode(report.Period.Previous.Label)}</th></tr>" +
                    string.Join("", rows.Select(r => $"<tr><td>{WebUtility.HtmlEncode(r.Label)}</td><td align=\"right\">{WebUtility.HtmlEncode(r.Cur)}</td><td align=\"right\">{WebUtility.HtmlEncode(r.Prev)}</td></tr>")) +
                    "</table>";
        var reportUrl = BaseUrl.Length == 0 ? null : $"{BaseUrl}/program-report";
        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Quarter"] = report.Period.Label,
            ["PreviousQuarter"] = report.Period.Previous.Label,
            ["ReportUrl"] = reportUrl ?? "",
        };
        var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["SummaryTable"] = table };
        var message = await _composer.ComposeAsync("executive-report", to, tokens, reportUrl, htmlTokens, ct);
        await _email.SendAsync(message, ct);
    }

    private static string OverdueSpan(double hours) =>
        hours >= 48 ? $"{Math.Floor(hours / 24):0} days" : $"{Math.Floor(hours):0} hours";

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
            var uid = ResolveRecipientUserId(item.OwnerUserId, item.IncidentCommanderUserId);
            if (uid is null) continue;
            if (!byRecipient.TryGetValue(uid, out var list)) byRecipient[uid] = list = [];
            list.Add(item);
        }

        var agendaUrl = AgendaUrl();
        var dueSoonMandatory = Mandatory("DueSoon");
        foreach (var (uid, list) in byRecipient)
        {
            if (!dueSoonMandatory && (await _prefs.GetAsync(uid, ct)).DueSoon) continue; // opted out / on digest
            var to = _users.EmailFor(uid);
            if (string.IsNullOrWhiteSpace(to)) continue;
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

    /// <summary>The user a reminder addresses: the owner when they have an address on file, else the case's
    /// incident commander (when they do). Returns the user id — the caller resolves opt-outs and the email
    /// from it. Null when nobody is reachable.</summary>
    private string? ResolveRecipientUserId(string? ownerUserId, string? incidentCommanderUserId)
    {
        if (!string.IsNullOrWhiteSpace(ownerUserId) && !string.IsNullOrWhiteSpace(_users.EmailFor(ownerUserId)))
            return ownerUserId;
        if (!string.IsNullOrWhiteSpace(incidentCommanderUserId) && !string.IsNullOrWhiteSpace(_users.EmailFor(incidentCommanderUserId)))
            return incidentCommanderUserId;
        return null;
    }

    private static string Ui(CaseAssignmentRole role) => role switch
    {
        CaseAssignmentRole.IncidentCommander => "Incident Commander",
        _ => role.ToString(),
    };
}
