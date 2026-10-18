using System.Globalization;
using System.Net;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using IncidentManager.Application.Common;

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
    private readonly ISeverityLabels? _severityLabels;
    private readonly ITaxonomyDisplay? _taxonomy;
    private readonly IExerciseEscalationPolicy? _exercise;   // BUG-100
    private readonly ICriticalAlertOutbox? _alerts;   // BUG-101
    private readonly INotificationMarks? _sent;   // BUG-148

    // The org's display labels (the same ones the UI shows), so emails and chat never print enum identifiers.
    private string Sev(Severity s) => _severityLabels?.For(s) ?? s.ToString();
    private string PhaseName(CasePhase p) => _taxonomy?.Label("CasePhase", p.ToString(), p.ToString()) ?? p.ToString();

    private readonly ILogger<CaseNotifications>? _log;

    public CaseNotifications(IEmailSender email, IEmailComposer composer, IUserDirectory users,
        IConfiguration config, IOptionsMonitor<EmailOptions> options, IChatNotifier chat,
        INotificationPreferenceProvider prefs, ISeverityLabels? severityLabels = null, ITaxonomyDisplay? taxonomy = null,
        IOrganizationTimeZone? zone = null, IExerciseEscalationPolicy? exercise = null, ICriticalAlertOutbox? alerts = null,
        INotificationMarks? sent = null, IncidentManager.Application.ApiTokens.ITokenOwnerCheck? owners = null,
        ILogger<CaseNotifications>? log = null)
    {
        _log = log;
        _owners = owners;
        _sent = sent;
        _alerts = alerts;
        _exercise = exercise;
        _zone = zone;
        _severityLabels = severityLabels;
        _taxonomy = taxonomy;
        _email = email;
        _composer = composer;
        _users = users;
        _config = config;
        _options = options;
        _chat = chat;
        _prefs = prefs;
    }

    private readonly IncidentManager.Application.ApiTokens.ITokenOwnerCheck? _owners;

    /// <summary>
    /// REV-50: the managers to send escalations and the executive report to. The user mirror holds the roles each person
    /// had when they last signed in, so a manager who was demoted or left (and never signs in again) stayed on both lists,
    /// receiving restricted-case task titles and program figures. Where the directory can say (Windows sign-in), each is
    /// checked now: an inactive account, or one whose groups no longer map to Manager, is left out.
    /// </summary>
    private async Task<List<string>> ManagersAsync(CancellationToken ct)
    {
        var mirrored = _users.All()
            // BUG-591: a legacy role named "Readers,Manager" isn't Manager (the names start-up found with a comma).
            .Where(u => IncidentManager.Domain.Common.RoleList.Split(u.RolesCsv).Contains(nameof(AppRole.Manager), StringComparer.OrdinalIgnoreCase))
            .Select(u => u.UserId)
            .ToList();
        if (_owners is null) return mirrored;
        var current = new List<string>(mirrored.Count);
        foreach (var id in mirrored)
            if (await _owners.CheckRecipientAsync(id, ct) is not { } access   // WF-57: AD out of reach leaves the mirror standing
                || (access.Active && access.Roles.Contains(nameof(AppRole.Manager), StringComparer.OrdinalIgnoreCase)))
                current.Add(id);   // the directory can't say (null): the mirror stands, as before
        return current;
    }

    // PROD-16: has this user opted out of a personal notification type — unless the org marks it mandatory?
    // Applies to the per-user EMAIL path only (never the compliance breach→Legal distribution, never chat).
    private bool Mandatory(string type) => _config.GetValue<bool>($"Notifications:Mandatory:{type}");

    private string BaseUrl => (_config["App:BaseUrl"] ?? "").TrimEnd('/');
    private string? CaseUrl(Guid id) => BaseUrl.Length == 0 ? null : $"{BaseUrl}/cases/{id}";
    private string? OverdueUrl() => Application.Cases.CaseListLinks.For(BaseUrl, Application.Cases.CaseListLinks.OverdueTasks);
    private string? AgendaUrl() => BaseUrl.Length == 0 ? null : $"{BaseUrl}/desk";
    // BUG-593: the deadline list (closed cases still owing a notice included) and the quietest open cases first, not a
    // bare /cases, which opens the default view.
    private string? DeadlinesUrl() => Application.Cases.CaseListLinks.For(BaseUrl, Application.Cases.CaseListLinks.NotificationDeadlines);
    private string? QuietUrl() => Application.Cases.CaseListLinks.For(BaseUrl, Application.Cases.CaseListLinks.QuietestFirst);
    private string? ImportQueueUrl() => BaseUrl.Length == 0 ? null : $"{BaseUrl}/cases/import";   // CAP-01

    // PROD-02: is a given notification type routed to the team chat channel? Requires both a configured
    // chat transport and the per-type in-app toggle (Notifications:Chat:*, layered from DB + appsettings).
    private bool ChatOn(string type) => _chat.Enabled && _config.GetValue<bool>($"Notifications:Chat:{type}");

    public async Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default)
    {
        if (to != Classification.Breach || from == Classification.Breach) return;
        // BUG-100: a tabletop's escalation is marked EXERCISE everywhere it goes, or stays inside CaseBook.
        if (c.IsExercise && _exercise?.Mode == ExerciseEscalation.Skip) return;
        var tag = c.IsExercise ? ExerciseMarking.Prefix : "";

        // Chat broadcast (PROD-02): independent of the Legal email distribution — the SOC channel should
        // learn of a breach escalation even when no Legal recipients are configured.
        if (ChatOn("BreachEscalations"))
            await _chat.SendAsync(c.IsRestricted
                ? new ChatNotification($"{tag}Breach escalation (restricted case)",
                    "A restricted case was escalated to Breach. Details are limited to its team; open it in CaseBook.",
                    CaseUrl(c.Id), ChatUrgency.Alert)
                : new ChatNotification(
                    $"{tag}Breach escalation: {c.CaseNumber}",
                    $"{c.Title} · severity {Sev(c.Severity)}, phase {PhaseName(c.Phase)}.",
                    CaseUrl(c.Id), ChatUrgency.Alert), ct);

        var options = _options.CurrentValue;
        if (options.LegalDistribution.Length == 0) return;

        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["CaseNumber"] = c.CaseNumber,
            ["CaseTitle"] = c.Title,
            ["Severity"] = Sev(c.Severity),
            ["Phase"] = PhaseName(c.Phase),
            ["CaseUrl"] = CaseUrl(c.Id) ?? "",
        };
        var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ReferralNote"] = (c.IsExercise ? ExerciseNoteHtml : "")
                + (c.LegalReferral.IsReferred ? "<p>A Legal/Privacy referral is already recorded.</p>" : ""),
        };

        EmailMessage message;
        try { message = await _composer.ComposeAsync("breach", options.LegalDistribution, tokens, CaseUrl(c.Id), htmlTokens, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // BUG-293: Legal must still hear of it (BUG-101), so a plain message goes to the outbox instead.
            _log?.LogError(ex, "Couldn't compose the breach email for {CaseNumber}; sending a plain one.", c.CaseNumber);
            var text = $"Case {c.CaseNumber} ({c.Title}) was escalated to Breach. Severity {Sev(c.Severity)}, phase {PhaseName(c.Phase)}."
                       + (CaseUrl(c.Id) is { } url ? $"\n\nOpen it in CaseBook: {url}" : "");
            message = new EmailMessage(options.LegalDistribution, $"Breach escalation: {c.CaseNumber}",
                "<p>" + System.Net.WebUtility.HtmlEncode(text).Replace("\n", "<br>") + "</p>", text);
        }
        if (c.IsExercise)
            message = message with
            {
                Subject = ExerciseMarking.Prefix + message.Subject,
                HtmlBody = WithExerciseNote(message.HtmlBody),
                TextBody = ExerciseNoteText + "\n\n" + WithoutLine(message.TextBody, ExerciseNoteText),
            };
        // BUG-101: Legal must hear of a breach. A failed send is retried, and shown if it never goes.
        if (_alerts is not null) await _alerts.SendAsync(Domain.Entities.AlertDelivery.BreachEscalation, c.Id, c.CaseNumber, message, ct);
        else await _email.SendAsync(message, ct);
    }

    private const string ExerciseNoteText = "EXERCISE. This is a tabletop case, not a real breach. No action is needed.";
    private const string ExerciseNoteHtml = "<p><strong>EXERCISE.</strong> This is a tabletop case, not a real breach. No action is needed.</p>";
    private const string ExerciseNoteMark = "<strong>EXERCISE.</strong> This is a tabletop case, not a real breach.";

    /// <summary>
    /// BUG-515: the HTML body carries the EXERCISE note once. It sits where the template places {{ReferralNote}}; a template
    /// without that token, or the plain BUG-293 fallback, gets it at the top of the body instead (it was missing there).
    /// </summary>
    private static string WithExerciseNote(string html)
    {
        if (html.Contains(ExerciseNoteMark, StringComparison.Ordinal)) return html;
        // Bounded (S6444): a body tag that can't be found in time gets the note in front, as the fallback does.
        System.Text.RegularExpressions.Match body;
        try
        {
            body = System.Text.RegularExpressions.Regex.Match(html, "<body[^>]*>",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase, RegexTimeout);
        }
        catch (System.Text.RegularExpressions.RegexMatchTimeoutException) { return ExerciseNoteHtml + html; }
        if (!body.Success) return ExerciseNoteHtml + html;
        const string banner = "<div style=\"margin:0;padding:12px 16px;background:#fff4ce;color:#3b2f00;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.5;\">"
                              + "<strong>EXERCISE.</strong> This is a tabletop case, not a real breach. No action is needed.</div>";
        return html.Insert(body.Index + body.Length, banner);
    }

    // BUG-515: the text body leads with the note, so the copy {{ReferralNote}} put in the content is taken out (it showed twice).
    private static string WithoutLine(string text, string line)
    {
        var kept = string.Join('\n', text.Split('\n').Where(l => !string.Equals(l.Trim(), line, StringComparison.Ordinal)));
        return System.Text.RegularExpressions.Regex.Replace(kept, "\n{3,}", "\n\n", System.Text.RegularExpressions.RegexOptions.None,
            RegexTimeout).Trim();
    }

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

    // INV-37: a link straight to one note (the workspace opens the Notes tab and brings it into view).
    private string? NoteUrl(Guid caseId, Guid noteId) => BaseUrl.Length == 0 ? null : $"{BaseUrl}/cases/{caseId}?tab=Notes&note={noteId}";

    public async Task OnMentionedAsync(Case c, string byUserId, IReadOnlyCollection<string> mentionedUserIds,
        string noteExcerpt, Guid noteId, CancellationToken ct = default)
    {
        // Distinct recipients, never the author.
        var recipients = mentionedUserIds
            .Where(id => !string.IsNullOrWhiteSpace(id) && !string.Equals(id, byUserId, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (recipients.Count == 0) return;

        // INV-39: notes are Markdown; email and chat get plain text (links and tags print their labels, never
        // an entity: / evidence: id). Flatten first, then excerpt.
        var plain = Application.Content.RichText.ToText(noteExcerpt).Trim();
        var excerpt = plain.Length > 280 ? plain[..280] + "…" : plain;
        var byName = _users.DisplayFor(byUserId);
        var url = NoteUrl(c.Id, noteId);

        // Chat broadcast (PROD-02): one summary to the shared channel when enabled.
        if (ChatOn("Mentions"))
        {
            var who = string.Join(", ", recipients.Select(_users.DisplayFor));
            // S-13: the shared channel isn't a restricted case's audience — say who, not what or where.
            // BUG-294: a tabletop's post is marked EXERCISE, as its escalation is (BUG-100), so the SOC channel doesn't read
            // it as a real case.
            var tag = c.IsExercise ? ExerciseMarking.Prefix : "";
            await _chat.SendAsync(c.IsRestricted
                ? new ChatNotification($"{tag}Mention (restricted case)", $"{byName} mentioned {who} on a restricted case.", url)
                : new ChatNotification($"{tag}Mention: {c.CaseNumber}", $"{byName} mentioned {who} in a note: {excerpt}", url), ct);
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
                ["Note"] = excerpt,
                ["NoteUrl"] = url ?? "",
            };

            var message = await _composer.ComposeAsync("mention", [to], tokens, url, null, ct);
            await _email.SendAsync(message, c.Id, [id], ct);   // BUG-654: held mail is checked against the case again
        }
    }

    public async Task OnHandedOffAsync(Case c, string byUserId, string toUserId, string handoff, CancellationToken ct = default)
    {
        if (string.Equals(toUserId, byUserId, StringComparison.OrdinalIgnoreCase)) return;
        var to = _users.EmailFor(toUserId);
        if (string.IsNullOrWhiteSpace(to)) return;

        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["HandedOffBy"] = _users.DisplayFor(byUserId),
            ["Recipient"] = _users.DisplayFor(toUserId),
            ["CaseNumber"] = c.CaseNumber,
            ["CaseTitle"] = c.Title,
            ["Handoff"] = Application.Content.RichText.ToText(handoff).Trim(),   // INV-39: Markdown → plain text
            ["CaseUrl"] = CaseUrl(c.Id) ?? "",
        };
        var message = await _composer.ComposeAsync("handoff", [to], tokens, CaseUrl(c.Id), null, ct);
        await _email.SendAsync(message, c.Id, [toUserId], ct);   // BUG-654
    }

    public async Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName,
        CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default)
    {
        if (string.Equals(assigneeUserId, assignedByUserId, StringComparison.OrdinalIgnoreCase)) return; // self-assign — neither channel

        // Chat broadcast (PROD-02): posts to the shared channel independent of the per-assignee email
        // toggle and of whether the assignee has an address on file.
        if (ChatOn("Assignments"))
            await _chat.SendAsync(c.IsRestricted
                ? new ChatNotification($"{(c.IsExercise ? ExerciseMarking.Prefix : "")}Case assigned (restricted case)",   // BUG-294
                    $"{assigneeDisplayName} assigned as {Ui(role)} by {_users.DisplayFor(assignedByUserId)} to a restricted case.",
                    CaseUrl(c.Id))
                : new ChatNotification(
                    $"{(c.IsExercise ? ExerciseMarking.Prefix : "")}Case assigned: {c.CaseNumber}",
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
            ["Severity"] = Sev(c.Severity),
            ["Phase"] = PhaseName(c.Phase),
            ["CaseUrl"] = CaseUrl(c.Id) ?? "",
        };

        var message = await _composer.ComposeAsync("assignment", [to], tokens, CaseUrl(c.Id), null, ct);
        await _email.SendAsync(message, c.Id, [assigneeUserId], ct);   // BUG-654
    }

    private readonly IOrganizationTimeZone? _zone;

    // BUG-102: a due time as people read it, in the organization's zone with its offset ("2026-09-08 23:59 (UTC-04:00)"),
    // not in UTC, where a task due late in the evening reads as the next day.
    private string Due(DateTimeOffset t)
    {
        if (_zone?.Current is not { } zone) return t.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";
        var local = TimeZoneInfo.ConvertTime(t, zone);
        var o = local.Offset;
        return local.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)
               + string.Create(CultureInfo.InvariantCulture, $" (UTC{(o < TimeSpan.Zero ? "-" : "+")}{o.Duration():hh\\:mm})");
    }

    // BUG-94: a reminder email to one person, watched so a failure is put down to the items it carried, not the batch.
    // True when it was delivered.
    private async Task<bool> SendForAsync(EmailMessage message, IEnumerable<string> itemKeys, CancellationToken ct)
    {
        int failures;
        using (var send = DeliveryWatch.Begin())
        {
            await _email.SendAsync(message, ct);
            failures = send.Failures;
        }
        if (failures > 0) DeliveryWatch.Attribute(itemKeys, failures);
        return failures == 0;
    }

    // BUG-156: items no recipient could be found for are tried again by the scan, so someone named later gets them.
    private static void Unreached<T>(IEnumerable<T> items, IEnumerable<List<T>> reached, Func<T, string> key)
    {
        var got = reached.SelectMany(l => l).Select(key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        DeliveryWatch.Unreached(items.Select(key).Where(k => !got.Contains(k)));
    }

    // BUG-148: a scheduled reminder that goes to several people is marked per recipient. When one person's send fails,
    // the scan tries the item again, and only those it didn't reach get it again. The address is hashed in the key.
    private List<T> NotYetSentTo<T>(IEnumerable<T> items, Func<T, string> itemKey, string to) =>
        _sent is null ? items.ToList() : items.Where(i => _sent.TryAdd(RecipientKey(itemKey(i), to))).ToList();

    private void Unsent<T>(IEnumerable<T> items, Func<T, string> itemKey, string to)
    {
        if (_sent is null) return;
        foreach (var i in items) _sent.Remove(RecipientKey(itemKey(i), to));
    }

    private static string RecipientKey(string itemKey, string to) =>
        $"to|{itemKey}|{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(to.Trim().ToLowerInvariant())))[..20]}";

    // WF-20: a scheduled broadcast is watched like a reminder email: when the post fails, the channel's mark is taken back
    // and the items it carried are tried again by the next scan (a Teams 429 during the first breached-deadline scan
    // otherwise lost that post for good).
    private Task ChatForAsync<T>(ChatNotification message, List<T> items, Func<T, string> markKey, Func<T, string> itemKey,
        CancellationToken ct) =>
        ChatWatchedAsync(message, items, posted => Unsent(posted, markKey, ChatRecipient), itemKey, ct);

    private async Task ChatWatchedAsync<T>(ChatNotification message, List<T> items, Action<List<T>> unsent, Func<T, string> itemKey,
        CancellationToken ct)
    {
        int failures;
        using (var send = DeliveryWatch.Begin())
        {
            await _chat.SendAsync(message, ct);
            failures = send.Failures;
        }
        if (failures == 0) return;
        unsent(items);
        DeliveryWatch.Attribute(items.Select(itemKey), failures);
    }

    // BUG-156: the team channel is a recipient too, so a reminder the scan tries again isn't broadcast again.
    private const string ChatRecipient = "chat:team-channel";

    private static string OverdueKey(OverdueActionItem i) =>
        string.Create(CultureInfo.InvariantCulture, $"overdue|{i.ActionItemId:N}|{i.DueAtUtc.UtcTicks}");

    private static string DueSoonKey(DueSoonActionItem i) =>
        string.Create(CultureInfo.InvariantCulture, $"duesoon|{i.ActionItemId:N}|{i.DueAtUtc.UtcTicks}");

    // BUG-619: a deadline reminder is marked per jurisdiction it names (DeadlineIdentity), so a regulator that joins a clock
    // already sent to this recipient is still sent, and one already sent isn't again. Returns each reminder narrowed to the
    // jurisdictions not yet sent; a legacy mark (no jurisdiction) counts for every one it names.
    private List<DeadlineReminder> DeadlinesNotYetSentTo(IEnumerable<DeadlineReminder> reminders, string to)
    {
        if (_sent is null) return reminders.ToList();
        var result = new List<DeadlineReminder>();
        foreach (var r in reminders)
        {
            var fresh = DeadlineIdentity.MarkNew(_sent, r.JurisdictionCodes,
                code => RecipientKey(DeadlineIdentity.Key(r.CaseId, code, r.State, r.DueAtUtc), to),
                RecipientKey(DeadlineIdentity.LegacyKey(r.CaseId, r.State, r.DueAtUtc), to));
            if (fresh.Count == r.Jurisdictions.Count) result.Add(r);
            else if (fresh.Count > 0)
                result.Add(r with { Jurisdictions = r.Jurisdictions.Where(j => fresh.Contains(j.Code, StringComparer.OrdinalIgnoreCase)).ToList() });
        }
        return result;
    }

    private void DeadlinesUnsent(IEnumerable<DeadlineReminder> reminders, string to)
    {
        if (_sent is null) return;
        foreach (var r in reminders)
            foreach (var code in r.JurisdictionCodes)
                _sent.Remove(RecipientKey(DeadlineIdentity.Key(r.CaseId, code, r.State, r.DueAtUtc), to));
    }

    // A recipient who is both IC and an assignee on the same case gets the same reminder twice.
    private static string SameReminder(DeadlineReminder r) =>
        string.Create(CultureInfo.InvariantCulture, $"{r.CaseId:N}|{r.State}|{r.DueAtUtc?.UtcTicks}|{string.Join(",", r.JurisdictionCodes)}");

    private static string StaleKey(StaleCaseReminder r) =>
        string.Create(CultureInfo.InvariantCulture, $"stale|{r.CaseId:N}|{r.LastActivityAtUtc.UtcTicks}");

    private static string EscalationKey(EscalatedActionItem e) =>
        string.Create(CultureInfo.InvariantCulture, $"escalation|{e.Item.ActionItemId:N}|{e.Item.DueAtUtc.UtcTicks}|{(int)e.Tier}");

    public async Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default)
    {
        if (items.Count == 0) return;

        // Chat broadcast (PROD-02): one summary to the shared channel, in addition to the per-owner emails.
        if (ChatOn("OverdueReminders") && NotYetSentTo(items, OverdueKey, ChatRecipient) is { Count: > 0 } chatItems)
        {
            var caseCount = chatItems.Select(i => i.CaseId).Distinct().Count();
            await ChatForAsync(new ChatNotification(
                $"{Plural.Of(chatItems.Count, "task")} overdue",
                $"Across {Plural.Of(caseCount, "case")}. Owners were emailed where reachable.",
                OverdueUrl(), ChatUrgency.Alert), chatItems, OverdueKey, i => i.ActionItemId.ToString(), ct);
        }

        // Group by recipient user (owner, else the case's incident commander), so opt-outs and address
        // resolution are per person (PROD-16).
        var byRecipient = new Dictionary<string, List<OverdueActionItem>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items)
        {
            var uid = ResolveRecipientUserId(item.OwnerUserId, item.IncidentCommanderUserId);
            if (uid is null || string.IsNullOrWhiteSpace(_users.EmailFor(uid))) continue;
            if (!byRecipient.TryGetValue(uid, out var list)) byRecipient[uid] = list = [];
            list.Add(item);
        }
        Unreached(items, byRecipient.Values, i => i.ActionItemId.ToString());

        var overdueUrl = OverdueUrl();
        var overdueMandatory = Mandatory("Overdue");
        foreach (var (uid, list) in byRecipient)
        {
            if (!overdueMandatory && (await _prefs.GetAsync(uid, ct)).Overdue) continue; // opted out / on digest
            var to = _users.EmailFor(uid);
            if (string.IsNullOrWhiteSpace(to)) continue;
            // WF-20 follow-up: marked per recipient, as escalations are, so a scan that retries an item (its channel post
            // failed, or another owner's email did) doesn't send this owner the same reminder again.
            var ordered = NotYetSentTo(list.OrderBy(i => i.DueAtUtc), OverdueKey, to);
            if (ordered.Count == 0) continue;
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
            if (!await SendForAsync(message, ordered.Select(i => i.ActionItemId.ToString()), ct)) Unsent(ordered, OverdueKey, to);
        }
    }

    public async Task OnActionItemsEscalatedAsync(IReadOnlyList<EscalatedActionItem> items, CancellationToken ct = default)
    {
        if (items.Count == 0) return;

        // REV-52: the team channel is a recipient here too (BUG-156), so a scan retrying one manager's failed email doesn't
        // post the escalation to the channel again, day after day.
        if (ChatOn("OverdueReminders") && NotYetSentTo(items, EscalationKey, ChatRecipient) is { Count: > 0 } chatItems)
        {
            var caseCount = chatItems.Select(i => i.Item.CaseId).Distinct().Count();
            await ChatForAsync(new ChatNotification(
                $"{Plural.Of(chatItems.Count, "overdue task")} escalated",
                $"Across {Plural.Of(caseCount, "case")}. Incident commanders and managers were emailed where reachable.",
                OverdueUrl(), ChatUrgency.Alert), chatItems, EscalationKey, e => e.Item.ActionItemId.ToString(), ct);
        }

        // Managers = everyone holding the Manager role, checked against the directory where it can say (REV-50).
        var managers = await ManagersAsync(ct);

        // (recipient, audience) → items. The IC step skips an IC who was already the first reminder's recipient.
        var byRecipient = new Dictionary<(string Uid, string Audience), List<EscalatedActionItem>>();
        void Add(string uid, string audience, EscalatedActionItem e)
        {
            if (!byRecipient.TryGetValue((uid, audience), out var list)) byRecipient[(uid, audience)] = list = [];
            list.Add(e);
        }
        var alreadyTold = new HashSet<EscalatedActionItem>();   // WF-17: the IC was the first reminder's recipient
        foreach (var e in items)
        {
            if (e.Tier == OverdueEscalationTier.IncidentCommander)
            {
                var ic = e.Item.IncidentCommanderUserId;
                var first = ResolveRecipientUserId(e.Item.OwnerUserId, ic);
                if (!string.IsNullOrWhiteSpace(ic) && !string.Equals(ic, first, StringComparison.OrdinalIgnoreCase))
                    Add(ic, "the incident commander", e);
                else if (!string.IsNullOrWhiteSpace(ic)) alreadyTold.Add(e);
            }
            else
            {
                foreach (var m in managers) Add(m, "a manager", e);
            }
        }

        var overdueUrl = OverdueUrl();
        var mandatory = Mandatory("Overdue");
        var handled = new HashSet<EscalatedActionItem>();
        foreach (var ((uid, audience), list) in byRecipient)
        {
            if (!mandatory && (await _prefs.GetAsync(uid, ct)).Escalation) { handled.UnionWith(list); continue; } // the user's overdue opt-out (not a digest: BUG-97)
            var to = _users.EmailFor(uid);
            if (string.IsNullOrWhiteSpace(to)) continue;
            handled.UnionWith(list);
            var ordered = NotYetSentTo(list.OrderBy(i => i.Item.DueAtUtc), EscalationKey, to);
            if (ordered.Count == 0) continue;
            var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemCount"] = ordered.Count.ToString(CultureInfo.InvariantCulture),
                ["Audience"] = audience,
                ["OverdueUrl"] = overdueUrl ?? "",
            };
            // BUG-427: the owner shown is the task's owner as written, not the filtered recipient (which falls to the IC).
            var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ItemsList"] = "<ul>" + string.Join("", ordered.Select(i =>
                    $"<li>{WebUtility.HtmlEncode(i.Item.CaseNumber)} — {WebUtility.HtmlEncode(i.Item.Title)} " +
                    $"(owner {WebUtility.HtmlEncode(_users.DisplayFor(i.Item.WrittenOwner ?? i.Item.OwnerUserId ?? i.Item.IncidentCommanderUserId))}; " +
                    $"due {WebUtility.HtmlEncode(Due(i.Item.DueAtUtc))}, {OverdueSpan(i.HoursOverdue)} overdue)</li>")) + "</ul>",
            };
            var message = await _composer.ComposeAsync("overdue-escalated", [to], tokens, overdueUrl, htmlTokens, ct);
            if (!await SendForAsync(message, ordered.Select(i => i.Item.ActionItemId.ToString()), ct)) Unsent(ordered, EscalationKey, to);
        }

        // WF-17: an escalation nobody could be sent (no manager the directory still holds, none with an address, an IC with
        // none) is tried again by the scan, as an unreached reminder is (BUG-156), rather than marked as escalated.
        DeliveryWatch.Unreached(items.Where(e => !handled.Contains(e) && !alreadyTold.Contains(e))
            .Select(e => e.Item.ActionItemId.ToString()));
    }

    public async Task OnExecutiveReportAsync(IncidentManager.Application.Dashboards.ProgramReport report, CancellationToken ct = default)
    {
        var to = (await ManagersAsync(ct))   // REV-50
            .Select(id => _users.EmailFor(id))
            .Where(e => !string.IsNullOrWhiteSpace(e))
            .Select(e => e!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        // WF-17: nobody to send it to (no manager the directory still holds, or none with an address, after a restart with
        // the domain controller out of reach, say) isn't a quarter reported: the scan tries again while its window is open.
        if (to.Count == 0) { DeliveryWatch.ReportFailure(); return; }

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
        var reportUrl = BaseUrl.Length == 0 ? null : $"{BaseUrl}/program/report";
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
        if (ChatOn("DueSoonReminders") && NotYetSentTo(items, DueSoonKey, ChatRecipient) is { Count: > 0 } chatItems)
        {
            var caseCount = chatItems.Select(i => i.CaseId).Distinct().Count();
            await ChatForAsync(new ChatNotification(
                $"{Plural.Of(chatItems.Count, "task")} due within {leadHours}h",
                $"Across {Plural.Of(caseCount, "case")}. Owners were emailed where reachable.",
                AgendaUrl()), chatItems, DueSoonKey, i => i.ActionItemId.ToString(), ct);
        }

        var byRecipient = new Dictionary<string, List<DueSoonActionItem>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items)
        {
            var uid = ResolveRecipientUserId(item.OwnerUserId, item.IncidentCommanderUserId);
            if (uid is null || string.IsNullOrWhiteSpace(_users.EmailFor(uid))) continue;
            if (!byRecipient.TryGetValue(uid, out var list)) byRecipient[uid] = list = [];
            list.Add(item);
        }
        Unreached(items, byRecipient.Values, i => i.ActionItemId.ToString());

        var agendaUrl = AgendaUrl();
        var dueSoonMandatory = Mandatory("DueSoon");
        foreach (var (uid, list) in byRecipient)
        {
            if (!dueSoonMandatory && (await _prefs.GetAsync(uid, ct)).DueSoon) continue; // opted out / on digest
            var to = _users.EmailFor(uid);
            if (string.IsNullOrWhiteSpace(to)) continue;
            var ordered = NotYetSentTo(list.OrderBy(i => i.DueAtUtc), DueSoonKey, to);   // WF-20 follow-up: per recipient
            if (ordered.Count == 0) continue;
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
            if (!await SendForAsync(message, ordered.Select(i => i.ActionItemId.ToString()), ct)) Unsent(ordered, DueSoonKey, to);
        }
    }

    public async Task OnDeadlineApproachingAsync(IReadOnlyList<DeadlineReminder> reminders, CancellationToken ct = default)
    {
        if (reminders.Count == 0) return;

        // Chat broadcast (PROD-02): one urgent summary to the shared channel, alongside the per-recipient emails.
        if (ChatOn("DeadlineReminders") && DeadlinesNotYetSentTo(reminders, ChatRecipient) is { Count: > 0 } chatItems)
        {
            var caseCount = chatItems.Select(r => r.CaseId).Distinct().Count();
            var breached = chatItems.Count(r => r.State == SlaState.Breached);
            var detail = breached > 0
                ? $"{breached} past deadline, {chatItems.Count - breached} at risk, across {Plural.Of(caseCount, "case")}. Incident commanders and owners were emailed where reachable."
                // BUG-232: a case can have more than one clock (BUG-191), so count the cases, and say the deadlines too.
                : (chatItems.Count == caseCount
                    ? $"{Plural.Of(caseCount, "case")} approaching a deadline."
                    : $"{Plural.Of(chatItems.Count, "deadline")} approaching, across {Plural.Of(caseCount, "case")}.")
                  + " Incident commanders and owners were emailed where reachable.";
            await ChatWatchedAsync(new ChatNotification(
                "Regulatory notification deadline", detail,
                DeadlinesUrl(), ChatUrgency.Alert), chatItems, posted => DeadlinesUnsent(posted, ChatRecipient), r => r.CaseId.ToString(), ct);
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
        Unreached(reminders, byRecipient.Values, r => r.CaseId.ToString());

        foreach (var (to, list) in byRecipient)
        {
            // A recipient who is both IC and an assignee on the same case would otherwise see it twice. BUG-191: a case can
            // have more than one clock needing attention (one per deadline), each listed.
            var ordered = DeadlinesNotYetSentTo(list
                .DistinctBy(SameReminder)
                .OrderBy(r => r.DueAtUtc ?? DateTimeOffset.MaxValue)
                .ThenBy(r => r.CaseNumber, StringComparer.OrdinalIgnoreCase), to);
            if (ordered.Count == 0) continue;

            // The CTA points at the one case when this recipient's list is a single case, else the case list. BUG-232: one
            // case with two clocks is still one case.
            var cta = ordered.Select(r => r.CaseId).Distinct().Count() == 1 ? CaseUrl(ordered[0].CaseId) : DeadlinesUrl();

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
            if (!await SendForAsync(message, ordered.Select(r => r.CaseId.ToString()), ct)) DeadlinesUnsent(ordered, to);
        }
    }

    public async Task OnCasesStaleAsync(IReadOnlyList<StaleCaseReminder> reminders, CancellationToken ct = default)
    {
        if (reminders.Count == 0) return;

        // Chat broadcast (PROD-02): one summary to the shared channel, alongside the per-recipient emails.
        if (ChatOn("StaleReminders") && NotYetSentTo(reminders, StaleKey, ChatRecipient) is { Count: > 0 } chatReminders)   // REV-52
        {
            var caseCount = chatReminders.Select(r => r.CaseId).Distinct().Count();
            await ChatForAsync(new ChatNotification(
                $"{Plural.Of(caseCount, "case")} with no recent activity",
                "These open cases have had no activity past their severity threshold. Incident commanders and owners were emailed where reachable.",
                QuietUrl()), chatReminders, StaleKey, r => r.CaseId.ToString(), ct);
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
        Unreached(reminders, byRecipient.Values, r => r.CaseId.ToString());   // WF-96: nobody reachable yet: tried again

        foreach (var (to, list) in byRecipient)
        {
            var ordered = NotYetSentTo(list
                .DistinctBy(r => r.CaseId)                         // IC who is also an assignee → list once
                .OrderByDescending(r => r.DaysInactive)
                .ThenBy(r => r.CaseNumber, StringComparer.OrdinalIgnoreCase), StaleKey, to);
            if (ordered.Count == 0) continue;

            var cta = ordered.Count == 1 ? CaseUrl(ordered[0].CaseId) : QuietUrl();

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
            if (!await SendForAsync(message, ordered.Select(r => r.CaseId.ToString()), ct)) Unsent(ordered, StaleKey, to);
        }
    }

    // CAP-01: the review queue, opened on one submission.
    private string? ImportUrl(Guid pendingId) => BaseUrl.Length == 0 ? null : $"{BaseUrl}/cases/import?pending={pendingId}";

    /// <summary>
    /// CAP-01: a submission waits in the import queue. The team channel (<c>Notifications:Chat:ImportSubmissions</c>) is
    /// told it's there, without its summary or origin when its target is restricted (S-13: the channel isn't that case's
    /// audience). Each reviewer the caller named is emailed (<c>Notifications:ImportSubmitted:Email</c>), one message each.
    /// Both are off by default. Nothing is applied: a reviewer confirms it on the Import page (ADR 0004).
    /// </summary>
    public async Task OnImportSubmittedAsync(ImportSubmission submission, CancellationToken ct = default)
    {
        var url = ImportUrl(submission.PendingImportId);
        var tag = submission.IsExercise ? ExerciseMarking.Prefix : "";
        var from = string.IsNullOrWhiteSpace(submission.Origin) ? "the API" : submission.Origin.Trim();
        var by = _users.DisplayFor(submission.SubmittedBy);

        if (ChatOn("ImportSubmissions"))
            await _chat.SendAsync(submission.IsRestricted
                ? new ChatNotification($"{tag}Import waiting for review (restricted case)",
                    "An import for a restricted case is waiting for review. Details are limited to its team; open the import queue in CaseBook.",
                    url)
                : new ChatNotification($"{tag}Import waiting for review",
                    $"{submission.Summary} · from {from}, submitted by {by}. A reviewer confirms it before anything is written.", url), ct);

        if (!_config.GetValue<bool>("Notifications:ImportSubmitted:Email")) return;
        foreach (var id in submission.ReviewerUserIds.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var to = _users.EmailFor(id);
            if (string.IsNullOrWhiteSpace(to)) continue;
            var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Reviewer"] = _users.DisplayFor(id),
                ["Summary"] = submission.Summary,
                ["Origin"] = from,
                ["SubmittedBy"] = by,
                ["ItemCount"] = submission.ItemCount.ToString(CultureInfo.InvariantCulture),
                ["ImportUrl"] = url ?? "",
            };
            var message = await _composer.ComposeAsync("import-submitted", [to], tokens, url, null, ct);
            if (submission.IsExercise) message = message with { Subject = ExerciseMarking.Prefix + message.Subject };
            // BUG-654: mail held for a restricted target is checked against that case's audience again before it goes.
            if (submission.TargetCaseId is { } caseId) await _email.SendAsync(message, caseId, [id], ct);
            else await _email.SendAsync(message, ct);
        }
    }

    public async Task OnDigestAsync(UserDigest digest, CancellationToken ct = default)
    {
        if (!digest.HasContent) return;   // CAP-01: items, or imports waiting too long
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
    private string RenderDigest(UserDigest digest)
    {
        var sb = new System.Text.StringBuilder();
        Section(sb, "Overdue", digest.Overdue);
        Section(sb, "Due today", digest.DueToday);
        Section(sb, "Due this week", digest.DueThisWeek);
        // CAP-01: a count only (the queue holds who sent what), for a reviewer: the imports they'd see that have waited.
        if (digest.ImportsWaiting is { Count: > 0 } waiting)
        {
            var count = waiting.More ? $"More than {waiting.Count}" : waiting.Count.ToString(CultureInfo.InvariantCulture);
            var link = ImportQueueUrl() is { } q ? $" <a href=\"{WebUtility.HtmlEncode(q)}\">Review them</a>." : " Review them under Cases → Import.";
            sb.Append("<p class=\"meta\"><strong>Imports waiting for review</strong></p><p>")
              .Append(WebUtility.HtmlEncode($"{count} {(waiting.Count == 1 && !waiting.More ? "import has" : "imports have")} waited more than {Plural.Of(digest.ImportWaitingHours, "hour")} for someone to confirm or reject {(waiting.Count == 1 && !waiting.More ? "it" : "them")}."))
              .Append(link).Append("</p>");
        }
        return sb.ToString();

        void Section(System.Text.StringBuilder sb, string heading, IReadOnlyList<DigestItem> items)
        {
            if (items.Count == 0) return;
            sb.Append("<p class=\"meta\"><strong>").Append(WebUtility.HtmlEncode(heading))
              .Append(" (").Append(items.Count).Append(")</strong></p><ul>");
            foreach (var i in items)
                sb.Append("<li>").Append(WebUtility.HtmlEncode(i.CaseNumber)).Append(" — ")
                  .Append(WebUtility.HtmlEncode(i.TaskTitle))
                  .Append(" (due ").Append(WebUtility.HtmlEncode(Due(i.DueAtUtc))).Append(")</li>");
            sb.Append("</ul>");
        }
    }

    // Composer-rendered safe HTML: every case-supplied field is HTML-encoded here.
    private string RenderStaleList(IEnumerable<StaleCaseReminder> reminders)
    {
        var lis = reminders.Select(r =>
            $"<li>{WebUtility.HtmlEncode(r.CaseNumber)} — {WebUtility.HtmlEncode(r.CaseTitle)} " +
            $"({WebUtility.HtmlEncode(Sev(r.Severity))}: no activity for {Plural.Of(r.DaysInactive, "day")})</li>");
        return "<ul>" + string.Join("", lis) + "</ul>";
    }

    // Composer-rendered safe HTML: every case-supplied field is HTML-encoded here.
    private string RenderDeadlineList(IEnumerable<DeadlineReminder> reminders)
    {
        var lis = reminders.Select(r =>
        {
            var standing = r.State == SlaState.Breached ? "past deadline" : "at risk";
            var due = r.DueAtUtc is { } d ? $", due {Due(d)}" : "";
            return $"<li>{WebUtility.HtmlEncode(r.CaseNumber)} — {WebUtility.HtmlEncode(r.CaseTitle)} " +
                   $"({WebUtility.HtmlEncode(r.JurisdictionLabel)}: {standing}{WebUtility.HtmlEncode(due)})</li>";
        });
        return "<ul>" + string.Join("", lis) + "</ul>";
    }

    // Composer-rendered safe HTML: every case-supplied field is HTML-encoded here.
    private string RenderItemList(IReadOnlyList<OverdueActionItem> items) =>
        RenderItemList(items.Select(i => (i.CaseNumber, i.Title, i.DueAtUtc)));

    private string RenderItemList(IEnumerable<(string CaseNumber, string Title, DateTimeOffset DueAtUtc)> items)
    {
        var lis = items.Select(i =>
            $"<li>{WebUtility.HtmlEncode(i.CaseNumber)} — {WebUtility.HtmlEncode(i.Title)} " +
            $"(due {WebUtility.HtmlEncode(Due(i.DueAtUtc))})</li>");
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
