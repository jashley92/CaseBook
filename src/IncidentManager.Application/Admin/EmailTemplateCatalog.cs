namespace IncidentManager.Application.Admin;

/// <summary>A placeholder an admin may use in a template's subject or body, with a human description.</summary>
public sealed record EmailToken(string Name, string Description);

/// <summary>
/// A notification email whose <b>subject</b> and <b>body content</b> an admin may edit (E-03b branded email).
/// The branded shell (logo, console colours, header/footer, CTA button) is applied automatically and is not
/// part of the editable content. Tokens are substituted at send time; scalar token values are HTML-encoded,
/// so case-supplied text cannot inject markup. List tokens (e.g. <c>{{ItemsList}}</c>) are rendered by the
/// composer as safe HTML. If the template declares a CTA, the shell appends the button linking to
/// <see cref="CtaUrlToken"/> (only when a public base URL is configured).
/// </summary>
public sealed record EmailTemplateDefinition(
    string Id,
    string Title,
    string Description,
    string DefaultSubject,
    string DefaultBodyHtml,
    IReadOnlyList<EmailToken> Tokens,
    string? CtaLabel = null,
    string? CtaUrlToken = null);

/// <summary>
/// The notification emails whose subject + body an admin may customise. Defaults live here (so a template
/// can always be reset); overrides are stored as <c>EmailTemplate:{id}:{Subject|Body}</c> rows in the same
/// audited settings table as operational settings and taxonomy labels, and read live via configuration.
/// Cosmetic content only — a known, non-security key space (like the taxonomy labels), so it is exempt from
/// the operational-whitelist tamper check on the settings read path (S-02).
/// </summary>
public static class EmailTemplateCatalog
{
    public const string KeyPrefix = "EmailTemplate:";
    public static string SubjectKey(string id) => $"{KeyPrefix}{id}:Subject";
    public static string BodyKey(string id) => $"{KeyPrefix}{id}:Body";

    // Shared token help.
    private static readonly EmailToken CaseNumber = new("CaseNumber", "The case number, for example 2026-01_Phishing_Wave.");
    private static readonly EmailToken CaseTitle = new("CaseTitle", "The case title.");
    private static readonly EmailToken Severity = new("Severity", "The case severity (Critical/High/Medium/Low).");
    private static readonly EmailToken Phase = new("Phase", "The case lifecycle phase.");

    public static readonly IReadOnlyList<EmailTemplateDefinition> Templates = new[]
    {
        new EmailTemplateDefinition(
            "assignment",
            "Case assignment",
            "Sent to a person when they're assigned to a case. Needs assignment notifications on.",
            "You've been assigned to {{CaseNumber}} ({{Role}})",
            """
            <h1>You've been assigned a case</h1>
            <p>Hi {{Assignee}},</p>
            <p>You have been assigned to <strong>{{CaseNumber}} — {{CaseTitle}}</strong> as <strong>{{Role}}</strong> by {{AssignedBy}}.</p>
            <p class="meta">Severity: {{Severity}} &middot; Phase: {{Phase}}</p>
            """,
            new[]
            {
                new EmailToken("Assignee", "Display name of the person assigned."),
                new EmailToken("Role", "Their role on the case (Incident Commander / Analyst / Observer)."),
                new EmailToken("AssignedBy", "Who made the assignment."),
                CaseNumber, CaseTitle, Severity, Phase,
            },
            CtaLabel: "Open the case",
            CtaUrlToken: "CaseUrl"),

        new EmailTemplateDefinition(
            "overdue",
            "Overdue task reminder",
            "Sent to an item's owner, or the incident commander, when a task passes its due date.",
            "Overdue tasks: {{ItemCount}}",
            """
            <h1>Overdue tasks</h1>
            <p>These tasks are past their due date:</p>
            {{ItemsList}}
            <p>Open each case to update or close them.</p>
            """,
            new[]
            {
                new EmailToken("ItemCount", "How many items are overdue for this recipient."),
                new EmailToken("ItemsList", "The formatted list of overdue items (case, title, due date). Rendered by the app."),
            },
            CtaLabel: "Review overdue items",
            CtaUrlToken: "OverdueUrl"),

        new EmailTemplateDefinition(
            "overdue-escalated",
            "Overdue item escalation",
            "Sent to a case's incident commander, then to managers, when a task stays overdue past the configured hours. A reminder only: nothing is reassigned.",
            "Escalation: tasks still overdue ({{ItemCount}})",
            """
            <h1>Tasks still overdue</h1>
            <p>You're receiving this as {{Audience}}. These tasks are still open well past their due date:</p>
            {{ItemsList}}
            <p>The owner has already been reminded. Check in with them or the case team.</p>
            """,
            new[]
            {
                new EmailToken("ItemCount", "How many escalated items are in this email."),
                new EmailToken("Audience", "Why this recipient is receiving it: \"the incident commander\" or \"a manager\"."),
                new EmailToken("ItemsList", "The formatted list of items (case, title, owner, how long overdue). Rendered by the app."),
            },
            CtaLabel: "Review overdue items",
            CtaUrlToken: "OverdueUrl"),

        new EmailTemplateDefinition(
            "executive-report",
            "Quarterly executive report",
            "Sent to managers in the first week of each quarter with last quarter's program figures.",
            "Program report {{Quarter}}",
            """
            <h1>Program report: {{Quarter}}</h1>
            <p>Headline figures for {{Quarter}}, compared with {{PreviousQuarter}}. Covers every case except exercises.</p>
            {{SummaryTable}}
            <p>The full report, with the breakdowns and a CSV export, is in CaseBook.</p>
            """,
            new[]
            {
                new EmailToken("Quarter", "The quarter reported on, for example Q3 2026."),
                new EmailToken("PreviousQuarter", "The quarter it's compared with."),
                new EmailToken("SummaryTable", "The headline figures table. Rendered by the app."),
            },
            CtaLabel: "Open the program report",
            CtaUrlToken: "ReportUrl"),

        new EmailTemplateDefinition(
            "action-item-due-soon",
            "Due-soon task reminder",
            "Sent to an item's owner, or the incident commander, when a task comes due within the lead window.",
            "Tasks due soon: {{ItemCount}}",
            """
            <h1>Tasks due soon</h1>
            <p>These tasks are due within the next {{LeadHours}} hours:</p>
            {{ItemsList}}
            <p>Open each case to progress or close them before they're overdue.</p>
            """,
            new[]
            {
                new EmailToken("ItemCount", "How many items are due soon for this recipient."),
                new EmailToken("LeadHours", "The lead window, in hours, that defines \"due soon\"."),
                new EmailToken("ItemsList", "The formatted list of items due soon (case, title, due date). Rendered by the app."),
            },
            CtaLabel: "Open my work",
            CtaUrlToken: "AgendaUrl"),

        new EmailTemplateDefinition(
            "notification-deadline",
            "Regulatory notification-deadline reminder",
            "Sent to a case's incident commander and assignees when its regulatory notification deadline is near or past and the case isn't marked reported. Needs the deadline clock on.",
            "Regulatory notification deadline near or past: {{ItemCount}}",
            """
            <h1>Regulatory notification deadline</h1>
            <p>These cases are at risk of, or already past, a regulatory notification deadline and have <strong>not yet been marked reported</strong>:</p>
            {{ItemsList}}
            <p>Review each case's notification status and record the reported milestone once notice is given. CaseBook only records the milestone. It never files on your behalf.</p>
            """,
            new[]
            {
                new EmailToken("ItemCount", "How many cases are approaching or past a deadline for this recipient."),
                new EmailToken("ItemsList", "The formatted list of cases (case, title, jurisdiction, standing, deadline). Rendered by the app."),
            },
            CtaLabel: "Review cases",
            CtaUrlToken: "DeadlinesUrl"),

        new EmailTemplateDefinition(
            "digest",
            "Personal work digest",
            "A user's open follow-up items, grouped as overdue, due today and due this week, sent daily or weekly. Users opt in under account menu → Notifications.",
            "Your CaseBook work digest: {{ItemCount}} open",
            """
            <h1>Your work digest</h1>
            <p>Here are your open follow-up items across the cases you're working, as of this {{Cadence}} digest:</p>
            {{ItemsList}}
            <p>Open <strong>My work</strong> to progress or close them.</p>
            """,
            new[]
            {
                new EmailToken("ItemCount", "How many open items are in this digest."),
                new EmailToken("Cadence", "The digest cadence: \"daily\" or \"weekly\"."),
                new EmailToken("ItemsList", "The formatted list of items, grouped as overdue, due today and due this week. Rendered by the app."),
            },
            CtaLabel: "Open my work",
            CtaUrlToken: "AgendaUrl"),

        new EmailTemplateDefinition(
            "stale-case",
            "Stale-case nudge",
            "Sent to a case's incident commander and assignees when an open case has no recorded activity for longer than its severity's threshold. Needs stale-case nudges on.",
            "Open cases with no recent activity: {{ItemCount}}",
            """
            <h1>Cases with no recent activity</h1>
            <p>These open cases have had no recorded activity for a while and may be stalled:</p>
            {{ItemsList}}
            <p>Open each case to record progress or move it forward. This is only a reminder. Nothing on the case has changed.</p>
            """,
            new[]
            {
                new EmailToken("ItemCount", "How many stale cases there are for this recipient."),
                new EmailToken("ItemsList", "The formatted list of stale cases (case, title, severity, days quiet). Rendered by the app."),
            },
            CtaLabel: "Review cases",
            CtaUrlToken: "StaleUrl"),

        new EmailTemplateDefinition(
            "breach",
            "Breach escalation (Legal / Privacy)",
            "Sent to the Legal / Privacy distribution when a case is escalated to Breach.",
            "Case escalated to Breach: {{CaseNumber}}",
            """
            <h1>Case escalated to Breach</h1>
            <p><strong>{{CaseNumber}} — {{CaseTitle}}</strong> has been classified as a <strong>Breach</strong>.</p>
            <p class="meta">Severity: {{Severity}} &middot; Phase: {{Phase}}</p>
            {{ReferralNote}}
            <p>Review it to assess regulatory relevance (NYDFS Part 500, GLBA).</p>
            """,
            new[]
            {
                CaseNumber, CaseTitle, Severity, Phase,
                new EmailToken("ReferralNote", "A note shown when a Legal / Privacy referral is already recorded (else blank)."),
            },
            CtaLabel: "Open the case",
            CtaUrlToken: "CaseUrl"),

        new EmailTemplateDefinition(
            "mention",
            "Comment mention",
            "Sent to a person @mentioned in a case discussion comment.",
            "{{MentionedBy}} mentioned you on {{CaseNumber}}",
            """
            <h1>You were mentioned in a case discussion</h1>
            <p>Hi {{Mentioned}},</p>
            <p><strong>{{MentionedBy}}</strong> mentioned you in a comment on <strong>{{CaseNumber}} — {{CaseTitle}}</strong>:</p>
            <p class="meta">{{Comment}}</p>
            <p>Open the case to read the full discussion and reply.</p>
            """,
            new[]
            {
                new EmailToken("Mentioned", "Display name of the person mentioned."),
                new EmailToken("MentionedBy", "Who wrote the comment."),
                new EmailToken("Comment", "A short excerpt of the comment."),
                CaseNumber, CaseTitle,
            },
            CtaLabel: "Open the case",
            CtaUrlToken: "CaseUrl"),

        new EmailTemplateDefinition(
            "audit-chain-alarm",
            "Audit-chain integrity alarm",
            "Sent to the integrity-alert distribution when the audit hash chain fails verification. A critical SIEM event is sent either way.",
            "ALERT: audit-chain integrity failure",
            """
            <h1>Audit-chain integrity failure</h1>
            <p>The CaseBook audit hash chain <strong>failed verification</strong>. The tamper-evident log may have been altered, truncated or reordered. Treat this as a potential integrity or security incident.</p>
            <p class="meta">First break at sequence: {{FirstBrokenSequence}}<br/>Detail: {{Detail}}</p>
            <p>1. Preserve the current database and the out-of-band integrity seals.<br/>
               2. Review Integrity &amp; audit and the most recent signed seal to locate the break.<br/>
               3. Follow the incident-response and restore procedures in OPERATIONS.md.</p>
            <p>No new seals will be recorded until the chain verifies intact again.</p>
            """,
            new[]
            {
                new EmailToken("FirstBrokenSequence", "The audit sequence number where the break was first detected."),
                new EmailToken("Detail", "A short technical description of the break."),
            },
            CtaLabel: "Open Integrity & audit",
            CtaUrlToken: "IntegrityUrl"),

        new EmailTemplateDefinition(
            "evidence-drift-alarm",
            "Evidence-at-rest drift alarm",
            "Sent to the integrity-alert distribution when stored evidence no longer matches its recorded hash. A critical SIEM event is sent either way.",
            "ALERT: evidence-at-rest integrity failure ({{DriftCount}} drifted)",
            """
            <h1>Evidence-at-rest integrity failure</h1>
            <p>Re-verification found stored evidence that no longer matches its recorded SHA-256. This may be bit-rot or tampering.</p>
            <p class="meta">Drifted: {{DriftCount}} of {{CheckedCount}} &middot; Verified at (UTC): {{VerifiedAtUtc}}</p>
            {{DriftList}}
            <p>Preserve the evidence store and database, and recover drifted files from the out-of-band evidence backups (OPERATIONS.md).</p>
            """,
            new[]
            {
                new EmailToken("DriftCount", "How many stored items drifted."),
                new EmailToken("CheckedCount", "How many items were checked."),
                new EmailToken("VerifiedAtUtc", "When the verification ran (UTC)."),
                new EmailToken("DriftList", "The formatted list of drifted items. Rendered by the app."),
            },
            CtaLabel: "Open Integrity & audit",
            CtaUrlToken: "IntegrityUrl"),
    };

    public static EmailTemplateDefinition? ById(string id) =>
        Templates.FirstOrDefault(t => string.Equals(t.Id, id, StringComparison.OrdinalIgnoreCase));
}
