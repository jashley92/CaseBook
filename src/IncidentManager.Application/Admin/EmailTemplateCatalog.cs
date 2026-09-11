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
    private static readonly EmailToken CaseNumber = new("CaseNumber", "The case number, e.g. 2026-01_Phishing_Wave.");
    private static readonly EmailToken CaseTitle = new("CaseTitle", "The case title.");
    private static readonly EmailToken Severity = new("Severity", "The case severity (Critical/High/Medium/Low).");
    private static readonly EmailToken Phase = new("Phase", "The case lifecycle phase.");

    public static readonly IReadOnlyList<EmailTemplateDefinition> Templates = new[]
    {
        new EmailTemplateDefinition(
            "assignment",
            "Case assignment",
            "Sent to a person when they are assigned to a case (E-03b). Requires assignment notifications on.",
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
            "Overdue after-action reminder",
            "Sent to an item's owner (or the case's incident commander) when a follow-up item passes its due date (E-03b).",
            "{{ItemCount}} overdue after-action item(s)",
            """
            <h1>Overdue after-action items</h1>
            <p>The following after-action follow-up item(s) are past their due date:</p>
            {{ItemsList}}
            <p>Please open the case(s) to update or close them.</p>
            """,
            new[]
            {
                new EmailToken("ItemCount", "How many items are overdue for this recipient."),
                new EmailToken("ItemsList", "The formatted list of overdue items (case, title, due date). Rendered by the app."),
            },
            CtaLabel: "Review overdue items",
            CtaUrlToken: "OverdueUrl"),

        new EmailTemplateDefinition(
            "breach",
            "Breach escalation (Legal/Privacy)",
            "Sent to the Legal/Privacy distribution when a case is escalated to a Breach (E-03).",
            "Case escalated to Breach: {{CaseNumber}}",
            """
            <h1>Case escalated to Breach</h1>
            <p><strong>{{CaseNumber}} — {{CaseTitle}}</strong> has been classified as a <strong>Breach</strong>.</p>
            <p class="meta">Severity: {{Severity}} &middot; Phase: {{Phase}}</p>
            {{ReferralNote}}
            <p>Review it for regulatory-relevance assessment (NYDFS Part 500 / GLBA).</p>
            """,
            new[]
            {
                CaseNumber, CaseTitle, Severity, Phase,
                new EmailToken("ReferralNote", "A note shown when a Legal/Privacy referral is already recorded (else blank)."),
            },
            CtaLabel: "Open the case",
            CtaUrlToken: "CaseUrl"),

        new EmailTemplateDefinition(
            "audit-chain-alarm",
            "Audit-chain integrity alarm (F-16)",
            "Sent to the integrity-alert distribution when the audit hash-chain fails verification. A critical SIEM/log event is always emitted regardless.",
            "ALERT: audit-chain integrity failure",
            """
            <h1>Audit-chain integrity failure</h1>
            <p>The CaseBook audit hash-chain <strong>failed verification</strong> — the tamper-evident log may have been altered, truncated, or reordered. Treat this as a potential integrity/security incident.</p>
            <p class="meta">First break at sequence: {{FirstBrokenSequence}}<br/>Detail: {{Detail}}</p>
            <p>1. Preserve the current database and the out-of-band integrity seals.<br/>
               2. Review Integrity &amp; Audit and the most recent signed seal to locate the break.<br/>
               3. Follow the incident-response and restore procedures in OPERATIONS.md.</p>
            <p>No new seals will be recorded until the chain verifies intact again.</p>
            """,
            new[]
            {
                new EmailToken("FirstBrokenSequence", "The audit sequence number where the break was first detected."),
                new EmailToken("Detail", "A short technical description of the break."),
            },
            CtaLabel: "Open Integrity & Audit",
            CtaUrlToken: "IntegrityUrl"),

        new EmailTemplateDefinition(
            "evidence-drift-alarm",
            "Evidence-at-rest drift alarm (F-17)",
            "Sent to the integrity-alert distribution when stored evidence no longer matches its recorded hash. A critical SIEM/log event is always emitted regardless.",
            "ALERT: evidence-at-rest integrity failure ({{DriftCount}} item(s))",
            """
            <h1>Evidence-at-rest integrity failure</h1>
            <p>Re-verification found stored evidence whose bytes no longer match their recorded SHA-256 — possible bit-rot or tampering of the files themselves.</p>
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
            CtaLabel: "Open Integrity & Audit",
            CtaUrlToken: "IntegrityUrl"),
    };

    public static EmailTemplateDefinition? ById(string id) =>
        Templates.FirstOrDefault(t => string.Equals(t.Id, id, StringComparison.OrdinalIgnoreCase));
}
