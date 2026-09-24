using System.Globalization;

namespace IncidentManager.Application.Admin;

/// <summary>How a setting's string value is typed and edited in the admin UI.</summary>
public enum SettingKind
{
    Text,
    MultiText,
    Bool,
    Int
}

/// <summary>Metadata for one administrable operational setting.</summary>
/// <param name="Key">Configuration key path (e.g. "Email:From"), matching the IConfiguration key it overrides.</param>
public sealed record SettingDefinition(
    string Key,
    string Label,
    string Group,
    SettingKind Kind,
    string Description,
    string? Default = null,
    bool CustomEditor = false);

/// <summary>
/// The whitelist of operational settings that may be administered in the web console (A-02).
/// Anything not listed here is <b>not</b> editable in-app — security- and infrastructure-sensitive
/// settings (auth mode, connection strings, signing keys, storage paths, AD group→role mapping) are
/// deliberately absent and remain in server-side configuration, surfaced read-only in the panel.
/// </summary>
public static class SettingsCatalog
{
    public static readonly IReadOnlyList<SettingDefinition> Editable = new[]
    {
        // --- Organization profile (X-01): who this white-label instance is for. One place to set the
        // identity that appears on reports and around the app. Keys are unchanged from where these
        // settings used to live (Reporting / Integrations), so every consumer reads them as before. ---
        new SettingDefinition("Reporting:OrganizationName", "Organisation name", "Organization", SettingKind.Text,
            "Your organisation's name. Printed on the first line of the report header and used as the app's white-label identity. Left blank, the report shows a [Company Name] placeholder. Upload a logo in the Reporting section to sit above it.", ""),
        new SettingDefinition("Reporting:TeamName", "Team name", "Organization", SettingKind.Text,
            "Your security team's name, printed under the organisation name in the report header (e.g. \"Cyber Defense\" / \"Security Operations\"). Blank shows a [Team Name] placeholder.", ""),
        new SettingDefinition("ExternalLinks:DetectionSourceLabel", "Detection source label", "Organization", SettingKind.Text,
            "Display name for your originating detection system (e.g. \"SIEM\", \"EDR\", \"SOAR\"). Shown on the case workspace and creation form. The deep-link template for it lives under Integrations.", "SIEM"),
        // Brand palette (X-08): edited with the colour pickers in the Brand card, not the generic text
        // renderer (CustomEditor). Blank = the built-in charcoal + gold defaults. Only the brand/accent
        // roles vary; the semantic status palette (severity/phase/danger) is never rebranded.
        new SettingDefinition("Branding:AccentColor", "Brand accent colour", "Organization", SettingKind.Text,
            "Primary brand colour used for links, active states, focus rings and highlights. Blank uses the built-in gold. A legible emphasis shade is derived automatically to stay AA-contrast.", "", CustomEditor: true),
        new SettingDefinition("Branding:InkColor", "Primary action colour", "Organization", SettingKind.Text,
            "Colour of primary buttons and structural \"ink\". Blank uses the built-in charcoal.", "", CustomEditor: true),
        new SettingDefinition("Organization:DefaultJurisdictions", "Default jurisdictions", "Organization", SettingKind.Text,
            "Home state(s) / jurisdiction(s) most cases involve (e.g. \"NY, NJ, PA\"). Pre-fills the impact assessment's affected-jurisdictions field on cases that have none yet; always editable per case. Blank pre-fills nothing.", ""),

        new SettingDefinition("Email:Enabled", "Send email", "Notifications", SettingKind.Bool,
            "When off, notifications are written to the log rather than delivered.", "false"),
        new SettingDefinition("Email:From", "From address", "Notifications", SettingKind.Text,
            "Envelope-from address for outbound notifications.", "incident-manager@localhost"),
        new SettingDefinition("Email:LegalDistribution", "Legal/Privacy distribution", "Notifications", SettingKind.MultiText,
            "Recipients notified when a case is escalated to a Breach — one email address per line.", ""),
        new SettingDefinition("Email:IntegrityAlertDistribution", "Integrity-alert distribution", "Notifications", SettingKind.MultiText,
            "Recipients alerted if the audit hash-chain fails verification (a possible tamper event) — usually SysAdmins/SecOps, one email address per line. A critical SIEM/log event is always emitted regardless of this list.", ""),
        new SettingDefinition("Email:AssignmentNotifications", "Assignment notifications", "Notifications", SettingKind.Bool,
            "When on, a person is emailed when they are assigned to a case (E-03b). The recipient is resolved from the user directory; self-assignments are skipped. Requires an email address on file and \"Send email\" on to actually deliver.", "false"),
        new SettingDefinition("Notifications:OverdueScan:Enabled", "Overdue after-action reminders", "Notifications", SettingKind.Bool,
            "When on, a background scan emails each after-action item's owner (or the case's incident commander if it has no reachable owner) once when the item passes its due date (E-03b). Read-only over case data — it records nothing. Takes effect within a few minutes of saving.", "false"),
        new SettingDefinition("Notifications:OverdueScan:IntervalHours", "Overdue scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between overdue after-action scans. Reminders are not time-critical, so this is deliberately slow (default daily). Takes effect within a few minutes of saving.", "24"),
        // PROD-03: escalation chain for items that stay overdue. Notifications only; nothing is reassigned.
        new SettingDefinition("Notifications:OverdueScan:Escalation:Enabled", "Escalate items that stay overdue", "Notifications", SettingKind.Bool,
            "When an overdue after-action item is still open after the hours below, email the case's incident commander, then managers. Reminders only: nothing is reassigned or changed. Needs overdue reminders on.", "false"),
        new SettingDefinition("Notifications:OverdueScan:Escalation:IncidentCommanderAfterHours", "Escalate to incident commander after (hours overdue)", "Notifications", SettingKind.Int,
            "Hours past the due date before the case's incident commander is emailed. 0 skips this step.", "48"),
        new SettingDefinition("Notifications:OverdueScan:Escalation:ManagersAfterHours", "Escalate to managers after (hours overdue)", "Notifications", SettingKind.Int,
            "Hours past the due date before everyone with the Manager role is emailed. 0 skips this step.", "120"),
        new SettingDefinition("Notifications:DueSoonScan:Enabled", "Due-soon after-action reminders", "Notifications", SettingKind.Bool,
            "When on, a background scan emails each after-action item's owner (or the case's incident commander if it has no reachable owner) once, ahead of the deadline, when the item is due within the lead window (E-03d). This fires before the item lapses; the overdue reminder still fires if it does. Read-only over case data. Takes effect within a few minutes of saving.", "false"),
        new SettingDefinition("Notifications:DueSoonScan:LeadHours", "Due-soon lead window (hours)", "Notifications", SettingKind.Int,
            "How far ahead of an item's due date to remind (default 24 = \"due within a day\"). An item is reminded once as it enters this window. Takes effect within a few minutes of saving.", "24"),
        new SettingDefinition("Notifications:DueSoonScan:IntervalHours", "Due-soon scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between due-soon scans. Keep this no larger than the lead window so an item can't jump from future to overdue between passes without a due-soon reminder. Default 6. Takes effect within a few minutes of saving.", "6"),
        new SettingDefinition("Notifications:DeadlineScan:Enabled", "Regulatory deadline reminders", "Notifications", SettingKind.Bool,
            "When on, a background scan reminds a case's incident commander and assignees as its regulatory notification deadline (PROD-07) approaches, and again if it passes — once per band. Also requires the deadline clock on (Administration → Regulatory deadlines) and a reachable recipient. Read-only over case data — it records nothing and never changes case state; a human still records the reported milestone. Takes effect within a few minutes of saving.", "false"),
        new SettingDefinition("Notifications:DeadlineScan:IntervalHours", "Deadline scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between regulatory-deadline scans. A notification window is time-critical (a 72-hour clock can move through its bands inside a day), so keep this small. Default 1. Takes effect within a few minutes of saving.", "1"),
        new SettingDefinition("Notifications:StaleScan:Enabled", "Stale-case nudges", "Notifications", SettingKind.Bool,
            "When on, a background scan nudges a case's incident commander and assignees once when an open case has had no recorded activity (any audited case work) for longer than its severity's threshold below. A new activity re-arms the nudge. Read-only over case data — it records nothing and never changes case state. Takes effect within a few minutes of saving.", "false"),
        new SettingDefinition("Notifications:StaleScan:IntervalHours", "Stale-case scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between stale-case scans. Staleness is measured in days, so this can be slow. Default 12. Takes effect within a few minutes of saving.", "12"),
        new SettingDefinition("Notifications:StaleScan:Days:Critical", "Stale after — Critical (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a Critical case is nudged as stale. 0 disables the nudge for Critical cases.", "2"),
        new SettingDefinition("Notifications:StaleScan:Days:High", "Stale after — High (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a High case is nudged as stale. 0 disables the nudge for High cases.", "5"),
        new SettingDefinition("Notifications:StaleScan:Days:Medium", "Stale after — Medium (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a Medium case is nudged as stale. 0 disables the nudge for Medium cases.", "10"),
        new SettingDefinition("Notifications:StaleScan:Days:Low", "Stale after — Low (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a Low case is nudged as stale. 0 disables the nudge for Low cases.", "21"),
        new SettingDefinition("Notifications:DigestScan:Enabled", "Personal work digests", "Notifications", SettingKind.Bool,
            "When on, users who opt in (account menu → Notifications) receive a consolidated digest of their open follow-up items — overdue / due today / due this week — on their chosen daily or weekly cadence, in place of a scatter of per-item reminders. This is the master switch; each user still chooses their own cadence (default off). Read-only over case data. Takes effect within a few minutes of saving.", "false"),
        new SettingDefinition("Notifications:DigestScan:IntervalHours", "Digest scan interval (hours)", "Notifications", SettingKind.Int,
            "How often to check whether a user's digest is due. A digest still sends only once per period (day/week); a small interval just means it goes out promptly. Default 1. Takes effect within a few minutes of saving.", "1"),
        new SettingDefinition("Notifications:Mandatory:Assignment", "Mandatory: assignment emails", "Notifications", SettingKind.Bool,
            "When on, assignment emails are enforced org-wide — users cannot opt out of them under their own account preferences. Off = each user may turn their assignment emails off.", "false"),
        new SettingDefinition("Notifications:Mandatory:Overdue", "Mandatory: overdue reminders", "Notifications", SettingKind.Bool,
            "When on, per-item overdue after-action reminders are enforced org-wide — users cannot opt out (and a digest subscriber still gets them). Off = each user may turn them off (or rely on their digest).", "false"),
        new SettingDefinition("Notifications:Mandatory:DueSoon", "Mandatory: due-soon reminders", "Notifications", SettingKind.Bool,
            "When on, per-item due-soon after-action reminders are enforced org-wide — users cannot opt out. Off = each user may turn them off (or rely on their digest).", "false"),
        new SettingDefinition("App:BaseUrl", "Public base URL", "Notifications", SettingKind.Text,
            "Absolute URL of this deployment (e.g. https://casebook.corp.example), used to build direct links and the logo in notification emails. Blank = emails omit links and the hosted logo (they still render, branded, with a text wordmark). No trailing slash needed.", ""),
        // PROD-02: which notification types are also broadcast to the team chat channel. These only deliver
        // when a chat webhook is configured on the host (Chat:Webhook, server-side); they post to that shared
        // channel and are independent of email. All off by default.
        new SettingDefinition("Notifications:Chat:BreachEscalations", "Chat: breach escalations", "Notifications", SettingKind.Bool,
            "When on, a Breach escalation is also posted to the team chat channel (Slack/Teams). Broadcasts to the shared channel independent of the Legal/Privacy email distribution. Requires a chat webhook configured on the host (Chat:Webhook).", "false"),
        new SettingDefinition("Notifications:Chat:Assignments", "Chat: assignments", "Notifications", SettingKind.Bool,
            "When on, a case assignment is also posted to the team chat channel. A shared-channel broadcast (not a direct message), independent of the per-assignee assignment email. Requires a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:Mentions", "Chat: comment mentions", "Notifications", SettingKind.Bool,
            "When on, an @mention in a case discussion comment is also posted to the team chat channel (in addition to emailing the mentioned people). Requires a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:OverdueReminders", "Chat: overdue reminders", "Notifications", SettingKind.Bool,
            "When on, each overdue after-action scan posts a short summary (count of newly-overdue items) to the team chat channel, in addition to the per-owner emails. Requires a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:DueSoonReminders", "Chat: due-soon reminders", "Notifications", SettingKind.Bool,
            "When on, each due-soon scan posts a short summary to the team chat channel, in addition to the per-owner emails. Requires a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:DeadlineReminders", "Chat: regulatory deadline reminders", "Notifications", SettingKind.Bool,
            "When on, each regulatory-deadline scan posts a short urgent summary (cases at risk / past deadline) to the team chat channel, in addition to the per-recipient emails. Requires a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:StaleReminders", "Chat: stale-case nudges", "Notifications", SettingKind.Bool,
            "When on, each stale-case scan posts a short summary (count of quiet cases) to the team chat channel, in addition to the per-recipient emails. Requires a chat webhook on the host.", "false"),
        new SettingDefinition("ExternalLinks:DetectionCaseUrlTemplate", "Detection case link template", "Integrations", SettingKind.Text,
            "Deep-link template for the referenced detection-source case. Use {0} where the case id should appear.", ""),
        new SettingDefinition("ExternalLinks:VirusTotalUrlTemplate", "VirusTotal lookup template", "Integrations", SettingKind.Text,
            "Indicator lookup template. Use {0} where the indicator value should appear.", "https://www.virustotal.com/gui/search/{0}"),
        new SettingDefinition("Retention:CaseYears", "Case retention (years)", "Retention", SettingKind.Int,
            "How long closed cases are retained before becoming eligible for archival. A legal hold always overrides this.", "7"),
        new SettingDefinition("Integrity:AutoSeal:Enabled", "Auto-seal enabled", "Integrity", SettingKind.Bool,
            "Whether the background job periodically verifies the audit chain and records a signed seal.", "true"),
        new SettingDefinition("Integrity:AutoSeal:IntervalHours", "Auto-seal interval (hours)", "Integrity", SettingKind.Int,
            "Hours between signed seals of the audit chain. Verification and tamper-alarming run continuously " +
            "(about every 10 minutes) regardless, so this interval only bounds how much recent history is not " +
            "yet covered by a seal — not how quickly a tamper is detected. Takes effect within a few minutes of saving.", "6"),
        new SettingDefinition("Integrity:EvidenceVerify:Enabled", "Evidence re-verification enabled", "Integrity", SettingKind.Bool,
            "Whether the background job periodically re-hashes stored evidence and alarms when the bytes no longer " +
            "match their recorded SHA-256 (F-17). Off by default — a full re-hash of the evidence store is I/O-heavy. " +
            "The recorded hash is protected by the audit chain, so this catches bit-rot or tampering of the files themselves. " +
            "Alerts go to the same distribution as the audit-chain alarm. Takes effect within a few minutes of saving.", "false"),
        new SettingDefinition("Integrity:EvidenceVerify:IntervalHours", "Evidence re-verification interval (hours)", "Integrity", SettingKind.Int,
            "Hours between full re-verification passes over the evidence store. Deliberately slow (default daily) " +
            "because each pass re-hashes every stored file. A pass also runs once at startup. Takes effect within a few minutes of saving.", "24"),
        new SettingDefinition("Sla:Containment:Critical", "Containment — Critical (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for Critical cases. Blank disables the SLA for this severity.", "4"),
        new SettingDefinition("Sla:Containment:High", "Containment — High (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for High cases. Blank disables the SLA for this severity.", "12"),
        new SettingDefinition("Sla:Containment:Medium", "Containment — Medium (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for Medium cases. Blank disables the SLA for this severity.", "24"),
        new SettingDefinition("Sla:Containment:Low", "Containment — Low (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for Low cases. Blank disables the SLA for this severity.", "72"),
        new SettingDefinition("Sla:Resolution:Critical", "Resolution — Critical (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for Critical cases. Blank disables the SLA for this severity.", "24"),
        new SettingDefinition("Sla:Resolution:High", "Resolution — High (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for High cases. Blank disables the SLA for this severity.", "72"),
        new SettingDefinition("Sla:Resolution:Medium", "Resolution — Medium (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for Medium cases. Blank disables the SLA for this severity.", "168"),
        new SettingDefinition("Sla:Resolution:Low", "Resolution — Low (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for Low cases. Blank disables the SLA for this severity.", "336"),
        // PROD-08: detection SLA (occurred → detected). Blank by default: dwell targets are an org choice.
        new SettingDefinition("Sla:Detection:Critical", "Detection — Critical (hours)", "Response SLA", SettingKind.Int,
            "Target hours from when activity began (Occurred) to detection for Critical cases. Measured only when the occurred time is recorded. Blank disables it."),
        new SettingDefinition("Sla:Detection:High", "Detection — High (hours)", "Response SLA", SettingKind.Int,
            "Target hours from when activity began (Occurred) to detection for High cases. Measured only when the occurred time is recorded. Blank disables it."),
        new SettingDefinition("Sla:Detection:Medium", "Detection — Medium (hours)", "Response SLA", SettingKind.Int,
            "Target hours from when activity began (Occurred) to detection for Medium cases. Measured only when the occurred time is recorded. Blank disables it."),
        new SettingDefinition("Sla:Detection:Low", "Detection — Low (hours)", "Response SLA", SettingKind.Int,
            "Target hours from when activity began (Occurred) to detection for Low cases. Measured only when the occurred time is recorded. Blank disables it."),
        new SettingDefinition("Sla:AtRiskThresholdPercent", "At-risk threshold (%)", "Response SLA", SettingKind.Int,
            "How much of a target must elapse before an open case is flagged \"at risk\" (e.g. 80 = flag once 80% of the target time has passed). 1–100.", "80"),
        // PROD-08: optional per-classification targets — Breach cases only, falling back to the general target.
        new SettingDefinition("Sla:Breach:Containment:Critical", "Breach cases: containment — Critical (hours)", "Response SLA — Breach cases", SettingKind.Int,
            "Overrides the containment target for Critical cases classified Breach (detection to containment). Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Containment:High", "Breach cases: containment — High (hours)", "Response SLA — Breach cases", SettingKind.Int,
            "Overrides the containment target for High cases classified Breach (detection to containment). Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Containment:Medium", "Breach cases: containment — Medium (hours)", "Response SLA — Breach cases", SettingKind.Int,
            "Overrides the containment target for Medium cases classified Breach (detection to containment). Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Containment:Low", "Breach cases: containment — Low (hours)", "Response SLA — Breach cases", SettingKind.Int,
            "Overrides the containment target for Low cases classified Breach (detection to containment). Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Resolution:Critical", "Breach cases: resolution — Critical (hours)", "Response SLA — Breach cases", SettingKind.Int,
            "Overrides the resolution target for Critical cases classified Breach (detection to resolution (recovery)). Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Resolution:High", "Breach cases: resolution — High (hours)", "Response SLA — Breach cases", SettingKind.Int,
            "Overrides the resolution target for High cases classified Breach (detection to resolution (recovery)). Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Resolution:Medium", "Breach cases: resolution — Medium (hours)", "Response SLA — Breach cases", SettingKind.Int,
            "Overrides the resolution target for Medium cases classified Breach (detection to resolution (recovery)). Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Resolution:Low", "Breach cases: resolution — Low (hours)", "Response SLA — Breach cases", SettingKind.Int,
            "Overrides the resolution target for Low cases classified Breach (detection to resolution (recovery)). Blank uses the general target."),

        // PROD-07 / UX-15: regulatory notification-deadline clock. Off by default; per-jurisdiction timers are
        // managed as reference data in the "Per-jurisdiction rules" editor on the same Regulatory deadlines page.
        // Group "Deadline clock" so the settings card reads clearly beneath the page's "Regulatory deadlines" title.
        // Takes effect within a few minutes of saving.
        new SettingDefinition("Compliance:NotificationDeadlines:Enabled", "Regulatory deadline clock", "Deadline clock", SettingKind.Bool,
            "Master switch for the regulatory notification-deadline countdown (per-jurisdiction, e.g. NYDFS Part 500 = 72h). " +
            "Off by default; when on, breach/material cases show a deadline to notify each triggered jurisdiction. Nothing auto-acts — it only surfaces and reminds.", "false"),
        new SettingDefinition("Compliance:NotificationDeadlines:StartBasis", "Clock starts from", "Deadline clock", SettingKind.Text,
            "What instant the clock is measured from: \"Determination\" (the materiality \"Material\" determination — NYDFS 500.17(a) / SEC Item 1.05; the clock runs only once a case is determined material) or " +
            "\"Detection\" (the detection timestamp, for a Breach-classified case). Defaults to Determination.", "Determination"),
        new SettingDefinition("Compliance:NotificationDeadlines:DefaultWindowHours", "Default window (hours)", "Deadline clock", SettingKind.Int,
            "The deadline window applied to any triggered jurisdiction that has no explicit rule in the Per-jurisdiction rules editor below, so a countdown always exists.", "72"),
        new SettingDefinition("Compliance:NotificationDeadlines:AtRiskThresholdPercent", "At-risk threshold (%)", "Deadline clock", SettingKind.Int,
            "How much of a jurisdiction's window must elapse before its deadline is flagged \"at risk\" (e.g. 80 = flag at 80% elapsed). 1–100.", "80"),

        new SettingDefinition("Severity:Label:Critical", "Critical label", "Severity labels", SettingKind.Text,
            "Display name shown for the Critical severity. The level, ordering, colour and SLA are unchanged; only the shown name varies (e.g. \"SEV-1\").", "Critical"),
        new SettingDefinition("Severity:Label:High", "High label", "Severity labels", SettingKind.Text,
            "Display name shown for the High severity.", "High"),
        new SettingDefinition("Severity:Label:Medium", "Medium label", "Severity labels", SettingKind.Text,
            "Display name shown for the Medium severity.", "Medium"),
        new SettingDefinition("Severity:Label:Low", "Low label", "Severity labels", SettingKind.Text,
            "Display name shown for the Low severity.", "Low"),
        new SettingDefinition("Severity:Label:Informational", "Informational label", "Severity labels", SettingKind.Text,
            "Display name shown for the Informational severity.", "Informational"),

        new SettingDefinition("Access:LogScope", "Access-log scope", "Access logging", SettingKind.Text,
            "How much read/access activity is recorded to the access log (C-05). One of: Off (log nothing), " +
            "RestrictedOnly (restricted-case opens plus all artifact/export access), or All (every case open and " +
            "artifact/export access). This log is out of the tamper-evident audit chain and prunable. Default: All.", "All"),
        new SettingDefinition("Access:CoalesceWindowMinutes", "Access-log coalesce window (minutes)", "Access logging", SettingKind.Int,
            "Repeated accesses of the same case/artifact by the same user within this many minutes fold into one " +
            "view-session row (with a count) instead of many rows, to keep the log readable. Default: 30.", "30"),
        new SettingDefinition("Security:IdleTimeoutMinutes", "Idle session timeout (minutes)", "Security", SettingKind.Int,
            "Lock the screen and tear down the live session after this many minutes with no keyboard or mouse activity, prompting the user to resume. Complements — does not replace — the workstation/AD screen-lock policy. Set 0 to disable the app-level timeout and rely on OS lock alone. Applies to sessions started after saving.", "15"),
        new SettingDefinition("Reporting:RequireSeparateApprover", "Require separate report approver", "Report defaults", SettingKind.Bool,
            "When on, a report must be approved by someone other than the analyst who generated it (two-person / maker-checker control). Off by default so small teams aren't blocked; the approver is recorded in the audit trail either way.", "false"),
        new SettingDefinition("Reporting:LessonsLegend", "Lessons-learned report legend", "Report defaults", SettingKind.Text,
            "Optional text printed at the top of every page of the lessons-learned report, e.g. \"Privileged & Confidential — Prepared at the Direction of Counsel\". Use wording your counsel has approved; a legend alone does not make a document privileged. Blank prints nothing. The case report is unaffected.", ""),
        new SettingDefinition("Reporting:SectionLayout", "Report sections", "Report defaults", SettingKind.Text,
            "Which report body sections are included, and in what order. Edited with the layout designer below; the document title, header/footer and integrity stamp always appear.", "", CustomEditor: true),
    };

    public static readonly IReadOnlyDictionary<string, SettingDefinition> ByKey =
        Editable.ToDictionary(d => d.Key, StringComparer.OrdinalIgnoreCase);

    /// <summary>The distinct groups in catalog order, for section layout in the UI.</summary>
    public static readonly IReadOnlyList<string> Groups =
        Editable.Select(d => d.Group).Distinct().ToList();

    public static bool IsEditable(string key) => ByKey.ContainsKey(key);

    /// <summary>
    /// Validates and canonicalizes a raw value for a setting. Throws <see cref="ArgumentException"/>
    /// with a user-facing message on invalid input. Returns the value as it should be stored.
    /// </summary>
    public static string? Normalize(SettingDefinition def, string? value)
    {
        var v = value?.Trim();
        switch (def.Kind)
        {
            case SettingKind.Bool:
                if (bool.TryParse(v, out var b)) return b ? "true" : "false";
                throw new ArgumentException($"{def.Label} must be true or false.");

            case SettingKind.Int:
                if (string.IsNullOrWhiteSpace(v)) return null;
                if (int.TryParse(v, out var n) && n >= 0) return n.ToString(CultureInfo.InvariantCulture);
                throw new ArgumentException($"{def.Label} must be a non-negative whole number.");

            case SettingKind.MultiText:
                if (string.IsNullOrWhiteSpace(v)) return "";
                var lines = v.Replace("\r\n", "\n").Split('\n')
                    .Select(x => x.Trim())
                    .Where(x => x.Length > 0);
                return string.Join("\n", lines);

            default:
                return v ?? "";
        }
    }
}
