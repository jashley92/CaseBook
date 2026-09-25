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
    bool CustomEditor = false,
    IReadOnlyList<SettingOption>? Options = null);

/// <summary>One allowed value of a fixed-choice text setting, shown as a dropdown instead of a free-text box.</summary>
public sealed record SettingOption(string Value, string Label);

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
        new SettingDefinition("Reporting:OrganizationName", "Organization name", "Organization", SettingKind.Text,
            "Printed on the first line of the report header and used as the app's white-label name. Blank shows a [Company Name] placeholder.", ""),
        new SettingDefinition("Reporting:TeamName", "Team name", "Organization", SettingKind.Text,
            "Printed under the organization name in the report header, for example \"Cyber Defense\". Blank shows a [Team Name] placeholder.", ""),
        new SettingDefinition("ExternalLinks:DetectionSourceLabel", "Detection source label", "Organization", SettingKind.Text,
            "Name of your detection system, for example \"SIEM\" or \"EDR\". Shown on the case workspace and new-case form. Set its link template under Integrations.", "SIEM"),
        // Brand palette (X-08): edited with the colour pickers in the Brand card, not the generic text
        // renderer (CustomEditor). Blank = the built-in charcoal + gold defaults. Only the brand/accent
        // roles vary; the semantic status palette (severity/phase/danger) is never rebranded.
        new SettingDefinition("Branding:AccentColor", "Brand accent color", "Organization", SettingKind.Text,
            "Used for links, active states, focus rings and highlights. Blank uses the built-in gold.", "", CustomEditor: true),
        new SettingDefinition("Branding:InkColor", "Primary action color", "Organization", SettingKind.Text,
            "Used for primary buttons and structural ink. Blank uses the built-in charcoal.", "", CustomEditor: true),
        new SettingDefinition("Organization:DefaultJurisdictions", "Default jurisdictions", "Organization", SettingKind.Text,
            "Pre-fills affected jurisdictions on a case's impact assessment when none are set, for example \"NY, NJ, PA\". Editable per case.", ""),

        new SettingDefinition("Email:Enabled", "Send email", "Notifications", SettingKind.Bool,
            "When off, notifications are logged, not delivered.", "false"),
        new SettingDefinition("Email:From", "From address", "Notifications", SettingKind.Text,
            "Envelope-from address for outbound notifications.", "incident-manager@localhost"),
        new SettingDefinition("Email:LegalDistribution", "Legal / Privacy distribution", "Notifications", SettingKind.MultiText,
            "Emailed when a case is escalated to Breach. One address per line.", ""),
        new SettingDefinition("Email:IntegrityAlertDistribution", "Integrity-alert distribution", "Notifications", SettingKind.MultiText,
            "Emailed if the audit hash chain fails verification, a possible sign of tampering. One address per line. A critical SIEM event is sent either way.", ""),
        new SettingDefinition("Email:AssignmentNotifications", "Assignment notifications", "Notifications", SettingKind.Bool,
            "Emails people when they're assigned to a case. Self-assignments are skipped. Needs an email address on file and Send email on.", "false"),
        new SettingDefinition("Notifications:OverdueScan:Enabled", "Overdue task reminders", "Notifications", SettingKind.Bool,
            "Emails a task's owner once when it passes its due date, or the incident commander if the owner can't be reached. Records nothing on the case.", "false"),
        new SettingDefinition("Notifications:OverdueScan:IntervalHours", "Overdue scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between overdue scans. Default 24.", "24"),
        // PROD-03: escalation chain for items that stay overdue. Notifications only; nothing is reassigned.
        new SettingDefinition("Notifications:OverdueScan:Escalation:Enabled", "Escalate items that stay overdue", "Notifications", SettingKind.Bool,
            "Emails the incident commander, then managers, when an overdue task stays open past the hours below. Nothing is reassigned. Needs overdue reminders on.", "false"),
        new SettingDefinition("Notifications:OverdueScan:Escalation:IncidentCommanderAfterHours", "Escalate to incident commander after (hours overdue)", "Notifications", SettingKind.Int,
            "Hours past the due date before the case's incident commander is emailed. 0 skips this step.", "48"),
        new SettingDefinition("Notifications:OverdueScan:Escalation:ManagersAfterHours", "Escalate to managers after (hours overdue)", "Notifications", SettingKind.Int,
            "Hours past the due date before everyone with the Manager role is emailed. 0 skips this step.", "120"),
        new SettingDefinition("Notifications:DueSoonScan:Enabled", "Due-soon task reminders", "Notifications", SettingKind.Bool,
            "Emails a task's owner once when it comes due within the lead window, or the incident commander if the owner can't be reached.", "false"),
        new SettingDefinition("Notifications:DueSoonScan:LeadHours", "Due-soon lead window (hours)", "Notifications", SettingKind.Int,
            "How far ahead of the due date to send the reminder. Default 24 (due within a day).", "24"),
        new SettingDefinition("Notifications:DueSoonScan:IntervalHours", "Due-soon scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between due-soon scans. Keep this at or below the lead window so no item skips its reminder. Default 6.", "6"),
        new SettingDefinition("Notifications:DeadlineScan:Enabled", "Regulatory deadline reminders", "Notifications", SettingKind.Bool,
            "Reminds the incident commander and assignees as a case's regulatory deadline nears, and again if it passes. Needs the deadline clock on under Regulatory deadlines. Reminders only; someone still records when notice was given.", "false"),
        new SettingDefinition("Notifications:DeadlineScan:IntervalHours", "Deadline scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between deadline scans. Keep this small, since a 72-hour clock can pass through its bands in a day. Default 1.", "1"),
        new SettingDefinition("Notifications:StaleScan:Enabled", "Stale-case nudges", "Notifications", SettingKind.Bool,
            "Nudges the incident commander and assignees once when an open case has no activity for longer than its severity's threshold below. New activity resets the nudge.", "false"),
        new SettingDefinition("Notifications:StaleScan:IntervalHours", "Stale-case scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between stale-case scans. Default 12.", "12"),
        new SettingDefinition("Notifications:StaleScan:Days:Critical", "Stale after: Critical (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a Critical case is nudged as stale. 0 disables the nudge for Critical cases.", "2"),
        new SettingDefinition("Notifications:StaleScan:Days:High", "Stale after: High (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a High case is nudged as stale. 0 disables the nudge for High cases.", "5"),
        new SettingDefinition("Notifications:StaleScan:Days:Medium", "Stale after: Medium (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a Medium case is nudged as stale. 0 disables the nudge for Medium cases.", "10"),
        new SettingDefinition("Notifications:StaleScan:Days:Low", "Stale after: Low (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a Low case is nudged as stale. 0 disables the nudge for Low cases.", "21"),
        new SettingDefinition("Notifications:DigestScan:Enabled", "Personal work digests", "Notifications", SettingKind.Bool,
            "Master switch for opt-in digests of each user's open follow-up items (overdue, due today, due this week). Users choose daily or weekly under account menu → Notifications.", "false"),
        new SettingDefinition("Notifications:DigestScan:IntervalHours", "Digest scan interval (hours)", "Notifications", SettingKind.Int,
            "How often to check whether a digest is due. Each digest still sends once per day or week. Default 1.", "1"),
        // PROD-15: quarterly executive report email to managers (the E-31 program report's headline figures).
        new SettingDefinition("Notifications:ExecutiveReport:Enabled", "Quarterly executive report email", "Notifications", SettingKind.Bool,
            "In the first week of each quarter, emails everyone with the Manager role last quarter's headline figures and a link to the full program report.", "false"),
        new SettingDefinition("Notifications:Mandatory:Assignment", "Mandatory: assignment emails", "Notifications", SettingKind.Bool,
            "When on, users can't turn off assignment emails.", "false"),
        new SettingDefinition("Notifications:Mandatory:Overdue", "Mandatory: overdue reminders", "Notifications", SettingKind.Bool,
            "When on, users can't turn off per-item overdue reminders, even if they get a digest.", "false"),
        new SettingDefinition("Notifications:Mandatory:DueSoon", "Mandatory: due-soon reminders", "Notifications", SettingKind.Bool,
            "When on, users can't turn off per-item due-soon reminders.", "false"),
        new SettingDefinition("App:BaseUrl", "Public base URL", "Notifications", SettingKind.Text,
            "This deployment's absolute URL, for example https://casebook.corp.example. Used for links and the logo in emails. Blank sends emails without links or the hosted logo.", ""),
        // PROD-02: which notification types are also broadcast to the team chat channel. These only deliver
        // when a chat webhook is configured on the host (Chat:Webhook, server-side); they post to that shared
        // channel and are independent of email. All off by default.
        new SettingDefinition("Notifications:Chat:BreachEscalations", "Chat: breach escalations", "Notifications", SettingKind.Bool,
            "Posts Breach escalations to the team chat channel (Slack/Teams), separately from the Legal / Privacy email. Needs a chat webhook on the host (Chat:Webhook).", "false"),
        new SettingDefinition("Notifications:Chat:Assignments", "Chat: assignments", "Notifications", SettingKind.Bool,
            "Posts case assignments to the shared team channel, not as direct messages. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:Mentions", "Chat: comment mentions", "Notifications", SettingKind.Bool,
            "Posts @mentions in case comments to the team channel. The people mentioned are still emailed. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:OverdueReminders", "Chat: overdue reminders", "Notifications", SettingKind.Bool,
            "Posts a count of newly overdue items to the team channel after each overdue scan. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:DueSoonReminders", "Chat: due-soon reminders", "Notifications", SettingKind.Bool,
            "Posts a summary to the team channel after each due-soon scan. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:DeadlineReminders", "Chat: regulatory deadline reminders", "Notifications", SettingKind.Bool,
            "Posts cases at risk of or past their regulatory deadline to the team channel after each scan. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:StaleReminders", "Chat: stale-case nudges", "Notifications", SettingKind.Bool,
            "Posts a count of quiet cases to the team channel after each stale-case scan. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("ExternalLinks:DetectionCaseUrlTemplate", "Detection case link template", "Integrations", SettingKind.Text,
            "Deep-link template for the referenced detection-source case. Use {0} where the case id should appear.", ""),
        new SettingDefinition("ExternalLinks:VirusTotalUrlTemplate", "VirusTotal lookup template", "Integrations", SettingKind.Text,
            "Indicator lookup template. Use {0} where the indicator value should appear.", "https://www.virustotal.com/gui/search/{0}"),
        new SettingDefinition("Retention:CaseYears", "Case retention (years)", "Retention", SettingKind.Int,
            "How long closed cases are kept before they can be archived. A legal hold always overrides this.", "7"),
        // F-12: two-person control for lifting a legal hold. Off by default.
        new SettingDefinition("Governance:LegalHoldRelease:RequireSecondApprover", "Second approver to release a legal hold", "Retention", SettingKind.Bool,
            "When on, releasing a legal hold is a request with a reason that a different person with Manage Legal must approve. Placing a hold stays a single action.", "false"),
        new SettingDefinition("Integrity:AutoSeal:Enabled", "Auto-seal enabled", "Integrity", SettingKind.Bool,
            "Periodically verifies the audit chain and records a signed seal.", "true"),
        new SettingDefinition("Integrity:AutoSeal:IntervalHours", "Auto-seal interval (hours)", "Integrity", SettingKind.Int,
            "Hours between signed seals. Tamper checks still run about every 10 minutes. This only limits " +
            "how much recent history waits for a seal. Applies within a few minutes.", "6"),
        new SettingDefinition("Integrity:EvidenceVerify:Enabled", "Evidence re-verification enabled", "Integrity", SettingKind.Bool,
            "Periodically re-hashes stored evidence and alerts if a file no longer matches its recorded SHA-256. " +
            "Off by default because a full pass is I/O-heavy. Alerts go to the integrity-alert distribution.", "false"),
        new SettingDefinition("Integrity:EvidenceVerify:IntervalHours", "Evidence re-verification interval (hours)", "Integrity", SettingKind.Int,
            "Hours between full passes. Each pass re-hashes every stored file, so keep it slow. " +
            "A pass also runs at startup. Default 24.", "24"),
        new SettingDefinition("Sla:Containment:Critical", "Containment: Critical (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for Critical cases. Blank disables the SLA for this severity.", "4"),
        new SettingDefinition("Sla:Containment:High", "Containment: High (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for High cases. Blank disables the SLA for this severity.", "12"),
        new SettingDefinition("Sla:Containment:Medium", "Containment: Medium (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for Medium cases. Blank disables the SLA for this severity.", "24"),
        new SettingDefinition("Sla:Containment:Low", "Containment: Low (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for Low cases. Blank disables the SLA for this severity.", "72"),
        new SettingDefinition("Sla:Resolution:Critical", "Resolution: Critical (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for Critical cases. Blank disables the SLA for this severity.", "24"),
        new SettingDefinition("Sla:Resolution:High", "Resolution: High (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for High cases. Blank disables the SLA for this severity.", "72"),
        new SettingDefinition("Sla:Resolution:Medium", "Resolution: Medium (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for Medium cases. Blank disables the SLA for this severity.", "168"),
        new SettingDefinition("Sla:Resolution:Low", "Resolution: Low (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for Low cases. Blank disables the SLA for this severity.", "336"),
        // PROD-08: detection SLA (occurred → detected). Blank by default: dwell targets are an org choice.
        new SettingDefinition("Sla:Detection:Critical", "Detection: Critical (hours)", "Response SLA", SettingKind.Int,
            "Target hours from Occurred to detection for Critical cases, measured only when Occurred is recorded. Blank disables it."),
        new SettingDefinition("Sla:Detection:High", "Detection: High (hours)", "Response SLA", SettingKind.Int,
            "Target hours from Occurred to detection for High cases, measured only when Occurred is recorded. Blank disables it."),
        new SettingDefinition("Sla:Detection:Medium", "Detection: Medium (hours)", "Response SLA", SettingKind.Int,
            "Target hours from Occurred to detection for Medium cases, measured only when Occurred is recorded. Blank disables it."),
        new SettingDefinition("Sla:Detection:Low", "Detection: Low (hours)", "Response SLA", SettingKind.Int,
            "Target hours from Occurred to detection for Low cases, measured only when Occurred is recorded. Blank disables it."),
        new SettingDefinition("Sla:AtRiskThresholdPercent", "At-risk threshold (%)", "Response SLA", SettingKind.Int,
            "Percent of a target that must elapse before an open case is flagged at risk (1–100).", "80"),
        // PROD-08: optional per-classification targets — Breach cases only, falling back to the general target.
        new SettingDefinition("Sla:Breach:Containment:Critical", "Breach containment: Critical (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the containment target for Critical cases Breach cases. Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Containment:High", "Breach containment: High (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the containment target for High cases Breach cases. Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Containment:Medium", "Breach containment: Medium (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the containment target for Medium cases Breach cases. Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Containment:Low", "Breach containment: Low (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the containment target for Low cases Breach cases. Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Resolution:Critical", "Breach resolution: Critical (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the resolution target for Critical cases Breach cases. Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Resolution:High", "Breach resolution: High (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the resolution target for High cases Breach cases. Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Resolution:Medium", "Breach resolution: Medium (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the resolution target for Medium cases Breach cases. Blank uses the general target."),
        new SettingDefinition("Sla:Breach:Resolution:Low", "Breach resolution: Low (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the resolution target for Low cases Breach cases. Blank uses the general target."),

        // PROD-07 / UX-15: regulatory notification-deadline clock. Off by default; per-jurisdiction timers are
        // managed as reference data in the "Per-jurisdiction rules" editor on the same Regulatory deadlines page.
        // Group "Deadline clock" so the settings card reads clearly beneath the page's "Regulatory deadlines" title.
        // Takes effect within a few minutes of saving.
        new SettingDefinition("Compliance:NotificationDeadlines:Enabled", "Regulatory deadline clock", "Deadline clock", SettingKind.Bool,
            "Master switch for the per-jurisdiction notification-deadline countdown, for example 72 hours for NYDFS Part 500. " +
            "When on, breach and material cases show a deadline for each triggered jurisdiction. It displays and reminds. It never notifies anyone.", "false"),
        new SettingDefinition("Compliance:NotificationDeadlines:StartBasis", "Clock starts from", "Deadline clock", SettingKind.Text,
            "Determination starts the clock when a case is determined Material (NYDFS 500.17(a), SEC Item 1.05). " +
            "Detection starts it at detection, for Breach-classified cases.", "Determination",
            Options: [new("Determination", "Materiality determination"), new("Detection", "Detection")]),
        new SettingDefinition("Compliance:NotificationDeadlines:DefaultWindowHours", "Default window (hours)", "Deadline clock", SettingKind.Int,
            "Window used for any triggered jurisdiction without its own rule below.", "72"),
        new SettingDefinition("Compliance:NotificationDeadlines:AtRiskThresholdPercent", "At-risk threshold (%)", "Deadline clock", SettingKind.Int,
            "Percent of a jurisdiction's window that must elapse before its deadline is flagged at risk (1–100).", "80"),

        new SettingDefinition("Severity:Label:Critical", "Critical label", "Severity labels", SettingKind.Text,
            "Display name for Critical, for example \"SEV-1\". Level, order, color and SLA don't change.", "Critical"),
        new SettingDefinition("Severity:Label:High", "High label", "Severity labels", SettingKind.Text,
            "Display name shown for the High severity.", "High"),
        new SettingDefinition("Severity:Label:Medium", "Medium label", "Severity labels", SettingKind.Text,
            "Display name shown for the Medium severity.", "Medium"),
        new SettingDefinition("Severity:Label:Low", "Low label", "Severity labels", SettingKind.Text,
            "Display name shown for the Low severity.", "Low"),
        new SettingDefinition("Severity:Label:Informational", "Informational label", "Severity labels", SettingKind.Text,
            "Display name shown for the Informational severity.", "Informational"),

        new SettingDefinition("Access:LogScope", "Access-log scope", "Access logging", SettingKind.Text,
            "Which views are logged. Artifact and export access is always logged unless this is off. " +
            "This log sits outside the audit chain and can be pruned.", "All",
            Options: [new("All", "Every case open"), new("RestrictedOnly", "Restricted-case opens only"), new("Off", "Off")]),
        new SettingDefinition("Access:CoalesceWindowMinutes", "Access-log coalesce window (minutes)", "Access logging", SettingKind.Int,
            "Repeat views of the same case or artifact by the same user within this window fold into one row " +
            "with a count. Default 30.", "30"),
        new SettingDefinition("Security:IdleTimeoutMinutes", "Idle session timeout (minutes)", "Security", SettingKind.Int,
            "Locks the app after this many minutes without keyboard or mouse activity. Works alongside the workstation screen lock, not instead of it. 0 turns it off. Applies to new sessions.", "15"),
        new SettingDefinition("Reporting:RequireSeparateApprover", "Require separate report approver", "Report defaults", SettingKind.Bool,
            "When on, a report must be approved by someone other than the analyst who generated it. The approver is audited either way.", "false"),
        new SettingDefinition("Reporting:LessonsLegend", "Lessons-learned report legend", "Report defaults", SettingKind.Text,
            "Printed at the top of every page of the lessons-learned report (not the case report), for example \"Prepared at the Direction of Counsel\". Use counsel-approved wording. A legend alone doesn't make a document privileged.", ""),
        new SettingDefinition("Reporting:DefangIndicators", "Defang indicators in reports", "Report defaults", SettingKind.Bool,
            "Prints URLs, domains, IPs and email addresses defanged (hxxp://, [.], [at]) in case and lessons-learned reports so they can't become live links. IOC CSV, STIX and import files keep live values.", "true"),
        new SettingDefinition("Reporting:DefaultTlp", "Default TLP marking", "Report defaults", SettingKind.Text,
            "TLP marking for new reports unless the analyst picks another. Printed on every page.", "AMBER",
            Options: [new("CLEAR", "TLP:CLEAR"), new("GREEN", "TLP:GREEN"), new("AMBER", "TLP:AMBER"), new("AMBER+STRICT", "TLP:AMBER+STRICT"), new("RED", "TLP:RED")]),
        new SettingDefinition("Reporting:SectionLayout", "Report sections", "Report defaults", SettingKind.Text,
            "Which report sections appear, and in what order. Edited with the layout designer below.", "", CustomEditor: true),
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
                throw new ArgumentException($"{def.Label} must be a whole number (0 or more).");

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
