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
        new SettingDefinition("Notifications:DueSoonScan:Enabled", "Due-soon after-action reminders", "Notifications", SettingKind.Bool,
            "When on, a background scan emails each after-action item's owner (or the case's incident commander if it has no reachable owner) once, ahead of the deadline, when the item is due within the lead window (E-03d). This fires before the item lapses; the overdue reminder still fires if it does. Read-only over case data. Takes effect within a few minutes of saving.", "false"),
        new SettingDefinition("Notifications:DueSoonScan:LeadHours", "Due-soon lead window (hours)", "Notifications", SettingKind.Int,
            "How far ahead of an item's due date to remind (default 24 = \"due within a day\"). An item is reminded once as it enters this window. Takes effect within a few minutes of saving.", "24"),
        new SettingDefinition("Notifications:DueSoonScan:IntervalHours", "Due-soon scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between due-soon scans. Keep this no larger than the lead window so an item can't jump from future to overdue between passes without a due-soon reminder. Default 6. Takes effect within a few minutes of saving.", "6"),
        new SettingDefinition("App:BaseUrl", "Public base URL", "Notifications", SettingKind.Text,
            "Absolute URL of this deployment (e.g. https://casebook.corp.example), used to build direct links and the logo in notification emails. Blank = emails omit links and the hosted logo (they still render, branded, with a text wordmark). No trailing slash needed.", ""),
        // PROD-02: which notification types are also broadcast to the team chat channel. These only deliver
        // when a chat webhook is configured on the host (Chat:Webhook, server-side); they post to that shared
        // channel and are independent of email. All off by default.
        new SettingDefinition("Notifications:Chat:BreachEscalations", "Chat: breach escalations", "Notifications", SettingKind.Bool,
            "When on, a Breach escalation is also posted to the team chat channel (Slack/Teams). Broadcasts to the shared channel independent of the Legal/Privacy email distribution. Requires a chat webhook configured on the host (Chat:Webhook).", "false"),
        new SettingDefinition("Notifications:Chat:Assignments", "Chat: assignments", "Notifications", SettingKind.Bool,
            "When on, a case assignment is also posted to the team chat channel. A shared-channel broadcast (not a direct message), independent of the per-assignee assignment email. Requires a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:OverdueReminders", "Chat: overdue reminders", "Notifications", SettingKind.Bool,
            "When on, each overdue after-action scan posts a short summary (count of newly-overdue items) to the team chat channel, in addition to the per-owner emails. Requires a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:DueSoonReminders", "Chat: due-soon reminders", "Notifications", SettingKind.Bool,
            "When on, each due-soon scan posts a short summary to the team chat channel, in addition to the per-owner emails. Requires a chat webhook on the host.", "false"),
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
        new SettingDefinition("Sla:AtRiskThresholdPercent", "At-risk threshold (%)", "Response SLA", SettingKind.Int,
            "How much of a target must elapse before an open case is flagged \"at risk\" (e.g. 80 = flag once 80% of the target time has passed). 1–100.", "80"),

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
        new SettingDefinition("Reporting:RequireSeparateApprover", "Require separate report approver", "Reporting", SettingKind.Bool,
            "When on, a report must be approved by someone other than the analyst who generated it (two-person / maker-checker control). Off by default so small teams aren't blocked; the approver is recorded in the audit trail either way.", "false"),
        new SettingDefinition("Reporting:SectionLayout", "Report sections", "Reporting", SettingKind.Text,
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
