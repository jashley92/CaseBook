using System.Globalization;
using IncidentManager.Application.Abstractions;

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
/// <param name="BlankIsOff">BUG-192: a value saved blank means none (an SLA target that's off), so it hides the
/// appsettings.json default instead of falling back to it. Only for settings read as raw strings: a bound int can't
/// take an empty value.</param>
/// <param name="EmailAddress">BUG-468: a single sender address, never blank; a display-name form is allowed.</param>
/// <param name="DomainList">CAP-28 exclusions: a list of domain names, one per line (a pasted "a, b" list is split).</param>
/// <param name="AddressRangeList">CAP-28 exclusions: a list of IPv4 or IPv6 ranges in CIDR form, one per line.</param>
public sealed record SettingDefinition(
    string Key,
    string Label,
    string Group,
    SettingKind Kind,
    string Description,
    string? Default = null,
    bool CustomEditor = false,
    IReadOnlyList<SettingOption>? Options = null,
    int Min = 0,
    int? Max = null,
    bool BlankIsOff = false,
    bool EmailList = false,
    bool LinkTemplate = false,
    bool AbsoluteUrl = false,
    bool EmailAddress = false,
    bool DomainList = false,
    bool AddressRangeList = false);

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
    // BUG-262: an interval, a wait or a window becomes a TimeSpan; "999999999" meant as "never" overflowed it and stopped
    // the app. A month is the longest interval any scan needs, a year the longest wait.
    public const int MaxIntervalHours = 24 * 31;
    public const int MaxWaitHours = 24 * 366;
    public const int MaxStaleDays = 366;

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
        // F-08: where calendar months and quarters begin (dashboard trend and drill-in, E-31 program report). DST follows the zone.
        new SettingDefinition("Organization:TimeZone", "Reporting time zone", "Organization", SettingKind.Text,
            "Where days, months and quarters begin: the dashboard trend, the quarterly program report and the daily digest. Daylight saving follows the zone. Set it once, before go-live: changing it later regroups past months and quarters, so a regenerated report won't match one already sent. Stored times and the audit trail stay in UTC.",
            "America/New_York",
            Options: [new("America/New_York", "Eastern (New York)"), new("America/Chicago", "Central (Chicago)"),
                new("America/Denver", "Mountain (Denver)"), new("America/Phoenix", "Mountain, no daylight saving (Phoenix)"),
                new("America/Los_Angeles", "Pacific (Los Angeles)"), new("America/Anchorage", "Alaska (Anchorage)"),
                new("Pacific/Honolulu", "Hawaii (Honolulu)"), new("UTC", "UTC"), new("Europe/London", "UK (London)"),
                new("Europe/Dublin", "Ireland (Dublin)"), new("Europe/Paris", "Central Europe (Paris)"),
                new("Asia/Kolkata", "India (Kolkata)"), new("Asia/Singapore", "Singapore"), new("Australia/Sydney", "Australia East (Sydney)")]),
        new SettingDefinition("Organization:DefaultJurisdictions", "Default jurisdictions", "Organization", SettingKind.Text,
            "Pre-fills affected jurisdictions on a case's impact assessment when none are set, for example \"NY, NJ, PA\". Editable per case.", ""),

        new SettingDefinition("Email:Enabled", "Send email", "Notifications", SettingKind.Bool,
            "When off, notifications are logged, not delivered.", "false"),
        new SettingDefinition("Email:From", "From address", "Notifications", SettingKind.Text,
            "Envelope-from address for outbound notifications, for example casebook@contoso.com or CaseBook <casebook@contoso.com>.",
            "incident-manager@localhost", EmailAddress: true),
        new SettingDefinition("Email:LegalDistribution", "Legal / Privacy distribution", "Notifications", SettingKind.MultiText,
            "Emailed when a case is escalated to Breach. One address per line (a pasted \"a@x; b@x\" list is split).", "",
            EmailList: true),
        new SettingDefinition("Email:IntegrityAlertDistribution", "Integrity-alert distribution", "Notifications", SettingKind.MultiText,
            "Emailed if the audit hash chain fails verification, a possible sign of tampering. One address per line. A critical SIEM event is sent either way.", "",
            EmailList: true),
        new SettingDefinition("Email:AssignmentNotifications", "Assignment notifications", "Notifications", SettingKind.Bool,
            "Emails people when they're assigned to a case. Self-assignments are skipped. Needs an email address on file and Send email on.", "false"),
        new SettingDefinition("Notifications:OverdueScan:Enabled", "Overdue task reminders", "Notifications", SettingKind.Bool,
            "Emails a task's owner once when it passes its due date, or the incident commander if the owner can't be reached. Records nothing on the case.", "false"),
        new SettingDefinition("Notifications:OverdueScan:IntervalHours", "Overdue scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between overdue scans. Default 24 (0 also means 24).", "24", Max: MaxIntervalHours),
        // PROD-03: escalation chain for items that stay overdue. Notifications only; nothing is reassigned.
        new SettingDefinition("Notifications:OverdueScan:Escalation:Enabled", "Escalate items that stay overdue", "Notifications", SettingKind.Bool,
            "Emails the incident commander, then managers, when an overdue task stays open past the hours below. Nothing is reassigned. Needs overdue reminders on.", "false"),
        new SettingDefinition("Notifications:OverdueScan:Escalation:IncidentCommanderAfterHours", "Escalate to incident commander after (hours overdue)", "Notifications", SettingKind.Int,
            "Hours past the due date before the case's incident commander is emailed. 0 skips this step.", "48", Max: MaxWaitHours),
        new SettingDefinition("Notifications:OverdueScan:Escalation:ManagersAfterHours", "Escalate to managers after (hours overdue)", "Notifications", SettingKind.Int,
            "Hours past the due date before everyone with the Manager role is emailed. 0 skips this step.", "120", Max: MaxWaitHours),
        new SettingDefinition("Notifications:DueSoonScan:Enabled", "Due-soon task reminders", "Notifications", SettingKind.Bool,
            "Emails a task's owner once when it comes due within the lead window, or the incident commander if the owner can't be reached.", "false"),
        new SettingDefinition("Notifications:DueSoonScan:LeadHours", "Due-soon lead window (hours)", "Notifications", SettingKind.Int,
            "How far ahead of the due date to send the reminder. Default 24 (due within a day).", "24", Max: MaxWaitHours),
        new SettingDefinition("Notifications:DueSoonScan:IntervalHours", "Due-soon scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between due-soon scans. Keep this at or below the lead window so no item skips its reminder. Default 6 (0 also means 6).", "6", Max: MaxIntervalHours),
        new SettingDefinition("Notifications:DeadlineScan:Enabled", "Regulatory deadline reminders", "Notifications", SettingKind.Bool,
            "Reminds the incident commander and assignees as a case's regulatory deadline nears, and again if it passes. Needs the deadline clock on under Regulatory deadlines. Reminders only; someone still records when notice was given.", "false"),
        new SettingDefinition("Notifications:DeadlineScan:IntervalHours", "Deadline scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between deadline scans. Keep this small, since a 72-hour clock can pass through its bands in a day. Default 1 (0 also means 1).", "1", Max: MaxIntervalHours),
        new SettingDefinition("Notifications:StaleScan:Enabled", "Stale-case nudges", "Notifications", SettingKind.Bool,
            "Nudges the incident commander and assignees once when an open case has no activity for longer than its severity's threshold below. New activity resets the nudge.", "false"),
        new SettingDefinition("Notifications:StaleScan:IntervalHours", "Stale-case scan interval (hours)", "Notifications", SettingKind.Int,
            "Hours between stale-case scans. Default 12 (0 also means 12).", "12", Max: MaxIntervalHours),
        new SettingDefinition("Notifications:StaleScan:Days:Critical", "Stale after: Critical (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a Critical case is nudged as stale. 0 disables the nudge for Critical cases.", "2", Max: MaxStaleDays),
        new SettingDefinition("Notifications:StaleScan:Days:High", "Stale after: High (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a High case is nudged as stale. 0 disables the nudge for High cases.", "5", Max: MaxStaleDays),
        new SettingDefinition("Notifications:StaleScan:Days:Medium", "Stale after: Medium (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a Medium case is nudged as stale. 0 disables the nudge for Medium cases.", "10", Max: MaxStaleDays),
        new SettingDefinition("Notifications:StaleScan:Days:Low", "Stale after: Low (days)", "Notifications", SettingKind.Int,
            "Days of no activity before a Low case is nudged as stale. 0 disables the nudge for Low cases.", "21", Max: MaxStaleDays),
        new SettingDefinition("Notifications:DigestScan:Enabled", "Personal work digests", "Notifications", SettingKind.Bool,
            "Master switch for opt-in digests of each user's open follow-up items (overdue, due today, due this week). Users choose daily or weekly under account menu → Notifications.", "false"),
        new SettingDefinition("Notifications:DigestScan:IntervalHours", "Digest scan interval (hours)", "Notifications", SettingKind.Int,
            "How often to check whether a digest is due. Each digest still sends once per day or week. Default 1 (0 also means 1).", "1", Max: MaxIntervalHours),
        // CAP-01: an API import that waits is found only when someone opens Import.
        new SettingDefinition("Notifications:DigestScan:ImportWaitingHours", "Digest: imports waiting longer than (hours)", "Notifications", SettingKind.Int,
            "The digest of someone who can confirm imports says how many API imports they could review have waited longer than this. 0 leaves the line out. Default 24.", "24", Max: MaxWaitHours),
        new SettingDefinition("Notifications:ImportSubmitted:Email", "Email reviewers about new imports", "Notifications", SettingKind.Bool,
            "Emails everyone who can confirm imports when a case-import document arrives through the API. One into a restricted case goes only to those who can see it. Nothing is applied until someone confirms it.", "false"),
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
            "This deployment's absolute URL, for example https://casebook.corp.example. Used for links and the logo in emails. Blank sends emails without links or the hosted logo.", "", AbsoluteUrl: true),
        // PROD-02: which notification types are also broadcast to the team chat channel. These only deliver
        // when a chat webhook is configured on the host (Chat:Webhook, server-side); they post to that shared
        // channel and are independent of email. All off by default.
        // BUG-100: a tabletop escalated to Breach either tests the real alert paths, marked, or stays inside CaseBook.
        new SettingDefinition("Notifications:ExerciseEscalation", "Exercise escalations", "Notifications", SettingKind.Text,
            "What an exercise case escalated to Breach sends: the Legal / Privacy email, the chat alert and the SIEM event as for a real case, each marked EXERCISE, or none of them. The escalation is recorded on the case either way.",
            "Tag",
            Options: [new("Tag", "Send them, marked EXERCISE"), new("Skip", "Don't send them")]),
        new SettingDefinition("Notifications:Chat:BreachEscalations", "Chat: breach escalations", "Notifications", SettingKind.Bool,
            "Posts Breach escalations to the team chat channel (Slack/Teams), separately from the Legal / Privacy email. Needs a chat webhook on the host (Chat:Webhook).", "false"),
        new SettingDefinition("Notifications:Chat:Assignments", "Chat: assignments", "Notifications", SettingKind.Bool,
            "Posts case assignments to the shared team channel, not as direct messages. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:Mentions", "Chat: note mentions", "Notifications", SettingKind.Bool,
            "Posts @mentions in case notes to the team channel. The people mentioned are still emailed. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:OverdueReminders", "Chat: overdue reminders", "Notifications", SettingKind.Bool,
            "Posts a count of newly overdue items to the team channel after each overdue scan. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:DueSoonReminders", "Chat: due-soon reminders", "Notifications", SettingKind.Bool,
            "Posts a summary to the team channel after each due-soon scan. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:DeadlineReminders", "Chat: regulatory deadline reminders", "Notifications", SettingKind.Bool,
            "Posts cases at risk of or past their regulatory deadline to the team channel after each scan. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("Notifications:Chat:StaleReminders", "Chat: stale-case nudges", "Notifications", SettingKind.Bool,
            "Posts a count of quiet cases to the team channel after each stale-case scan. Needs a chat webhook on the host.", "false"),
        // CAP-01
        new SettingDefinition("Notifications:Chat:ImportSubmissions", "Chat: imports waiting for review", "Notifications", SettingKind.Bool,
            "Posts to the team channel when a case-import document arrives through the API. For a restricted case it says only that one is waiting. Needs a chat webhook on the host.", "false"),
        new SettingDefinition("ExternalLinks:DetectionCaseUrlTemplate", "Detection case link template", "Integrations", SettingKind.Text,
            "Deep-link template for the referenced detection-source case: a full https:// address with {0} where the case id should appear.", "", LinkTemplate: true),
        new SettingDefinition("ExternalLinks:VirusTotalUrlTemplate", "VirusTotal lookup template", "Integrations", SettingKind.Text,
            "Indicator lookup template: a full https:// address with {0} where the indicator value should appear.", "https://www.virustotal.com/gui/search/{0}", LinkTemplate: true),
        // CAP-28 exclusions: CaseBook can't tell the organization's own domains and ranges from an attacker's, so they were
        // suggested as "possibly related" across every case. Read live (IRelatedExclusionsProvider).
        // CAP-28 discovery: the domains' static default stays blank; while nothing is saved (nor in the settings file) the
        // provider uses the domains found on the network (IOrganizationDomains), which are never stored, so never exported.
        new SettingDefinition(RelatedExclusionSettings.DomainsKey, "Your organization's domains", "Related indicators", SettingKind.MultiText,
            "Domains that are yours, one per line, for example contoso.com and corp.contoso.local. Each covers every name under it " +
            "(mail.contoso.com, a@corp.contoso.com), not notcontoso.com. A domain, URL, email address or account on one is never " +
            "used to suggest possibly related indicators, and nothing is suggested because of it. Until you save a list, the " +
            "domains found on this server's network (its Active Directory domain, forest and trusts) are used; once saved, " +
            "blank included, yours is.", "",
            DomainList: true),
        new SettingDefinition(RelatedExclusionSettings.RangesKey, "Excluded address ranges", "Related indicators", SettingKind.MultiText,
            "Address ranges in CIDR form, one per line, for example 10.0.0.0/8 or fd00::/8. An address inside one, or a URL on " +
            "one, is never related by its /24 or /48. The default lists the private (RFC 1918), loopback, link-local and unique " +
            "local ranges, which every organization uses; add your own public ranges, or clear the list to relate everything.",
            string.Join("\n", Domain.Observables.RelatedExclusions.DefaultRanges), AddressRangeList: true),
        new SettingDefinition(RelatedExclusionSettings.FreeMailKey, "Leave out free mail providers", "Related indicators", SettingKind.Bool,
            "Two addresses at Gmail, Outlook.com, Yahoo, iCloud, Proton and the like say nothing about who sent them, so they " +
            "aren't related by their email domain. Default on.", "true"),
        // CAP-10: read by the retention review (Administration › Retention review) and its nightly count. Never purges.
        new SettingDefinition("Retention:CaseYears", "Case retention (years)", "Retention", SettingKind.Int,
            "How long after closing a case is listed under Administration › Retention review, for an administrator to archive. " +
            "Nothing is archived or deleted automatically, and a case under a legal hold or with a regulatory notice not yet " +
            "recorded can't be archived. 0 turns the review off. Default 7.", "7", Max: 100),
        new SettingDefinition("Notifications:RetentionReview:Email", "Monthly retention-review email to Legal", "Retention", SettingKind.Bool,
            "Once a month, when closed cases are past the case retention period, emails the Legal / Privacy distribution how many " +
            "are waiting for review (a count only, no case named). Nothing is archived by it.", "false"),
        // PROD-52: the access log (who opened a case, downloaded evidence or a report, exported) is outside the audit chain
        // and grew without limit.
        new SettingDefinition("Retention:AccessLogYears", "Access log retention (years)", "Retention", SettingKind.Int,
            "How long the access log (who opened which case, downloaded which file, exported what) is kept. Older entries are " +
            "deleted nightly, except for cases under a legal hold. 0 keeps it forever. Check your own record-keeping rules " +
            "(some apply six years to access logs). Default 3.", "3", Max: 100),
        // CAP-31: a decided import's submitted document (up to 5 MB) was kept for good.
        new SettingDefinition("Retention:DecidedImportDays", "Decided import retention (days)", "Retention", SettingKind.Int,
            "How long an applied or rejected import keeps the document it was sent with. After that it's cleared nightly; who sent " +
            "it, who decided, when, why and the case it went into are kept. Imports waiting for review or being applied keep " +
            "theirs. 0 keeps every document. Default 90.", "90", Max: Import.DecidedImportRetention.MaxDays),
        // F-12: two-person control for lifting a legal hold. Off by default.
        new SettingDefinition("Governance:LegalHoldRelease:RequireSecondApprover", "Second approver to release a legal hold", "Retention", SettingKind.Bool,
            "When on, releasing a legal hold is a request with a reason that a different person with Manage Legal must approve. Placing a hold stays a single action.", "false"),
        new SettingDefinition("Integrity:AutoSeal:Enabled", "Auto-seal enabled", "Integrity", SettingKind.Bool,
            "Periodically verifies the audit chain and records a signed seal.", "true"),
        new SettingDefinition("Integrity:AutoSeal:IntervalHours", "Auto-seal interval (hours)", "Integrity", SettingKind.Int,
            "Hours between signed seals. Tamper checks still run about every 10 minutes (the whole audit chain re-hashed every 6 hours). This only limits " +
            "how much recent history waits for a seal. Default 6 (0 also means 6). Applies within a few minutes.", "6", Max: MaxIntervalHours),
        // PROD-55: how large a file, and how much evidence in all, the store takes (EvidenceRoom).
        new SettingDefinition("Evidence:MaxUploadMB", "Largest evidence file (MB)", "Evidence storage", SettingKind.Int,
            "The largest single file that can be uploaded as evidence, in MB. Files over 100 MB upload in parts with a progress " +
            "bar. Up to 65,536 (64 GB). Default 500.", "500", Min: 1, Max: 65_536),
        new SettingDefinition("Evidence:StorageQuotaGB", "Evidence storage limit (GB)", "Evidence storage", SettingKind.Int,
            "The most all stored evidence may take, in GB. An upload that would go past it is refused, and uploaders are warned " +
            "at 90 %. 0 is no limit. Two uploads at once may together go slightly over.", "0", Max: 1_000_000),
        new SettingDefinition("Evidence:MinFreeSpaceGB", "Free space to keep on the evidence store (GB)", "Evidence storage", SettingKind.Int,
            "An upload is refused if it would leave less than this free on the evidence store's disk or share. Default 10.",
            "10", Max: 1_000_000),
        new SettingDefinition("Evidence:ReadBackCheck", "Re-check large uploads before recording them", "Evidence storage", SettingKind.Bool,
            "Reads a file uploaded in parts back from the store and checks its SHA-256 before recording it, so a write damaged " +
            "on its way to a network share is caught at once. Doubles the reads for large files. Default on.", "true"),
        // PROD-58: the safe download, a zip with the password "infected".
        new SettingDefinition("Evidence:SafeDownload", "Safe download as the main button", "Evidence storage", SettingKind.Text,
            "Which evidence files download by default inside a zip with the password 'infected', so a double-click can't run them and " +
            "the analyst's antivirus doesn't delete them on arrival. Programs, scripts, shortcuts, disk images, Office files with " +
            "macros and web pages count as risky. The zip and the plain file are both always available.", "RiskyTypes",
            Options: [new("RiskyTypes", "Risky files only"), new("Always", "Every file"), new("Off", "No file (offer the zip beside it)")]),
        new SettingDefinition("Integrity:EvidenceVerify:Enabled", "Evidence re-verification enabled", "Integrity", SettingKind.Bool,
            "Periodically re-hashes stored evidence and alerts if a file no longer matches its recorded SHA-256. " +
            "Off by default because a full pass is I/O-heavy. Alerts go to the integrity-alert distribution.", "false"),
        new SettingDefinition("Integrity:EvidenceVerify:IntervalHours", "Evidence re-verification interval (hours)", "Integrity", SettingKind.Int,
            "Hours between runs. Each run re-hashes a share of the stored files (see the full-pass setting), and one also runs at " +
            "startup. Default 24 (0 also means 24).", "24", Max: MaxIntervalHours),
        new SettingDefinition("Integrity:EvidenceVerify:PassDays", "Evidence re-verification full pass (days)", "Integrity", SettingKind.Int,
            "Every stored file is re-hashed at least once in this many days: each run checks its share, so the disk reads spread out. " +
            "1 re-hashes everything on every run. A damaged or swapped file is found within this time (up to twice it after a long " +
            "outage). Default 7.", "7", Min: 1, Max: 90),
        // PROD-49: the update check. Off by default; the repository and any proxy stay server-side (Updates:Repository, Updates:Proxy).
        new SettingDefinition("Updates:CheckEnabled", "Check for new releases", "Updates", SettingKind.Bool,
            "Asks GitHub (api.github.com) which CaseBook releases are newer than this one and shows them here with their notes. " +
            "One anonymous request; nothing about this installation is sent. The server needs outbound HTTPS, or a proxy in Updates:Proxy.", "false"),
        new SettingDefinition("Updates:CheckIntervalHours", "Check interval (hours)", "Updates", SettingKind.Int,
            "Hours between checks. Default 24.", "24", Min: 6, Max: 168),
        new SettingDefinition("Sla:Containment:Critical", "Containment: Critical (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for Critical cases. Blank disables the SLA for this severity.", "4", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Containment:High", "Containment: High (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for High cases. Blank disables the SLA for this severity.", "12", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Containment:Medium", "Containment: Medium (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for Medium cases. Blank disables the SLA for this severity.", "24", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Containment:Low", "Containment: Low (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to containment for Low cases. Blank disables the SLA for this severity.", "72", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Resolution:Critical", "Resolution: Critical (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for Critical cases. Blank disables the SLA for this severity.", "24", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Resolution:High", "Resolution: High (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for High cases. Blank disables the SLA for this severity.", "72", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Resolution:Medium", "Resolution: Medium (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for Medium cases. Blank disables the SLA for this severity.", "168", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Resolution:Low", "Resolution: Low (hours)", "Response SLA", SettingKind.Int,
            "Target hours from detection to resolution (recovery) for Low cases. Blank disables the SLA for this severity.", "336", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        // PROD-08: detection SLA (occurred → detected). Blank by default: dwell targets are an org choice.
        new SettingDefinition("Sla:Detection:Critical", "Detection: Critical (hours)", "Response SLA", SettingKind.Int,
            "Target hours from Occurred to detection for Critical cases, measured only when Occurred is recorded. Blank disables it.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Detection:High", "Detection: High (hours)", "Response SLA", SettingKind.Int,
            "Target hours from Occurred to detection for High cases, measured only when Occurred is recorded. Blank disables it.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Detection:Medium", "Detection: Medium (hours)", "Response SLA", SettingKind.Int,
            "Target hours from Occurred to detection for Medium cases, measured only when Occurred is recorded. Blank disables it.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Detection:Low", "Detection: Low (hours)", "Response SLA", SettingKind.Int,
            "Target hours from Occurred to detection for Low cases, measured only when Occurred is recorded. Blank disables it.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:AtRiskThresholdPercent", "At-risk threshold (%)", "Response SLA", SettingKind.Int,
            "Percent of a target that must elapse before an open case is flagged at risk (1–100).", "80", Min: 1, Max: 100),
        // PROD-08: optional per-classification targets — Breach cases only, falling back to the general target.
        new SettingDefinition("Sla:Breach:Containment:Critical", "Breach containment: Critical (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the containment target for Critical cases Breach cases. Blank uses the general target.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Breach:Containment:High", "Breach containment: High (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the containment target for High cases Breach cases. Blank uses the general target.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Breach:Containment:Medium", "Breach containment: Medium (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the containment target for Medium cases Breach cases. Blank uses the general target.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Breach:Containment:Low", "Breach containment: Low (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the containment target for Low cases Breach cases. Blank uses the general target.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Breach:Resolution:Critical", "Breach resolution: Critical (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the resolution target for Critical cases Breach cases. Blank uses the general target.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Breach:Resolution:High", "Breach resolution: High (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the resolution target for High cases Breach cases. Blank uses the general target.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Breach:Resolution:Medium", "Breach resolution: Medium (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the resolution target for Medium cases Breach cases. Blank uses the general target.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),
        new SettingDefinition("Sla:Breach:Resolution:Low", "Breach resolution: Low (hours)", "Breach SLA overrides", SettingKind.Int,
            "Overrides the resolution target for Low cases Breach cases. Blank uses the general target.", Max: Sla.SlaPolicy.MaxTargetHours, BlankIsOff: true),

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
            "Window used for any triggered jurisdiction without its own rule below (1 to 8,760 hours, as a rule's window is).", "72",
            Min: 1, Max: NotificationRuleService.MaxWindowHours),   // REV-48
        new SettingDefinition("Compliance:NotificationDeadlines:AtRiskThresholdPercent", "At-risk threshold (%)", "Deadline clock", SettingKind.Int,
            "Percent of a jurisdiction's window that must elapse before its deadline is flagged at risk (1–100).", "80", Min: 1, Max: 100),

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
            "with a count. Default 30; 0 also means 30, so the shortest window is 1 minute.", "30", Max: 1440),
        new SettingDefinition("Security:IdleTimeoutMinutes", "Idle session timeout (minutes)", "Security", SettingKind.Int,
            "Locks the app after this many minutes without keyboard or mouse activity. Works alongside the workstation screen lock, not instead of it. 0 turns it off; at most 1,440 (a day). Applies to new sessions.", "15",
            Min: 0, Max: Security.IdleTimeoutPolicy.MaxMinutes),   // REV-46
        // CAP-15: the periodic user-access review (NYDFS 500.7), recorded under Roles & access.
        new SettingDefinition("Governance:AccessReview:ReminderDays", "Access review reminder (days)", "Security", SettingKind.Int,
            "Diagnostics reminds that the access review is due when none has been recorded under Roles & access in this many days. " +
            "0 turns the reminder off. Default 90.", "90", Max: AccessReviewService.MaxReminderDays),
        new SettingDefinition("Reporting:RequireSeparateApprover", "Require separate report approver", "Report defaults", SettingKind.Bool,
            "When on, a report must be approved by someone other than the analyst who generated it. The approver is audited either way.", "false"),
        new SettingDefinition("Reporting:LessonsLegend", "Lessons-learned report legend", "Report defaults", SettingKind.Text,
            "Printed at the top of every page of the lessons-learned report (not the case report), for example \"Prepared at the Direction of Counsel\". Use counsel-approved wording. A legend alone doesn't make a document privileged.", ""),
        new SettingDefinition("Reporting:DefangIndicators", "Defang indicators in reports", "Report defaults", SettingKind.Bool,
            "Prints URLs, domains, IPs and email addresses defanged (hxxp://, [.], [at]) in case and lessons-learned reports so they can't become live links. IOC CSV, STIX and import files keep live values.", "true"),
        new SettingDefinition("Reporting:IncludeMilestones", "Include response milestones", "Report defaults", SettingKind.Bool,
            "Adds classification, severity and phase changes, stage gates, the materiality decision, reporting to regulators, completed tasks and evidence to the report's investigation timeline, dated when they happened.", "true"),
        new SettingDefinition("Reporting:MarkLateEntries", "Mark entries recorded later", "Report defaults", SettingKind.Bool,
            "Adds a short \"Recorded …\" note to timeline entries and milestones entered more than an hour after they happened. The audit trail keeps both times either way.", "true"),
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

    /// <summary>Why <paramref name="value"/> breaks the setting's rules, or null when it's acceptable.</summary>
    public static string? Problem(SettingDefinition def, string? value)
    {
        try { Normalize(def, value); return null; }
        catch (ArgumentException ex) { return ex.Message; }
    }

    /// <summary>
    /// Administrable settings whose current value breaks today's rules, for example one saved before a limit existed
    /// or set in appsettings. Such a value blocks saving its Administration section until it's corrected.
    /// <paramref name="read"/> returns a key's effective value; blank values (the default applies) are skipped.
    /// </summary>
    public static IReadOnlyList<(SettingDefinition Definition, string Value, string Problem)> FindInvalid(Func<string, string?> read) =>
        Editable
            .Select(d => (Definition: d, Value: read(d.Key)))
            // BUG-468: a blank sender address isn't "the default applies"; it's what every send would use, and fails.
            .Where(x => !string.IsNullOrWhiteSpace(x.Value) || (x.Value is not null && x.Definition.EmailAddress))
            .Select(x => (x.Definition, Value: x.Value!, Problem: Problem(x.Definition, x.Value)))
            .Where(x => x.Problem is not null)
            .Select(x => (x.Definition, x.Value, x.Problem!))
            .ToList();

    /// <summary>A time zone's name as the reporting time zone list shows it, or its id when it isn't listed.</summary>
    public static string TimeZoneLabel(TimeZoneInfo zone) =>
        ByKey["Organization:TimeZone"].Options!.FirstOrDefault(o => string.Equals(o.Value, zone.Id, StringComparison.OrdinalIgnoreCase))?.Label
        ?? zone.Id;

    /// <summary>
    /// Validates and canonicalizes a raw value for a setting. Throws <see cref="ArgumentException"/>
    /// with a user-facing message on invalid input. Returns the value as it should be stored.
    /// </summary>
    // BUG-241: a distribution list holds addresses and nothing else. .NET reads "legal@corp.com; privacy@corp.com" as one
    // address (privacy@, with "legal@corp.com;" as its display name), so Legal silently missed breach emails; and a line
    // that isn't an address failed the send to everyone on the list. Lists pasted with ; or , are split here.
    private static IEnumerable<string> EmailAddresses(SettingDefinition def, IEnumerable<string> lines)
    {
        var addresses = lines.SelectMany(l => l.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToList();
        foreach (var a in addresses)
            if (!System.Net.Mail.MailAddress.TryCreate(a, out var parsed) || !string.Equals(parsed.Address, a, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException($"{def.Label}: \"{a}\" isn't an email address. Put one address per line, like legal@contoso.com.");
        return addresses.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    // CAP-28 exclusions: a list of domains or ranges, pasted one per line or as "a, b; c d". Each entry is stored as the
    // rule reads it (lowercased, canonical), once; one that isn't refuses the save with the entry named.
    private delegate string? EntryNormalizer(string? entry, out string? problem);

    private static IEnumerable<string> ListEntries(SettingDefinition def, IEnumerable<string> lines, EntryNormalizer normalize)
    {
        var entries = new List<string>();
        foreach (var e in lines.SelectMany(l => l.Split([';', ',', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))
        {
            if (normalize(e, out var problem) is not { } stored)
                throw new ArgumentException($"{def.Label}: \"{e}\" {problem}");
            entries.Add(stored);
        }
        return entries.Distinct(StringComparer.Ordinal);
    }

    private static string? SenderProblem(string? v)
    {
        if (string.IsNullOrEmpty(v))
            return "enter an address, like casebook@contoso.com. Use Reset to go back to the default.";
        // "a@x; b@x" parses as one address (b@x) named "a@x;", so a pasted list is refused rather than half-used: a "," or
        // ";" outside quotes, or an unquoted name holding an "@" ("a@x b@x"). A quoted name may hold either
        // ("IR @ Contoso" <ir@contoso.com>), as MailAddress, and so the sender, accepts it.
        if (!System.Net.Mail.MailAddress.TryCreate(v, out var parsed) || LooksLikeAList(v)
            || (parsed.DisplayName.Contains('@') && !v.StartsWith('"')))
            return $"\"{v}\" isn't one email address. Use one address, like casebook@contoso.com or CaseBook <casebook@contoso.com>.";
        return null;
    }

    private static bool LooksLikeAList(string v)
    {
        var quoted = false;
        var angle = v.IndexOf('<');
        for (var i = 0; i < v.Length; i++)
        {
            var c = v[i];
            // A backslash-escaped quote doesn't end the quoted name.
            if (c == '"' && (i == 0 || v[i - 1] != '\\')) quoted = !quoted;
            else if (!quoted && (c == ',' || c == ';')) return true;
            else if (!quoted && c == '@' && angle > i) return true;   // an "@" in an unquoted name before <address>
        }
        return false;
    }

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
                if (int.TryParse(v, out var n) && n >= def.Min && (def.Max is null || n <= def.Max))
                    return n.ToString(CultureInfo.InvariantCulture);
                throw new ArgumentException(def.Max is { } max
                    ? $"{def.Label} must be a whole number from {def.Min} to {max:N0}."
                    : $"{def.Label} must be a whole number ({def.Min} or more).");

            case SettingKind.MultiText:
                if (string.IsNullOrWhiteSpace(v)) return "";
                var lines = v.Replace("\r\n", "\n").Split('\n')
                    .Select(x => x.Trim())
                    .Where(x => x.Length > 0);
                if (def.EmailList) lines = EmailAddresses(def, lines);
                if (def.DomainList) lines = ListEntries(def, lines, Domain.Observables.RelatedExclusions.NormalizeDomain);
                if (def.AddressRangeList) lines = ListEntries(def, lines, Domain.Observables.RelatedExclusions.NormalizeRange);
                return string.Join("\n", lines);

            default:
                // BUG-264: a link template is a full http(s) address with {0} in it; the base URL a full http(s) address.
                if (def.LinkTemplate && Content.LinkTemplate.Problem(v) is { } problem)
                    throw new ArgumentException($"{def.Label}: {problem}");
                // BUG-468: every email is sent from this address, so one that doesn't parse stops all of them, Legal's included.
                if (def.EmailAddress && SenderProblem(v) is { } sender)
                    throw new ArgumentException($"{def.Label}: {sender}");
                if (def.AbsoluteUrl && !string.IsNullOrEmpty(v)
                    && !(Uri.TryCreate(v, UriKind.Absolute, out var url) && (url.Scheme == Uri.UriSchemeHttps || url.Scheme == Uri.UriSchemeHttp)))
                    throw new ArgumentException($"{def.Label}: use a full http:// or https:// address, like https://casebook.contoso.com.");
                // A fixed-choice setting only takes one of its listed values (canonical casing); blank uses the default.
                if (def.Options is { } options && !string.IsNullOrEmpty(v))
                    return options.FirstOrDefault(o => string.Equals(o.Value, v, StringComparison.OrdinalIgnoreCase))?.Value
                           ?? throw new ArgumentException($"{def.Label} must be one of the listed options.");
                return v ?? "";
        }
    }
}
