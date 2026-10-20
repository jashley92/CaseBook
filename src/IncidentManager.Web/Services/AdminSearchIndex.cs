using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Web.Components.Layout;
using IncidentManager.Web.Components.Pages;

namespace IncidentManager.Web.Services;

/// <summary>One thing Administration search found: a setting, a page, or a server-only setting (set on the host).</summary>
public sealed record AdminSearchHit(AdminSearchKind Kind, string Title, string Where, string Href, string? Key);

public enum AdminSearchKind
{
    Setting,
    Page,
    ServerSetting,
}

/// <summary>
/// Where things are in Administration, and searching it: every in-app setting (its label, key, help, group and page, plus
/// a few everyday words such as "upload size"), every page in the rail, and the server-only settings (which land on Server
/// configuration, "set on the host"). Used by the search box on the overview and the rail, and by the command palette. A
/// result lands on its page scrolled to the setting (the control's id is its key), and so do Diagnostics' fix links and
/// errors that name the setting behind them.
/// </summary>
public static class AdminSearchIndex
{
    private static readonly IReadOnlyDictionary<string, (string Href, string Title)> SectionByGroup =
        Admin.Sections.SelectMany(s => s.Groups.Select(g => (g, s.Href, s.Title)))
            .ToDictionary(x => x.g, x => (x.Href, x.Title), StringComparer.Ordinal);

    /// <summary>The page a setting is edited on, scrolled to it (the control's id is its key); Setting sources if it has none.</summary>
    public static string SettingHref(string key) =>
        SettingsCatalog.ByKey.TryGetValue(key, out var def) && SectionByGroup.TryGetValue(def.Group, out var s)
            ? $"{s.Href}#{key}"
            : "admin/settings/source";

    /// <summary>The title of the page a setting is edited on.</summary>
    public static string? SectionTitle(string key) =>
        SettingsCatalog.ByKey.TryGetValue(key, out var def) && SectionByGroup.TryGetValue(def.Group, out var s) ? s.Title : null;

    // Everyday words for what a setting or page is called here.
    private static readonly IReadOnlyDictionary<string, string> Synonyms = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Evidence:MaxUploadMB"] = "upload size file size max upload largest limit",
        ["Evidence:ReinstateWithinDays"] = "withdraw withdrawn reinstate undo restore soft delete purge retention",
        ["Evidence:StorageQuotaGB"] = "quota disk space storage limit full",
        ["Evidence:MinFreeSpaceGB"] = "disk space free space reserve full",
        ["Evidence:SafeDownload"] = "zip infected malware password",
        ["Email:Enabled"] = "smtp mail send email on",
        ["Email:From"] = "smtp sender mail",
        ["App:BaseUrl"] = "url hostname link base address",
        ["Security:IdleTimeoutMinutes"] = "timeout session lock logout sign out",
        ["Organization:TimeZone"] = "timezone tz clock",
        ["Retention:CaseYears"] = "archive purge keep",
        ["Search:Mode"] = "full-text fulltext",
        ["Reporting:OrganizationName"] = "company name",
        ["Reporting:DefaultTlp"] = "traffic light protocol",
        ["Access:LogScope"] = "who viewed opened",
        ["Integrity:AutoSeal:Enabled"] = "seal signature",
        ["Admin:Identity"] = "logo colour color theme brand organization name",
        ["Admin:Roles"] = "ad groups users permissions people access review",
        ["Admin:ApiTokens"] = "api key token",
        ["Admin:EmailTemplates"] = "email subject body wording",
        ["Admin:Diagnostics"] = "health status problems errors backups jobs",
        ["Admin:Updates"] = "upgrade version release",
        ["Admin:Server"] = "appsettings host configuration connection string paths",
        ["Admin:Integrations"] = "siem chat webhook virustotal detection",
    };

    private static readonly IReadOnlyDictionary<string, string> PageSynonymKeys = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["admin/settings/identity"] = "Admin:Identity",
        ["admin/roles"] = "Admin:Roles",
        ["admin/api-tokens"] = "Admin:ApiTokens",
        ["admin/email-templates"] = "Admin:EmailTemplates",
        ["admin/settings/diagnostics"] = "Admin:Diagnostics",
        ["admin/settings/updates"] = "Admin:Updates",
        ["admin/settings/server"] = "Admin:Server",
        ["admin/settings/integrations"] = "Admin:Integrations",
    };

    // Server-only settings: set on the host, never in Administration (ADR 0007), so they land on Server configuration.
    private static readonly (string Label, string Key, string Words)[] ServerSettings =
    [
        ("Database connection string", "ConnectionStrings:Default", "sql server database connection"),
        ("Evidence store folder", "EvidenceStore:RootPath", "evidence path share folder"),
        ("Seal signing key", "Integrity:SigningKey", "signing key certificate pem cyberark"),
        ("Audit chain key", "Integrity:ChainKey", "chain key hmac"),
        ("Evidence encryption", "Storage:Encryption", "encrypt evidence key recovery certificate"),
        ("SIEM webhook", "Siem:Webhook", "siem splunk sentinel collector http"),
        ("SIEM syslog", "Siem:Syslog", "siem syslog cef tls"),
        ("SIEM Windows Event Log", "Siem:EventLog", "siem event log"),
        ("Team chat webhook switch", "Chat:Webhook:Enabled", "chat slack teams"),
        ("CyberArk", "Secrets:CyberArk", "secrets vault ccp"),
        ("Email relay host and port", "Email:SmtpHost", "smtp relay host port tls"),
        ("Authentication mode", "Auth:Mode", "windows sign-in login"),
        ("Update check proxy", "Updates:Proxy", "proxy internet"),
        ("Agenda feed key", "Agenda:FeedKey", "calendar ics outlook subscription"),
    ];

    /// <summary>The rail's pages: title, where, and its group.</summary>
    public static IEnumerable<(string Title, string Href, string Group)> Pages =>
        AdminLayout.AllGroups.SelectMany(g => g.Items.Select(i => (i.Title, i.Href, g.Label)));

    /// <summary>
    /// The best matches for <paramref name="query"/>, best first: every word must appear somewhere in the entry. Labels and
    /// page titles rank above keys and everyday words, and those above help text.
    /// </summary>
    public static IReadOnlyList<AdminSearchHit> Search(string? query, ISeverityLabels? labels = null, int max = 8)
    {
        var words = (query ?? "").Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (words.Length == 0 || string.Join("", words).Length < 2) return [];

        var hits = new List<(int Score, AdminSearchHit Hit)>();
        foreach (var (title, href, group) in Pages)
        {
            var words2 = PageSynonymKeys.TryGetValue(href, out var sk) ? Synonyms[sk] : "";
            if (Score(words, title, $"{group} {words2}", "") is { } score)
                hits.Add((score + 5, new AdminSearchHit(AdminSearchKind.Page, title, group, href, null)));
        }
        foreach (var def in SettingsCatalog.Editable)
        {
            if (!SectionByGroup.TryGetValue(def.Group, out var section)) continue;
            var label = labels is null ? def.Label : AdminSettingsDisplay.Label(def, labels);
            var where = def.Group == section.Title ? section.Title : $"{section.Title} › {def.Group}";
            if (Score(words, label, $"{def.Key} {def.Group} {section.Title} {Synonyms.GetValueOrDefault(def.Key)}", def.Description) is { } score)
                hits.Add((score, new AdminSearchHit(AdminSearchKind.Setting, label, where, $"{section.Href}#{def.Key}", def.Key)));
        }
        foreach (var (label, key, extra) in ServerSettings)
        {
            if (Score(words, label, $"{key} {extra}", "") is { } score)
                hits.Add((score - 1, new AdminSearchHit(AdminSearchKind.ServerSetting, label, "Server configuration · set on the host", "admin/settings/server", key)));
        }
        return [.. hits.OrderByDescending(h => h.Score).ThenBy(h => h.Hit.Title, StringComparer.OrdinalIgnoreCase).Take(max).Select(h => h.Hit)];
    }

    // Every word must match somewhere; where it matches decides the rank. Null when a word matches nowhere.
    private static int? Score(string[] words, string title, string terms, string help)
    {
        var score = 0;
        foreach (var w in words)
        {
            if (title.StartsWith(w, StringComparison.OrdinalIgnoreCase)) score += 30;
            else if (title.Contains(w, StringComparison.OrdinalIgnoreCase)) score += 20;
            else if (terms.Contains(w, StringComparison.OrdinalIgnoreCase)) score += 10;
            else if (help.Contains(w, StringComparison.OrdinalIgnoreCase)) score += 2;
            else return null;
        }
        return score;
    }
}
