using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Branding;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// Renders branded HTML notification emails (E-03b). The shell (logo, colours, header/footer, CTA) is fixed
/// and derived from the console theme; only the per-template subject and body content are admin-editable
/// (via <see cref="EmailTemplateCatalog"/> defaults + <c>EmailTemplate:*</c> overrides read from
/// configuration). Emails can't use external CSS or CSS variables, so colours are resolved to literal hex
/// and a small set of known tags is style-inlined for cross-client rendering (incl. Outlook).
/// </summary>
public sealed partial class EmailComposer : IEmailComposer
{
    private readonly IConfiguration _config;
    private readonly IReportBrandingStore _branding;

    public EmailComposer(IConfiguration config, IReportBrandingStore branding)
    {
        _config = config;
        _branding = branding;
    }

    public async Task<EmailMessage> ComposeAsync(string templateId, IReadOnlyCollection<string> to,
        IReadOnlyDictionary<string, string> tokens, string? ctaUrl = null,
        IReadOnlyDictionary<string, string>? htmlTokens = null, CancellationToken ct = default)
    {
        var def = EmailTemplateCatalog.ById(templateId)
                  ?? throw new ArgumentException($"Unknown email template '{templateId}'.", nameof(templateId));

        var subjectTemplate = _config[EmailTemplateCatalog.SubjectKey(templateId)] is { Length: > 0 } s ? s : def.DefaultSubject;
        var bodyTemplate = _config[EmailTemplateCatalog.BodyKey(templateId)] is { Length: > 0 } b ? b : def.DefaultBodyHtml;

        var subject = SubstitutePlain(subjectTemplate, tokens);
        var contentHtml = SubstituteHtml(bodyTemplate, tokens, htmlTokens);
        var contentText = SubstituteText(bodyTemplate, tokens, htmlTokens);

        var palette = BrandPalette.EmailColors(_config["Branding:AccentColor"], _config["Branding:InkColor"]);
        var (html, text) = await RenderShellAsync(contentHtml, contentText, palette,
            def.CtaLabel, ctaUrl, subject, ct);

        return new EmailMessage(to, subject, html, text);
    }

    public async Task<(string Subject, string Html)> PreviewAsync(string templateId, string subject, string bodyHtml,
        CancellationToken ct = default)
    {
        var def = EmailTemplateCatalog.ById(templateId)
                  ?? throw new ArgumentException($"Unknown email template '{templateId}'.", nameof(templateId));

        var (tokens, htmlTokens, ctaUrl) = SampleTokens(def);
        var subj = SubstitutePlain(subject, tokens);
        var content = SubstituteHtml(bodyHtml, tokens, htmlTokens);
        var palette = BrandPalette.EmailColors(_config["Branding:AccentColor"], _config["Branding:InkColor"]);
        var (html, _) = await RenderShellAsync(content, "", palette, def.CtaLabel, ctaUrl, subj, ct);
        return (subj, html);
    }

    public Task<EmailMessage> ComposeSampleAsync(string templateId, IReadOnlyCollection<string> to, CancellationToken ct = default)
    {
        var def = EmailTemplateCatalog.ById(templateId)
                  ?? throw new ArgumentException($"Unknown email template '{templateId}'.", nameof(templateId));
        var (tokens, htmlTokens, ctaUrl) = SampleTokens(def);
        return ComposeAsync(templateId, to, tokens, ctaUrl, htmlTokens, ct);
    }

    // --- token substitution ----------------------------------------------------

    [GeneratedRegex(@"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")]
    private static partial Regex TokenRegex();

    [GeneratedRegex(@"<[^>]+>")]
    private static partial Regex TagRegex();

    private static string SubstitutePlain(string template, IReadOnlyDictionary<string, string> tokens) =>
        TokenRegex().Replace(template, m => tokens.TryGetValue(m.Groups[1].Value, out var v) ? v : "");

    private static string SubstituteHtml(string template, IReadOnlyDictionary<string, string> tokens,
        IReadOnlyDictionary<string, string>? htmlTokens) =>
        TokenRegex().Replace(template, m =>
        {
            var name = m.Groups[1].Value;
            if (htmlTokens is not null && htmlTokens.TryGetValue(name, out var raw)) return raw;   // app-rendered safe HTML
            return tokens.TryGetValue(name, out var v) ? WebUtility.HtmlEncode(v) : "";             // encode scalar values
        });

    private static string SubstituteText(string template, IReadOnlyDictionary<string, string> tokens,
        IReadOnlyDictionary<string, string>? htmlTokens)
    {
        var html = SubstituteHtml(template, tokens, htmlTokens);
        // <li> and block ends become line breaks so lists survive the tag strip.
        html = html.Replace("</li>", "\n").Replace("</p>", "\n\n").Replace("<br/>", "\n").Replace("<br>", "\n");
        var text = WebUtility.HtmlDecode(TagRegex().Replace(html, ""));
        return string.Join('\n', text.Split('\n').Select(l => l.Trim())).Trim();
    }

    // --- branded shell ---------------------------------------------------------

    private async Task<(string Html, string Text)> RenderShellAsync(string contentHtml, string contentText,
        BrandPalette.EmailPalette p, string? ctaLabel, string? ctaUrl, string subject, CancellationToken ct)
    {
        var org = _config["Reporting:OrganizationName"] is { Length: > 0 } o ? o : "CaseBook";
        var team = _config["Reporting:TeamName"];
        var baseUrl = (_config["App:BaseUrl"] ?? "").TrimEnd('/');
        var logoUrl = await LogoUrlAsync(baseUrl, ct);

        var styledContent = InlineStyles(contentHtml, p);
        var hasCta = !string.IsNullOrWhiteSpace(ctaLabel) && !string.IsNullOrWhiteSpace(ctaUrl);

        var header = logoUrl is not null
            ? $"<img src=\"{WebUtility.HtmlEncode(logoUrl)}\" alt=\"{WebUtility.HtmlEncode(org)}\" height=\"32\" style=\"display:block;border:0;max-height:32px;\">"
            : $"<span style=\"font-size:18px;font-weight:700;color:{p.HeaderText};\">{WebUtility.HtmlEncode(org)}</span>";
        var headerSub = string.IsNullOrWhiteSpace(team) ? "" :
            $"<div style=\"font-size:12px;color:{p.HeaderText};opacity:.75;margin-top:2px;\">{WebUtility.HtmlEncode(team)}</div>";

        var cta = hasCta
            ? $"""
               <table role="presentation" cellpadding="0" cellspacing="0" style="margin:24px 0 8px;">
                 <tr><td style="border-radius:6px;background:{p.ButtonBg};">
                   <a href="{WebUtility.HtmlEncode(ctaUrl)}" style="display:inline-block;padding:11px 22px;font-size:15px;font-weight:600;color:{p.ButtonText};text-decoration:none;border-radius:6px;">{WebUtility.HtmlEncode(ctaLabel)}</a>
                 </td></tr>
               </table>
               """
            : "";

        var year = DateTimeOffset.UtcNow.Year;
        var footer = $"{WebUtility.HtmlEncode(org)}{(string.IsNullOrWhiteSpace(team) ? "" : " · " + WebUtility.HtmlEncode(team))} · automated notification — please do not reply.";

        var html = $"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>{WebUtility.HtmlEncode(subject)}</title></head>
            <body style="margin:0;padding:0;background:{p.PageBg};">
              <span style="display:none!important;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;">{WebUtility.HtmlEncode(subject)}</span>
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{p.PageBg};">
                <tr><td align="center" style="padding:24px 12px;">
                  <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:100%;background:{p.CardBg};border:1px solid {p.Border};border-radius:10px;overflow:hidden;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
                    <tr><td style="background:{p.HeaderBg};padding:18px 28px;">{header}{headerSub}</td></tr>
                    <tr><td style="height:4px;background:{p.Accent};line-height:4px;font-size:4px;">&nbsp;</td></tr>
                    <tr><td style="padding:28px;">
                      {styledContent}
                      {cta}
                    </td></tr>
                    <tr><td style="padding:16px 28px;background:{p.PageBg};border-top:1px solid {p.Border};font-size:12px;color:{p.Muted};line-height:1.5;">
                      {footer}<br>&copy; {year}
                    </td></tr>
                  </table>
                </td></tr>
              </table>
            </body></html>
            """;

        var text = contentText;
        if (hasCta) text += $"\n\n{ctaLabel}: {ctaUrl}";
        text += $"\n\n— {org}{(string.IsNullOrWhiteSpace(team) ? "" : " · " + team)} (automated notification)";
        return (html, text);
    }

    private async Task<string?> LogoUrlAsync(string baseUrl, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(baseUrl)) return null;          // no absolute base → can't host the image
        var logo = await _branding.GetLogoAsync(ct);
        return logo is null ? null : $"{baseUrl}/branding/logo";
    }

    // Lightweight style inliner for the constrained tag set the templates use, so content renders
    // consistently across email clients (which ignore <style>/external CSS) without admins writing inline CSS.
    private static string InlineStyles(string html, BrandPalette.EmailPalette p)
    {
        var h1 = $"margin:0 0 16px;font-size:22px;line-height:1.3;font-weight:700;color:{p.Text};";
        var h2 = $"margin:20px 0 10px;font-size:17px;line-height:1.3;font-weight:700;color:{p.Text};";
        var para = $"margin:0 0 14px;font-size:15px;line-height:1.6;color:{p.Text};";
        var meta = $"margin:0 0 14px;font-size:13px;line-height:1.6;color:{p.Muted};";
        var ul = "margin:0 0 14px;padding-left:20px;";
        var li = $"margin:0 0 6px;font-size:15px;line-height:1.5;color:{p.Text};";

        return html
            .Replace("<p class=\"meta\">", $"<p style=\"{meta}\">")
            .Replace("<h1>", $"<h1 style=\"{h1}\">")
            .Replace("<h2>", $"<h2 style=\"{h2}\">")
            .Replace("<p>", $"<p style=\"{para}\">")
            .Replace("<ul>", $"<ul style=\"{ul}\">")
            .Replace("<ol>", $"<ol style=\"{ul}\">")
            .Replace("<li>", $"<li style=\"{li}\">")
            .Replace("<a href", $"<a style=\"color:{p.Link};\" href");
    }

    // --- admin preview sample data ---------------------------------------------

    private static (Dictionary<string, string> Tokens, Dictionary<string, string> HtmlTokens, string CtaUrl) SampleTokens(
        EmailTemplateDefinition def)
    {
        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Assignee"] = "Robin Reyes",
            ["Role"] = "Analyst",
            ["AssignedBy"] = "Ivy Commander",
            ["CaseNumber"] = "2026-01_Phishing_Wave",
            ["CaseTitle"] = "Credential-phishing wave targeting Finance",
            ["Severity"] = "Critical",
            ["Phase"] = "Containment",
            ["ItemCount"] = "2",
            ["ReferralNote"] = "",
            ["FirstBrokenSequence"] = "4821",
            ["Detail"] = "row hash mismatch at sequence 4821",
            ["DriftCount"] = "1",
            ["CheckedCount"] = "37",
            ["VerifiedAtUtc"] = DateTimeOffset.UtcNow.ToString("u"),
        };
        var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ItemsList"] = "<ul><li>2026-01_Phishing_Wave — Reset affected credentials (due 2026-09-08 12:00:00Z)</li>"
                          + "<li>2026-118_Malware_Beacon — Rebuild the beaconing host (due 2026-09-09 09:00:00Z)</li></ul>",
            ["DriftList"] = "<ul><li>2026-01_Phishing_Wave — capture.pcap — hash mismatch</li></ul>",
        };
        return (tokens, htmlTokens, "https://casebook.example/cases/preview");
    }
}
