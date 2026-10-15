using FluentAssertions;
using IncidentManager.Application.Abstractions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// E-03b: the composer substitutes tokens, HTML-encodes scalar (case-supplied) values so they can't inject
/// markup, inserts app-rendered list HTML verbatim, honours admin overrides, appends the CTA only with a
/// URL, and produces a readable plain-text alternative.
/// </summary>
public class EmailComposerTests
{
    private static readonly Dictionary<string, string> AssignTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Assignee"] = "Robin Reyes",
        ["Role"] = "Analyst",
        ["AssignedBy"] = "Ivy Commander",
        ["CaseNumber"] = "2026-01",
        ["CaseTitle"] = "Phish wave",
        ["Severity"] = "High",
        ["Phase"] = "Triage",
    };

    [Fact]
    public async Task Substitutes_tokens_into_subject_and_body()
    {
        var msg = await TestEmail.Composer().ComposeAsync("assignment", ["a@x.test"], AssignTokens);

        msg.Subject.Should().Be("You've been assigned to 2026-01 (Analyst)");
        msg.HtmlBody.Should().Contain("Robin Reyes").And.Contain("Phish wave").And.Contain("<html");
    }

    [Fact]
    public async Task HtmlEncodes_case_supplied_values_so_they_cannot_inject_markup()
    {
        var tokens = new Dictionary<string, string>(AssignTokens) { ["CaseTitle"] = "<script>alert(1)</script>" };

        var msg = await TestEmail.Composer().ComposeAsync("assignment", ["a@x.test"], tokens);

        msg.HtmlBody.Should().NotContain("<script>");
        msg.HtmlBody.Should().Contain("&lt;script&gt;");
    }

    [Fact]
    public async Task Inserts_list_html_tokens_verbatim()
    {
        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["ItemCount"] = "1" };
        var html = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ItemsList"] = "<ul><li>2026-09 — do the thing</li></ul>",
        };

        var msg = await TestEmail.Composer().ComposeAsync("overdue", ["a@x.test"], tokens, htmlTokens: html);

        msg.HtmlBody.Should().Contain("<li").And.Contain("do the thing");
    }

    [Fact]
    public async Task Appends_the_cta_button_only_when_a_url_is_supplied()
    {
        var withCta = await TestEmail.Composer().ComposeAsync("assignment", ["a@x.test"], AssignTokens, "https://cb.test/cases/1");
        withCta.HtmlBody.Should().Contain("https://cb.test/cases/1").And.Contain("Open the case");
        withCta.TextBody.Should().Contain("https://cb.test/cases/1");

        var noCta = await TestEmail.Composer().ComposeAsync("assignment", ["a@x.test"], AssignTokens, ctaUrl: null);
        noCta.HtmlBody.Should().NotContain("Open the case");
    }

    [Fact]
    public async Task An_admin_override_wins_over_the_default_subject()
    {
        var composer = TestEmail.Composer(("EmailTemplate:assignment:Subject", "New case for you: {{CaseNumber}}"));

        var msg = await composer.ComposeAsync("assignment", ["a@x.test"], AssignTokens);

        msg.Subject.Should().Be("New case for you: 2026-01");
    }

    [Fact]
    public async Task Produces_a_plain_text_alternative_without_tags()
    {
        var msg = await TestEmail.Composer().ComposeAsync("assignment", ["a@x.test"], AssignTokens);

        msg.TextBody.Should().Contain("Robin Reyes");
        msg.TextBody.Should().NotContain("<");
    }

    [Fact]
    public async Task Uses_a_text_wordmark_when_no_base_url_or_logo()
    {
        var msg = await TestEmail.Composer(("Reporting:OrganizationName", "Acme Cyber"))
            .ComposeAsync("assignment", ["a@x.test"], AssignTokens);

        msg.HtmlBody.Should().Contain("Acme Cyber");   // header wordmark (no <img> without a base URL + logo)
        msg.HtmlBody.Should().NotContain("<img");
    }

    [Fact]
    public async Task The_preview_has_a_sample_for_every_token_a_template_offers(/* REV-56 */)
    {
        var composer = TestEmail.Composer();
        foreach (var def in IncidentManager.Application.Admin.EmailTemplateCatalog.Templates)
            foreach (var token in def.Tokens)
            {
                var (_, html) = await composer.PreviewAsync(def.Id, "s", $"<p>[{{{{{token.Name}}}}}]</p>");
                html.Should().NotContain("[]", $"{def.Id} offers {{{{{token.Name}}}}}, so the preview should show a sample of it");
            }
    }

    [Fact]
    public async Task The_executive_reports_text_body_keeps_one_line_per_figure(/* BUG-554 */)
    {
        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Quarter"] = "Q3 2026", ["PreviousQuarter"] = "Q2 2026", ["ReportUrl"] = "",
        };
        // The markup CaseNotifications renders for the report.
        var html = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SummaryTable"] = "<table cellpadding=\"4\" style=\"border-collapse:collapse\"><tr><th align=\"left\"></th>" +
                               "<th align=\"right\">Q3 2026</th><th align=\"right\">Q2 2026</th></tr>" +
                               "<tr><td>Cases opened</td><td align=\"right\">12</td><td align=\"right\">9</td></tr>" +
                               "<tr><td>Median time to contain</td><td align=\"right\">2.5 h</td><td align=\"right\">—</td></tr></table>",
        };

        var msg = await TestEmail.Composer().ComposeAsync("executive-report", ["a@x.test"], tokens, htmlTokens: html);

        var lines = msg.TextBody.Split('\n');
        lines.Should().Contain("| Q3 2026 | Q2 2026");
        lines.Should().Contain("Cases opened | 12 | 9");
        lines.Should().Contain("Median time to contain | 2.5 h | —");
    }
}

/// <summary>BUG-373: a token holding a line break mustn't put one in the subject header, where MailMessage refuses it.</summary>
public class EmailComposerSubjectLineTests
{
    [Fact]
    public async Task A_multi_line_token_in_the_subject_collapses_to_one_line()
    {
        var composer = TestEmail.Composer(("EmailTemplate:mention:Subject", "{{MentionedBy}}: {{Note}}"));
        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["MentionedBy"] = "Ivy", ["Note"] = "First paragraph.\r\n\r\nSecond\tparagraph.\n", ["CaseNumber"] = "2026-01",
        };

        var msg = await composer.ComposeAsync("mention", ["a@x.test"], tokens);

        msg.Subject.Should().Be("Ivy: First paragraph. Second paragraph.");
        var act = () => new System.Net.Mail.MailMessage { Subject = msg.Subject };
        act.Should().NotThrow();
        msg.TextBody.Should().Contain("First paragraph.\n", "the body keeps its line breaks");
    }

    [Fact]
    public async Task The_preview_subject_is_one_line_too()
    {
        var (subject, _) = await TestEmail.Composer().PreviewAsync("mention", "Hi\r\n{{CaseNumber}}", "<p>x</p>");
        subject.Should().Be("Hi 2026-01_Phishing_Wave");
    }

    [Fact]
    public async Task Unicode_line_and_paragraph_separators_collapse_too()
    {
        var (subject, _) = await TestEmail.Composer().PreviewAsync("mention", "Hi" + (char)0x2028 + "there" + (char)0x2029 + "{{CaseNumber}}", "<p>x</p>");
        subject.Should().Be("Hi there 2026-01_Phishing_Wave");
    }
}
