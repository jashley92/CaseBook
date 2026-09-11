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
}
