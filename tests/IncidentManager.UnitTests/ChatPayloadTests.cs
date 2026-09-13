using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Unit tests for the pure Slack/Teams webhook payload serializer (PROD-02).</summary>
public class ChatPayloadTests
{
    [Fact]
    public void Slack_payload_is_a_single_mrkdwn_text_field_with_a_link()
    {
        var json = ChatPayload.Serialize(ChatWebhookFormat.Slack,
            new ChatNotification("Breach escalation — 2026-01", "Phishing wave · severity High.", "https://cb.example/cases/1"));

        using var doc = JsonDocument.Parse(json);
        var text = doc.RootElement.GetProperty("text").GetString();
        text.Should().Contain("*Breach escalation — 2026-01*")
            .And.Contain("Phishing wave")
            .And.Contain("<https://cb.example/cases/1|Open in CaseBook>");
    }

    [Fact]
    public void Teams_payload_is_a_messagecard_with_theme_and_action()
    {
        var json = ChatPayload.Serialize(ChatWebhookFormat.Teams,
            new ChatNotification("Breach escalation", "text", "https://cb.example/cases/1", ChatUrgency.Alert));

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        root.GetProperty("@type").GetString().Should().Be("MessageCard");
        root.GetProperty("themeColor").GetString().Should().Be("D64545");   // alert = red
        root.GetProperty("title").GetString().Should().Be("Breach escalation");
        root.GetProperty("potentialAction")[0].GetProperty("targets")[0].GetProperty("uri").GetString()
            .Should().Be("https://cb.example/cases/1");
    }

    [Fact]
    public void Teams_payload_without_a_url_omits_the_action()
    {
        var json = ChatPayload.Serialize(ChatWebhookFormat.Teams, new ChatNotification("Title", "text"));

        using var doc = JsonDocument.Parse(json);
        doc.RootElement.TryGetProperty("potentialAction", out _).Should().BeFalse();
        doc.RootElement.GetProperty("themeColor").GetString().Should().Be("2563EB");  // normal = accent
    }

    [Fact]
    public void Values_are_json_escaped()
    {
        var json = ChatPayload.Serialize(ChatWebhookFormat.Slack, new ChatNotification("A \"quote\"", "b & c"));

        using var doc = JsonDocument.Parse(json);   // must parse cleanly despite the quote/ampersand
        doc.RootElement.GetProperty("text").GetString().Should().Contain("\"quote\"").And.Contain("b & c");
    }
}
