using System.Text;
using System.Text.Json;
using IncidentManager.Application.Abstractions;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// Serializes a <see cref="ChatNotification"/> to the JSON body a Slack or Teams incoming webhook expects.
/// Pure and side-effect free (mirrors <c>SecurityEventJson</c>): the Web transport owns the HTTP mechanics.
/// <see cref="JsonSerializer"/> handles all escaping, so a title/body containing quotes or braces is safe.
/// </summary>
public static class ChatPayload
{
    public static string Serialize(ChatWebhookFormat format, ChatNotification n) =>
        format == ChatWebhookFormat.Teams ? Teams(n) : Slack(n);

    // Slack incoming webhook: a single mrkdwn "text" field — *bold* title, then the body, then a link.
    private static string Slack(ChatNotification n)
    {
        var sb = new StringBuilder();
        sb.Append('*').Append(SlackEscape(n.Title)).Append('*');
        if (!string.IsNullOrWhiteSpace(n.Text)) sb.Append('\n').Append(SlackEscape(n.Text));
        if (!string.IsNullOrWhiteSpace(n.Url)) sb.Append('\n').Append('<').Append(n.Url).Append("|Open in CaseBook>");
        return JsonSerializer.Serialize(new { text = sb.ToString() });
    }

    // Teams incoming webhook: a MessageCard (broadly supported by channel connectors). themeColor tints it,
    // and a link becomes an OpenUri action button.
    private static string Teams(ChatNotification n)
    {
        var color = n.Urgency == ChatUrgency.Alert ? "D64545" : "2563EB";
        var card = new Dictionary<string, object?>
        {
            ["@type"] = "MessageCard",
            ["@context"] = "https://schema.org/extensions",
            ["themeColor"] = color,
            ["summary"] = n.Title,
            ["title"] = TeamsEscape(n.Title),
            ["text"] = TeamsEscape(n.Text),
        };
        if (!string.IsNullOrWhiteSpace(n.Url))
        {
            card["potentialAction"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["@type"] = "OpenUri",
                    ["name"] = "Open in CaseBook",
                    ["targets"] = new object[] { new Dictionary<string, string> { ["os"] = "default", ["uri"] = n.Url! } },
                },
            };
        }
        return JsonSerializer.Serialize(card);
    }

    // BUG-361: case text is text. Slack reads &, < and > as its control sequences, so a title or note holding
    // "<!channel>" pinged the channel and "<https://evil|Open in CaseBook>" was a disguised link. The link built above
    // is left as it is.
    private static string SlackEscape(string s) =>
        s.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal)
         .Replace(">", "&gt;", StringComparison.Ordinal);

    // BUG-361: a MessageCard's title and text are Markdown, so "[Open in CaseBook](https://evil)" was a disguised link.
    // Only the brackets are escaped: Teams connectors aren't documented to honour every Markdown escape, and an
    // unhonoured one would show as a stray backslash in ordinary case text (2026-01_Wave). The summary is plain text.
    // BUG-580: they're also HTML, so <a href> was a disguised link and <img> a tracking pixel: &, < and > are entities
    // (& first, so an entity typed in case text shows as typed).
    private static string? TeamsEscape(string? s) =>
        string.IsNullOrEmpty(s) ? s : s.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("[", @"\[", StringComparison.Ordinal).Replace("]", @"\]", StringComparison.Ordinal);
}
