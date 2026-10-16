namespace IncidentManager.Application.Cases;

/// <summary>
/// BUG-593 (BUG-453/501's class): links into the case list, each naming its filter. A bare <c>cases</c> opens the user's
/// default view (PROD-24), which needn't show what the link is about: the deadline reminder's link left out closed cases
/// still owing a notice. Relative to the app's base; <see cref="For"/> makes an absolute one for an email or a chat post.
/// </summary>
public static class CaseListLinks
{
    /// <summary>Cases whose notification deadline is at risk or past, closed ones still owing a notice included.</summary>
    public const string NotificationDeadlines = "cases?notify=true";

    /// <summary>Cases with overdue tasks, closed ones included (the overdue count includes them).</summary>
    public const string OverdueTasks = "cases?overdue=true&closed=true";

    /// <summary>Open cases, the longest without activity first (the stale-case nudge).</summary>
    public const string QuietestFirst = "cases?sort=updated&dir=asc";

    /// <summary>The absolute form of <paramref name="link"/> under <paramref name="baseUrl"/>, or null when there's no base URL.</summary>
    public static string? For(string? baseUrl, string link)
    {
        var b = (baseUrl ?? "").TrimEnd('/');
        return b.Length == 0 ? null : $"{b}/{link}";
    }
}
