namespace IncidentManager.Application.Content;

/// <summary>
/// BUG-264: an administered deep-link template ("https://siem.example/case/{0}") filled with a value. Rendered with
/// <c>string.Format</c>, a template holding any other brace (a Kibana or Sentinel URL often does) threw during render, and
/// the error boundary replaced every case page; and nothing kept the link to http(s). A template is usable when it's an
/// absolute http(s) address with one <c>{0}</c>; the value is escaped and put in place of it, and other braces stay as typed.
/// </summary>
public static class LinkTemplate
{
    public const string Placeholder = "{0}";

    /// <summary>Why <paramref name="template"/> can't be used, or null when it can (blank is allowed: no link).</summary>
    public static string? Problem(string? template)
    {
        if (string.IsNullOrWhiteSpace(template)) return null;
        var t = template.Trim();
        var at = t.IndexOf(Placeholder, StringComparison.Ordinal);
        if (at < 0) return "Put {0} where the value should go.";
        if (t.IndexOf(Placeholder, at + Placeholder.Length, StringComparison.Ordinal) >= 0) return "Use {0} only once.";
        return Uri.TryCreate(t.Replace(Placeholder, "x", StringComparison.Ordinal), UriKind.Absolute, out var uri)
               && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
            ? null
            : "Use a full http:// or https:// address.";
    }

    /// <summary>The link for <paramref name="value"/>, or null when there's no usable template or no value.</summary>
    public static string? Fill(string? template, string? value) =>
        string.IsNullOrWhiteSpace(template) || string.IsNullOrWhiteSpace(value) || Problem(template) is not null
            ? null
            : template.Trim().Replace(Placeholder, Uri.EscapeDataString(value), StringComparison.Ordinal);
}
