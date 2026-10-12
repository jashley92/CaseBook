namespace IncidentManager.Web.Security;

/// <summary>
/// BUG-186: the downloads record who fetched what (a custody "Downloaded" event, an access-log row, the rate limit), so
/// they answer only a person's request: a navigation or a script fetch, not a page's passive load (an image, a style
/// sheet, a script tag) that a browser makes on the viewer's behalf, e.g. for a URL planted in case text.
/// </summary>
public static class PassiveLoadGuard
{
    private static readonly HashSet<string> Passive = new(StringComparer.OrdinalIgnoreCase)
    {
        "image", "script", "style", "font", "audio", "video", "track", "object", "embed", "manifest", "xslt",
        "worker", "sharedworker", "serviceworker", "audioworklet", "paintworklet", "report",
    };

    /// <summary>Whether the request's <c>Sec-Fetch-Dest</c> says it's a passive load. Clients that send none pass.</summary>
    public static bool IsPassive(HttpRequest request) =>
        request.Headers["Sec-Fetch-Dest"].ToString() is { Length: > 0 } dest && Passive.Contains(dest);

    // With a body, so the status-code page doesn't turn it into the access-denied redirect and an AuthorizationDenied event:
    // the person wasn't refused anything they asked for.
    public static TBuilder RefusePassiveLoads<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder =>
        builder.AddEndpointFilter(async (context, next) => IsPassive(context.HttpContext.Request)
            ? Results.Text("Downloads open only from a link or button, not as an image or script on a page.",
                statusCode: StatusCodes.Status403Forbidden)
            : await next(context));
}
