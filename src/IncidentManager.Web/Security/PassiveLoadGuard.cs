namespace IncidentManager.Web.Security;

/// <summary>
/// BUG-186: the downloads record who fetched what (a custody "Downloaded" event, an access-log row, the rate limit), so
/// they answer only a person's request: a navigation or a script fetch, not a page's passive load (an image, a style
/// sheet, a script tag) that a browser makes on the viewer's behalf, e.g. for a URL planted in case text. BUG-222: nor a
/// frame (X-Frame-Options stops only the drawing; the download has already run), nor anything another site starts:
/// Windows sign-in goes with every request, so a hidden frame or auto-redirect on an intranet page or an HTML email
/// would record custody and access in the viewer's name. A typed URL, a bookmark or a link from a desktop mail client
/// sends <c>Sec-Fetch-Site: none</c> and passes.
/// </summary>
public static class PassiveLoadGuard
{
    private static readonly HashSet<string> Passive = new(StringComparer.OrdinalIgnoreCase)
    {
        "image", "script", "style", "font", "audio", "video", "track", "object", "embed", "manifest", "xslt",
        "worker", "sharedworker", "serviceworker", "audioworklet", "paintworklet", "report", "iframe", "frame",
        "fencedframe",
    };

    // Sec-Fetch-Site values that mean another site (even a sibling host on the intranet) started the request.
    private static readonly HashSet<string> OtherSite = new(StringComparer.OrdinalIgnoreCase) { "cross-site", "same-site" };

    /// <summary>Whether the request's <c>Sec-Fetch-Dest</c> says it's a passive load or a frame, or its
    /// <c>Sec-Fetch-Site</c> says another site started it. Clients that send neither (scripts, curl) pass.</summary>
    public static bool IsPassive(HttpRequest request) =>
        (request.Headers["Sec-Fetch-Dest"].ToString() is { Length: > 0 } dest && Passive.Contains(dest))
        || (request.Headers["Sec-Fetch-Site"].ToString() is { Length: > 0 } site && OtherSite.Contains(site));

    /// <summary>REV-61: marks an endpoint that refuses passive loads, so the download rate limit (which runs before the
    /// endpoint's filter) doesn't spend a token on a request the endpoint is about to refuse.</summary>
    public sealed class RefusesPassiveLoads;
    private static readonly RefusesPassiveLoads Marker = new();

    /// <summary>Whether this request is one the endpoint it's for will refuse as a passive or cross-site load.</summary>
    public static bool WillBeRefused(HttpContext http) =>
        http.GetEndpoint()?.Metadata.GetMetadata<RefusesPassiveLoads>() is not null && IsPassive(http.Request);

    // With a body, so the status-code page doesn't turn it into the access-denied redirect and an AuthorizationDenied event:
    // the person wasn't refused anything they asked for.
    public static TBuilder RefusePassiveLoads<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder =>
        builder.WithMetadata(Marker).AddEndpointFilter(async (context, next) => IsPassive(context.HttpContext.Request)
            ? Results.Text("Downloads open only from a link or button in CaseBook (or a typed or bookmarked address), " +
                           "not from another site or as an image, script or frame on a page.",
                statusCode: StatusCodes.Status403Forbidden)
            : await next(context));
}
