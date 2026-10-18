using System.Globalization;
using IncidentManager.Application.Access;
using IncidentManager.Application.Export;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Net.Http.Headers;

namespace IncidentManager.Web.Security;

/// <summary>
/// CAP-09: the malicious-IOC feed for machines (a firewall, an EDR, a threat-intel platform), as the CSV the Windows-signed-in
/// <c>/export/iocs.csv</c> gives and as a STIX 2.1 bundle across cases. Under <c>/api</c>, so IIS lets the request through
/// without Windows sign-in, and signed in with an API token whose roles grant ViewCases. The token's need-to-know decides the
/// content (<c>ForUser</c> for its owner: a restricted case's indicators only if the owner could open that case), exercises
/// never appear, and each indicator keeps its TLP marking (WF-37/79).
/// </summary>
/// <remarks>
/// A scheduled pull stays cheap two ways: <c>?since=</c> (ISO 8601) asks only for indicators added or changed since then, and
/// the weak ETag answers a pull that would get the same feed again with 304 and no body. <c>If-Modified-Since</c> isn't
/// honoured: an indicator leaving the feed (removed, cleared, its case restricted) leaves no newer time behind, so a date
/// can't say the feed is unchanged. Each pull with a body is an export: the access log and SIEM 5304. A 304 sends nothing,
/// so records nothing. At most <see cref="IocFeedService.MaxOccurrences"/> occurrences are read (C10); past that the feed
/// holds the most recently changed and says it was cut, in the body and in the <c>X-CaseBook-Truncated</c> header.
/// </remarks>
public static class IocFeedApiEndpoints
{
    /// <summary>The rate-limit policy for these pulls, per token (<c>RateLimiting:ApiFeeds</c>).</summary>
    public const string RateLimitPolicy = "api-feeds";

    /// <summary>Set (to "true") on a feed cut at <see cref="IocFeedService.MaxOccurrences"/>.</summary>
    public const string TruncatedHeader = "X-CaseBook-Truncated";

    private static readonly System.Text.Json.JsonSerializerOptions StixJson = new() { WriteIndented = true };

    public static void MapIocFeedApi(this IEndpointRouteBuilder app)
    {
        var token = new AuthorizeAttribute { Policy = Policies.ViewCases, AuthenticationSchemes = ApiKeyAuthenticationHandler.SchemeName };

        app.MapGet("/api/export/iocs.csv", (string? since, HttpContext http, IocFeedService feeds, IAccessLogService access,
                IncidentManager.Application.Abstractions.IClock clock, CancellationToken ct) =>
            ServeAsync(http, feeds, access, since, "CSV", feed => feed.Fingerprint("csv"),
                // No BOM: machines read it (BUG-168).
                feed => (System.Text.Encoding.UTF8.GetBytes(IocFeedCsv.Build(feed, clock.UtcNow)), "text/csv; charset=utf-8"), ct))
            .RequireAuthorization(token).RequireRateLimiting(RateLimitPolicy);

        app.MapGet("/api/export/iocs.stix.json", (string? since, HttpContext http, IocFeedService feeds, StixExportService stix,
                IAccessLogService access, CancellationToken ct) =>
            ServeAsync(http, feeds, access, since, "STIX", stix.Fingerprint,
                feed => (System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(stix.BuildFeed(feed), StixJson), "application/json"), ct))
            .RequireAuthorization(token).RequireRateLimiting(RateLimitPolicy);
    }

    private static async Task<IResult> ServeAsync(HttpContext http, IocFeedService feeds, IAccessLogService access, string? sinceText,
        string format, Func<IocFeed, string> fingerprint, Func<IocFeed, (byte[] Body, string ContentType)> write, CancellationToken ct)
    {
        DateTimeOffset? since = null;
        if (!string.IsNullOrWhiteSpace(sinceText))
        {
            if (!TryParseSince(sinceText, out var from))
                return Results.BadRequest(new { error = "since must be an ISO 8601 time, for example 2026-10-01T00:00:00Z (write a + offset as %2B)." });
            since = from;
        }

        var feed = await feeds.GetFeedAsync(since, ct: ct);
        var tag = new EntityTagHeaderValue($"\"{format.ToLowerInvariant()}-{fingerprint(feed)}\"", isWeak: true);
        http.Response.Headers.ETag = tag.ToString();
        http.Response.Headers.CacheControl = "private, no-cache";   // a proxy asks again each time, and keeps it to itself
        if (feed.Cut) http.Response.Headers[TruncatedHeader] = "true";
        if (Unchanged(http.Request, tag)) return Results.StatusCode(StatusCodes.Status304NotModified);

        var (body, contentType) = write(feed);
        // The access log and SIEM 5304, as the signed-in export; the token's identity is the actor.
        var label = since is { } s
            ? string.Create(CultureInfo.InvariantCulture, $"IOC feed ({format}, API) since {s.UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC")
            : $"IOC feed ({format}, API)";
        await access.RecordArtifactAsync(AccessType.Export, null, feed.Cut ? label + ", cut" : label, null, ct);
        return Results.Bytes(body, contentType);
    }

    /// <summary>An ISO 8601 time; one without an offset is UTC.</summary>
    private static bool TryParseSince(string text, out DateTimeOffset since)
    {
        since = default;
        var t = text.Trim();
        // A date first (yyyy-MM-dd...), not whatever else the invariant culture reads ("10/01/2026").
        return t.Length >= 10 && char.IsAsciiDigit(t[0]) && t[4] == '-'
            && DateTimeOffset.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out since);
    }

    // If-None-Match names this feed (weak comparison, as RFC 9110 has it for If-None-Match), or "*".
    private static bool Unchanged(HttpRequest request, EntityTagHeaderValue tag) =>
        EntityTagHeaderValue.TryParseList(request.Headers.IfNoneMatch, out var tags)
        && tags.Any(t => t.Equals(EntityTagHeaderValue.Any) || t.Compare(tag, useStrongComparison: false));
}
