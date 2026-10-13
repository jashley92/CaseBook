using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace IncidentManager.Application.Updates;

/// <summary>One published release newer than the running one (PROD-49).</summary>
/// <param name="Notes">The release body: the version's section of docs/UPGRADE.md, as Markdown. Empty when the
/// release has none.</param>
/// <param name="BundleUrl">The release bundle (casebook-vX.Y.Z.zip), when attached.</param>
/// <param name="Sha256Url">Its .sha256, when attached.</param>
public sealed record AvailableRelease(
    string Tag, Version Version, DateTimeOffset? PublishedAtUtc, string Notes, string PageUrl,
    string? BundleUrl, string? Sha256Url);

/// <summary>
/// Reads the GitHub Releases API response (<c>GET /repos/{owner}/{repo}/releases</c>) for the update check. The
/// response comes from outside, so it's read strictly: drafts and pre-releases are skipped, only <c>vX.Y.Z</c> tags
/// count, the notes are capped, and a link is kept only when it points at this repository's own release pages.
/// </summary>
public static partial class ReleaseFeed
{
    /// <summary>The most of a release body that's kept (the notes are a few KB; anything bigger is cut).</summary>
    public const int MaxNotesChars = 64 * 1024;

    [GeneratedRegex(@"^v\d{1,4}\.\d{1,4}\.\d{1,4}$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex ReleaseTag();

    [GeneratedRegex(@"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex RepositoryName();

    /// <summary>True for an "owner/name" repository.</summary>
    public static bool IsRepository(string? repository) =>
        !string.IsNullOrWhiteSpace(repository) && RepositoryName().IsMatch(repository);

    /// <summary>The API address that lists the repository's releases.</summary>
    public static Uri ApiUri(string repository) =>
        new($"https://api.github.com/repos/{repository}/releases?per_page=50", UriKind.Absolute);

    /// <summary>
    /// Every published release newer than <paramref name="current"/>, newest first. Throws
    /// <see cref="JsonException"/> when the response isn't a list of releases.
    /// </summary>
    public static IReadOnlyList<AvailableRelease> Newer(string json, string repository, Version current)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
            throw new JsonException("The releases response isn't a list.");

        var pages = $"https://github.com/{repository}/releases/";
        var found = new Dictionary<Version, AvailableRelease>();
        foreach (var r in doc.RootElement.EnumerateArray())
        {
            if (r.ValueKind != JsonValueKind.Object) continue;
            if (Bool(r, "draft") || Bool(r, "prerelease")) continue;

            var tag = Str(r, "tag_name");
            if (tag is null || !ReleaseTag().IsMatch(tag)) continue;
            var version = AppVersionInfo.ParseVersion(tag);
            if (version is null || version <= current || found.ContainsKey(version)) continue;

            var page = Str(r, "html_url");
            if (page is null || !page.StartsWith(pages, StringComparison.Ordinal)) page = pages + "tag/" + tag;

            var notes = Str(r, "body") ?? "";
            if (notes.Length > MaxNotesChars) notes = notes[..MaxNotesChars] + "\n\n…";

            DateTimeOffset? published = DateTimeOffset.TryParse(Str(r, "published_at"), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var p) ? p : null;

            found[version] = new AvailableRelease(tag, version, published, notes, page,
                Asset(r, pages + "download/" + tag + "/", $"casebook-{tag}.zip"),
                Asset(r, pages + "download/" + tag + "/", $"casebook-{tag}.zip.sha256"));
        }
        return [.. found.Values.OrderByDescending(x => x.Version)];
    }

    // An asset's download link, kept only when it's the expected file under this release's own download folder.
    private static string? Asset(JsonElement release, string prefix, string name)
    {
        if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array) return null;
        foreach (var a in assets.EnumerateArray())
        {
            if (a.ValueKind != JsonValueKind.Object || Str(a, "name") != name) continue;
            var url = Str(a, "browser_download_url");
            return url == prefix + name ? url : null;
        }
        return null;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool Bool(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
}
