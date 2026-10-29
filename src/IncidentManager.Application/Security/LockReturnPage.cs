namespace IncidentManager.Application.Security;

/// <summary>
/// Where <em>Resume session</em> on the lock page goes (F-15 idle lock, S-24 Lock now). Just before a tab locks, the
/// browser keeps the page it was on in that tab's <c>sessionStorage</c>, never in the lock page's URL, so a case number
/// isn't left in the address bar of an unattended screen. The stored value is the browser's to change, so only a page
/// of this app is taken back; anything else resumes on the home page, as before.
/// </summary>
public static class LockReturnPage
{
    /// <summary>The lock page's own path, relative to the app's base.</summary>
    public const string LockPath = "session-expired";

    /// <summary>Longer than any page of the app's address; a longer value isn't one.</summary>
    public const int MaxLength = 2048;

    /// <summary>
    /// The page to resume on, relative to <paramref name="baseUri"/> (the app's base address, ending in <c>/</c>), or
    /// <c>null</c> to resume on the home page: nothing kept, a value that isn't an address within the app, or the lock
    /// page itself.
    /// </summary>
    public static string? Resolve(string? stored, string baseUri)
    {
        if (string.IsNullOrWhiteSpace(stored) || stored.Length > MaxLength) return null;
        if (!Uri.TryCreate(stored, UriKind.Absolute, out var page) || !Uri.TryCreate(baseUri, UriKind.Absolute, out var root))
            return null;
        // Same scheme, host and port, and under the app's base path: an address elsewhere is never followed.
        if (Uri.Compare(page, root, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) != 0)
            return null;
        if (!page.AbsolutePath.StartsWith(root.AbsolutePath, StringComparison.OrdinalIgnoreCase)) return null;

        var relative = page.PathAndQuery[root.AbsolutePath.Length..] + page.Fragment;
        if (relative.Length == 0) return null;   // the home page: the default already
        if (relative.StartsWith('/') || relative.StartsWith('\\')) return null;   // "//host" would leave the app
        var path = relative.Split('?', '#')[0];
        return string.Equals(path.TrimEnd('/'), LockPath, StringComparison.OrdinalIgnoreCase) ? null : relative;
    }
}
