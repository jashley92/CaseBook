using System.Reflection;

namespace IncidentManager.Application.Updates;

/// <summary>
/// The version this build of CaseBook is (PROD-49). The release workflow stamps the tag's version into every assembly
/// (<c>-p:Version=1.6.0</c>) and the SDK appends the commit, so the informational version reads "1.6.0+&lt;sha&gt;". A
/// local build has no version set and reads "1.0.0+&lt;sha&gt;": that's a development build, which the update check
/// leaves alone (there's nothing meaningful to compare).
/// </summary>
public static class AppVersionInfo
{
    // The SDK's default when no Version is given.
    private static readonly Version Unversioned = new(1, 0, 0);

    /// <summary>The raw informational version, e.g. "1.6.0+a1b2c3d…".</summary>
    public static string Informational { get; } =
        typeof(AppVersionInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(AppVersionInfo).Assembly.GetName().Version?.ToString(3)
        ?? "0.0.0";

    /// <summary>The release version (major.minor.patch), or null when it can't be read.</summary>
    public static Version? Current { get; } = ParseVersion(Informational);

    /// <summary>The commit this build came from, shortened, when the SDK recorded it.</summary>
    public static string? Commit { get; } = ParseCommit(Informational);

    /// <summary>True for a build the release workflow stamped; false for a local or unversioned build.</summary>
    public static bool IsReleaseBuild => Current is { } v && v != Unversioned;

    /// <summary>For people: "1.6.0 (a1b2c3d)", or "development build (a1b2c3d)".</summary>
    public static string Display
    {
        get
        {
            var name = IsReleaseBuild ? Current!.ToString(3) : "development build";
            return Commit is { } c ? $"{name} ({c})" : name;
        }
    }

    /// <summary>"1.6.0+sha", "1.6.0" or "v1.6.0" as a three-part version; null when it isn't one.</summary>
    public static Version? ParseVersion(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var s = text.Trim();
        if (s.StartsWith('v') || s.StartsWith('V')) s = s[1..];
        var plus = s.IndexOfAny(['+', '-']);
        if (plus >= 0) s = s[..plus];
        return Version.TryParse(s, out var v) && v.Build >= 0 ? new Version(v.Major, v.Minor, v.Build) : null;
    }

    private static string? ParseCommit(string informational)
    {
        var plus = informational.IndexOf('+');
        if (plus < 0 || plus == informational.Length - 1) return null;
        var sha = informational[(plus + 1)..];
        return sha.Length > 7 ? sha[..7] : sha;
    }
}
