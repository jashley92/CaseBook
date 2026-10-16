namespace IncidentManager.Domain.Common;

/// <summary>
/// BUG-591: a list of role names as stored, comma-separated (a user's roles, a token's roles). Role names could hold a
/// comma before v1.5.1 (BUG-21), so splitting on every comma read "Readers,SysAdmin" as SysAdmin. Every reader and writer
/// of such a list goes through here: <see cref="Split"/> matches the known names that contain a comma first, then splits
/// the rest. Known names are the legacy ones found at start-up (<see cref="UseLegacyNames"/>) and, where a caller has the
/// role directory, any name it knows.
/// </summary>
public static class RoleList
{
    private static readonly object Gate = new();
    private static volatile string[] _legacy = [];

    /// <summary>The role names holding a comma that start-up found (they stay known for the life of the process).</summary>
    public static IReadOnlyList<string> LegacyNames => _legacy;

    /// <summary>Adds role names that contain a comma to those <see cref="Split"/> keeps whole. Names without one are ignored.</summary>
    public static void UseLegacyNames(IEnumerable<string> names)
    {
        lock (Gate)
            _legacy = _legacy.Concat(names.Where(n => !string.IsNullOrWhiteSpace(n) && n.Contains(',')).Select(n => n.Trim()))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>
    /// The role names in <paramref name="csv"/>, trimmed, blanks dropped, in order. A run of comma-separated parts that
    /// together make a known name with a comma (the longest first) is read as that one name.
    /// </summary>
    /// <param name="isRole">Whether a name is a role the caller's role directory knows (it holds every legacy name).</param>
    public static IReadOnlyList<string> Split(string? csv, Func<string, bool>? isRole = null)
    {
        var parts = (csv ?? "").Split(',');
        var legacy = _legacy;
        var result = new List<string>(parts.Length);
        var i = 0;
        while (i < parts.Length)
        {
            var next = i + 1;
            var name = parts[i].Trim();
            for (var j = parts.Length - 1; j > i; j--)
            {
                var joined = string.Join(',', parts[i..(j + 1)]).Trim();
                if (!legacy.Contains(joined, StringComparer.OrdinalIgnoreCase) && !(isRole?.Invoke(joined) ?? false)) continue;
                name = joined;
                next = j + 1;
                break;
            }
            if (name.Length > 0) result.Add(name);
            i = next;
        }
        return result;
    }

    /// <summary>The names as stored: comma-separated, as they have always been written (so <see cref="Split"/> reads them back).</summary>
    public static string Join(IEnumerable<string> names) => string.Join(',', names);
}
