namespace IncidentManager.Domain.Common;

/// <summary>
/// BUG-592: an enum value read from text (a stored value, a setting, a link, an imported file) by its declared name only.
/// <c>Enum.TryParse</c> also reads a number ("4", "-1", "+7", undefined ones too) and a comma list ("Closing,Reopen", the
/// values OR-ed into another member), so stored and imported text never goes through it. The result is always a defined
/// member.
/// </summary>
public static class EnumNames
{
    /// <summary>The member named <paramref name="raw"/> (surrounding whitespace ignored), or false.</summary>
    public static bool TryParse<TEnum>(string? raw, out TEnum value, bool ignoreCase = false) where TEnum : struct, Enum =>
        TryParseExact(raw?.Trim(), out value, ignoreCase);

    /// <summary>As <see cref="TryParse{TEnum}"/>, but a padded name isn't one (a role name, say, is matched as stored).</summary>
    public static bool TryParseExact<TEnum>(string? name, out TEnum value, bool ignoreCase = false) where TEnum : struct, Enum
    {
        if (!string.IsNullOrEmpty(name))
        {
            var comparison = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            foreach (var (n, v) in Members<TEnum>.All)
                if (string.Equals(n, name, comparison)) { value = v; return true; }
        }
        value = default;
        return false;
    }

    /// <summary>The member named <paramref name="raw"/>, or null.</summary>
    public static TEnum? OrNull<TEnum>(string? raw, bool ignoreCase = false) where TEnum : struct, Enum =>
        TryParse<TEnum>(raw, out var v, ignoreCase) ? v : null;

    private static class Members<TEnum> where TEnum : struct, Enum
    {
        public static readonly (string Name, TEnum Value)[] All =
            Enum.GetNames<TEnum>().Select(n => (n, Enum.Parse<TEnum>(n))).ToArray();
    }
}
