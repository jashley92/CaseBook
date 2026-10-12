using System.Globalization;

namespace IncidentManager.Domain.Common;

/// <summary>
/// Formatting for <see cref="IHashableEntity.BuildCanonicalContent"/> that doesn't depend on the server: a time is its UTC
/// instant in round-trip form whatever offset it was read back with (BUG-25), an enum is its number.
/// <para>BUG-24: a canonical joins its fields with '|', so in the first format text could move between two fields of a
/// record ("a|b" + "c" and "a" + "b|c") without changing the hash. Format 2 escapes '\' and '|' in free text
/// (<see cref="Text"/>). Row hashes are written in format 2 and say so with a <see cref="V2Prefix"/>; a hash without it
/// is checked in the first format, in which <see cref="Text"/> leaves text as it is, so older rows verify unchanged.</para>
/// </summary>
public static class Canonical
{
    /// <summary>Starts a row hash computed over a format-2 canonical.</summary>
    public const string V2Prefix = "v2:";

    [ThreadStatic] private static int t_format;

    /// <summary>A free-text field: escaped in format 2, as it is in the first format.</summary>
    public static string? Text(string? value) =>
        t_format >= 2 && value is not null && value.AsSpan().IndexOfAny('\\', '|') >= 0
            ? value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("|", "\\|", StringComparison.Ordinal)
            : value;

    /// <summary>Builds a canonical in the given format (1 or 2). Canonicals are built synchronously, so the format is
    /// per thread.</summary>
    public static string InFormat(int format, Func<string> build)
    {
        var previous = t_format;
        t_format = format;
        try { return build(); }
        finally { t_format = previous; }
    }

    public static string Time(DateTimeOffset t) => t.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

    public static string Time(DateTimeOffset? t) => t is { } v ? Time(v) : "";

    public static string Num<TEnum>(TEnum value) where TEnum : struct, Enum => Convert.ToInt32(value, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);

    public static string Num<TEnum>(TEnum? value) where TEnum : struct, Enum => value is { } v ? Num(v) : "";
}
