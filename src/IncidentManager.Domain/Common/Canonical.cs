using System.Globalization;

namespace IncidentManager.Domain.Common;

/// <summary>
/// Formatting for <see cref="IHashableEntity.BuildCanonicalContent"/> that doesn't depend on the server: a time is its UTC
/// instant in round-trip form whatever offset it was read back with (BUG-25), an enum is its number.
/// </summary>
public static class Canonical
{
    public static string Time(DateTimeOffset t) => t.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

    public static string Time(DateTimeOffset? t) => t is { } v ? Time(v) : "";

    public static string Num<TEnum>(TEnum value) where TEnum : struct, Enum => Convert.ToInt32(value, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);

    public static string Num<TEnum>(TEnum? value) where TEnum : struct, Enum => value is { } v ? Num(v) : "";
}
