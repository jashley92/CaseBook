namespace IncidentManager.Application.Import;

/// <summary>
/// BUG-115: an imported enum value by name only. <c>Enum.TryParse</c> also takes numbers ("7", a rung that doesn't
/// exist) and comma lists ("AdverseEvent,Incident", whose flags add up to Breach), which an import must never read.
/// </summary>
internal static class ImportEnums
{
    public static bool TryName<TEnum>(string? raw, out TEnum value) where TEnum : struct, Enum
    {
        value = default;
        if (string.IsNullOrWhiteSpace(raw)) return false;
        var name = raw.Trim();
        var match = Enum.GetNames<TEnum>().FirstOrDefault(n => n.Equals(name, StringComparison.OrdinalIgnoreCase));
        return match is not null && Enum.TryParse(match, out value);
    }
}
