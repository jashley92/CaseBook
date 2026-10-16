using IncidentManager.Domain.Common;

namespace IncidentManager.Application.Import;

/// <summary>
/// BUG-115: an imported enum value by name only. <c>Enum.TryParse</c> also takes numbers ("7", a rung that doesn't
/// exist) and comma lists ("AdverseEvent,Incident", whose flags add up to Breach), which an import must never read.
/// BUG-592: the shared <see cref="EnumNames"/> reading, ignoring case.
/// </summary>
internal static class ImportEnums
{
    public static bool TryName<TEnum>(string? raw, out TEnum value) where TEnum : struct, Enum =>
        EnumNames.TryParse(raw, out value, ignoreCase: true);
}
