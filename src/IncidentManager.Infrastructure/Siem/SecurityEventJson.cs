using System.Text.Json;
using System.Text.Json.Serialization;
using IncidentManager.Application.Security;

namespace IncidentManager.Infrastructure.Siem;

/// <summary>
/// Serializes a <see cref="SecurityEvent"/> to the JSON wire format for the SIEM webhook (F-18). The
/// field names (camelCase) and enum-as-string values are a <b>stable parse contract</b> for SIEM —
/// change with care. Nulls are omitted to keep payloads lean.
/// </summary>
public static class SecurityEventJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string Serialize(SecurityEvent e) => JsonSerializer.Serialize(e, Options);
}
