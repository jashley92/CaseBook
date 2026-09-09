using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Taxonomy;

/// <summary>
/// Reads admin-set taxonomy display labels (X-02) from live configuration (DB override + appsettings), the
/// same mechanism the severity labels use. A rename takes effect at runtime with no restart; an unset member
/// returns the caller's built-in fallback so the code-defined defaults always stand.
/// </summary>
public sealed class ConfigurationTaxonomyDisplay : ITaxonomyDisplay
{
    private readonly IConfiguration _config;

    public ConfigurationTaxonomyDisplay(IConfiguration config) => _config = config;

    public string Label(string kind, string member, string fallback)
    {
        var value = _config[TaxonomyCatalog.LabelKey(kind, member)];
        return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
    }

    public bool IsHidden(string kind, string member) =>
        bool.TryParse(_config[TaxonomyCatalog.HiddenKey(kind, member)], out var hidden) && hidden;

    public IReadOnlyList<string> Order(string kind)
    {
        var csv = _config[TaxonomyCatalog.OrderKey(kind)];
        if (string.IsNullOrWhiteSpace(csv)) return Array.Empty<string>();
        return csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
