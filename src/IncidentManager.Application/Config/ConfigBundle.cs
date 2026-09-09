using System.Text.Json;
using System.Text.Json.Serialization;

namespace IncidentManager.Application.Config;

// X-07: a portable, signed, versioned snapshot of an instance's editable configuration — the "seed pack".
// It captures reference data and operational/taxonomy settings (never cases, audit, or security/infra
// config), so an IRP revision can be diffed against it, dev config promoted to prod, or a fresh white-label
// instance stood up from a curated baseline. Enum-valued fields are stored as their names for portability
// and human diff-ability; collections are exported in a deterministic order so the signed canonical form and
// a git-style text diff are both stable.

/// <summary>One operational or taxonomy setting row (key + value), bounded by the editable whitelist.</summary>
public sealed record ConfigSetting(string Key, string? Value);

/// <summary>A role and the permissions it grants. System roles are code-owned and carried for diffing only.</summary>
public sealed record ConfigRole(string Name, string? Description, bool IsSystem, string PermissionsCsv);

/// <summary>An AD-group → role grant.</summary>
public sealed record ConfigRoleMapping(string AdGroup, string RoleName);

/// <summary>One playbook step inside a case template.</summary>
public sealed record ConfigTemplateStep(int Order, string Title, string? Description, string? OwnerHint, int? DueOffsetHours);

/// <summary>A case template (playbook) with its ordered steps and field defaults.</summary>
public sealed record ConfigCaseTemplate(
    string Name, string? Description, bool IsActive, int SortOrder,
    string? DefaultClassification, string? DefaultSeverity, string? DefaultDataTypes, string? SummaryBoilerplate,
    IReadOnlyList<ConfigTemplateStep> Steps);

/// <summary>One requirement inside a stage gate (a machine check or an attestation).</summary>
public sealed record ConfigGateRequirement(int Order, string Kind, string? Check, int? CheckParam, string Label, bool IsBlocking);

/// <summary>A stage gate for one transition, with its ordered requirements.</summary>
public sealed record ConfigStageGate(
    string Trigger, bool IsActive, string Name, string? Description, IReadOnlyList<ConfigGateRequirement> Requirements,
    int CommentaryMinLength = 0);

/// <summary>A report profile (named report section layout).</summary>
public sealed record ConfigReportProfile(string Name, string? Description, bool IsActive, int SortOrder, string? SectionLayout);

/// <summary>A data-element reference row (X-03). Matched on import by its stable <see cref="Key"/>.</summary>
public sealed record ConfigDataElement(
    string Key, string Label, int SortOrder, bool IsActive, bool IsSystem, string? NotificationJurisdictions);

/// <summary>The editable-configuration payload. This is the object that gets canonically serialized and signed.</summary>
public sealed record ConfigBundle(
    IReadOnlyList<ConfigSetting> Settings,
    IReadOnlyList<ConfigRole> Roles,
    IReadOnlyList<ConfigRoleMapping> RoleMappings,
    IReadOnlyList<ConfigCaseTemplate> CaseTemplates,
    IReadOnlyList<ConfigStageGate> StageGates,
    IReadOnlyList<ConfigReportProfile> ReportProfiles,
    IReadOnlyList<ConfigDataElement> DataElements);

/// <summary>
/// The downloadable file: the <see cref="ConfigBundle"/> plus provenance and a signature over the bundle's
/// canonical form. <see cref="PublicKeyPem"/> lets a recipient verify authenticity offline; <see
/// cref="SchemaVersion"/> guards cross-version imports.
/// </summary>
public sealed record ConfigBundleEnvelope(
    string Format, int SchemaVersion, string AppVersion,
    DateTimeOffset ExportedAtUtc, string ExportedBy, string SourceHost,
    string Algorithm, string KeyId, string PublicKeyPem, string Signature,
    ConfigBundle Bundle);

/// <summary>Serialization contract shared by export (sign) and import (verify) so the signed bytes match.</summary>
public static class ConfigBundleJson
{
    public const string FormatTag = "casebook-config-bundle";
    public const int CurrentSchemaVersion = 1;

    /// <summary>Human-readable, stable-cased options for the downloadable envelope file (diff-friendly).</summary>
    public static readonly JsonSerializerOptions File = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    /// <summary>Compact, deterministic options used only to produce the exact bytes that get signed/verified.</summary>
    public static readonly JsonSerializerOptions Canonical = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    /// <summary>The exact string the signature covers — the bundle payload, compact and order-stable.</summary>
    public static string Canonicalize(ConfigBundle bundle) => JsonSerializer.Serialize(bundle, Canonical);
}
