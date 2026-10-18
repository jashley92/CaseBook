using System.Text.Json;
using IncidentManager.Domain.Enums;
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
public sealed record ConfigTemplateStep(int Order, string Title, string? Description, string? OwnerHint, int? DueOffsetHours,
    TaskKind Kind = TaskKind.General);

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

/// <summary>A report profile (named report section layout). <see cref="Template"/> names its default Word template
/// (schema v3); null means the built-in layout. Left out of the JSON when null, so a v2 bundle still verifies.</summary>
public sealed record ConfigReportProfile(string Name, string? Description, bool IsActive, int SortOrder, string? SectionLayout,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Template = null);

/// <summary>A Word report template from the library (PROD-47, schema v3), carried with its file so a promoted
/// report profile keeps its default. Matched on import by <see cref="Name"/>; the file is checked again before
/// it's stored, and <see cref="Sha256"/> must match <see cref="ContentBase64"/>. <see cref="LessonsDefault"/> marks the
/// lessons-learned reports' default (left out of the JSON when false).</summary>
public sealed record ConfigReportTemplate(string Name, string FileName, bool IsActive, string Sha256, string ContentBase64,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool LessonsDefault = false);

/// <summary>A data-element reference row (X-03). Matched on import by its stable <see cref="Key"/>.</summary>
public sealed record ConfigDataElement(
    string Key, string Label, int SortOrder, bool IsActive, bool IsSystem, string? NotificationJurisdictions);

/// <summary>A per-jurisdiction notification-deadline rule (PROD-07). Matched on import by its <see cref="Code"/>,
/// which is a portable shared key (e.g. "NY", "US"), so rules travel between instances like report profiles.</summary>
public sealed record ConfigNotificationRule(
    string Code, string Label, int WindowHours, bool IsActive, bool IsSystem);

/// <summary>A case outcome (HR-01, schema v4). Matched on import by its stable <see cref="Key"/>.</summary>
public sealed record ConfigCaseOutcome(string Key, string Label, string? Description, int SortOrder, bool IsActive, bool IsSystem);

/// <summary>
/// CAP-36 (schema v5): a team that owns cases. Matched on import by its stable <see cref="Key"/>. Its members (people,
/// which differ between servers) and its chat webhook URL (a secret, kept encrypted on the server it was entered on) never
/// travel: a team brought in by a bundle has no members and no webhook until they're set on that server.
/// </summary>
public sealed record ConfigTeam(string Key, string Name, bool IsActive, string? DetectionSourceLabel, string? DetectionLinkTemplate);

/// <summary>The editable-configuration payload. This is the object that gets canonically serialized and signed.</summary>
public sealed record ConfigBundle(
    IReadOnlyList<ConfigSetting> Settings,
    IReadOnlyList<ConfigRole> Roles,
    IReadOnlyList<ConfigRoleMapping> RoleMappings,
    IReadOnlyList<ConfigCaseTemplate> CaseTemplates,
    IReadOnlyList<ConfigStageGate> StageGates,
    IReadOnlyList<ConfigReportProfile> ReportProfiles,
    IReadOnlyList<ConfigDataElement> DataElements,
    // Added in schema v2 (PROD-07). A v1 bundle omits it and deserializes to null — read sites guard with `?? []`.
    IReadOnlyList<ConfigNotificationRule> NotificationRules,
    // Added in schema v3 (PROD-47). Null on an older bundle, which then leaves the library and profile defaults alone.
    // Left out of the JSON when null, so a v2 bundle's canonical form (and signature) is unchanged.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<ConfigReportTemplate>? ReportTemplates = null,
    // Added in schema v4 (HR-01). Null on an older bundle, which then leaves the outcomes alone; left out of the JSON
    // when null, so an older bundle's canonical form (and signature) is unchanged.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<ConfigCaseOutcome>? CaseOutcomes = null,
    // Added in schema v5 (CAP-36). Null on an older bundle, which then leaves the teams alone; left out of the JSON when
    // null, so an older bundle's canonical form (and signature) is unchanged.
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<ConfigTeam>? Teams = null);

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
    // v2 (PROD-07) added ConfigBundle.NotificationRules. Older v1 bundles still import (the field reads as empty).
    // v3 (PROD-47) added the Word template library and each report profile's default template.
    // v4 (HR-01) added the case outcomes.
    // v5 (CAP-36) added the teams (never their members or webhook).
    public const int CurrentSchemaVersion = 5;

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

    // BUG-335: v1.0.x and v1.1.x signed their steps before ConfigTemplateStep.Kind existed (v1.2.0, INV-28), and Kind is
    // written even at its default. This is the canonical such a bundle was signed over: the same bytes, without a step's
    // kind where it's General. A step of any other kind keeps it, so it can't verify this way.
    private static readonly JsonSerializerOptions CanonicalWithoutDefaultStepKind = new(Canonical)
    {
        TypeInfoResolver = new System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver
        {
            Modifiers =
            {
                info =>
                {
                    if (info.Type != typeof(ConfigTemplateStep)) return;
                    foreach (var p in info.Properties)
                        if (p.Name == "kind") p.ShouldSerialize = (_, v) => v is TaskKind k && k != TaskKind.General;
                }
            }
        }
    };

    /// <summary>BUG-335: the canonical form of a bundle exported before step kinds (v1.0.x / v1.1.x).</summary>
    public static string CanonicalizeWithoutDefaultStepKind(ConfigBundle bundle) =>
        JsonSerializer.Serialize(bundle, CanonicalWithoutDefaultStepKind);
}
