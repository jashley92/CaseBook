using System.Text.Json;

namespace IncidentManager.Application.Import;

// PROD-31: a portable, versioned document that seeds a new or existing case with timeline entries, an
// analyst summary note, entities/IOCs and action items. Unlike the config bundle it is NOT signed — it is
// authored outside CaseBook (by an analyst's own AI via the PROD-32 prompt, by hand, or by a producer over
// the PROD-33 API), so it is treated as UNTRUSTED input: every field is validated/clamped and the analyst
// confirms an editable preview before anything is written. Enum-valued fields are carried as strings for
// portability and graceful handling — an unrecognised value falls back to a safe default and is flagged,
// rather than failing the whole import.

/// <summary>The import payload. All sections are optional; the target is a new case or an existing one.</summary>
public sealed class CaseImportDocument
{
    public string? Format { get; set; }
    public int? SchemaVersion { get; set; }

    /// <summary>Provenance for this import (e.g. "AI-assisted (Copilot)", "manual", "XSIAM"). A schema field —
    /// not a hardcoded label — so manual / AI / programmatic imports are all recorded honestly. Applied as the
    /// default <c>Source</c> on imported entities and timeline entries.</summary>
    public string? Origin { get; set; }

    public CaseImportTarget? Target { get; set; }

    /// <summary>A narrative summary of the matter, imported as an analyst note.</summary>
    public string? Summary { get; set; }

    public List<CaseImportTimelineEntry>? Timeline { get; set; }
    public List<CaseImportEntity>? Entities { get; set; }
    public List<CaseImportActionItem>? ActionItems { get; set; }
}

/// <summary>Where the import lands: an existing case (by id) or a new one (with its opening fields).</summary>
public sealed class CaseImportTarget
{
    /// <summary>Import into this existing case. Takes precedence over <see cref="NewCase"/> when set and visible.</summary>
    public Guid? CaseId { get; set; }

    /// <summary>Open a new case with these fields (mapped to a CreateCaseRequest, validated on apply).</summary>
    public CaseImportNewCase? NewCase { get; set; }
}

/// <summary>Opening fields for a new case (enum fields as strings; parsed with a safe fallback).</summary>
public sealed class CaseImportNewCase
{
    public string? DescriptiveName { get; set; }
    public string? Title { get; set; }
    public string? Classification { get; set; }
    public string? Severity { get; set; }
    public string? Origin { get; set; }
    public string? Summary { get; set; }
    public DateTimeOffset? DetectedAtUtc { get; set; }
    public DateTimeOffset? OccurredAtUtc { get; set; }
    public string? DataTypesInvolved { get; set; }
    public string? ImpactedAssets { get; set; }

    /// <summary>The source platform's own id for the event (e.g. the XSIAM incident id) — the case's detection-source
    /// back-link (E-05). Optional; up to 100 characters.</summary>
    public string? DetectionCaseId { get; set; }
}

/// <summary>One timeline entry to import. <see cref="Kind"/>/<see cref="Type"/> are strings (safe fallback).</summary>
public sealed class CaseImportTimelineEntry
{
    public DateTimeOffset? OccurredAtUtc { get; set; }
    public string? Kind { get; set; }
    public string? Type { get; set; }
    public string? Description { get; set; }
    public string? Source { get; set; }
}

/// <summary>One entity/IOC to import. <see cref="Type"/> is optional (auto-detected) and a string (safe fallback).</summary>
public sealed class CaseImportEntity
{
    public string? Type { get; set; }
    public string? Value { get; set; }
    public string? Label { get; set; }
    public string? Disposition { get; set; }
    public string? Description { get; set; }
    public string? Source { get; set; }
}

/// <summary>One action item / follow-up to import.</summary>
public sealed class CaseImportActionItem
{
    public string? Title { get; set; }
    public string? Owner { get; set; }
    public DateTimeOffset? DueAtUtc { get; set; }
}

/// <summary>Serialization contract for the import document (matches the PROD-32 prompt's schema).</summary>
public static class CaseImportJson
{
    public const string FormatTag = "casebook-case-import";
    public const int CurrentSchemaVersion = 1;

    /// <summary>Lenient, web-cased options: camelCase, case-insensitive, ignore trailing commas/comments so a
    /// hand- or AI-authored file is forgiving. Enum fields are plain strings on the DTOs, parsed with fallback.</summary>
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true
    };
}
