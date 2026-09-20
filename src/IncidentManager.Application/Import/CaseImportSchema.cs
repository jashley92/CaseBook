using System.Text.Json;
using System.Text.Json.Nodes;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Import;

/// <summary>
/// PROD-35: builds a JSON Schema (draft 2020-12) for the <see cref="CaseImportDocument"/> format. It is
/// generated from the real enums (via <see cref="Enum.GetNames{T}()"/>), so the published schema can't drift
/// from what the importer accepts. Served anonymously at <c>GET /api/import/cases/schema</c> and committed at
/// <c>docs/case-import.schema.json</c>; the import page's sample and the PROD-32 prompt point at it.
/// </summary>
public static class CaseImportSchema
{
    /// <summary>The schema as an indented JSON string (the canonical machine-readable reference).</summary>
    public static string Build() => Root().ToJsonString(new JsonSerializerOptions { WriteIndented = true });

    /// <summary>The schema as a mutable node (for tests that inspect specific keywords).</summary>
    public static JsonObject Root()
    {
        // Classification allows the on-ladder values plus the intake "Complex Event" (a null classification).
        var classifications = new JsonArray { "ComplexEvent" };
        foreach (var n in Enum.GetNames<Classification>()) classifications.Add(n);

        return new JsonObject
        {
            ["$schema"] = "https://json-schema.org/draft/2020-12/schema",
            ["$id"] = "urn:casebook:schema:case-import:v1",
            ["title"] = "CaseBook case import (v1)",
            ["description"] = "A structured document that seeds a new or existing CaseBook case with a summary, "
                + "timeline entries, entities/IOCs and action items. Imported as a human-confirmed draft.",
            ["type"] = "object",
            ["additionalProperties"] = false,
            ["required"] = new JsonArray { "format", "schemaVersion" },
            ["properties"] = new JsonObject
            {
                ["format"] = new JsonObject { ["const"] = CaseImportJson.FormatTag },
                ["schemaVersion"] = new JsonObject { ["type"] = "integer", ["const"] = CaseImportJson.CurrentSchemaVersion },
                ["origin"] = Str("Provenance recorded as the source of imported indicators and timeline entries "
                    + "(e.g. \"AI-assisted (Copilot)\", \"manual\", \"XSIAM\")."),
                ["target"] = Ref("target"),
                ["summary"] = Str("A narrative summary of the matter, imported as an analyst note."),
                ["timeline"] = Array("timelineEntry"),
                ["entities"] = Array("entity"),
                ["actionItems"] = Array("actionItem"),
            },
            ["$defs"] = new JsonObject
            {
                ["target"] = new JsonObject
                {
                    ["type"] = "object",
                    ["description"] = "Where the import lands: an existing case (by id) or a new one.",
                    ["additionalProperties"] = false,
                    ["properties"] = new JsonObject
                    {
                        ["caseId"] = new JsonObject { ["type"] = "string", ["format"] = "uuid",
                            ["description"] = "Import into this existing case (takes precedence over newCase when visible)." },
                        ["newCase"] = Ref("newCase"),
                    },
                },
                ["newCase"] = new JsonObject
                {
                    ["type"] = "object",
                    ["description"] = "Opening fields for a new case.",
                    ["additionalProperties"] = false,
                    ["required"] = new JsonArray { "title" },
                    ["properties"] = new JsonObject
                    {
                        ["title"] = Str("Short, specific case title."),
                        ["descriptiveName"] = Str("Optional short slug source; derived from the title when omitted."),
                        ["classification"] = EnumProp(classifications, "Omit or \"ComplexEvent\" files an intake Complex Event."),
                        ["severity"] = EnumOf<Severity>(),
                        ["origin"] = EnumOf<CaseOrigin>(),
                        ["summary"] = Str("The case's own summary field (distinct from the top-level summary note)."),
                        ["detectedAtUtc"] = DateTime("When the matter was detected (defaults to now; not in the future)."),
                        ["occurredAtUtc"] = DateTime("When activity began (must not be after detection)."),
                        ["dataTypesInvolved"] = Str(null),
                        ["impactedAssets"] = Str(null),
                    },
                },
                ["timelineEntry"] = new JsonObject
                {
                    ["type"] = "object",
                    ["additionalProperties"] = false,
                    ["required"] = new JsonArray { "description" },
                    ["properties"] = new JsonObject
                    {
                        ["occurredAtUtc"] = DateTime("When it happened (defaults to now if omitted; future entries are excluded)."),
                        ["kind"] = EnumOf<TimelineKind>(),
                        ["type"] = EnumOf<TimelineEntryType>(),
                        ["description"] = Str("What happened."),
                        ["source"] = Str("Optional origin of this entry (defaults to the document origin)."),
                    },
                },
                ["entity"] = new JsonObject
                {
                    ["type"] = "object",
                    ["additionalProperties"] = false,
                    ["required"] = new JsonArray { "value" },
                    ["properties"] = new JsonObject
                    {
                        ["type"] = EnumOf<EntityType>("Optional — auto-detected from the value when omitted."),
                        ["value"] = Str("The indicator; defanged notation (hxxp://, 1.1.1[.]1) is accepted and refanged."),
                        ["label"] = Str(null),
                        ["disposition"] = EnumOf<EntityDisposition>(),
                        ["description"] = Str(null),
                        ["source"] = Str("Optional (defaults to the document origin)."),
                    },
                },
                ["actionItem"] = new JsonObject
                {
                    ["type"] = "object",
                    ["additionalProperties"] = false,
                    ["required"] = new JsonArray { "title" },
                    ["properties"] = new JsonObject
                    {
                        ["title"] = Str("The follow-up task."),
                        ["owner"] = Str(null),
                        ["dueAtUtc"] = DateTime(null),
                    },
                },
            },
        };
    }

    private static JsonObject Str(string? description)
    {
        var o = new JsonObject { ["type"] = "string" };
        if (description is not null) o["description"] = description;
        return o;
    }

    private static JsonObject DateTime(string? description)
    {
        var o = new JsonObject { ["type"] = "string", ["format"] = "date-time" };
        if (description is not null) o["description"] = description;
        return o;
    }

    private static JsonObject Ref(string def) => new() { ["$ref"] = $"#/$defs/{def}" };

    private static JsonObject Array(string def) => new()
    {
        ["type"] = "array",
        ["items"] = Ref(def),
    };

    private static JsonObject EnumOf<TEnum>(string? description = null) where TEnum : struct, Enum
    {
        var values = new JsonArray();
        foreach (var n in Enum.GetNames<TEnum>()) values.Add(n);
        return EnumProp(values, description);
    }

    private static JsonObject EnumProp(JsonArray values, string? description)
    {
        var o = new JsonObject { ["type"] = "string", ["enum"] = values };
        if (description is not null) o["description"] = description;
        return o;
    }
}
