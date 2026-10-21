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
    /// <summary>CAP-14: the longest detection case id (the cases' <c>DetectionCaseId</c> column).</summary>
    public const int MaxDetectionCaseId = 100;

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
            ["$id"] = $"urn:casebook:schema:case-import:v{CaseImportJson.CurrentSchemaVersion}",
            ["title"] = $"CaseBook case import (v1 and v{CaseImportJson.CurrentSchemaVersion})",
            ["description"] = "A structured document that seeds a new or existing CaseBook case with a summary, "
                + "timeline entries, entities/IOCs and action items; from v2, a new case can also carry its phase history, "
                + "outcome, conclusion, incident commander and team (a historical or closed case). Imported as a human-confirmed draft.",
            ["type"] = "object",
            ["additionalProperties"] = false,
            ["required"] = new JsonArray { "format", "schemaVersion" },
            // CAP-35: a v1 document is what it always was: the v2 parts of a new case aren't allowed in one.
            ["if"] = new JsonObject { ["properties"] = new JsonObject { ["schemaVersion"] = new JsonObject { ["const"] = 1 } } },
            ["then"] = new JsonObject
            {
                ["properties"] = new JsonObject
                {
                    ["target"] = new JsonObject
                    {
                        ["properties"] = new JsonObject
                        {
                            ["newCase"] = new JsonObject { ["properties"] = V2NewCaseFields().Aggregate(new JsonObject(), (o, f) => { o[f] = false; return o; }) },
                        },
                    },
                },
            },
            ["properties"] = new JsonObject
            {
                ["format"] = new JsonObject { ["const"] = CaseImportJson.FormatTag },
                // CAP-35: every version this importer reads; the current one is the last.
                ["schemaVersion"] = new JsonObject { ["type"] = "integer", ["enum"] = new JsonArray { 1, CaseImportJson.CurrentSchemaVersion } },
                ["origin"] = Str("Where this import came from, recorded as the source of imported indicators and timeline entries "
                    + "(e.g. \"AI-assisted (Copilot)\", \"manual\", \"XSIAM\"). Not the case's origin: that is target.newCase.origin."),
                ["target"] = Ref("target"),
                // BUG-636
                ["timeZone"] = Str("The time zone of times written without an offset, as an IANA id such as America/New_York. "
                    + "Omit it when every time has an offset or a Z; times without one are then UTC."),
                ["summary"] = Str("A narrative summary of the matter, imported as an analyst note."),
                // BUG-202: the most one import takes.
                ["timeline"] = Array("timelineEntry", CaseImportService.MaxTimelineEntries),
                ["entities"] = Array("entity", CaseImportService.MaxEntities),
                ["actionItems"] = Array("actionItem", CaseImportService.MaxActionItems),
            },
            ["$defs"] = new JsonObject
            {
                ["target"] = new JsonObject
                {
                    ["type"] = "object",
                    ["description"] = "Where the import lands: an existing case (by id, or by its detection case id) or a new one.",
                    ["additionalProperties"] = false,
                    ["properties"] = new JsonObject
                    {
                        ["caseId"] = new JsonObject { ["type"] = "string", ["format"] = "uuid",
                            ["description"] = "Import into this existing case (takes precedence over newCase when visible)." },
                        // CAP-14
                        ["detectionCaseId"] = new JsonObject { ["type"] = "string", ["maxLength"] = MaxDetectionCaseId,
                            ["description"] = "Import into the one open case carrying this detection case id (for example the XSIAM "
                                + "incident id), as the reviewer sees cases when it's reviewed. With none, newCase is prepared; with "
                                + "several, the reviewer picks. Given with caseId, both must name the same case." },
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
                        ["origin"] = EnumOf<CaseOrigin>("Who found it: InternalDetection (our own monitoring or staff) or ThirdParty (a vendor "
                            + "told us, with vendorName). When omitted: ThirdParty if vendorName is given, else InternalDetection."),
                        ["summary"] = Str("The case's own summary field (distinct from the top-level summary note)."),
                        // BUG-663: the preferred names; the "...Utc" ones are their deprecated v1 names.
                        ["detectedAt"] = DateTime("When the matter was detected (defaults to now; not in the future)."),
                        ["occurredAt"] = DateTime("When activity began (must not be after detection)."),
                        ["detectedAtUtc"] = Deprecated("detectedAt"),
                        ["occurredAtUtc"] = Deprecated("occurredAt"),
                        ["dataTypesInvolved"] = Str("Free-text data context (notes). Regulated data elements are recorded in the impact assessment, not here."),
                        ["impactedAssets"] = Str(null),
                        ["detectionCaseId"] = Str("The source platform's id for the event, e.g. the XSIAM incident id (the case's detection-source back-link). Up to 100 characters."),
                        ["vendorName"] = Str("The vendor that disclosed it. Required when origin is ThirdParty. Up to 300 characters."),
                        // BUG-635
                        ["exercise"] = new JsonObject { ["type"] = "boolean", ["description"] = "A tabletop or exercise case (a drill): badged and kept out of dashboards, reminders, the IOC feed and correlation with live cases. Can't be changed once the case is created. Defaults to false." },
                        // CAP-35 (v2): a historical or closed case.
                        ["history"] = new JsonObject
                        {
                            ["type"] = "array", ["items"] = Ref("phaseChange"), ["maxItems"] = CaseImportService.MaxHistory,
                            ["description"] = "v2: the phase transitions the case went through, oldest first, each with when it happened. "
                                + "Needs detectedAt; no step may be in the future, before detection or before the step before it. A history "
                                + "may close the case only at its last step, with outcome and conclusion.",
                        },
                        ["outcome"] = Str("v2: the outcome key (Administration › Case outcomes) for a history that ends in Closed."),
                        ["conclusion"] = Str("v2: what the team concluded, for a history that ends in Closed."),
                        ["incidentCommander"] = Str("v2: the incident commander, by user id or UPN (matched when it's reviewed; someone unknown is a warning, not added)."),
                        ["assignments"] = new JsonObject
                        {
                            ["type"] = "array", ["items"] = Ref("assignment"), ["maxItems"] = CaseImportService.MaxAssignments,
                            ["description"] = "v2: the rest of the case team.",
                        },
                        // CAP-36
                        ["team"] = new JsonObject
                        {
                            ["type"] = "string", ["maxLength"] = Domain.Entities.Team.NameMax,
                            ["description"] = "v2: the team that owns the case, by its key or name (Administration › Teams), matched when it's reviewed; " +
                                              "one that isn't an active team is a warning, and the case is opened without one.",
                        },
                    },
                },
                // CAP-35
                ["phaseChange"] = new JsonObject
                {
                    ["type"] = "object",
                    ["additionalProperties"] = false,
                    ["required"] = new JsonArray { "phase", "at" },
                    ["properties"] = new JsonObject
                    {
                        ["phase"] = EnumOf<CasePhase>("The phase the case moved to."),
                        ["at"] = DateTime("When it moved (the transition's effective time)."),
                        ["reason"] = Str("Why. Defaults to \"imported record: <origin>\"."),
                        ["containedAt"] = DateTime("On a step that goes past Containment without it, or moves on from Containment: when it was contained (moving on, it defaults to the Containment step's time)."),
                        ["containmentNotNeeded"] = Str("On a step that goes past Containment without it: why containment wasn't needed (instead of containedAt)."),
                        ["resolvedAt"] = DateTime("On a step to PostIncident that skips Recovery: when it was resolved."),
                    },
                },
                ["assignment"] = new JsonObject
                {
                    ["type"] = "object",
                    ["additionalProperties"] = false,
                    ["required"] = new JsonArray { "user" },
                    ["properties"] = new JsonObject
                    {
                        ["user"] = Str("A user id or UPN, matched in CaseBook's user directory when it's reviewed."),
                        ["role"] = EnumProp(new JsonArray { nameof(CaseAssignmentRole.Analyst), nameof(CaseAssignmentRole.Observer) }, "Defaults to Analyst."),
                    },
                },
                ["timelineEntry"] = new JsonObject
                {
                    ["type"] = "object",
                    ["additionalProperties"] = false,
                    ["required"] = new JsonArray { "description" },
                    ["properties"] = new JsonObject
                    {
                        ["occurredAt"] = DateTime("When it happened (defaults to now if omitted; future entries are excluded). With timePrecision Day or OnOrBefore, the date; with Window, the first date."),
                        ["occurredAtUtc"] = Deprecated("occurredAt"),
                        // ST-03: an event step's time as it was stated, never a guessed time.
                        ["timePrecision"] = EnumOf<TimePrecision>("For kind Event: how precisely the time was stated. Exact (default), Day (date only), Window (between occurredAt and occurredUntil), OnOrBefore (on or before occurredAt's date), NotStated (no time; placed after the step before it)."),
                        ["occurredUntil"] = DateTime("For timePrecision Window: the last date."),
                        ["occurredUntilUtc"] = Deprecated("occurredUntil"),
                        ["kind"] = EnumOf<TimelineKind>(),
                        ["type"] = EnumProp(ImportableTimelineTypes(), null),
                        ["description"] = Str("What happened."),
                        ["source"] = Str("Optional origin of this entry (defaults to the document origin)."),
                        // INV-18: a decision, recorded with why it was made.
                        ["rationale"] = Str("For type Decision: why it was decided (required for a decision). Ignored for other types."),
                        ["optionsConsidered"] = Str("For type Decision: the other options considered. Optional."),
                        ["decidedBy"] = Str("For type Decision: who made the decision, e.g. \"Incident Commander with Legal\". Optional."),
                        // The attack detail of an event step. On a third-party case, an event step with any of these is an attack
                        // step (the vendor's, or ours if the attacker pivoted in); one with none is a disclosure milestone (use
                        // the disclosure types: Notified, ScopeConfirmed, DataConfirmed, Remediation, RegulatoryNotification).
                        ["tactics"] = new JsonObject
                        {
                            ["type"] = "array",
                            ["items"] = EnumOf<MitreTactic>(),
                            ["description"] = "For kind Event: the ATT&CK tactics of the step, by name (e.g. InitialAccess, CredentialAccess). Ignored for Investigation entries.",
                        },
                        ["techniqueId"] = Str("For kind Event: the ATT&CK technique id, T1566 or T1566.001."),
                        ["environment"] = EnumOf<StepEnvironment>("For kind Event on a third-party case: where the attack step happened. Vendor (in the vendor's environment, the default for an attack step) or Ours (the attacker reached our environment). Ignored on an internal case, whose steps are all ours."),
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
                        ["tlp"] = EnumOf<TlpLevel>("Optional sharing marking (TLP 2.0); kept on the indicator and in exports."),
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
                        ["dueAt"] = DateTime("When the task is due."),
                        ["dueAtUtc"] = Deprecated("dueAt"),
                    },
                },
            },
        };
    }

    /// <summary>CAP-35: the new-case fields v2 added, which a v1 document may not carry. CAP-36: and the owning team.</summary>
    public static IReadOnlyList<string> V2NewCaseFields() => ["history", "outcome", "conclusion", "incidentCommander", "assignments", "team"];

    private static JsonObject Str(string? description)
    {
        var o = new JsonObject { ["type"] = "string" };
        if (description is not null) o["description"] = description;
        return o;
    }

    /// <summary>
    /// BUG-662: an ISO 8601 date-time with or without an offset. "format": "date-time" (RFC 3339) requires an offset, so a
    /// document using "timeZone" for its local times (BUG-636), which CaseBook imports, failed a strict validator. The
    /// field names keep their "Utc" (the v1 contract): each time is stored as a UTC instant, whatever zone it's written in.
    /// </summary>
    internal const string DateTimePattern = @"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,7})?)?)?(Z|[+-]\d{2}:\d{2})?$";

    private const string ZoneNote = " An ISO 8601 date-time: with an offset or Z it's kept as written; without one it's read in timeZone (UTC when there's none).";

    /// <summary>BUG-663: a time's old v1 name, still read; a document gives this or the new name, never both.</summary>
    private static JsonObject Deprecated(string preferred) => new()
    {
        ["type"] = "string",
        ["pattern"] = DateTimePattern,
        ["deprecated"] = true,
        ["description"] = $"The old name for {preferred}, still read. Use {preferred}; don't give both.",
    };

    private static JsonObject DateTime(string? description) => new()
    {
        ["type"] = "string",
        ["pattern"] = DateTimePattern,
        ["description"] = (description is null ? "" : description.TrimEnd() + " ") + ZoneNote.TrimStart(),
    };

    private static JsonObject Ref(string def) => new() { ["$ref"] = $"#/$defs/{def}" };

    private static JsonObject Array(string def, int maxItems) => new()
    {
        ["type"] = "array",
        ["items"] = Ref(def),
        ["maxItems"] = maxItems,
    };

    // INV-15: every timeline type except Handoff (a person-to-person act inside CaseBook, not something an import
    // brings in). Decision is importable with its rationale (INV-18).
    public static readonly string[] NotImportableTimelineTypes = [nameof(TimelineEntryType.Handoff)];

    private static JsonArray ImportableTimelineTypes()
    {
        var values = new JsonArray();
        foreach (var n in Enum.GetNames<TimelineEntryType>().Where(n => !NotImportableTimelineTypes.Contains(n))) values.Add(n);
        return values;
    }

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
