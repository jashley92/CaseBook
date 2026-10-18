using System.Text.Json;
using System.Text.Json.Serialization;

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

    /// <summary>BUG-636: the time zone of the document's times that have no offset (an IANA id such as America/New_York,
    /// or a Windows id). Omitted: such times are UTC. A time with an offset or a "Z" keeps it either way.</summary>
    public string? TimeZone { get; set; }

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

    /// <summary>
    /// CAP-14: import into the one open case that carries this detection-platform id (its detection case id, for example the
    /// XSIAM incident id), found among the cases the reviewer can see when it's reviewed. None, or several, is a warning in
    /// the preview and the reviewer picks; with none, <see cref="NewCase"/> is prepared. With <see cref="CaseId"/> too, both
    /// must name the same case (<c>CaseImportService.CheckTargetAsync</c>). Up to 100 characters.
    /// </summary>
    public string? DetectionCaseId { get; set; }

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
    /// <summary>BUG-663: the preferred name. The old "...Utc" name is still read (the v1 contract), but it suggested the value had to be UTC, so an AI converted local times itself and they shifted when the document also named its timeZone.</summary>
    public DateTimeOffset? DetectedAt { get; set; }
    /// <summary>BUG-663: the preferred name; see <see cref="DetectedAt"/>.</summary>
    public DateTimeOffset? OccurredAt { get; set; }
    /// <summary>Deprecated name for <see cref="DetectedAt"/>; the one the importer reads after <c>CaseImportService.Parse</c>.</summary>
    public DateTimeOffset? DetectedAtUtc { get; set; }
    /// <summary>Deprecated name for <see cref="OccurredAt"/>; the one the importer reads after <c>CaseImportService.Parse</c>.</summary>
    public DateTimeOffset? OccurredAtUtc { get; set; }
    public string? DataTypesInvolved { get; set; }
    public string? ImpactedAssets { get; set; }

    /// <summary>The source platform's own id for the event (e.g. the XSIAM incident id) — the case's detection-source
    /// back-link (E-05). Optional; up to 100 characters.</summary>
    public string? DetectionCaseId { get; set; }

    /// <summary>BUG-117: the vendor that disclosed it, required when <see cref="Origin"/> is ThirdParty. Up to 300 characters.</summary>
    public string? VendorName { get; set; }

    /// <summary>BUG-635: a tabletop or exercise case (PROD-43): badged, kept out of dashboards, reminders, the IOC feed and
    /// correlation with live cases. Fixed when the case is created. Optional; false when omitted.</summary>
    public bool? Exercise { get; set; }

    // CAP-35 (schema v2): a historical or closed case comes in with how it went. Read only from a v2 document; a v1
    // document that carries them has them ignored, with a warning.

    /// <summary>CAP-35: the phase transitions the case went through, oldest first, each with when it happened.</summary>
    public List<CaseImportPhaseChange>? History { get; set; }

    /// <summary>CAP-35: the outcome key (Administration › Case outcomes) of a history that ends in Closed.</summary>
    public string? Outcome { get; set; }

    /// <summary>CAP-35: what the team concluded, for a history that ends in Closed (the closing brief's conclusion).</summary>
    public string? Conclusion { get; set; }

    /// <summary>CAP-35: the incident commander, by user id or UPN, resolved in the user directory when it's reviewed.</summary>
    public string? IncidentCommander { get; set; }

    /// <summary>CAP-35: the rest of the case team, each by user id or UPN with a role.</summary>
    public List<CaseImportAssignment>? Assignments { get; set; }
}

/// <summary>CAP-35: one phase transition of an imported case's history, applied through <c>Case.ChangePhase</c> at its
/// effective time (decisions 0010, 0011).</summary>
public sealed class CaseImportPhaseChange
{
    public string? Phase { get; set; }
    /// <summary>When it happened (the transition's effective time). Required.</summary>
    public DateTimeOffset? At { get; set; }
    public string? Reason { get; set; }
    /// <summary>BUG-165: going past Containment without it, when it was contained (or <see cref="ContainmentNotNeeded"/>).</summary>
    public DateTimeOffset? ContainedAt { get; set; }
    public string? ContainmentNotNeeded { get; set; }
    /// <summary>BUG-208: going to Post-incident without Recovery, when it was resolved.</summary>
    public DateTimeOffset? ResolvedAt { get; set; }
}

/// <summary>CAP-35: one member of an imported case's team.</summary>
public sealed class CaseImportAssignment
{
    /// <summary>A user id or UPN, resolved in the user directory when it's reviewed.</summary>
    public string? User { get; set; }
    /// <summary>Analyst (default) or Observer; IncidentCommander goes in <c>incidentCommander</c>.</summary>
    public string? Role { get; set; }
}

/// <summary>One timeline entry to import. <see cref="Kind"/>/<see cref="Type"/> are strings (safe fallback).</summary>
public sealed class CaseImportTimelineEntry
{
    /// <summary>BUG-663: the preferred name; see <see cref="CaseImportNewCase.DetectedAt"/>.</summary>
    public DateTimeOffset? OccurredAt { get; set; }
    /// <summary>BUG-663: the preferred name for <see cref="OccurredUntilUtc"/>.</summary>
    public DateTimeOffset? OccurredUntil { get; set; }
    /// <summary>Deprecated name for <see cref="OccurredAt"/>; the one the importer reads after <c>CaseImportService.Parse</c>.</summary>
    public DateTimeOffset? OccurredAtUtc { get; set; }

    // ST-03: an event step's time as stated (Exact, Day, Window, OnOrBefore, NotStated) and a window's last date.
    public string? TimePrecision { get; set; }
    public DateTimeOffset? OccurredUntilUtc { get; set; }
    public string? Kind { get; set; }
    public string? Type { get; set; }
    public string? Description { get; set; }
    public string? Source { get; set; }

    // INV-18: a Decision entry's details (ignored for other types).
    public string? Rationale { get; set; }
    public string? OptionsConsidered { get; set; }
    public string? DecidedBy { get; set; }
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
    /// <summary>BUG-152: the indicator's sharing marking (TLP 2.0: Clear, Green, Amber, AmberStrict, Red).</summary>
    public string? Tlp { get; set; }
}

/// <summary>One action item / follow-up to import.</summary>
public sealed class CaseImportActionItem
{
    public string? Title { get; set; }
    public string? Owner { get; set; }
    /// <summary>BUG-663: the preferred name; see <see cref="CaseImportNewCase.DetectedAt"/>.</summary>
    public DateTimeOffset? DueAt { get; set; }
    /// <summary>Deprecated name for <see cref="DueAt"/>; the one the importer reads after <c>CaseImportService.Parse</c>.</summary>
    public DateTimeOffset? DueAtUtc { get; set; }
}

/// <summary>Serialization contract for the import document (matches the PROD-32 prompt's schema).</summary>
public static class CaseImportJson
{
    public const string FormatTag = "casebook-case-import";
    /// <summary>CAP-35: v2 adds a new case's history, outcome, conclusion, incident commander and team. v1 documents are
    /// read as they always were.</summary>
    public const int CurrentSchemaVersion = 2;

    /// <summary>CAP-35: the first schema version with a new case's history and team.</summary>
    public const int HistorySchemaVersion = 2;

    /// <summary>Lenient, web-cased options: camelCase, case-insensitive, ignore trailing commas/comments so a
    /// hand- or AI-authored file is forgiving. Enum fields are plain strings on the DTOs, parsed with fallback.</summary>
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true,
        Converters = { new UtcUnlessStated() },
    };

    /// <summary>
    /// BUG-207: a time written without an offset (a producer that dropped the "Z") is read in a stated zone, UTC unless
    /// the document or the reviewer names another (BUG-636), never as the server's local time, which shifted every such
    /// time by the server's offset. One with an offset keeps it. The format is still ISO 8601, as before.
    /// </summary>
    internal sealed class UtcUnlessStated(TimeZoneInfo? zone = null) : JsonConverter<DateTimeOffset>
    {
        private readonly TimeZoneInfo _zone = zone ?? TimeZoneInfo.Utc;

        /// <summary>How many times had no offset and were read in the zone.</summary>
        public int Unzoned { get; private set; }

        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.String || !reader.TryGetDateTimeOffset(out var stated))
                throw new JsonException("A time must be an ISO 8601 date-time, for example 2026-09-18T13:05:00Z or 2026-09-18T09:05:00-04:00.");
            if (!reader.TryGetDateTime(out var plain) || plain.Kind != DateTimeKind.Unspecified) return stated;
            Unzoned++;
            return InZone(plain, _zone);
        }

        /// <summary>A wall-clock time in <paramref name="zone"/>, in UTC. One in the spring-forward gap is read with the
        /// standard offset, which lands just after the jump (02:30 becomes 03:30); one in the repeated autumn hour as the
        /// later (standard-time) instant. Held at the calendar's ends rather than throwing (BUG-577).</summary>
        internal static DateTimeOffset InZone(DateTime local, TimeZoneInfo zone)
        {
            local = DateTime.SpecifyKind(local, DateTimeKind.Unspecified);
            var offset = zone.IsInvalidTime(local) ? zone.BaseUtcOffset
                : zone.IsAmbiguousTime(local) ? zone.GetAmbiguousTimeOffsets(local).Min()
                : zone.GetUtcOffset(local);
            return Common.Instants.FromLocalClamped(local, offset);
        }

        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value);
    }
}
