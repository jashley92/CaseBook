using System.Text.Json;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// Turns the raw before/after property snapshots captured on each <see cref="AuditLogEntry"/> into a
/// human-readable account of <em>what changed</em> — used both to enrich the stored summary at write time
/// (the audit interceptor) and to show a field-level diff in the Audit tab and the examiner CSV.
///
/// The interceptor records a generic <c>Update Case</c> line whose before/after JSON already holds the exact
/// fields that moved; this presentation helper is where that captured detail becomes legible, without any
/// change to the tamper-evident write path or the stored data.
/// </summary>
public static class AuditChangeDetail
{
    /// <summary>One field's movement, already formatted for display (e.g. "Legal hold", "No", "Yes").</summary>
    public readonly record struct FieldChange(string Label, string Before, string After);

    // Bookkeeping / integrity plumbing that changes on almost every write — noise in a "what changed" view.
    // Includes the owned value objects' own recorder/timestamp stamps: the substantive move (referred?,
    // materiality status, …) is shown, while "who recorded / when" stays out of the headline diff.
    private static readonly HashSet<string> Suppressed = new(StringComparer.Ordinal)
    {
        "RowHash", "ModifiedAtUtc", "ModifiedBy", "CreatedAtUtc", "CreatedBy", "HasCustomNumber",
        "LegalReferral.ReferredAtUtc", "LegalReferral.ReferredBy",
        "Materiality.RecordedAtUtc", "Materiality.RecordedBy",
    };

    // Friendly labels for the fields that don't humanise cleanly from their property name.
    private static readonly Dictionary<string, string> Labels = new(StringComparer.Ordinal)
    {
        ["LegalHold"] = "Legal hold",
        ["IsArchived"] = "Archived",
        ["IsRestricted"] = "Restricted",
        ["CaseNumber"] = "Case number",
        ["IncidentCommander"] = "Incident commander",
        ["ImpactedAssets"] = "Impacted assets",
        ["DataTypesInvolved"] = "Data types involved",
        ["AffectedIndividualsCount"] = "Affected individuals",
        ["AffectedStates"] = "Affected states",
        ["DetectionCaseId"] = "Detection case ID",
        ["ReportProfileId"] = "Report profile",
        ["Summary"] = "Case summary",
        ["ReportedAtUtc"] = "Reported (regulatory)",
        ["Phase"] = "Status", // the phase field is surfaced as "status" everywhere the user acts on it
        // Owned value objects, folded into the case diff by the interceptor as "Nav.Prop".
        ["LegalReferral.IsReferred"] = "Referred to Legal",
        ["LegalReferral.ReferredToContact"] = "Legal contact",
        ["LegalReferral.RegulatoryRelevanceNote"] = "Legal relevance note",
        ["Materiality.Status"] = "Materiality",
        ["Materiality.DecisionMaker"] = "Materiality decision-maker",
        ["Materiality.DecidedOnUtc"] = "Materiality decision date",
        ["Materiality.Rationale"] = "Materiality rationale",
        ["ThirdParty.VendorName"] = "Vendor name",
        ["ThirdParty.VendorContact"] = "Vendor contact",
        ["ThirdParty.VendorReference"] = "Vendor reference",
    };

    // For the one-line summary, owned value-object fields collapse to their group so a materiality change
    // reads "Update Case — Materiality" rather than repeating every sub-field.
    private static readonly Dictionary<string, string> GroupLabels = new(StringComparer.Ordinal)
    {
        ["LegalReferral"] = "Legal referral",
        ["Materiality"] = "Materiality",
        ["ThirdParty"] = "Third-party details",
    };

    // Enum fields whose stored value is a number: mapped back to the member name so a transition reads
    // "Status: Triage → Containment" rather than "Phase: 1 → 2". Keyed by (entity, field) to stay unambiguous.
    private static Type? EnumTypeFor(string entityType, string field) => (entityType, field) switch
    {
        ("Case", "Classification") => typeof(Classification),
        ("Case", "Severity") => typeof(Severity),
        ("Case", "Phase") => typeof(CasePhase),
        ("Case", "Origin") => typeof(CaseOrigin),
        ("Case", "Materiality.Status") => typeof(MaterialityStatus),
        _ => null
    };

    /// <summary>Whether a field is hidden from the readable diff and the enriched summary.</summary>
    public static bool IsMeaningful(string propertyName) => !Suppressed.Contains(propertyName);

    /// <summary>A display label for a property name — a curated one, else a humanised fallback.</summary>
    public static string Label(string propertyName) =>
        Labels.TryGetValue(propertyName, out var l) ? l : Humanize(propertyName);

    // For the summary: an owned "Nav.Prop" key collapses to its group label ("Materiality"); anything else
    // uses its normal field label.
    private static string GroupOrLabel(string field)
    {
        var dot = field.IndexOf('.');
        if (dot > 0 && GroupLabels.TryGetValue(field[..dot], out var group)) return group;
        return Label(field);
    }

    /// <summary>
    /// The stored audit summary for an entry. For an update it names the meaningful fields that moved
    /// (e.g. <c>Update Case — Legal hold</c>); create/delete keep the plain <c>Action Entity</c> form.
    /// </summary>
    public static string ComposeSummary(AuditAction action, string entityType, IEnumerable<string> changedFields)
    {
        var baseline = $"{action} {entityType}";
        if (action != AuditAction.Update) return baseline;

        // Collapse owned value-object fields to their group so the summary stays short, and de-dup.
        var fields = changedFields.Where(IsMeaningful).Select(GroupOrLabel).Distinct().ToList();
        return fields.Count == 0 ? baseline : $"{baseline} — {string.Join(", ", fields)}";
    }

    /// <summary>
    /// The field-level diff for an <em>update</em> entry, parsed from its before/after JSON (empty for
    /// create/delete, or when only bookkeeping moved). Never throws on malformed JSON — returns empty.
    /// </summary>
    public static IReadOnlyList<FieldChange> Changes(AuditLogEntry entry)
    {
        if (entry.Action != AuditAction.Update ||
            string.IsNullOrWhiteSpace(entry.BeforeJson) || string.IsNullOrWhiteSpace(entry.AfterJson))
            return Array.Empty<FieldChange>();

        Dictionary<string, JsonElement>? before, after;
        try
        {
            before = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(entry.BeforeJson);
            after = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(entry.AfterJson);
        }
        catch (JsonException)
        {
            return Array.Empty<FieldChange>();
        }
        if (before is null || after is null) return Array.Empty<FieldChange>();

        var changes = new List<FieldChange>();
        // Union of keys, in the after-then-before order they were captured, meaningful fields only.
        foreach (var key in after.Keys.Concat(before.Keys.Where(k => !after.ContainsKey(k))))
        {
            if (!IsMeaningful(key)) continue;
            var enumType = EnumTypeFor(entry.EntityType, key);
            var from = before.TryGetValue(key, out var b) ? Format(b, enumType) : "—";
            var to = after.TryGetValue(key, out var a) ? Format(a, enumType) : "—";
            if (from == to) continue; // unchanged (e.g. a field re-serialised but not actually moved)
            changes.Add(new FieldChange(Label(key), from, to));
        }
        return changes;
    }

    /// <summary>A compact one-line rendering of a diff for the CSV (e.g. "Legal hold: No → Yes; Restricted: No → Yes").</summary>
    public static string ToLine(IReadOnlyList<FieldChange> changes) =>
        string.Join("; ", changes.Select(c => $"{c.Label}: {c.Before} → {c.After}"));

    private static string Format(JsonElement value, Type? enumType = null)
    {
        // A known enum field stored as a number → its member name (humanised), e.g. 2 → "Containment".
        if (enumType is not null && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var iv)
            && Enum.GetName(enumType, iv) is { } name)
            return Humanize(name);

        return value.ValueKind switch
        {
            JsonValueKind.Null or JsonValueKind.Undefined => "—",
            JsonValueKind.True => "Yes",
            JsonValueKind.False => "No",
            JsonValueKind.String => value.GetString() is { Length: > 0 } s ? s : "—",
            JsonValueKind.Number => value.GetRawText(),
            _ => value.GetRawText(),
        };
    }

    // "LegalHold" → "Legal hold"; "IsRestricted" → "Restricted"; "AffectedStates" → "Affected states".
    private static string Humanize(string name)
    {
        if (string.IsNullOrEmpty(name)) return name;
        if (name.StartsWith("Is", StringComparison.Ordinal) && name.Length > 2 && char.IsUpper(name[2]))
            name = name[2..];

        var sb = new System.Text.StringBuilder(name.Length + 4);
        for (var i = 0; i < name.Length; i++)
        {
            var ch = name[i];
            if (i > 0 && char.IsUpper(ch) && !char.IsUpper(name[i - 1])) sb.Append(' ');
            sb.Append(i == 0 ? char.ToUpperInvariant(ch) : char.ToLowerInvariant(ch));
        }
        return sb.ToString();
    }
}
