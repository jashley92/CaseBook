using System.Globalization;
using System.Text.RegularExpressions;

namespace IncidentManager.Application.Reporting;

/// <summary>One placeholder a Word template may use, with the text an admin sees in the field reference.</summary>
public sealed record TemplateField(string Name, string Description);

/// <summary>A repeating list: a table row (or paragraph) containing any of its fields repeats once per item.</summary>
public sealed record TemplateCollection(string Prefix, string Description, IReadOnlyList<TemplateField> Fields);

/// <summary>
/// PROD-47: every placeholder a customer-designed Word report template may use, and how each is filled from the
/// report model — one list shared by upload validation, the renderer, the starter template and the admin's field
/// reference, so they can't disagree. Values carry the same defanging, labels and TLP marking as the built-in report.
/// <para>Syntax: <c>{{case.title}}</c> anywhere (body, header, footer). A table row containing <c>{{ioc.value}}</c>
/// (any field of a list) repeats once per item. <c>{{image.attack_chain}}</c> or <c>{{image.entity_graph}}</c> alone
/// in a paragraph becomes the picture.</para>
/// </summary>
public static partial class ReportTemplateFields
{
    public const string AttackChainImage = "image.attack_chain";
    public const string EntityGraphImage = "image.entity_graph";

    [GeneratedRegex(@"\{\{\s*([a-z_]+(?:\.[a-z0-9_]+)+)\s*\}\}", RegexOptions.IgnoreCase)]
    public static partial Regex Placeholder();

    private static string D(DateTimeOffset? t) => t is { } v ? v.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture) : "";
    private static string Day(DateTimeOffset? t) => t is { } v ? v.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "";

    private static readonly (TemplateField Field, Func<CaseReportModel, string> Value)[] ScalarDefs =
    [
        (new("case.number", "Case number"), m => m.CaseNumber),
        (new("case.title", "Case title"), m => m.Title),
        (new("case.classification", "Classification"), m => m.Classification),
        (new("case.phase", "Current phase"), m => m.Phase),
        (new("case.severity", "Severity"), m => m.Severity),
        (new("case.origin", "Internal detection or third-party"), m => m.Origin),
        (new("case.vendor", "Vendor name (third-party cases)"), m => m.VendorName ?? ""),
        (new("case.detection_id", "Detection-source case id (e.g. the XSIAM incident)"), m => m.DetectionCaseId ?? ""),
        (new("case.summary", "Summary (plain text, paragraphs kept)"), m => m.Summary ?? ""),
        (new("case.data_context", "Data context (analyst notes)"), m => m.DataTypesInvolved ?? ""),
        (new("case.impacted_assets", "Impacted assets"), m => m.ImpactedAssets ?? ""),
        (new("case.affected_individuals", "Affected individuals"), m => m.AffectedIndividualsCount?.ToString("N0", CultureInfo.InvariantCulture) ?? ""),
        (new("case.data_elements", "Data elements involved"), m => m.DataElementsSummary ?? ""),
        (new("case.notification_triggers", "Notification triggers"), m => m.NotificationTriggersSummary ?? ""),
        (new("case.jurisdictions", "Affected jurisdictions"), m => m.AffectedStates ?? ""),
        (new("case.legal_referral", "Legal/Privacy referral note, if referred"), m => m.LegalReferred ? (m.LegalNote ?? "Referred") : ""),
        (new("case.legal_hold", "\"Yes\" when a legal hold is in effect, else \"No\""), m => m.LegalHold ? "Yes" : "No"),
        (new("case.materiality", "Materiality determination"), m => m.MaterialityStatus ?? ""),
        (new("case.materiality_decided_by", "Who made the materiality call"), m => m.MaterialityDecisionMaker ?? ""),
        (new("case.materiality_decided_on", "When it was made"), m => Day(m.MaterialityDecidedOnUtc)),
        (new("case.materiality_rationale", "Materiality rationale"), m => m.MaterialityRationale ?? ""),
        (new("case.detected", "Detected (UTC)"), m => D(m.DetectedAtUtc)),
        (new("case.reported", "Reported (UTC)"), m => D(m.ReportedAtUtc)),
        (new("case.contained", "Contained (UTC)"), m => D(m.ContainedAtUtc)),
        (new("case.resolved", "Resolved (UTC)"), m => D(m.ResolvedAtUtc)),
        (new("case.closed", "Closed (UTC)"), m => D(m.ClosedAtUtc)),
        (new("org.name", "Organisation name (Administration → Organization)"), m => m.OrganizationName ?? ""),
        (new("org.team", "Team name"), m => m.TeamName ?? ""),
        (new("report.tlp", "TLP marking, e.g. TLP:AMBER"), m => m.TlpLabel ?? ""),
        (new("report.sharing", "The TLP sharing sentence"), m => m.SharingLine ?? ""),
        (new("report.defang_note", "The note explaining defanged indicators (blank when not defanged)"), m => m.IndicatorsDefanged ? CaseReportModel.DefangNote : ""),
        (new("report.generated_by", "Who generated the report"), m => m.GeneratedBy),
        (new("report.generated_at", "When (UTC)"), m => D(m.GeneratedAtUtc)),
        (new("report.content_hash", "Case content hash (integrity stamp)"), m => m.ContentHash),
    ];

    private sealed record CollectionDef(TemplateCollection Info, Func<CaseReportModel, IReadOnlyList<object>> Items,
        IReadOnlyDictionary<string, Func<object, string>> Values);

    private static CollectionDef Coll<T>(string prefix, string description, Func<CaseReportModel, IEnumerable<T>> items,
        params (string Name, string Description, Func<T, string> Value)[] fields) =>
        new(new TemplateCollection(prefix, description, fields.Select(f => new TemplateField($"{prefix}.{f.Name}", f.Description)).ToList()),
            m => items(m).Cast<object>().ToList(),
            fields.ToDictionary(f => $"{prefix}.{f.Name}", f => (Func<object, string>)(o => f.Value((T)o)), StringComparer.OrdinalIgnoreCase));

    private static readonly CollectionDef[] CollectionDefs =
    [
        Coll("step", "Attack chain (event timeline) steps", m => m.AttackChain,
            ("number", "Step number", s => s.Order.ToString(CultureInfo.InvariantCulture)),
            ("when", "When (UTC)", s => D(s.OccurredAtUtc)),
            ("tactics", "ATT&CK tactic(s)", s => s.Tactics),
            ("actor", "Actor", s => s.Actor),
            ("target", "Target", s => s.Target),
            ("technique", "Technique id", s => s.TechniqueId ?? ""),
            ("description", "What happened", s => s.Description)),
        Coll("activity", "Investigation timeline entries", m => m.InvestigationTimeline,
            ("when", "When (UTC)", x => D(x.OccurredAtUtc)),
            ("type", "Entry type", x => x.Type),
            ("description", "Description", x => x.Description),
            ("source", "Source", x => x.Source ?? "")),
        Coll("ioc", "Indicators of compromise (malicious/suspicious)", m => m.Iocs,
            ("type", "Type", x => x.Type),
            ("value", "Indicator (defanged when reports defang)", x => x.Value),
            ("verdict", "Verdict", x => x.Verdict),
            ("tlp", "The indicator's own TLP marking, if any", x => x.Tlp ?? ""),
            ("added", "Date added", x => Day(x.AddedAtUtc)),
            ("context", "Context / description", x => x.Description ?? ""),
            ("source", "Source", x => x.Source ?? "")),
        Coll("entity", "Every entity examined (Systems Reviewed)", m => m.Entities,
            ("type", "Type", x => x.Type),
            ("value", "Value", x => x.Value),
            ("label", "Label", x => x.Label ?? ""),
            ("verdict", "Verdict", x => x.Disposition),
            ("source", "Source", x => x.Source ?? "")),
        Coll("relationship", "Entity relationships", m => m.Relationships,
            ("source", "From", x => x.Source),
            ("relationship", "Relationship", x => x.Relationship),
            ("target", "To", x => x.Target),
            ("notes", "Notes", x => x.Description ?? "")),
        Coll("technique", "ATT&CK techniques", m => m.Techniques,
            ("id", "Technique id", x => x.TechniqueId),
            ("name", "Name", x => x.Name),
            ("tactic", "Tactic", x => x.Tactic)),
        Coll("action", "Recommendations / follow-up tasks", m => m.ActionItems,
            ("task", "Task", x => x.Title),
            ("owner", "Owner", x => x.Owner ?? ""),
            ("due", "Due date", x => Day(x.DueAtUtc)),
            ("status", "Status", x => x.Status)),
        Coll("evidence", "Evidence index", m => m.Evidence,
            ("file", "File name", x => x.FileName),
            ("size", "Size in bytes", x => x.SizeBytes.ToString("N0", CultureInfo.InvariantCulture)),
            ("sha256", "SHA-256", x => x.Sha256),
            ("uploaded", "Uploaded (UTC)", x => D(x.UploadedAtUtc)),
            ("by", "Uploaded by", x => x.UploadedBy)),
        Coll("note", "Analyst notes (a paragraph containing a note field repeats per note)", m => m.Notes,
            ("when", "When (UTC)", x => D(x.AtUtc)),
            ("author", "Author", x => x.Author),
            ("text", "Note text", x => x.Body)),
        Coll("assignment", "Case team", m => m.Assignments,
            ("user", "Person", x => x.User),
            ("role", "Role on the case", x => x.Role)),
    ];

    private static readonly Dictionary<string, Func<CaseReportModel, string>> Scalars =
        ScalarDefs.ToDictionary(d => d.Field.Name, d => d.Value, StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<TemplateField> ScalarFields { get; } = ScalarDefs.Select(d => d.Field).ToList();
    public static IReadOnlyList<TemplateCollection> Collections { get; } = CollectionDefs.Select(c => c.Info).ToList();
    public static IReadOnlyList<TemplateField> ImageFields { get; } =
    [
        new(AttackChainImage, "The attack-chain picture (alone in its paragraph)"),
        new(EntityGraphImage, "The entity relationship graph picture (alone in its paragraph)"),
    ];

    /// <summary>Whether <paramref name="name"/> is a placeholder a template may use.</summary>
    public static bool IsKnown(string name) =>
        Scalars.ContainsKey(name) || CollectionFor(name) is not null
        || name.Equals(AttackChainImage, StringComparison.OrdinalIgnoreCase)
        || name.Equals(EntityGraphImage, StringComparison.OrdinalIgnoreCase);

    /// <summary>The list prefix a field belongs to ("ioc" for "ioc.value"), or null for a scalar/unknown.</summary>
    public static string? CollectionFor(string name) =>
        CollectionDefs.FirstOrDefault(c => c.Values.ContainsKey(name))?.Info.Prefix;

    /// <summary>A scalar's value for this report ("" for an unknown name).</summary>
    public static string Scalar(CaseReportModel m, string name) => Scalars.TryGetValue(name, out var f) ? f(m) : "";

    /// <summary>The items of a list, each paired with a lookup of its field values.</summary>
    public static IReadOnlyList<Func<string, string>> Items(CaseReportModel m, string prefix)
    {
        var def = CollectionDefs.First(c => c.Info.Prefix.Equals(prefix, StringComparison.OrdinalIgnoreCase));
        return def.Items(m)
            .Select(item => (Func<string, string>)(name => def.Values.TryGetValue(name, out var f) ? f(item) : ""))
            .ToList();
    }
}
