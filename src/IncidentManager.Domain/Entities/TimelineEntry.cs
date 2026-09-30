using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>A single chronological entry in a case's investigation log.</summary>
public class TimelineEntry : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }

    /// <summary>Which timeline this belongs to: the event's facts, or the investigation's actions.</summary>
    public TimelineKind Kind { get; set; } = TimelineKind.Investigation;

    /// <summary>When the described event actually occurred (may differ from when it was logged).</summary>
    public DateTimeOffset OccurredAtUtc { get; set; }

    /// <summary>Response category — meaningful for Investigation entries; Event entries use <see cref="Tactics"/>.</summary>
    public TimelineEntryType Type { get; set; }

    /// <summary>Free text (Investigation entries store Markdown; Event entries a short factual line).</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Origin of the entry, e.g. "SIEM", analyst name, vendor.</summary>
    public string? Source { get; set; }

    // ---- Event-timeline attribution (Kind == Event); null/empty for Investigation entries ----

    /// <summary>Optional MITRE ATT&amp;CK technique ID behind this step, e.g. "T1078".</summary>
    public string? TechniqueId { get; set; }

    /// <summary>The acting entity (attacker asset) for this step — a <see cref="CaseEntity"/> on the same case.</summary>
    public Guid? ActorEntityId { get; set; }

    /// <summary>The target entity (victim asset) for this step — a <see cref="CaseEntity"/> on the same case.</summary>
    public Guid? TargetEntityId { get; set; }

    /// <summary>MITRE ATT&amp;CK tactics attributed to this step (an Event step may span several).</summary>
    public List<EventStepTactic> Tactics { get; set; } = new();

    /// <summary>
    /// Optional screenshot attached to this entry (U-40): the id of an <see cref="Evidence"/> item the
    /// image was stored as — so a pasted screenshot stays hashed and in the chain of custody like any other
    /// evidence, and this entry just references it. Null when no screenshot is attached. Folded into the
    /// canonical only when set, so existing (screenshot-less) rows never re-baseline.
    /// </summary>
    public Guid? EvidenceId { get; set; }

    // ---- Investigation-entry versioning (Kind == Investigation) ----
    // Investigation entries are corrected via the supersede pattern (like AnalystNote): an edit keeps
    // the prior version (IsCurrent = false) and inserts an incremented one, so long meeting notes can be
    // clarified without ever losing what was recorded. Event steps are corrected in place instead, so
    // these stay at their defaults for them.

    /// <summary>Version of this Investigation entry; incremented each time it is superseded by an edit.</summary>
    public int Version { get; set; } = 1;

    /// <summary>The prior version this Investigation entry supersedes, if it is an edit.</summary>
    public Guid? SupersedesEntryId { get; set; }

    /// <summary>False once a newer version supersedes this Investigation entry.</summary>
    public bool IsCurrent { get; set; } = true;

    // ---- INV-06: a Decision entry (Type == Decision) records why, what else was considered, and who decided ----

    /// <summary>Why the decision was made. Required for a Decision entry; null otherwise.</summary>
    public string? Rationale { get; set; }

    /// <summary>The other options the team considered, if any.</summary>
    public string? OptionsConsidered { get; set; }

    /// <summary>Who made the decision, as free text (e.g. "Incident Commander with Legal"); the analyst who
    /// recorded it is <see cref="AuditableEntity.CreatedBy"/>.</summary>
    public string? DecidedBy { get; set; }

    /// <summary>
    /// INV-08: the task this entry records the result of, when it was logged as the task was completed. Lets the
    /// timeline show where it came from and stand in for the task's "Task done" milestone. Folded into the row
    /// hash only when set.
    /// </summary>
    public Guid? ActionItemId { get; set; }

    /// <summary>
    /// INV-07: where this entry was promoted from — "note:&lt;id&gt;", "comment:&lt;id&gt;" or "taskcomment:&lt;id&gt;" — so the
    /// source can show it's already on the timeline; INV-23: <see cref="Imported"/> for an entry brought in by a
    /// structured import. Null for an entry written on the timeline. Folded into the row hash only when set.
    /// </summary>
    public string? PromotedFrom { get; set; }

    /// <summary>INV-23: the <see cref="PromotedFrom"/> of an entry brought in by a structured import.</summary>
    public const string Imported = "import";

    /// <summary>
    /// INV-23: brought in by a structured import. Its occurred time comes from the imported document and its
    /// recorded time is the import, so it isn't marked as recorded later; it's marked as imported instead.
    /// </summary>
    public bool IsImported => PromotedFrom == Imported;

    /// <summary>INV-06: a Decision entry must say why.</summary>
    public static void EnsureDecisionHasRationale(TimelineEntryType type, string? rationale)
    {
        if (type == TimelineEntryType.Decision && string.IsNullOrWhiteSpace(rationale))
            throw new ArgumentException("Record why the decision was made.");
    }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent()
    {
        var baseContent = string.Join('|',
            CaseId, (int)Kind, OccurredAtUtc.ToString("o"), (int)Type, Description, Source, CreatedBy, CreatedAtUtc.ToString("o"));

        string content;
        if (Kind == TimelineKind.Event)
        {
            var tactics = string.Join(',', Tactics.Select(t => (int)t.Tactic).OrderBy(x => x));
            content = string.Join('|', baseContent, TechniqueId, ActorEntityId, TargetEntityId, tactics);
        }
        // Investigation: original entries (Version 1) hash exactly as before, so no existing row
        // re-baselines. Only edited versions (2+) fold in their lineage — and those are new rows.
        else if (Version > 1)
            content = string.Join('|', baseContent, Version, SupersedesEntryId);
        else
            content = baseContent;

        // A linked screenshot (U-40) is tamper-evident too, but folded in ONLY when present so existing
        // screenshot-less rows keep their exact canonical (no re-baseline). Appended last, deterministically.
        if (EvidenceId is { } eid) content = string.Join('|', content, "ev", eid);

        // INV-07: where it was promoted from, folded in only when present (no re-baseline).
        if (PromotedFrom is { } from) content = string.Join('|', content, "from", from);

        // INV-08: the task this entry records the result of, folded in only when present (no re-baseline).
        if (ActionItemId is { } task) content = string.Join('|', content, "task", task);

        // INV-06: a decision's rationale / options / decider, folded in only when present (no re-baseline).
        if (Rationale is not null || OptionsConsidered is not null || DecidedBy is not null)
            content = string.Join('|', content, "dec", Rationale, OptionsConsidered, DecidedBy);
        return content;
    }
}

/// <summary>
/// One MITRE ATT&amp;CK tactic attributed to an Event-timeline step. A step may carry several, forming
/// the kill-chain lanes of the attack narrative. Its content is folded into the parent step's canonical
/// hash, so it is tamper-evident without needing its own chain entry.
/// </summary>
public class EventStepTactic : Entity
{
    public Guid TimelineEntryId { get; set; }
    public MitreTactic Tactic { get; set; }
}
