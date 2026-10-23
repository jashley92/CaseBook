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

    /// <summary>On a third-party case, where the attack step happened (the vendor's environment or ours); null otherwise.</summary>
    public StepEnvironment? Environment { get; set; }

    // ---- ST-01: an attack step's time as it was stated, and its order (null on every other entry) ----

    /// <summary>How precisely <see cref="OccurredAtUtc"/> is known; null means exact.</summary>
    public TimePrecision? OccurredPrecision { get; set; }

    /// <summary>The last day of a <see cref="TimePrecision.Window"/> (12:00 UTC on it); null otherwise.</summary>
    public DateTimeOffset? OccurredUntilUtc { get; set; }

    /// <summary>Breaks ties between event steps with the same <see cref="OccurredAtUtc"/> (same date, or a step
    /// whose time wasn't stated placed after another); null sorts as 0, then by when each was recorded.</summary>
    public int? StepOrder { get; set; }

    /// <summary>True when the step's time is approximate (anything but exact).</summary>
    public bool IsApproximate => OccurredPrecision is { } p && p != TimePrecision.Exact;

    /// <summary>
    /// Optional screenshot attached to this entry (U-40): the id of an <see cref="Evidence"/> item the
    /// image was stored as — so a pasted screenshot stays hashed and in the chain of custody like any other
    /// evidence, and this entry just references it. Null when no screenshot is attached. Folded into the
    /// canonical only when set, so existing (screenshot-less) rows never re-baseline.
    /// </summary>
    public Guid? EvidenceId { get; set; }

    /// <summary>
    /// BUG-722: the screenshots after the first (<see cref="EvidenceId"/>), in order, as lowercase evidence ids joined by
    /// commas; null with one or none. Kept beside <see cref="EvidenceId"/> rather than in a link table, so an entry with one
    /// screenshot is stored, shown and hashed exactly as before, and an edit that unlinks one is a new version (an
    /// Investigation entry) or an audited in-place change (an Event step), like any other edit of the entry. Folded into
    /// the canonical only when set.
    /// </summary>
    public string? MoreEvidenceIds { get; set; }

    /// <summary>
    /// BUG-722 follow-up: the screenshots an edit took off this entry, as <see cref="MoreEvidenceIds"/> holds ids, in the
    /// order they went; null when none has. An attack step's edit is in place, so this is where it remembers a screenshot it
    /// once showed (an Investigation entry's earlier version keeps its own as well), and the case doesn't list that file as
    /// newly added evidence (<c>CaseMilestones</c>). Folded into the canonical only when set.
    /// </summary>
    public string? FormerEvidenceIds { get; set; }

    /// <summary>BUG-722 follow-up: <see cref="FormerEvidenceIds"/> as ids.</summary>
    public IReadOnlyList<Guid> FormerScreenshotIds => ParseIds(FormerEvidenceIds);

    /// <summary>BUG-722: the most screenshots one entry shows.</summary>
    public const int MaxScreenshots = 10;

    /// <summary>BUG-722: every screenshot on the entry, in order: <see cref="EvidenceId"/>, then <see cref="MoreEvidenceIds"/>.</summary>
    public IReadOnlyList<Guid> ScreenshotIds
    {
        get
        {
            var ids = new List<Guid>();
            if (EvidenceId is { } first) ids.Add(first);
            ids.AddRange(ParseIds(MoreEvidenceIds));
            return ids;
        }
    }

    private static List<Guid> ParseIds(string? joined)
    {
        var ids = new List<Guid>();
        if (joined is not null)
            foreach (var part in joined.Split(',', StringSplitOptions.RemoveEmptyEntries))
                if (Guid.TryParse(part, out var id)) ids.Add(id);
        return ids;
    }

    /// <summary>BUG-722: links the entry to exactly these screenshots, in this order (at most <see cref="MaxScreenshots"/>,
    /// each once). Which evidence may be linked is the caller's check (<see cref="Case"/>'s edits, the service's add).</summary>
    public void SetScreenshotIds(IEnumerable<Guid> ids)
    {
        var list = ids.ToList();
        if (list.Count > MaxScreenshots)
            throw new ArgumentException($"An entry takes up to {MaxScreenshots} screenshots.");
        if (list.Distinct().Count() != list.Count)
            throw new ArgumentException("That screenshot is on the entry already.");
        // BUG-722 follow-up: a screenshot taken off is remembered (see FormerEvidenceIds), once.
        var former = FormerScreenshotIds.ToList();
        former.AddRange(ScreenshotIds.Where(id => !list.Contains(id) && !former.Contains(id)));
        FormerEvidenceIds = former.Count > 0 ? string.Join(',', former.Select(MoreKey)) : null;
        EvidenceId = list.Count > 0 ? list[0] : null;
        MoreEvidenceIds = list.Count > 1 ? string.Join(',', list.Skip(1).Select(MoreKey)) : null;
    }

    /// <summary>BUG-722: an id as <see cref="MoreEvidenceIds"/> holds it (and as a query looks for it there).</summary>
    public static string MoreKey(Guid id) => id.ToString("D");

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
    /// INV-07: where this entry was promoted from — "note:&lt;id&gt;" or "taskcomment:&lt;id&gt;" — so the
    /// source can show it's already on the timeline; INV-23: <see cref="Imported"/> for an entry brought in by a
    /// structured import. Null for an entry written on the timeline. Folded into the row hash only when set.
    /// </summary>
    public string? PromotedFrom { get; set; }

    /// <summary>
    /// CAP-20 review: on a handoff entry, the user id of the person it was handed to, so the "watch for" card finds them
    /// by who they are rather than by the display name the text gives (a rename, or two people with one name). Null on
    /// every other entry, and on a handoff recorded before it was kept. Folded into the row hash only when set (format 5).
    /// </summary>
    public string? HandedToUserId { get; set; }

    /// <summary>INV-23: the <see cref="PromotedFrom"/> of an entry brought in by a structured import.</summary>
    public const string Imported = "import";

    /// <summary>
    /// INV-23: brought in by a structured import. Its occurred time comes from the imported document and its
    /// recorded time is the import, so it isn't marked as recorded later; it's marked as imported instead.
    /// </summary>
    public bool IsImported => PromotedFrom == Imported;

    // ---- BUG-413: a retracted entry (never deleted, R3). It stops being current, so it leaves the record (reports,
    // the attack chain, counts), and the timeline shows it as a struck-through stub with who retracted it and why. ----

    /// <summary>When the entry was retracted; null while it stands.</summary>
    public DateTimeOffset? RetractedAtUtc { get; set; }

    /// <summary>Who retracted it.</summary>
    public string? RetractedBy { get; set; }

    /// <summary>Why it was retracted (required).</summary>
    public string? RetractReason { get; set; }

    /// <summary>True once the entry has been retracted.</summary>
    public bool IsRetracted => RetractedAtUtc is not null;

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
            CaseId, (int)Kind, OccurredAtUtc.ToString("o"), (int)Type, Canonical.Text(Description), Canonical.Text(Source), CreatedBy, CreatedAtUtc.ToString("o"));

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
            content = string.Join('|', content, "dec", Canonical.Text(Rationale), Canonical.Text(OptionsConsidered), Canonical.Text(DecidedBy));

        // Where a third-party case's attack step happened, folded in only when present (no re-baseline).
        if (Environment is { } env) content = string.Join('|', content, "env", (int)env);

        // ST-01: the stated precision, a window's end and the step's order, each folded in only when set.
        if (OccurredPrecision is { } prec) content = string.Join('|', content, "prec", (int)prec);
        if (OccurredUntilUtc is { } until) content = string.Join('|', content, "until", until.ToString("o"));
        if (StepOrder is { } order) content = string.Join('|', content, "ord", order);

        // BUG-413: a retraction, folded in only when there is one (no re-baseline).
        if (RetractedAtUtc is { } retracted)
            content = string.Join('|', content, "retracted", Canonical.Time(retracted), RetractedBy, Canonical.Text(RetractReason));

        // C18: from format 4, what the branches above leave out, each only when set: an attack step's (or a first
        // version's) lineage, and attack fields on an investigation entry.
        var lineageIn = Kind != TimelineKind.Event && Version > 1;
        content += Canonical.Since(4, !lineageIn && (Version != 1 || SupersedesEntryId is not null),
            () => "|lin|" + Version.ToString(System.Globalization.CultureInfo.InvariantCulture) + "|" + SupersedesEntryId);
        if (Kind != TimelineKind.Event)
            content += Canonical.Since(4, TechniqueId is not null || ActorEntityId is not null || TargetEntityId is not null || Tactics.Count > 0,
                () => "|step|" + Canonical.Text(TechniqueId) + "|" + ActorEntityId + "|" + TargetEntityId + "|"
                      + string.Join(',', Tactics.Select(t => (int)t.Tactic).OrderBy(x => x)));
        // CAP-20 review: a handoff's recipient, from format 5, only when set.
        content += Canonical.Since(5, HandedToUserId is not null, () => "|to|" + Canonical.Text(HandedToUserId));
        // BUG-722: the screenshots after the first, in order, from format 9, only when there are any (no re-baseline).
        content += Canonical.Since(9, MoreEvidenceIds is not null, () => "|evs|" + MoreEvidenceIds);
        // BUG-722 follow-up: the screenshots an edit took off a step, likewise only when there are any.
        content += Canonical.Since(9, FormerEvidenceIds is not null, () => "|was|" + FormerEvidenceIds);
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
