using IncidentManager.Application.Content;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Reporting;

public sealed record ReportClassificationItem(DateTimeOffset AtUtc, string From, string To, string Reason, string By);
/// <param name="Imported">INV-23: brought in by a structured import, dated as the imported document gave it.</param>
/// <param name="By">INV-46: who recorded the entry (as the timeline says "logged by"), or who made the milestone's change.</param>
/// <param name="Stated">BUG-71: a disclosure milestone's time as it was stated ("2026-03-04, time not stated"), when it
/// wasn't given exactly; null otherwise.</param>
public sealed record ReportTimelineItem(DateTimeOffset OccurredAtUtc, string Type, string Description, string? Source,
    bool Imported = false, string? By = null, string? Stated = null)
{
    /// <summary>The time for the report: the stated wording, or the exact time in UTC.</summary>
    public string When => Stated ?? OccurredAtUtc.ToString("u", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>INV-16: the <see cref="Type"/> of a response milestone in the investigation timeline.</summary>
    public const string Milestone = "Milestone";

    /// <summary>
    /// INV-46: the description as the built-in report prints it, beside a "By" column: an entry's optional source
    /// (the tool it came from) follows the text, unless it only repeats the entry type (a handoff's "Handoff").
    /// A milestone's source is its actor, already in "By".
    /// </summary>
    public string DescriptionWithSource =>
        Type != Milestone && Source is { Length: > 0 } s && !string.Equals(s, Type, StringComparison.OrdinalIgnoreCase)
            ? $"{Description} (Source: {s})"
            : Description;

    /// <summary>
    /// The subtitle of the investigation-timeline section, naming the milestones when it carries them, and
    /// (INV-23) saying once how many entries came from an import, instead of marking each as recorded later.
    /// </summary>
    public static string InvestigationSubtitle(IEnumerable<ReportTimelineItem> items)
    {
        var list = items as IReadOnlyCollection<ReportTimelineItem> ?? items.ToList();
        var text = list.Any(x => x.Type == Milestone)
            ? "Analyst and team actions, with the response milestones."
            : "Analyst and team actions.";
        var imported = list.Count(x => x.Imported);
        if (imported > 0)
            text += imported == 1
                ? " One entry was imported from a structured summary and is dated as the summary gave it."
                : $" {imported} entries were imported from a structured summary and are dated as the summary gave them.";
        return text;
    }
}
/// <summary>INV-19: the case brief as plain text (Markdown flattened, indicators defanged), with its version. INV-36:
/// its first part is the case summary, which the report already prints as the summary, so it isn't repeated here.</summary>
public sealed record ReportBrief(int Version, DateTimeOffset RevisedAtUtc, string RevisedBy,
    string? WorkingAssessment, string? Known, string? OpenQuestions, string? NextSteps);

/// <summary>A file in the evidence index. CAP-08: when, where from and by whom it was collected, each when recorded
/// (where from and by whom defanged as the rest of the report is).</summary>
public sealed record ReportEvidenceItem(string FileName, long SizeBytes, string Sha256, DateTimeOffset UploadedAtUtc, string UploadedBy,
    DateTimeOffset? CollectedAtUtc = null, string? CollectedFrom = null, string? CollectedBy = null)
{
    /// <summary>CAP-08: the collection in one line ("2026-10-01 09:30 UTC, from mail01 by J. Smith"); empty when none is recorded.</summary>
    public string Collected => Evidence.EvidenceCollection.Line(CollectedAtUtc, CollectedFrom, CollectedBy);
}
/// <summary>An analyst note: <see cref="Body"/> is plain text; <see cref="Blocks"/> keeps its Markdown formatting for print.</summary>
public sealed record ReportNoteItem(DateTimeOffset AtUtc, string Author, string Body, IReadOnlyList<RichBlock>? Blocks = null);
/// <summary>A response task. HR-02: a done task carries its recorded result, when it was completed and by whom.</summary>
public sealed record ReportActionItemRow(string Title, string? Owner, DateTimeOffset? DueAtUtc, string Status,
    string? Result = null, DateTimeOffset? CompletedAtUtc = null, string? CompletedBy = null)
{
    /// <summary>The status as printed: "Done, 2026-10-01 10:18 UTC by Dev Analyst" for a completed task.</summary>
    public string StatusLine => CompletedAtUtc is { } at
        ? string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{Status}, {at.UtcDateTime:yyyy-MM-dd HH:mm} UTC{(string.IsNullOrWhiteSpace(CompletedBy) ? "" : " by " + CompletedBy)}")
        : Status;
}
public sealed record ReportAssignmentRow(string User, string Role);
/// <summary>
/// CAP-07: one regulator's notice, as the notification summary (Business Impact) and the <c>notice.*</c> template fields
/// print it: when, and how it was given when that's recorded. <paramref name="Method"/> is its label, <paramref name="File"/>
/// the evidence file's name, and <paramref name="How"/> all of it in words, as the timeline milestone says it.
/// </summary>
public sealed record ReportNoticeRow(string Jurisdiction, DateTimeOffset NotifiedAtUtc, DateTimeOffset? DueAtUtc, string? Method,
    string? Reference, string? NotifiedBy, string? File, string? How)
{
    /// <summary>"Notice to NY: 2026-10-02 14:00 UTC. By portal, reference NYDFS-114, notified by Pat Lee, notice file ack.pdf."</summary>
    public string Line => string.Create(System.Globalization.CultureInfo.InvariantCulture,
        $"Notice to {Jurisdiction}: {NotifiedAtUtc.UtcDateTime:yyyy-MM-dd HH:mm} UTC.{(How is null ? "" : $" {How}.")}");
}
/// <summary>
/// CAP-34: one outside party, as the report's legal and governance lines and the <c>party.*</c> template fields print it.
/// <paramref name="Role"/> is its label. <paramref name="Notes"/> is only in the template field: the built-in layout prints
/// the facts that identify the party (ADR 0012).
/// </summary>
public sealed record ReportPartyRow(string Role, string Name, string? Contact, string? Reference, DateTimeOffset? EngagedAtUtc,
    string? Notes, string Line);
/// <summary>E-26: the post-incident review, as printed in the lessons-learned report (Markdown kept as blocks).</summary>
public sealed record ReportReview(IReadOnlyList<RichBlock> WhatHappened, IReadOnlyList<RichBlock> ContributingFactors,
    IReadOnlyList<RichBlock> WhatWorkedWell, IReadOnlyList<RichBlock> OpportunitiesToImprove, bool NoActionsIdentified);
/// <summary>PROD-41: one improvement action row in the lessons-learned report.</summary>
public sealed record ReportImprovementActionRow(string Title, string? RelatedArea, string? Details, string Owner,
    DateTimeOffset? TargetDateUtc, string Status, string? OutcomeNote);
/// <param name="Tlp">BUG-72: the entity's own TLP marking ("TLP:RED"), if any, printed beside it as in the IOC table.</param>
public sealed record ReportEntityRow(string Type, string Value, string? Label, string Disposition, string? Description, string? Source,
    string? Tlp = null);
public sealed record ReportRelationshipRow(string Source, string Relationship, string Target, string? Description);
/// <param name="Source">HR-13: "Tagged", "Attack chain (2 steps)" or both.</param>
public sealed record ReportTechniqueRow(string TechniqueId, string Name, string Tactic, string Source = "Tagged");
/// <summary>PROD-45: one indicator of compromise (malicious or suspicious), value defanged when reports defang.</summary>
public sealed record ReportIocRow(string Type, string Value, string Verdict, string? Tlp, DateTimeOffset AddedAtUtc,
    string? Source, string? Description)
{
    /// <summary>BUG-537: the date added as both renderers print it, in the invariant (Gregorian) calendar whatever the
    /// server's culture.</summary>
    public string Added => AddedAtUtc.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
}

/// <summary>One ordered step of the reconstructed attack narrative (Event timeline), for the report.</summary>
/// <param name="Where">On a third-party case, "Vendor" or "Our environment" (after a pivot); null on an internal case.</param>
/// <param name="Stated">ST-02: the time as stated when it isn't exact ("Between 2026-03-02 and 2026-03-06"); null when exact.</param>
public sealed record ReportAttackStep(int Order, DateTimeOffset OccurredAtUtc, string Tactics, string Actor,
    string Target, string? TechniqueId, string Description, string? Where = null, string? Stated = null)
{
    /// <summary>The step's time for the report: the stated wording, or the exact time in UTC.</summary>
    public string When => Stated ?? OccurredAtUtc.ToString("u", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>The note printed under an attack chain with any approximate time.</summary>
    public const string ApproximateNote = "Times are as reported. Where only a date, a range or no time was given, the step says so, and its place in the order is as reported.";
}

/// <summary>Flat, presentation-ready projection of a case for the report generator and Word templates. A record, so
/// a template can be filled from the case model with the review added (<c>with</c>).</summary>
public sealed record CaseReportModel
{
    // Deployment branding for the header (out of source; set in the admin console).
    public string? OrganizationName { get; init; }
    public string? TeamName { get; init; }
    /// <summary>Raw logo image bytes for the header, or null. Paired with <see cref="LogoContentType"/>.</summary>
    public byte[]? LogoBytes { get; init; }
    public string? LogoContentType { get; init; }

    /// <summary>
    /// Which document this model renders. <see cref="ReportKind.Case"/> is the examiner-facing case report
    /// (sections below); <see cref="ReportKind.LessonsLearned"/> renders only the review + improvement actions
    /// (E-26/PROD-41), kept as a separate document so it can be handled and shared on its own terms.
    /// </summary>
    public ReportKind Kind { get; init; } = ReportKind.Case;

    public bool IsLessonsLearned => Kind == ReportKind.LessonsLearned;

    /// <summary>
    /// Optional confidentiality legend printed at the top of every page (lessons-learned report only). Admin-set
    /// wording (e.g. a privilege marking counsel has approved); null prints nothing.
    /// </summary>
    public string? Legend { get; init; }

    /// <summary>PROD-44: indicators in this report are defanged; the renderers print a one-line explanation.</summary>
    public bool IndicatorsDefanged { get; init; }

    /// <summary>The explanation printed wherever indicators appear, when <see cref="IndicatorsDefanged"/>.</summary>
    public const string DefangNote =
        "Indicators are defanged (hxxp://, [.], [at]) so they can't be clicked. Restore them before using them in security tools.";

    /// <summary>Enabled body sections in print order (from the administered layout). Empty = default all.</summary>
    public IReadOnlyList<ReportSection> Sections { get; init; } = Enum.GetValues<ReportSection>();

    public required string CaseNumber { get; init; }
    public required string Title { get; init; }
    public required string Classification { get; init; }
    public required string Phase { get; init; }
    public required string Severity { get; init; }
    public required string Origin { get; init; }
    public string? VendorName { get; init; }
    public string? DetectionCaseId { get; init; }
    public string? Summary { get; init; }
    /// <summary>The Summary with its Markdown formatting kept (headings, emphasis, lists) for print.</summary>
    public IReadOnlyList<RichBlock> SummaryBlocks { get; init; } = [];
    /// <summary>E-36: free-text data context. Printed as analyst notes, beneath the authoritative data elements.</summary>
    public string? DataTypesInvolved { get; init; }
    public string? ImpactedAssets { get; init; }

    // Structured impact assessment (E-12).
    public int? AffectedIndividualsCount { get; init; }
    public string? DataElementsSummary { get; init; }
    /// <summary>Regulatory-notification grouping (X-03): which jurisdictions the involved data elements
    /// trigger notification in, e.g. "NY — Social Security number, Medical / health information; US — Payment
    /// card". Null when no involved element carries a notification jurisdiction.</summary>
    public string? NotificationTriggersSummary { get; init; }
    public string? AffectedStates { get; init; }

    public bool LegalReferred { get; init; }
    public string? LegalNote { get; init; }

    // Materiality determination (PROD-18): a Legal/committee decision recorded for the file. Surfaced in the
    // report because Legal reads the report, not the app. Only rendered once a determination has been started.
    /// <summary>Human label for the current determination (e.g. "Material", "Under review"); null when Undetermined.</summary>
    public string? MaterialityStatus { get; init; }
    /// <summary>True once a final material / not-material call has been recorded.</summary>
    public bool MaterialityDetermined { get; init; }
    public string? MaterialityDecisionMaker { get; init; }
    public DateTimeOffset? MaterialityDecidedOnUtc { get; init; }
    public string? MaterialityRationale { get; init; }
    /// <summary>UX-10: a legal hold is in effect — case data must be preserved (no deletion). Surfaced in
    /// the report because Legal reads the report, not the app.</summary>
    public bool LegalHold { get; init; }

    public DateTimeOffset? DetectedAtUtc { get; init; }
    /// <summary>PROD-07: the regulatory-notification milestone, when set. Legal reads the report, not the app.</summary>
    public DateTimeOffset? ReportedAtUtc { get; init; }
    /// <summary>CAP-07: each regulator's notice, in the order given, with how it was given when that's recorded.</summary>
    public IReadOnlyList<ReportNoticeRow> Notices { get; init; } = [];
    /// <summary>CAP-34: the outside parties (counsel, forensics, the insurer, law enforcement), by role and when engaged.</summary>
    public IReadOnlyList<ReportPartyRow> Parties { get; init; } = [];
    public DateTimeOffset? ContainedAtUtc { get; init; }
    /// <summary>BUG-165: why containment wasn't needed (then <see cref="ContainedAtUtc"/> is null, and this was decided
    /// at <see cref="ContainmentDecidedAtUtc"/>).</summary>
    public string? ContainmentNotNeeded { get; init; }
    public DateTimeOffset? ContainmentDecidedAtUtc { get; init; }
    /// <summary>When recovery began (the case's resolved time is set on entering Recovery).</summary>
    public DateTimeOffset? ResolvedAtUtc { get; init; }
    /// <summary>HR-16: when the activity began, if recorded, so the Outcome section tells the story in order.</summary>
    public DateTimeOffset? ActivityBeganAtUtc { get; init; }

    /// <summary>ST-04: why <see cref="ActivityBeganAtUtc"/> is approximate ("the first attack step is …"); null when it isn't.</summary>
    public string? ActivityBeganApproximate { get; init; }
    public DateTimeOffset? ClosedAtUtc { get; init; }
    /// <summary>HR-01: what the case concluded when it closed (the outcome's label), when one was recorded.</summary>
    public string? Outcome { get; init; }
    /// <summary>HR-01: the closing brief's conclusion, printed with the outcome.</summary>
    public string? Conclusion { get; init; }
    /// <summary>HR-15: on a closed case changed since it closed, a neutral note saying how often and by whom.</summary>
    public string? ChangedAfterClosure { get; init; }

    public IReadOnlyList<ReportClassificationItem> ClassificationHistory { get; init; } = [];
    public IReadOnlyList<ReportClassificationItem> SeverityHistory { get; init; } = [];
    /// <summary>A third-party case's disclosure milestones (empty on an internal case).</summary>
    public IReadOnlyList<ReportTimelineItem> DisclosureMilestones { get; init; } = [];
    public IReadOnlyList<ReportAttackStep> AttackChain { get; init; } = [];
    public IReadOnlyList<ReportTimelineItem> InvestigationTimeline { get; init; } = [];
    public IReadOnlyList<ReportEvidenceItem> Evidence { get; init; } = [];
    public IReadOnlyList<ReportNoteItem> Notes { get; init; } = [];

    /// <summary>INV-19: the current case brief, if one has been written.</summary>
    public ReportBrief? Brief { get; init; }
    public IReadOnlyList<ReportActionItemRow> ActionItems { get; init; } = [];

    // Lessons-learned report only (Kind == LessonsLearned).
    public ReportReview? Review { get; init; }
    public IReadOnlyList<ReportImprovementActionRow> ImprovementActions { get; init; } = [];

    /// <summary>The review's labelled sections in print order, skipping empty ones — shared by every renderer.</summary>
    public IReadOnlyList<(string Label, IReadOnlyList<RichBlock> Blocks)> ReviewParagraphs => Review is null ? [] :
        new (string Label, IReadOnlyList<RichBlock> Blocks)[]
        {
            ("What happened", Review.WhatHappened), ("Contributing factors", Review.ContributingFactors),
            ("What worked well", Review.WhatWorkedWell), ("Opportunities to improve", Review.OpportunitiesToImprove)
        }.Where(p => p.Blocks.Count > 0).ToList();

    /// <summary>What prints when there are no improvement actions: an explicit "none identified", else "(none recorded)".</summary>
    public string NoActionsText => Review?.NoActionsIdentified == true
        ? "The review identified no improvement actions." : "(none recorded)";

    /// <summary>An action's detail cell: the plan, plus the outcome note once it is closed.</summary>
    public static string ActionDetail(ReportImprovementActionRow a) =>
        string.Join(" ", new[] { a.Details, a.OutcomeNote is null ? null : $"Outcome: {a.OutcomeNote}" }
            .Where(s => !string.IsNullOrWhiteSpace(s)));

    /// <summary>The provenance stamp's hash label — the lessons report hashes its own content, not the case row.</summary>
    public string ContentHashLabel => IsLessonsLearned ? "Review content hash" : "Case content hash";
    public IReadOnlyList<ReportAssignmentRow> Assignments { get; init; } = [];
    public IReadOnlyList<ReportEntityRow> Entities { get; init; } = [];
    public IReadOnlyList<ReportRelationshipRow> Relationships { get; init; } = [];
    public IReadOnlyList<ReportTechniqueRow> Techniques { get; init; } = [];

    /// <summary>PROD-46: the attack chain drawn across ATT&amp;CK tactic lanes (PNG; several when it wraps). Empty = none.</summary>
    public IReadOnlyList<byte[]> AttackChainImages { get; init; } = [];

    /// <summary>PROD-46: the entity relationship graph (PNG), or null.</summary>
    public byte[]? EntityGraphImage { get; init; }

    /// <summary>PROD-46: alt text for the pictures (the tables carry the same facts).</summary>
    public const string AttackChainAlt = "Attack chain: each step in time order, placed in its ATT&CK tactic lane. The table below lists the same steps.";
    public const string EntityGraphAlt = "Entity relationship graph: entities colored by verdict, arrows for relationships. Appendix B lists the same relationships.";

    /// <summary>PROD-45: the indicators-of-compromise table (malicious and suspicious entities).</summary>
    public IReadOnlyList<ReportIocRow> Iocs { get; init; } = [];

    /// <summary>PROD-45: the report's TLP marking, printed on every page (null only for legacy callers).</summary>
    public TlpLevel? Tlp { get; init; }

    /// <summary>PROD-45: the marking text ("TLP:AMBER"), or null.</summary>
    public string? TlpLabel => Tlp is { } t ? Domain.Enums.Tlp.Label(t) : null;

    /// <summary>PROD-45: the one-line sharing statement printed with the case facts.</summary>
    public string? SharingLine => Tlp is { } t ? $"Sharing: {Domain.Enums.Tlp.Label(t)}. {Domain.Enums.Tlp.Meaning(t)}" : null;

    /// <summary>PROD-45: the caption under the Indicators of Compromise heading.</summary>
    public string IocCaption =>
        "Indicators judged malicious or suspicious, for blocking and hunting. Every entity examined is listed under Systems Reviewed."
        + (Iocs.Any(i => i.Tlp is not null) ? " A TLP value on an indicator applies to that indicator in place of the report's marking." : "")
        + (IndicatorsDefanged ? " " + DefangNote : "");

    // --- BUG-517: what the built-in report prints, shared by the Word report and the in-app preview so they can't drift.

    /// <summary>BUG-81: the referral and hold, the data context and the impacted assets are each printed once. Their home
    /// is Business Impact when the profile includes it; otherwise the facts (and Systems Reviewed for the assets).</summary>
    public bool ImpactHome => Sections.Contains(ReportSection.BusinessImpact);

    /// <summary>The lines after the sharing statement in the case facts: a pointer to Business Impact, or (without that
    /// section) the data context and the legal referral and hold themselves.</summary>
    public IReadOnlyList<string> FactsLines
    {
        get
        {
            if (ImpactHome)
            {
                var held = new[] { LegalReferred ? "Legal/Privacy referral" : null, LegalHold ? "legal hold" : null,
                    Parties.Count > 0 ? "outside parties" : null,   // CAP-34
                    DataTypesInvolved is not null ? "data context" : null }.OfType<string>().ToList();
                if (held.Count == 0) return [];
                var said = string.Join(", ", held);
                return [$"{char.ToUpperInvariant(said[0])}{said[1..]}: see Business Impact."];
            }
            var lines = new List<string>();
            if (DataTypesInvolved is not null) lines.Add($"Data context (analyst notes): {DataTypesInvolved}");
            lines.AddRange(LegalLines);
            return lines;
        }
    }

    private IEnumerable<string> LegalLines
    {
        get
        {
            if (LegalReferred) yield return $"Legal/Privacy referral recorded. {LegalNote}";
            if (LegalHold) yield return "Legal hold in effect. Case data must be preserved and not deleted.";
            // CAP-34: the outside parties with their references, beside the referral and the hold.
            foreach (var p in Parties) yield return p.Line;
        }
    }

    /// <summary>The Business Impact section's lines, in order; empty when no impact assessment is recorded.</summary>
    public IReadOnlyList<string> BusinessImpactLines
    {
        get
        {
            var ic = System.Globalization.CultureInfo.InvariantCulture;
            var lines = new List<string>();
            if (AffectedIndividualsCount is { } n) lines.Add(string.Create(ic, $"Affected individuals: {n:N0}"));
            if (DataElementsSummary is not null) lines.Add($"Data elements: {DataElementsSummary}");
            if (NotificationTriggersSummary is not null) lines.Add($"Notification triggers: {NotificationTriggersSummary}");
            lines.AddRange(Notices.Select(x => x.Line));   // CAP-07: the notification summary
            if (!string.IsNullOrWhiteSpace(AffectedStates)) lines.Add($"Affected jurisdictions: {AffectedStates}");
            if (!string.IsNullOrWhiteSpace(ImpactedAssets)) lines.Add($"Impacted assets: {ImpactedAssets}");
            if (DataTypesInvolved is not null) lines.Add($"Data context (analyst notes): {DataTypesInvolved}");
            lines.AddRange(LegalLines);
            if (MaterialityStatus is { } ms)
            {
                var by = string.IsNullOrWhiteSpace(MaterialityDecisionMaker) ? "" : $" by {MaterialityDecisionMaker}";
                // WF-36: the day the call was made, in the organization's zone (the model carries it there).
                var on = MaterialityDecidedOnUtc is { } d ? string.Create(ic, $" on {d.DateTime:yyyy-MM-dd}") : "";
                lines.Add($"Materiality: {ms}{(MaterialityDetermined ? $", determined{by}{on}" : "")}.");
                if (!string.IsNullOrWhiteSpace(MaterialityRationale)) lines.Add($"Materiality rationale: {MaterialityRationale}");
            }
            return lines;
        }
    }

    /// <summary>A third-party case: its Event Timeline has the vendor's steps (with a "Where" column) and the disclosure
    /// milestones.</summary>
    public bool IsVendorCase => DisclosureMilestones.Count > 0 || !string.IsNullOrWhiteSpace(VendorName);

    /// <summary>The attack chain is printed on an internal case always (with "(none)"), on a vendor case when it has steps.</summary>
    public bool ShowsAttackChain => AttackChain.Count > 0 || !IsVendorCase;

    /// <summary>The caption above the attack chain.</summary>
    public string AttackChainCaption
    {
        get
        {
            if (!IsVendorCase) return "Reconstructed adversary activity in order: MITRE ATT&CK tactic(s), actor → target, and technique.";
            var vendor = string.IsNullOrWhiteSpace(VendorName) ? "the vendor" : VendorName;
            return AttackChain.Any(x => x.Where == "Our environment")
                ? $"The attacker's activity in order: in {vendor}'s environment as the vendor reported it, then in our environment after the pivot. MITRE ATT&CK tactic(s), actor → target, and technique."
                : $"The attacker's activity in {vendor}'s environment, as the vendor reported it: MITRE ATT&CK tactic(s), actor → target, and technique.";
        }
    }

    /// <summary>The attack chain table's columns: a vendor case adds "Where" after the time.</summary>
    public string[] AttackChainHeaders => IsVendorCase
        ? ["#", "When (UTC)", "Where", "Tactic(s)", "Actor → Target", "Technique", "What happened"]
        : ["#", "When (UTC)", "Tactic(s)", "Actor → Target", "Technique", "What happened"];

    /// <summary>One attack-chain row, matching <see cref="AttackChainHeaders"/>.</summary>
    public string[] AttackChainRow(ReportAttackStep x)
    {
        string[] row =
        [
            x.Order.ToString(System.Globalization.CultureInfo.InvariantCulture),
            x.When,
            x.Tactics,
            string.IsNullOrEmpty(x.Actor) && string.IsNullOrEmpty(x.Target) ? "" : $"{x.Actor} → {x.Target}",
            x.TechniqueId ?? "",
            x.Description
        ];
        return IsVendorCase ? [.. row.Take(2), x.Where ?? "", .. row.Skip(2)] : row;
    }

    public const string DisclosureCaption = "What the vendor reported to us and what we confirmed, in order.";
    public static readonly string[] DisclosureHeaders = ["When (UTC)", "Milestone", "What happened", "Source"];
    public static string[] DisclosureRow(ReportTimelineItem x) => [x.When, x.Type, x.Description, x.Source ?? ""];

    /// <summary>Systems Reviewed: the impacted assets, or a pointer to Business Impact where they are printed; null when none.</summary>
    public string? SystemsImpactedAssetsLine => string.IsNullOrWhiteSpace(ImpactedAssets) ? null
        : ImpactHome ? "Impacted assets: see Business Impact." : $"Impacted assets: {ImpactedAssets}";

    public static readonly string[] EntityHeaders = ["Type", "Value", "Label", "Disposition", "TLP", "Source"];
    public static string[] EntityRow(ReportEntityRow x) => [x.Type, x.Value, x.Label ?? "", x.Disposition, x.Tlp ?? "", x.Source ?? ""];

    /// <summary>
    /// The Outcome section's dated lines. HR-16: in the order they happened, as the timeline tells it; "Resolved" was the
    /// move into Recovery. ST-04: an approximate start says why.
    /// </summary>
    public IReadOnlyList<string> OutcomeStamps
    {
        get
        {
            var stamps = new (string Label, DateTimeOffset? At)[]
            {
                ("Activity began", ActivityBeganAtUtc), ("Detected", DetectedAtUtc),
                ContainmentNotNeeded is { } why ? ($"Containment not needed ({why})", ContainmentDecidedAtUtc) : ("Contained", ContainedAtUtc),
                ("Recovery started", ResolvedAtUtc), ("Reported to regulators", ReportedAtUtc), ("Closed", ClosedAtUtc)
            };
            var ic = System.Globalization.CultureInfo.InvariantCulture;
            return stamps.Where(s => s.At is not null).OrderBy(s => s.At)
                .Select(s => s.Label == "Activity began" && ActivityBeganApproximate is { } approx
                    ? string.Create(ic, $"{s.Label}: {s.At:u} (approximate: {approx})")
                    : string.Create(ic, $"{s.Label}: {s.At:u}"))
                .ToList();
        }
    }

    /// <summary>BUG-81: the Outcome points to where the referral and hold are printed; null when there's neither.</summary>
    public string? OutcomeLegalPointer => !LegalReferred && !LegalHold ? null
        : ImpactHome ? "Legal/Privacy: see Business Impact." : "Legal/Privacy: see the case facts at the top.";

    public required string GeneratedBy { get; init; }
    public required DateTimeOffset GeneratedAtUtc { get; init; }

    /// <summary>SHA-256 of the case content (provenance stamp embedded in the document).</summary>
    public required string ContentHash { get; init; }
}
