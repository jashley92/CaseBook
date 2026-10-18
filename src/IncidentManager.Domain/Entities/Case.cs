using System.Globalization;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using IncidentManager.Domain.ValueObjects;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// The central item: an escalated security matter tracked end-to-end. Aggregate root that
/// owns its history, timeline, notes, evidence, tasks, assignments and reports, and enforces
/// classification/lifecycle invariants through behavior rather than open setters.
/// </summary>
public class Case : AuditableEntity, IHashableEntity
{
    // --- Human identifier: YYYY-NN_DescriptiveName (e.g. 2026-01_PhishingWave) ---
    public int Year { get; private set; }
    public int Sequence { get; private set; }
    public string DescriptiveName { get; private set; } = string.Empty;

    /// <summary>Composed, unique human key persisted for lookup.</summary>
    public string CaseNumber { get; private set; } = string.Empty;

    /// <summary>
    /// True when an analyst set the case number explicitly rather than letting it auto-generate. Custom
    /// numbers are excluded from the auto-sequence counters and are preserved through a promotion (they
    /// are not renumbered). Not part of the tamper-evident canonical — the number itself already is.
    /// </summary>
    public bool HasCustomNumber { get; private set; }

    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// The formal IRP classification on the regulatory ladder (AdverseEvent → Incident → Breach), or
    /// <c>null</c> for a <b>Complex Event</b> — a pre-triage holding state for a matter still being worked
    /// that has not yet entered the ladder. The first assignment of a real classification is a
    /// <see cref="Reclassify">promotion</see> onto the ladder. Null carries no regulatory weight; all
    /// notification/bundle logic keys on <see cref="Domain.Enums.Classification.Breach"/>.
    /// </summary>
    public Classification? Classification { get; private set; }
    public CasePhase Phase { get; private set; }
    public Severity Severity { get; private set; }
    public CaseOrigin Origin { get; set; }

    public string? Summary { get; set; }
    public string? ImpactedAssets { get; set; }
    public string? DataTypesInvolved { get; set; }

    // --- Structured impact assessment (E-12): the facts Legal needs for a breach determination. ---
    /// <summary>Estimated number of affected individuals (nullable = not yet assessed).</summary>
    public int? AffectedIndividualsCount { get; set; }
    /// <summary>The involved personal / non-public <see cref="DataElement"/>s, by stable key (X-03). Replaces
    /// the former <c>DataElementTypes</c> bit set; the keys (not labels) are what the canonical hashes.</summary>
    public List<CaseDataElement> DataElements { get; set; } = new();
    /// <summary>Comma-separated US state/jurisdiction codes affected (e.g. "NY,NJ,CT").</summary>
    public string? AffectedStates { get; set; }

    /// <summary>Optional reference to the originating detection-source case (e.g. the SIEM/XDR case id;
    /// reference only, no live sync). The source's display label is a configurable operational setting.</summary>
    public string? DetectionCaseId { get; set; }

    public ThirdPartyDetails? ThirdParty { get; set; }
    public LegalReferral LegalReferral { get; set; } = new();

    /// <summary>
    /// The materiality determination (E-12 sibling of <see cref="LegalReferral"/>): whether this is a
    /// material, disclosure-triggering matter. Not the SOC's call — recorded here on behalf of Legal /
    /// a disclosure committee. Enforced at closure for Incidents/Breaches via the stage gate.
    /// </summary>
    public MaterialityDetermination Materiality { get; set; } = new();

    /// <summary>AD identifier of the assigned Incident Commander.</summary>
    public string? IncidentCommander { get; set; }

    /// <summary>Need-to-know: restricts visibility to assigned + IC + Legal + Admin.</summary>
    public bool IsRestricted { get; set; }
    public bool IsArchived { get; set; }

    /// <summary>
    /// PROD-43: a tabletop / IRP-exercise case (NYDFS 500.16 testing), not a real matter. Set at creation
    /// and immutable thereafter (no mutator — an exercise can never be relabelled as a live case, or a live
    /// case as a drill). It is fully usable in its own workspace, but is deliberately excluded from every
    /// org-posture aggregate, automated reminder, and pushed feed (dashboards, team workload, the reminder
    /// scanners, the personal digest / calendar feed, the outbound IOC feed) and from cross-case IOC
    /// correlation suggestions, so a drill never pollutes real metrics or gets linked to a real case. It
    /// remains in the tamper-evident audit chain — that chain must stay complete to verify — where its
    /// entries are attributable to the exercise case number. Part of the canonical, so the flag is hashed.
    /// </summary>
    public bool IsExercise { get; private set; }

    /// <summary>Legal hold blocks archival/retention purge.</summary>
    public bool LegalHold { get; set; }

    // F-12: a pending request to release the legal hold, awaiting a second person's approval (when the org turns
    // two-person release on). Audited like any change. BUG-632: in the canonical from format 4 (only when set, so no
    // other case re-baselines): a request planted in the database let its "requester" approve the release alone.
    public string? LegalHoldReleaseRequestedBy { get; private set; }
    public DateTimeOffset? LegalHoldReleaseRequestedAtUtc { get; private set; }
    public string? LegalHoldReleaseReason { get; private set; }
    public bool LegalHoldReleasePending => LegalHoldReleaseRequestedBy is not null;

    /// <summary>
    /// Optional per-case <see cref="ReportProfile"/> (E-28): when set, that profile's section layout
    /// overrides the global <c>Reporting:SectionLayout</c> for this case's report + preview. Null = use
    /// the global default. A reporting <em>preference</em>, deliberately kept out of the tamper-evident
    /// canonical (<see cref="BuildCanonicalContent"/>) — a change is still audited by the save interceptor.
    /// </summary>
    public Guid? ReportProfileId { get; set; }

    /// <summary>
    /// CAP-36: the <see cref="Team"/> that owns the case, for routing (its chat webhook, detection source) and filtering
    /// only. Null: no team (the global settings). It never changes who can see the case (ADR 0003). In the canonical from
    /// format 5, only when set, so a case without a team keeps its exact hash. See <see cref="SetTeam"/>.
    /// </summary>
    public Guid? TeamId { get; private set; }

    // --- Lifecycle timestamps (for MTTD/MTTR/containment metrics) ---
    public DateTimeOffset? OccurredAtUtc { get; set; }
    public DateTimeOffset? DetectedAtUtc { get; set; }
    public DateTimeOffset? ReportedAtUtc { get; set; }
    /// <summary>
    /// WF-11: the jurisdictions in play when the case became reported (comma-separated codes; empty when none were),
    /// so a later change to a data element's jurisdictions in Administration doesn't reopen, re-judge or invent notices
    /// for a case already reported. BUG-284: followed by ";" and the data elements the case had then
    /// ("NY,NJ;SSN,DL"), so what's in play is the jurisdictions kept plus those of elements added since, under today's
    /// settings (<see cref="KeptInPlay"/>). It stays as it was when the case goes back to unreported (an element added
    /// brings in a new regulator, a notice is removed), so today's settings don't come back in full, and removing the
    /// element added by mistake puts the case back to reported. Only clearing every notice (a mis-entry) empties it. Null
    /// for a case never reported, and for one reported before it was recorded (back-filled at start-up). BUG-563: a value
    /// from before the elements were recorded gets them at start-up, and before the elements next change. BUG-631: it
    /// decides which regulators a reported case owes, so it's in the canonical from format 4 (when set), and the start-up
    /// back-fills are audited changes.
    /// </summary>
    public string? ReportedJurisdictions { get; set; }

    /// <summary>WF-11: the kept jurisdictions as codes; null when none are kept.</summary>
    public IReadOnlyList<string>? FrozenJurisdictions => KeptJurisdictions(ReportedJurisdictions);

    /// <summary>BUG-284: the data elements the case had when it was reported; null when that wasn't recorded.</summary>
    public IReadOnlyList<string>? FrozenElementKeys => KeptElementKeys(ReportedJurisdictions);

    public const int MaxReportedJurisdictionsLength = 1000;

    // BUG-404: the separators of a ReportedJurisdictions value; a jurisdiction code can't hold either.
    private static readonly char[] CodeSeparators = [',', ';'];

    /// <summary>
    /// BUG-428: each notice's value under every code it covers. A notice recorded before BUG-404 refused separators can
    /// name "NY;CA", and counts for both (the row itself is hashed, so it isn't rewritten). A notice for the one code wins
    /// over such a combined one.
    /// </summary>
    public static Dictionary<string, T> ByNoticeCode<T>(IEnumerable<(string Jurisdiction, T Value)> notices)
    {
        var result = new Dictionary<string, T>(StringComparer.OrdinalIgnoreCase);
        foreach (var (jurisdiction, value) in notices.OrderBy(n => n.Jurisdiction.IndexOfAny(CodeSeparators) >= 0))
            foreach (var code in jurisdiction.Split(CodeSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                result.TryAdd(code, value);
        return result;
    }

    private static string[] Codes(string part) =>
        part.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>The jurisdictions part of a <see cref="ReportedJurisdictions"/> value.</summary>
    public static IReadOnlyList<string>? KeptJurisdictions(string? kept) =>
        kept is null ? null : Codes(kept.Split(';')[0]);

    /// <summary>The data-elements part of a <see cref="ReportedJurisdictions"/> value, or null when it has none.</summary>
    public static IReadOnlyList<string>? KeptElementKeys(string? kept) =>
        kept?.IndexOf(';') is >= 0 and var i ? Codes(kept[(i + 1)..]) : null;

    /// <summary>
    /// WF-11 / BUG-284: the jurisdictions in play on a case holding <paramref name="kept"/>: those kept when it was reported,
    /// plus those today's settings give the elements added since (<paramref name="live"/>). Without a kept value, today's
    /// settings for every element. A kept value without its elements (from before they were recorded) counts the elements
    /// in <paramref name="elementsIfUnknown"/> as the ones it had (the elements before an edit), or else just what was kept.
    /// </summary>
    public static IReadOnlyList<string> KeptInPlay(string? kept, IReadOnlyCollection<string> currentKeys,
        Func<IEnumerable<string>, IReadOnlyList<string>> live, IEnumerable<string>? elementsIfUnknown = null)
    {
        if (KeptJurisdictions(kept) is not { } jurisdictions) return live(currentKeys);
        if ((KeptElementKeys(kept) ?? elementsIfUnknown?.ToList()) is not { } had) return jurisdictions;
        var added = currentKeys.Where(k => !had.Contains(k, StringComparer.OrdinalIgnoreCase)).ToList();
        return added.Count == 0 ? jurisdictions
            : jurisdictions.Union(live(added), StringComparer.OrdinalIgnoreCase).ToList();
    }

    // WF-11: set when the case becomes reported, with the elements it has then (BUG-284); left as it was otherwise.
    private void FreezeJurisdictions(IEnumerable<string>? inPlay)
    {
        if (ReportedAtUtc is null) return;
        // BUG-404: a code holding a separator (an element's code stored with ";") is split, so it can't end the codes part.
        var codes = string.Join(',', (inPlay ?? []).SelectMany(j => j.Split(CodeSeparators))
            .Select(j => j.Trim().ToUpperInvariant()).Where(j => j.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(j => j, StringComparer.Ordinal));
        ReportedJurisdictions = WithElements(codes, DataElements.Select(d => d.ElementKey)) ?? codes;
    }

    /// <summary>
    /// BUG-618: an element added while the case stays reported (it brought no regulator in) counts as one it had (owner
    /// decision), so a later admin change to that element doesn't put a regulator in play on the case page and register
    /// while the reminders, dashboard, Desk and close gate (which go by the reported time) see none. Call after
    /// <see cref="ReportedFromNotices"/>. Too long to hold them, just the codes are kept: then every element counts as had.
    /// </summary>
    public void KeepElementsWhileReported()
    {
        if (ReportedAtUtc is null || ReportedJurisdictions is not { } kept || KeptElementKeys(kept) is not { } had) return;
        var current = DataElements.Select(d => d.ElementKey).ToList();
        if (current.All(k => had.Contains(k, StringComparer.OrdinalIgnoreCase))) return;
        ReportedJurisdictions = WithElements(kept, had.Concat(current)) ?? kept.Split(';')[0];
    }

    /// <summary>
    /// BUG-284: a kept value's codes followed by <paramref name="elements"/> ("NY,NJ;SSN,DL"); null when that's too long to
    /// store. BUG-563: also how a kept value from before the elements were recorded gets them.
    /// </summary>
    public static string? WithElements(string kept, IEnumerable<string> elements)
    {
        var withElements = kept.Split(';')[0] + ";" + string.Join(',', elements.Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(k => k, StringComparer.Ordinal));
        return withElements.Length <= MaxReportedJurisdictionsLength ? withElements : null;
    }
    public DateTimeOffset? ContainedAtUtc { get; set; }
    /// <summary>
    /// BUG-165: why containment wasn't needed, when the case went past Containment without it (a deliberate, recorded
    /// decision). The containment clock stops at that decision (<see cref="ContainedAtUtc"/> holds its time), and the
    /// case is left out of time-to-contain and the containment target's met/missed counts.
    /// </summary>
    public string? ContainmentNotNeededReason { get; set; }
    public const int MaxContainmentReason = 1000;
    public DateTimeOffset? ResolvedAtUtc { get; set; }
    public DateTimeOffset? ClosedAtUtc { get; set; }

    /// <summary>
    /// HR-15: when the current closure was recorded (the latest move to Closed, by recorded time, not its effective
    /// time), or null while the case is open. Anything recorded after it was added after closure. Needs
    /// <see cref="StatusChanges"/> loaded.
    /// </summary>
    public DateTimeOffset? ClosureRecordedAtUtc => Phase == CasePhase.Closed
        ? StatusChanges.Where(s => s.To == CasePhase.Closed).Select(s => (DateTimeOffset?)s.ChangedAtUtc).Max()
        : null;

    /// <summary>
    /// BUG-310: the brief version that was current when the case last closed (the closing brief, or the version it left
    /// unchanged), not a revision made after closure. Null while open, for a case closed without an outcome, or with no
    /// brief. Needs <see cref="StatusChanges"/> and <see cref="Briefs"/> loaded.
    /// </summary>
    public CaseBrief? ClosingBrief => Phase == CasePhase.Closed && OutcomeKey is not null
        && StatusChanges.Where(s => s.To == CasePhase.Closed).MaxBy(s => s.ChangedAtUtc) is { } close
            ? Briefs.Where(b => b.CreatedAtUtc <= close.ChangedAtUtc).MaxBy(b => b.Version)
            : null;

    /// <summary>
    /// HR-01: what the case concluded, as the stable key of a <see cref="CaseOutcome"/>. Recorded when it's closed
    /// (and on that close's <see cref="StatusChange"/>), cleared when it's reopened. Null on cases closed before
    /// outcomes were recorded.
    /// </summary>
    public string? OutcomeKey { get; set; }

    public string? RowHash { get; set; }

    // --- Owned collections ---
    public List<ClassificationChange> ClassificationChanges { get; set; } = new();
    public List<MaterialityChange> MaterialityChanges { get; set; } = new();
    public List<StatusChange> StatusChanges { get; set; } = new();
    public List<GatePassage> GatePassages { get; set; } = new();
    public List<SeverityChange> SeverityChanges { get; set; } = new();
    public List<TimelineEntry> TimelineEntries { get; set; } = new();
    public List<AnalystNote> Notes { get; set; } = new();
    public List<Evidence> Evidence { get; set; } = new();
    public List<ActionItem> ActionItems { get; set; } = new();
    public List<CaseAssignment> Assignments { get; set; } = new();
    /// <summary>INV-31: who joined, changed role or left, and when.</summary>
    public List<AssignmentChange> AssignmentChanges { get; set; } = new();
    /// <summary>HR-05: how entities' verdicts changed over the investigation.</summary>
    public List<EntityVerdictChange> VerdictChanges { get; set; } = new();
    public List<Report> Reports { get; set; } = new();
    public List<CaseEntity> Entities { get; set; } = new();
    public List<EntityRelationship> EntityRelationships { get; set; } = new();
    public List<CaseTechnique> Techniques { get; set; } = new();

    /// <summary>INV-10: evidence cited by timeline entries.</summary>
    public List<EvidenceCitation> Citations { get; set; } = new();

    /// <summary>INV-09: the case brief, one row per version (the current one has <c>IsCurrent</c>).</summary>
    public List<CaseBrief> Briefs { get; set; } = new();

    /// <summary>INV-05b: later corrections of when a transition happened (append-only).</summary>
    public List<TransitionTimeCorrection> TimeCorrections { get; set; } = new();

    /// <summary>BUG-09: when each regulator was notified (one per jurisdiction).</summary>
    public List<JurisdictionNotice> JurisdictionNotices { get; set; } = new();

    /// <summary>CAP-34: outside parties on the case (counsel, forensics, the insurer, law enforcement), each with its reference.</summary>
    public List<CaseParty> Parties { get; set; } = new();

    /// <summary>Saved graph node positions (cosmetic; not audited/hashed).</summary>
    public List<EntityLayout> EntityLayouts { get; set; } = new();

    private Case() { } // EF

    /// <summary>Opens a new case, seeding the initial classification and status history. A null
    /// <paramref name="classification"/> opens the case as a <b>Complex Event</b> (pre-triage intake);
    /// it enters the ladder later via <see cref="Reclassify"/>. <paramref name="numberDate"/> (BUG-112) is the moment
    /// on the organization's wall clock that dates a Complex Event's number; it defaults to <paramref name="nowUtc"/>.</summary>
    public static Case Open(int year, int sequence, string descriptiveName, string title,
        Classification? classification, Severity severity, CaseOrigin origin,
        string actor, DateTimeOffset nowUtc, bool isExercise = false, DateTimeOffset? numberDate = null)
    {
        var c = new Case
        {
            Year = year,
            Sequence = sequence,
            DescriptiveName = Slug(descriptiveName),
            Title = string.IsNullOrWhiteSpace(title) ? descriptiveName : title.Trim(),
            Classification = classification,
            Phase = CasePhase.New,
            Severity = severity,
            Origin = origin,
            IsExercise = isExercise,   // PROD-43: fixed at creation; there is no mutator to change it later
            CreatedAtUtc = nowUtc,
            CreatedBy = actor,
            DetectedAtUtc = nowUtc
        };
        // Complex Events (pre-triage intake, null classification) are numbered by creation date so they
        // never mix with IRP-ladder items and there is no sequence to reuse; a promotion later renumbers
        // into the sequence-based IRP scheme. IRP items use the per-year sequence.
        c.CaseNumber = classification is null
            ? FormatComplexEventNumber(numberDate ?? nowUtc, c.DescriptiveName)
            : FormatCaseNumber(year, sequence, c.DescriptiveName);
        // Only record an initial classification when the case opens on the ladder; a Complex Event
        // records its first classification when it is later promoted.
        if (classification is { } initial)
        {
            c.ClassificationChanges.Add(new ClassificationChange
            {
                CaseId = c.Id, From = null, To = initial,
                Reason = "Initial classification", ChangedBy = actor, ChangedAtUtc = nowUtc
            });
        }
        c.StatusChanges.Add(new StatusChange
        {
            CaseId = c.Id, From = null, To = CasePhase.New, ChangedBy = actor, ChangedAtUtc = nowUtc
        });
        c.SeverityChanges.Add(new SeverityChange
        {
            CaseId = c.Id, From = null, To = severity, Reason = "Initial severity", ChangedBy = actor, ChangedAtUtc = nowUtc
        });
        return c;
    }

    /// <summary>Changes classification (e.g. escalates to Breach), recording the reason and history.
    /// When the case is a Complex Event (null classification) this is its <b>promotion</b> onto the
    /// ladder — the recorded transition has a null <c>From</c>. The target is always a real rung.</summary>
    public void Reclassify(Classification to, string reason, string actor, DateTimeOffset nowUtc,
        DateTimeOffset? effectiveAtUtc = null)
    {
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("A reason is required to change classification.");
        if (to == Classification) return;
        EnsureNotArchived("change its classification");
        // BUG-107: raising a closed case would skip the close gate for the higher class (a closed Breach that never
        // passed the Breach close checks). Reopen it, raise it, and close it again; lowering it stays allowed.
        if (Phase == CasePhase.Closed && RaisesClassification(to))
            throw new InvalidOperationException("Reopen the case to raise its classification. Closing it again runs the close checks for the new class.");

        var effective = CheckEffective(effectiveAtUtc, nowUtc, "classification",
            ClassificationChanges.Where(x => x.From is not null || x.ChangedAtUtc > CreatedAtUtc).Select(x => x.EffectiveAt));

        var from = Classification;
        Classification = to;
        ClassificationChanges.Add(new ClassificationChange
        {
            CaseId = Id, From = from, To = to, Reason = reason.Trim(), ChangedBy = actor, ChangedAtUtc = nowUtc,
            EffectiveAtUtc = effective
        });
        Touch(actor, nowUtc);
    }

    /// <summary>True when <paramref name="to"/> is above the current classification (or promotes a Complex Event).</summary>
    public bool RaisesClassification(Classification to) => Classification is not { } from || to > from;

    /// <summary>
    /// Renumbers an (auto-numbered) Complex Event into the IRP scheme when it is promoted onto the ladder,
    /// keeping the original year and descriptive name. The application layer allocates the next IRP
    /// sequence; this applies it. No-op for a case that already carries a custom number.
    /// </summary>
    public void RenumberToIrp(int sequence, string actor, DateTimeOffset nowUtc)
    {
        if (HasCustomNumber) return;
        Sequence = sequence;
        CaseNumber = FormatCaseNumber(Year, sequence, DescriptiveName);
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// Re-formats this Complex Event's date-based number with a disambiguator suffix, used only while
    /// creating a second Complex Event that has the same descriptor on the same day. Not an audited edit —
    /// the case is still being created.
    /// </summary>
    public void SetComplexEventNumber(DateTimeOffset date, int disambiguator)
        => CaseNumber = FormatComplexEventNumber(date, DescriptiveName, disambiguator);

    /// <summary>
    /// Sets an explicit, analyst-chosen case number (uniqueness is enforced by the application layer + the
    /// unique index). Marks the case as custom-numbered so the auto-sequence counters skip it and a later
    /// promotion leaves the number as the analyst set it.
    /// </summary>
    public void AssignCustomNumber(string number, string actor, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(number))
            throw new ArgumentException("A case number is required.");

        CaseNumber = number.Trim();
        HasCustomNumber = true;
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// Records that this case passed (or was forced through) a stage gate (C-07). The evaluation itself
    /// lives in the application layer — this just captures the tamper-evident outcome on the aggregate.
    /// </summary>
    public GatePassage RecordGatePassage(StageGateTrigger trigger, bool overridden,
        string? overrideJustification, string? commentary, string detail, string actor, DateTimeOffset nowUtc)
    {
        var passage = new GatePassage
        {
            CaseId = Id, Trigger = trigger, PassedAtUtc = nowUtc, PassedBy = actor,
            WasOverridden = overridden,
            OverrideJustification = string.IsNullOrWhiteSpace(overrideJustification) ? null : overrideJustification.Trim(),
            Commentary = string.IsNullOrWhiteSpace(commentary) ? null : commentary.Trim(),
            Detail = detail
        };
        GatePassages.Add(passage);
        return passage;
    }

    /// <summary>Advances (or moves) the lifecycle phase, capturing containment/resolution/closure timestamps.
    /// <paramref name="effectiveAtUtc"/> (INV-05) is when the move actually happened, for a change recorded after
    /// the fact; the milestone timestamps take that time, not the moment it was recorded.</summary>
    /// <param name="containedAtUtc">BUG-165: when moving past Containment without going through it, when the case was
    /// contained.</param>
    /// <param name="containmentNotNeededReason">BUG-165: or why containment wasn't needed.</param>
    public void ChangePhase(CasePhase to, string? reason, string actor, DateTimeOffset nowUtc,
        DateTimeOffset? effectiveAtUtc = null, string? outcomeKey = null,
        DateTimeOffset? containedAtUtc = null, string? containmentNotNeededReason = null, DateTimeOffset? resolvedAtUtc = null)
    {
        if (to == Phase) return;
        // BUG-208: going past Recovery without it says when it was resolved, as skipping Containment says when it was
        // contained: otherwise the resolution clock runs on through the post-incident review.
        var skipsRecovery = SkipsRecovery(to);
        if (!skipsRecovery && resolvedAtUtc is not null)
            throw new ArgumentException("When it was resolved is recorded only when a case goes past Recovery without it.");
        if (skipsRecovery && resolvedAtUtc is null)
            throw new ArgumentException("This case hasn't been through Recovery. Say when it was resolved.");
        var notNeeded = string.IsNullOrWhiteSpace(containmentNotNeededReason) ? null : containmentNotNeededReason.Trim();
        var skips = SkipsContainment(to);
        if (!skips && (containedAtUtc is not null || notNeeded is not null))
            throw new ArgumentException("When it was contained, or why it wasn't needed, is recorded only when a case goes past Containment without it.");
        if (skips && containedAtUtc is null && notNeeded is null)
            throw new ArgumentException("This case hasn't been through Containment. Say when it was contained, or that containment wasn't needed and why.");
        if (notNeeded is { Length: > MaxContainmentReason })
            throw new ArgumentException($"Keep why containment wasn't needed to {MaxContainmentReason:N0} characters or fewer.");
        if (outcomeKey is not null && to != CasePhase.Closed)
            throw new ArgumentException("An outcome is recorded only when a case is closed.");
        // BUG-62: leaving Closed is a reopen by another route, so it needs a reason as Reopen does (E-27).
        if (Phase == CasePhase.Closed && string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("A reason is required to move a case out of Closed.");

        var effective = CheckEffective(effectiveAtUtc, nowUtc, "phase",
            StatusChanges.Where(x => x.From is not null).Select(x => x.EffectiveAt));
        var at = effective ?? nowUtc;

        // BUG-165 follow-up: checked before anything changes, so a refused move leaves the case as it was.
        if (skips && containedAtUtc is { } containedAt)
        {
            if (containedAt > nowUtc) throw new ArgumentException("When it was contained can't be in the future.");
            if (DetectedAtUtc is { } det && ToMinute(containedAt) < ToMinute(det)) throw new ArgumentException("It can't have been contained before it was detected.");
            if (containedAt > at) throw new ArgumentException("It can't have been contained after this move.");
        }
        // BUG-208: likewise, against the contained time this move leaves (unless it wasn't needed).
        if (skipsRecovery && resolvedAtUtc is { } resolvedAt)
        {
            if (resolvedAt > nowUtc) throw new ArgumentException("When it was resolved can't be in the future.");
            if (DetectedAtUtc is { } det && ToMinute(resolvedAt) < ToMinute(det)) throw new ArgumentException("It can't have been resolved before it was detected.");
            var containedBy = skips ? containedAtUtc : ContainmentNotNeededReason is null ? ContainedAtUtc : null;
            if (containedBy is { } cb && resolvedAt < cb) throw new ArgumentException("It can't have been resolved before it was contained.");
            if (resolvedAt > at) throw new ArgumentException("It can't have been resolved after this move.");
        }

        var from = Phase;
        Phase = to;
        StatusChanges.Add(new StatusChange
        {
            CaseId = Id, From = from, To = to, Reason = reason, ChangedBy = actor, ChangedAtUtc = nowUtc,
            EffectiveAtUtc = effective, OutcomeKey = to == CasePhase.Closed ? outcomeKey : null
        });
        // HR-01: the outcome belongs to this close. Reopening clears it (the close's history row keeps it).
        OutcomeKey = to == CasePhase.Closed ? outcomeKey : null;

        // BUG-165: going past Containment without it, the containment milestone is what was said: when it was contained,
        // or that it wasn't needed (the clock stops at this move).
        if (skips && containedAtUtc is { } contained) ContainedAtUtc = contained;   // checked above
        else if (skips)
        {
            ContainmentNotNeededReason = notNeeded;
            ContainedAtUtc = at;
        }

        if (skipsRecovery && resolvedAtUtc is { } resolved) ResolvedAtUtc = resolved;   // BUG-208, checked above

        // BUG-229: coming into Containment after recording that it wasn't needed takes that back: it needed containing
        // after all, so it's contained at this move and measured against the target again (the decision stays in the trail).
        if (to == CasePhase.Containment && ContainmentNotNeededReason is not null)
        {
            ContainmentNotNeededReason = null;
            ContainedAtUtc = at;
            // REV-11: and so it wasn't resolved before that. A resolution recorded on the way past (the skip to Recovery)
            // would now read as before the containment; it's resolved again when the case next reaches Recovery.
            if (ResolvedAtUtc < at) ResolvedAtUtc = null;
        }

        switch (to)
        {
            case CasePhase.Containment: ContainedAtUtc ??= at; break;
            case CasePhase.Recovery: ResolvedAtUtc ??= at; break;
            case CasePhase.Closed: ClosedAtUtc ??= at; break;
        }

        // Reopening: leaving Closed must clear the closure timestamp, else the case reads as "closed at X"
        // while active and corrupts MTTR / dashboard math keyed on ClosedAtUtc (E-27). The contained/
        // resolved milestones stay — they really happened.
        if (from == CasePhase.Closed && to != CasePhase.Closed) ClosedAtUtc = null;

        Touch(actor, nowUtc);
    }

    /// <summary>
    /// BUG-165: whether moving to <paramref name="to"/> goes past Containment without it: from before Containment to
    /// Eradication, Recovery or Post-incident, with no contained time. Closing straight away doesn't (closing stops the
    /// clocks), and neither does a case already contained or recorded as not needing it. BUG-228: nor does leaving
    /// Closed for one of those phases skip the question: a case closed from Triage has no contained time either.
    /// </summary>
    // BUG-231: times people pick are to the minute; a detected time with seconds (from the import API, or a case filed with
    // Detected left blank) mustn't refuse the lowest minute the picker offers. REV-16: every "not before it was detected"
    // check compares to the minute.
    public static DateTimeOffset ToMinute(DateTimeOffset t) => new(t.Ticks - t.Ticks % TimeSpan.TicksPerMinute, t.Offset);

    public bool SkipsContainment(CasePhase to) =>
        Phase is < CasePhase.Containment or CasePhase.Closed
        && to is CasePhase.Eradication or CasePhase.Recovery or CasePhase.PostIncident
        && ContainedAtUtc is null && ContainmentNotNeededReason is null;

    /// <summary>
    /// BUG-208: whether moving to <paramref name="to"/> goes past Recovery without it: from before Recovery to
    /// Post-incident, with no resolved time. Closing straight away doesn't (closing stops the clocks), and neither does a
    /// case already resolved. BUG-228: leaving Closed for Post-incident counts too.
    /// </summary>
    public bool SkipsRecovery(CasePhase to) =>
        Phase is < CasePhase.Recovery or CasePhase.Closed && to == CasePhase.PostIncident && ResolvedAtUtc is null;

    /// <summary>
    /// Reopens a closed case (E-27): moves it back to the phase it held before closure (or Recovery if that
    /// can't be determined), clears <see cref="ClosedAtUtc"/>, and records the transition with the caller's
    /// reason. A first-class, reason-captured lifecycle action — closing again re-runs the close stage gate.
    /// </summary>
    /// <param name="containedAtUtc">WF-50: when the phase reopened to goes past Containment without it (a case closed before
    /// BUG-165 recorded the decision), when it was contained; or <paramref name="containmentNotNeededReason"/>.</param>
    /// <param name="resolvedAtUtc">WF-50: likewise for Recovery (BUG-208).</param>
    public void Reopen(string reason, string actor, DateTimeOffset nowUtc, DateTimeOffset? containedAtUtc = null,
        string? containmentNotNeededReason = null, DateTimeOffset? resolvedAtUtc = null)
    {
        if (Phase != CasePhase.Closed)
            throw new InvalidOperationException("Only a closed case can be reopened.");
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("A reason is required to reopen a case.");

        ChangePhase(ReopenPhase(), reason.Trim(), actor, nowUtc, containedAtUtc: containedAtUtc,
            containmentNotNeededReason: containmentNotNeededReason, resolvedAtUtc: resolvedAtUtc);
    }

    /// <summary>The phase a reopened case returns to: the one it was in when it closed (Recovery if that can't be told),
    /// so the lifecycle reads truthfully.</summary>
    public CasePhase ReopenPhase() => StatusChanges
        .Where(s => s.To == CasePhase.Closed && s.From is { } f && f != CasePhase.Closed)
        .OrderByDescending(s => s.ChangedAtUtc)
        .Select(s => s.From!.Value)
        .DefaultIfEmpty(CasePhase.Recovery)
        .First();

    /// <summary>
    /// Updates the descriptive/core fields plus the two intake timestamps — when the matter was first
    /// <paramref name="detectedAtUtc">detected</paramref> and, optionally, when activity actually began
    /// (<paramref name="occurredAtUtc"/>, e.g. initial access / first malicious activity). Detected drives
    /// the response-SLA clock and the MTTD/dwell metrics, so it must be a real instant and not merely the
    /// moment the case was filed in the tool (E-34). Lifecycle milestones that the workflow captures
    /// automatically — contained/resolved/closed — are not edited here.
    /// </summary>
    /// <summary>How long before detection initial activity may be recorded: ten years.</summary>
    public const int MaxDwellYears = 10;

    /// <summary>
    /// Rejects an initial-activity time more than <see cref="MaxDwellYears"/> years before detection. Older is almost
    /// certainly a mistyped year, and it would distort dwell time and the detection SLA figures.
    /// </summary>
    public static void EnsurePlausibleDwell(DateTimeOffset? occurredAtUtc, DateTimeOffset detectedAtUtc)
    {
        // C12: a detection in the first ten years of the calendar has no earlier limit (AddYears would throw).
        if (occurredAtUtc is { } occurred && detectedAtUtc.Year > MaxDwellYears && occurred < detectedAtUtc.AddYears(-MaxDwellYears))
            throw new ArgumentException($"Initial activity can't be more than {MaxDwellYears} years before detection. Check the year.");
    }

    public void UpdateDetails(string title, string? summary, string? detectionCaseId, string? dataTypesInvolved,
        string? impactedAssets, DateTimeOffset detectedAtUtc, DateTimeOffset? occurredAtUtc,
        string actor, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(title))
            throw new ArgumentException("Title is required.");
        if (detectedAtUtc > nowUtc)
            throw new ArgumentException("The detected time can't be in the future.");
        if (occurredAtUtc is { } occurred && occurred > detectedAtUtc)
            throw new ArgumentException("Activity can't begin after it was detected.");
        if (occurredAtUtc != OccurredAtUtc || detectedAtUtc != DetectedAtUtc)
            EnsurePlausibleDwell(occurredAtUtc, detectedAtUtc);
        // Response times run from detection, so it can't move past a milestone already reached. Checked only when the
        // detected time changes, so an older record that breaks the rule can still have its other details edited.
        if (detectedAtUtc != DetectedAtUtc)
        {
            if (ContainedAtUtc is { } contained && detectedAtUtc > contained)
                throw new ArgumentException("The detected time can't be after the case was contained.");
            if (ResolvedAtUtc is { } resolved && detectedAtUtc > resolved)
                throw new ArgumentException("The detected time can't be after the case was resolved.");
            // BUG-39: nor past the other times that count from it.
            if (ClosedAtUtc is { } closed && detectedAtUtc > closed)
                throw new ArgumentException("The detected time can't be after the case was closed.");
            if (ReportedAtUtc is { } reported && detectedAtUtc > reported)
                throw new ArgumentException("The detected time can't be after regulators were notified.");
            if (StatusChanges.Where(x => x.From is not null).Select(x => x.EffectiveAt).DefaultIfEmpty(DateTimeOffset.MaxValue).Min()
                    is var firstMove && detectedAtUtc > firstMove)
                throw new ArgumentException($"The detected time can't be after the case first changed phase ({firstMove:u}).");
            // BUG-111: and the rest of what's dated from detection, each of which was checked against it when recorded.
            if (JurisdictionNotices.Select(n => (DateTimeOffset?)n.NotifiedAtUtc).Min() is { } firstNotice && detectedAtUtc > firstNotice)
                throw new ArgumentException($"The detected time can't be after a regulator was notified ({firstNotice:u}).");
            // BUG-164: a Complex Event's promotion (From is null, but after the case opened) counts too, as Reclassify dates it.
            if (ClassificationChanges.Where(x => x.From is not null || x.ChangedAtUtc > CreatedAtUtc)
                    .Select(x => (DateTimeOffset?)x.EffectiveAt).Min() is { } firstReclass
                && detectedAtUtc > firstReclass)
                throw new ArgumentException($"The detected time can't be after the case was first reclassified ({firstReclass:u}).");
            if (SeverityChanges.Where(x => x.From is not null).Select(x => (DateTimeOffset?)x.EffectiveAt).Min() is { } firstSeverity
                && detectedAtUtc > firstSeverity)
                throw new ArgumentException($"The detected time can't be after the severity first changed ({firstSeverity:u}).");
            if (ActionItems.Select(a => a.CompletedAtUtc).Min() is { } firstDone && detectedAtUtc > firstDone)
                throw new ArgumentException($"The detected time can't be after a task was completed ({firstDone:u}).");
            // BUG-436: nor a verdict's "determined at" (BUG-414), which was checked against detection to the minute.
            if (VerdictChanges.Select(v => (DateTimeOffset?)v.EffectiveAt).Min() is { } firstVerdict
                && ToMinute(detectedAtUtc) > ToMinute(firstVerdict))
                throw new ArgumentException($"The detected time can't be after a verdict was reached ({firstVerdict:u}).");            // BUG-209: nor the materiality decision, which can start the notification clock. BUG-231: to the minute (the
            // picker's precision), and saying what to do when the decision was recorded as a date only (before v1.5.1,
            // stored at 00:00 UTC that day).
            if (Materiality.DecidedOnUtc is { } decided && ToMinute(detectedAtUtc) > ToMinute(decided))
                throw new ArgumentException($"The detected time can't be after materiality was decided ({decided:u})." +
                    (decided.TimeOfDay == TimeSpan.Zero
                        ? " That decision was recorded as a date only (before v1.5.1): record its materiality again with the time it was made, then change the detected time."
                        : ""));
        }

        Title = title.Trim();
        // INV-36: a changed summary is a new brief version, so every summary the case has had stays readable.
        if (Clean(summary) != Clean(Summary))
        {
            var cur = Briefs.FirstOrDefault(b => b.IsCurrent);
            AddBriefVersion(summary, cur?.WorkingAssessment, cur?.Known, cur?.OpenQuestions, cur?.NextSteps,
                actor, nowUtc, requireContent: false, appended: true);   // WF-30
        }
        DetectionCaseId = detectionCaseId?.Trim();   // CAP-14 review: trimmed, as the import matches it
        DataTypesInvolved = dataTypesInvolved;
        ImpactedAssets = impactedAssets;
        DetectedAtUtc = detectedAtUtc;
        OccurredAtUtc = occurredAtUtc;
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// Records the structured impact assessment (affected count, data elements, jurisdictions). The data
    /// elements are supplied as stable <see cref="DataElement.Key"/>s; the join set is reconciled minimally
    /// (like the timeline tactic set) so the audit chain only records genuine additions/removals.
    /// </summary>
    public void SetImpactAssessment(int? affectedIndividualsCount, IEnumerable<string> dataElementKeys,
        string? affectedStates, string actor, DateTimeOffset nowUtc)
    {
        if (affectedIndividualsCount is < 0)
            throw new ArgumentException("The affected-individual count can't be negative.");
        EnsureNotArchived("change its impact assessment");

        AffectedIndividualsCount = affectedIndividualsCount;

        var desired = dataElementKeys.Distinct(StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal);
        // BUG-563: a kept value from before its elements were recorded gets the ones the case has before this change, so
        // every reader can tell an element added now from one it had (without them, only the kept codes were in play).
        if (ReportedJurisdictions is { } kept && KeptElementKeys(kept) is null && !desired.SetEquals(DataElements.Select(d => d.ElementKey))
            && WithElements(kept, DataElements.Select(d => d.ElementKey)) is { } withElements)
            ReportedJurisdictions = withElements;
        DataElements.RemoveAll(d => !desired.Contains(d.ElementKey));
        foreach (var key in desired.Where(k => DataElements.All(d => d.ElementKey != k)))
            DataElements.Add(new CaseDataElement { CaseId = Id, ElementKey = key });

        // Normalize to a readable comma-space list (U-47a): "NY, NJ, PA", not "NY,NJ,PA".
        AffectedStates = string.IsNullOrWhiteSpace(affectedStates)
            ? null
            : string.Join(", ", affectedStates.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                              .Select(s => s.ToUpperInvariant())
                                              .Distinct());
        Touch(actor, nowUtc);
    }

    /// <summary>Changes the analyst-assessed severity, recording the transition in history.</summary>
    public void ChangeSeverity(Severity to, string? reason, string actor, DateTimeOffset nowUtc,
        DateTimeOffset? effectiveAtUtc = null)
    {
        if (to == Severity) return;
        var effective = CheckEffective(effectiveAtUtc, nowUtc, "severity",
            SeverityChanges.Where(x => x.From is not null).Select(x => x.EffectiveAt));
        var from = Severity;
        Severity = to;
        SeverityChanges.Add(new SeverityChange
        {
            CaseId = Id, From = from, To = to, Reason = reason, ChangedBy = actor, ChangedAtUtc = nowUtc,
            EffectiveAtUtc = effective
        });
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// Assigns a user to the case with a role (idempotent by user: assigning someone already on the case changes
    /// their role). A case has one Incident Commander: assigning one sets <see cref="IncidentCommander"/> and makes
    /// the previous commander an analyst; moving the commander to another role clears it.
    /// </summary>
    public void Assign(string userId, string displayName, CaseAssignmentRole role, string assignedBy, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(userId))
            throw new ArgumentException("A user is required to assign.");

        var existing = Assignments.FirstOrDefault(a => a.UserId == userId);
        CaseAssignmentRole? before = existing?.Role;
        if (existing is null)
        {
            Assignments.Add(new CaseAssignment
            {
                CaseId = Id, UserId = userId, UserDisplayName = displayName,
                Role = role, AssignedAtUtc = nowUtc, AssignedBy = assignedBy
            });
        }
        else
        {
            existing.Role = role;
            existing.UserDisplayName = displayName;
            existing.AssignedAtUtc = nowUtc;
            existing.AssignedBy = assignedBy;
        }
        if (before != role) RecordAssignmentChange(userId, displayName, before, role, assignedBy, nowUtc);

        if (role == CaseAssignmentRole.IncidentCommander)
        {
            foreach (var other in Assignments.Where(a => a.UserId != userId && a.Role == CaseAssignmentRole.IncidentCommander))
            {
                other.Role = CaseAssignmentRole.Analyst;
                RecordAssignmentChange(other.UserId, other.UserDisplayName, CaseAssignmentRole.IncidentCommander,
                    CaseAssignmentRole.Analyst, assignedBy, nowUtc);
            }
            IncidentCommander = userId;
        }
        else if (IncidentCommander == userId)
            IncidentCommander = null;

        Touch(assignedBy, nowUtc);
    }

    /// <summary>Removes a user's assignment. Clears the IC if that user was the commander.</summary>
    public void Unassign(string userId, string actor, DateTimeOffset nowUtc)
    {
        var existing = Assignments.FirstOrDefault(a => a.UserId == userId);
        if (existing is null) return;

        Assignments.Remove(existing);
        RecordAssignmentChange(existing.UserId, existing.UserDisplayName, existing.Role, null, actor, nowUtc);
        if (IncidentCommander == userId) IncidentCommander = null;
        Touch(actor, nowUtc);
    }

    private void RecordAssignmentChange(string userId, string displayName, CaseAssignmentRole? from,
        CaseAssignmentRole? to, string actor, DateTimeOffset nowUtc) =>
        AssignmentChanges.Add(new AssignmentChange
        {
            CaseId = Id, UserId = userId, UserDisplayName = displayName, From = from, To = to,
            ChangedBy = actor, ChangedAtUtc = nowUtc
        });

    /// <summary>Records a Legal/Privacy referral (capture only &mdash; deadlines are Legal's responsibility).</summary>
    public void ReferToLegal(string referredBy, string? contact, string? relevanceNote, DateTimeOffset nowUtc)
    {
        // REV-12: editing an existing referral (fixing the contact or the note) keeps when it was referred and by whom.
        var already = LegalReferral is { IsReferred: true, ReferredAtUtc: not null };
        LegalReferral = new LegalReferral
        {
            IsReferred = true,
            ReferredAtUtc = already ? LegalReferral!.ReferredAtUtc : nowUtc,
            ReferredBy = already ? LegalReferral!.ReferredBy : referredBy,
            ReferredToContact = contact, RegulatoryRelevanceNote = relevanceNote
        };
        Touch(referredBy, nowUtc);
    }

    /// <summary>
    /// Records the materiality determination — a decision the SOC does <b>not</b> make but must capture for
    /// the file. Allowed only once the case is on the Incident/Breach rungs (materiality is meaningless for a
    /// pre-ladder Complex Event or a mere Adverse Event). A <em>final</em> call (Material / Not material) must
    /// name who decided, when, and why — this record stands in for an off-app decision, so its provenance is
    /// mandatory; the interim states carry only what is known so far. <paramref name="actor"/> is the SOC user
    /// recording it, kept distinct from <paramref name="decisionMaker"/> (the external authority). Each status
    /// transition is captured in <see cref="MaterialityChanges"/>; the determination is part of the canonical.
    /// </summary>
    public void RecordMateriality(MaterialityStatus status, string? decisionMaker, DateTimeOffset? decidedOnUtc,
        string? rationale, string actor, DateTimeOffset nowUtc)
    {
        // BUG-59: a case downgraded to an Adverse Event keeps the determination made while it was an Incident (it's a
        // record), and can revise it, since a Material call still runs the notification clock.
        if (!MaterialityApplies)
            throw new InvalidOperationException("Materiality is determined only for Incidents and Breaches.");
        EnsureNotArchived("record its materiality");
        // BUG-227: only a call (Material / Not material) has a decision time. One stored while under review was offered
        // back as the decision time when the call was made, dating the notification clock from when the review began.
        if (status is not (MaterialityStatus.Material or MaterialityStatus.NotMaterial)) decidedOnUtc = null;
        if (decidedOnUtc is { } future && future > nowUtc)
            throw new ArgumentException("The decision date can't be in the future.");
        // BUG-209: a decision about what was found can't come before it was found (it would start the clock early).
        if (decidedOnUtc is { } early && DetectedAtUtc is { } detected && ToMinute(early) < ToMinute(detected))
            throw new ArgumentException("The decision date can't be earlier than the detected time.");

        if (status is MaterialityStatus.Material or MaterialityStatus.NotMaterial)
        {
            if (string.IsNullOrWhiteSpace(decisionMaker))
                throw new ArgumentException("A final determination must record who made the decision.");
            if (string.IsNullOrWhiteSpace(rationale))
                throw new ArgumentException("A final determination must record the rationale.");
            if (decidedOnUtc is null)
                throw new ArgumentException("A final determination must record the decision date.");
        }

        var previous = Materiality;
        var from = previous.Status;
        Materiality = new MaterialityDetermination
        {
            Status = status,
            DecisionMaker = string.IsNullOrWhiteSpace(decisionMaker) ? null : decisionMaker.Trim(),
            DecidedOnUtc = decidedOnUtc,
            Rationale = string.IsNullOrWhiteSpace(rationale) ? null : rationale.Trim(),
            RecordedBy = actor,
            RecordedAtUtc = nowUtc
        };

        // History captures status transitions, mirroring how classification/severity changes are recorded. REV-13: and a
        // call re-recorded with a corrected decision date, decider or rationale, since the timeline and report are built
        // from these rows: without one they kept showing the provenance that was corrected.
        var revised = status is MaterialityStatus.Material or MaterialityStatus.NotMaterial
            && (previous.DecidedOnUtc != Materiality.DecidedOnUtc
                || !string.Equals(previous.DecisionMaker, Materiality.DecisionMaker, StringComparison.Ordinal)
                || !string.Equals(previous.Rationale, Materiality.Rationale, StringComparison.Ordinal));
        if (from != status || revised)
            MaterialityChanges.Add(new MaterialityChange
            {
                CaseId = Id, From = from, To = status,
                DecisionMaker = Materiality.DecisionMaker, DecidedOnUtc = decidedOnUtc,
                Rationale = Materiality.Rationale, ChangedBy = actor, ChangedAtUtc = nowUtc
            });

        Touch(actor, nowUtc);
    }

    /// <summary>The entity with this type and value on the case (matched after normalizing, ignoring case), or null.</summary>
    public CaseEntity? FindEntity(EntityType type, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = IocObservable.Normalize(type, value);
        return Entities.FirstOrDefault(e => e.Type == type && string.Equals(e.Value, v, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Adds an entity/IOC (account, host, IP, hash, URL…). Idempotent by (type, value). Adding one that's already on
    /// the case never overwrites what the case has recorded about it (HR-04): its verdict changes only when it's still
    /// Unknown, and its label, description and source are filled only where blank. Changing a recorded verdict or
    /// detail is an edit (<see cref="EditEntity"/>), so re-pasting a list of indicators can't erase a finding.
    /// </summary>
    /// <param name="promotedReason">WF-29: the reason recorded when an indicator already here as Unknown takes the verdict
    /// it was added again with (a paste says "Set by paste"); an edit asks for one, so this one isn't left blank.</param>
    public CaseEntity AddEntity(EntityType type, string value, string? label, EntityDisposition disposition,
        string? description, string? source, string actor, DateTimeOffset nowUtc, string? promotedReason = null)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("An entity value is required.");

        // Refang defanged IOC notation on entry so correlation (E-08), links (E-05) and the pushed
        // feed (E-13) all match on canonical values — and so this dedup catches "1.1.1[.]1" == "1.1.1.1".
        var v = IocObservable.Normalize(type, value);
        // REV-18: a value that's only dots ("." or "[.]" as a domain) is nothing once it's normalized.
        if (v.Length == 0) throw new ArgumentException("That value is empty once it's normalized. Enter the indicator itself.");
        var existing = FindEntity(type, v);
        if (existing is not null)
        {
            var changed = false;
            if (existing.Disposition == EntityDisposition.Unknown && disposition != EntityDisposition.Unknown)
            {
                RecordVerdictChange(existing, disposition, promotedReason ?? "Set when added again", actor, nowUtc);
                existing.Disposition = disposition;
                changed = true;
            }
            if (string.IsNullOrWhiteSpace(existing.Label) && !string.IsNullOrWhiteSpace(label)) { existing.Label = label; changed = true; }
            if (string.IsNullOrWhiteSpace(existing.Description) && !string.IsNullOrWhiteSpace(description)) { existing.Description = description; changed = true; }
            if (string.IsNullOrWhiteSpace(existing.Source) && !string.IsNullOrWhiteSpace(source)) { existing.Source = source; changed = true; }
            if (changed)
            {
                existing.ModifiedBy = actor;
                existing.ModifiedAtUtc = nowUtc;
                Touch(actor, nowUtc);
            }
            return existing;
        }

        var entity = new CaseEntity
        {
            CaseId = Id, Type = type, Value = v, Label = label, Disposition = disposition,
            Description = description, Source = source, CreatedBy = actor, CreatedAtUtc = nowUtc
        };
        Entities.Add(entity);
        Touch(actor, nowUtc);
        return entity;
    }

    /// <summary>
    /// Corrects an existing entity in place (e.g. a mis-typed value, or a disposition re-assessed from
    /// Malicious to Benign). Nothing is versioned in the row itself — the append-only audit chain records
    /// the before→after — but <see cref="AuditableEntity.ModifiedBy"/>/<c>ModifiedAtUtc</c> mark it edited.
    /// </summary>
    public CaseEntity EditEntity(Guid entityId, EntityType type, string value, string? label,
        EntityDisposition disposition, string? description, string? source, string actor, DateTimeOffset nowUtc,
        string? reason = null, DateTimeOffset? determinedAtUtc = null)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("An entity value is required.");

        var entity = Entities.FirstOrDefault(e => e.Id == entityId)
            ?? throw new InvalidOperationException("Entity not found on this case.");

        var v = IocObservable.Normalize(type, value);
        // REV-18: a value that's only dots ("." or "[.]" as a domain) is nothing once it's normalized.
        if (v.Length == 0) throw new ArgumentException("That value is empty once it's normalized. Enter the indicator itself.");
        // Don't let an edit collapse this entity onto a different one of the same type+value.
        if (Entities.Any(e => e.Id != entityId && e.Type == type &&
                string.Equals(e.Value, v, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Another entity with the same type and value already exists on this case.");

        if (entity.Disposition != disposition)
            RecordVerdictChange(entity, disposition, reason, actor, nowUtc, determinedAtUtc);   // HR-05: before the label changes
        entity.Type = type;
        entity.Value = v;
        entity.Label = label;
        entity.Disposition = disposition;
        entity.Description = description;
        entity.Source = source;
        entity.ModifiedBy = actor;
        entity.ModifiedAtUtc = nowUtc;
        Touch(actor, nowUtc);
        return entity;
    }

    // HR-05: the findings history. Reads the entity as it is before the change.
    // BUG-414: <paramref name="determinedAtUtc"/> is when the verdict was actually reached, if before it's recorded: not in
    // the future, not before detection, not before this entity's previous verdict.
    private void RecordVerdictChange(CaseEntity entity, EntityDisposition to, string? reason, string actor, DateTimeOffset nowUtc,
        DateTimeOffset? determinedAtUtc = null)
    {
        var effective = CheckEffective(determinedAtUtc, nowUtc, "verdict",
            VerdictChanges.Where(v => v.EntityId == entity.Id).Select(v => v.EffectiveAt));
        var name = string.IsNullOrWhiteSpace(entity.Label) ? entity.Value : entity.Label!;
        VerdictChanges.Add(new EntityVerdictChange
        {
            CaseId = Id, EntityId = entity.Id, EntityLabel = name.Length > 400 ? name[..400] : name,
            From = entity.Disposition, To = to, Reason = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim(),
            ChangedBy = actor, ChangedAtUtc = nowUtc, EffectiveAtUtc = effective
        });
    }

    /// <summary>INV-32: pins an entity to (or unpins it from) the case context panel's key entities.</summary>
    public void SetEntityPinned(Guid entityId, bool pinned, string actor, DateTimeOffset nowUtc)
    {
        var entity = Entities.FirstOrDefault(e => e.Id == entityId)
            ?? throw new InvalidOperationException("Entity not found on this case.");
        if (entity.IsPinned == pinned) return;
        entity.IsPinned = pinned;
        entity.ModifiedBy = actor;
        entity.ModifiedAtUtc = nowUtc;
        Touch(actor, nowUtc);
    }

    /// <summary>PROD-45: sets (or clears, with null) an indicator's TLP sharing marking.</summary>
    public void SetEntityTlp(Guid entityId, TlpLevel? tlp, string actor, DateTimeOffset nowUtc)
    {
        var entity = Entities.FirstOrDefault(e => e.Id == entityId)
            ?? throw new InvalidOperationException("Entity not found on this case.");
        if (entity.Tlp == tlp) return;
        entity.Tlp = tlp;
        entity.ModifiedBy = actor;
        entity.ModifiedAtUtc = nowUtc;
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// Corrects an Event-timeline step in place (typo in the description, wrong tactic/technique, or a
    /// re-attributed actor/target). Event steps are short factual records; the audit chain preserves the
    /// prior value, so — unlike Investigation entries — they are not versioned.
    /// </summary>
    public TimelineEntry EditEventStep(Guid entryId, DateTimeOffset occurredAtUtc, IEnumerable<MitreTactic> tactics,
        string? techniqueId, Guid? actorEntityId, Guid? targetEntityId, string description, string? source,
        string actor, DateTimeOffset nowUtc, TimelineEntryType type = TimelineEntryType.Other, StepEnvironment? environment = null,
        StepTiming? timing = null)
    {
        if (string.IsNullOrWhiteSpace(description))
            throw new ArgumentException("A description is required.");

        var entry = TimelineEntries.FirstOrDefault(t => t.Id == entryId && t.Kind == TimelineKind.Event)
            ?? throw new InvalidOperationException("Event step not found on this case.");
        if (entry.IsRetracted)   // BUG-413
            throw new InvalidOperationException("That step was retracted, so it can't be edited. Add a new step instead.");
        if (timing?.AfterStepId == entryId) throw new ArgumentException("A step can't come after itself.");

        var normalisedTechnique = string.IsNullOrWhiteSpace(techniqueId) ? null : CaseTechnique.NormaliseId(techniqueId);

        if (actorEntityId is { } aid && Entities.All(e => e.Id != aid))
            throw new ArgumentException("The actor is not an entity on this case.");
        if (targetEntityId is { } tid && Entities.All(e => e.Id != tid))
            throw new ArgumentException("The target is not an entity on this case.");

        ApplyTiming(entry, occurredAtUtc, timing, editing: true);
        entry.Type = type;   // vendor-disclosure stage for third-party cases (E-32); Other for first-party
        entry.Description = description.Trim();
        entry.Source = source;
        entry.TechniqueId = normalisedTechnique;
        entry.ActorEntityId = actorEntityId;
        entry.TargetEntityId = targetEntityId;
        entry.Environment = Origin == CaseOrigin.ThirdParty ? environment : null;
        entry.ModifiedBy = actor;
        entry.ModifiedAtUtc = nowUtc;

        // Reconcile the tactic set minimally, so the audit chain only records genuine additions/removals.
        var desired = tactics.Distinct().ToHashSet();
        entry.Tactics.RemoveAll(t => !desired.Contains(t.Tactic));
        foreach (var tactic in desired.Where(d => entry.Tactics.All(x => x.Tactic != d)))
            entry.Tactics.Add(new EventStepTactic { TimelineEntryId = entry.Id, Tactic = tactic });

        Touch(actor, nowUtc);
        return entry;
    }

    /// <summary>
    /// Edits an Investigation-timeline entry by superseding the current version with a new one (the
    /// F-03 note pattern). The prior text and its timestamp are preserved, so lengthy meeting notes can
    /// be clarified without breaking the record of what was documented and when.
    /// </summary>
    public TimelineEntry EditInvestigationEntry(Guid entryId, TimelineEntryType type, DateTimeOffset occurredAtUtc,
        string newDescription, string? source, string actor, DateTimeOffset nowUtc,
        string? rationale = null, string? optionsConsidered = null, string? decidedBy = null)
    {
        if (string.IsNullOrWhiteSpace(newDescription))
            throw new ArgumentException("A description is required.");
        TimelineEntry.EnsureDecisionHasRationale(type, rationale);

        var current = TimelineEntries.FirstOrDefault(t =>
                t.Id == entryId && t.Kind == TimelineKind.Investigation && t.IsCurrent)
            ?? throw new InvalidOperationException("Investigation entry not found or already superseded.");

        current.IsCurrent = false;
        var next = new TimelineEntry
        {
            CaseId = Id,
            Kind = TimelineKind.Investigation,
            Type = type,
            OccurredAtUtc = occurredAtUtc,
            Description = newDescription.Trim(),
            Source = source,
            Version = current.Version + 1,
            SupersedesEntryId = current.Id,
            IsCurrent = true,
            EvidenceId = current.EvidenceId, // an attached screenshot (U-40) carries to the new version
            ActionItemId = current.ActionItemId, // INV-08: still the result of the same task
            PromotedFrom = current.PromotedFrom,  // INV-07: still promoted from the same source
            // INV-06: only a Decision keeps its decision details.
            Rationale = type == TimelineEntryType.Decision ? Clean(rationale) : null,
            OptionsConsidered = type == TimelineEntryType.Decision ? Clean(optionsConsidered) : null,
            DecidedBy = type == TimelineEntryType.Decision ? Clean(decidedBy) : null,
            CreatedBy = actor,
            CreatedAtUtc = nowUtc
        };
        TimelineEntries.Add(next);
        // INV-10: the evidence the entry cited still supports the new version.
        foreach (var cite in Citations.Where(x => x.TimelineEntryId == current.Id))
            cite.TimelineEntryId = next.Id;
        Touch(actor, nowUtc);
        return next;
    }

    /// <summary>
    /// BUG-413: takes a wrong entry off the record without deleting it (R3). The entry stops being current, so it leaves
    /// the timeline's counts, the attack chain and every report, and keeps its text with who retracted it, when and why.
    /// An Investigation entry is retracted at its latest version; its earlier versions stay as they were.
    /// </summary>
    public TimelineEntry RetractTimelineEntry(Guid entryId, string reason, string actor, DateTimeOffset nowUtc)
    {
        reason = (reason ?? "").Trim();
        if (reason.Length == 0) throw new ArgumentException("Say why it's being retracted.");
        if (reason.Length > 2000) throw new ArgumentException("Keep the reason to 2,000 characters or fewer.");
        var entry = TimelineEntries.FirstOrDefault(t => t.Id == entryId)
            ?? throw new InvalidOperationException("That entry isn't on this case.");
        if (entry.IsRetracted) throw new InvalidOperationException("That entry has already been retracted.");
        if (!entry.IsCurrent)
            throw new InvalidOperationException("That's an earlier version of an entry; retract the entry as it stands now.");

        entry.IsCurrent = false;
        entry.RetractedAtUtc = nowUtc;
        entry.RetractedBy = actor;
        entry.RetractReason = reason;
        entry.ModifiedBy = actor;
        entry.ModifiedAtUtc = nowUtc;
        Touch(actor, nowUtc);
        return entry;
    }

    /// <summary>
    /// INV-10: sets which evidence a current timeline entry cites (adding and removing only what changed, so the
    /// audit trail records just the real changes). Both the entry and the evidence must be on this case.
    /// </summary>
    public void SetCitations(Guid entryId, IEnumerable<Guid> evidenceIds, string actor, DateTimeOffset nowUtc)
    {
        if (TimelineEntries.All(t => t.Id != entryId || !t.IsCurrent))
            throw new InvalidOperationException("That timeline entry isn't on this case, or it has been superseded.");
        var desired = evidenceIds.Distinct().ToHashSet();
        if (desired.Any(id => Evidence.All(e => e.Id != id)))
            throw new InvalidOperationException("Only evidence on this case can be cited.");
        // CAP-21: a withdrawn file can't be newly cited; a citation made before it was withdrawn stays (and can be removed).
        if (desired.Any(id => Evidence.Any(e => e.Id == id && e.IsWithdrawn)
                              && !Citations.Any(x => x.TimelineEntryId == entryId && x.EvidenceId == id)))
            throw new InvalidOperationException("A withdrawn file can't be cited.");

        Citations.RemoveAll(x => x.TimelineEntryId == entryId && !desired.Contains(x.EvidenceId));
        foreach (var id in desired.Where(id => !Citations.Any(x => x.TimelineEntryId == entryId && x.EvidenceId == id)))
            Citations.Add(new EvidenceCitation { CaseId = Id, TimelineEntryId = entryId, EvidenceId = id });
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// Adds an Event-timeline step describing an adversary action: the attack narrative. Categorised by
    /// one or more MITRE ATT&amp;CK tactics, optionally a technique, and attributed actor &rarr; target
    /// (both must be entities already on this case). Append-only, like the other timeline entries.
    /// </summary>
    public TimelineEntry AddEventStep(DateTimeOffset occurredAtUtc, IEnumerable<MitreTactic> tactics,
        string? techniqueId, Guid? actorEntityId, Guid? targetEntityId, string description, string? source,
        string actor, DateTimeOffset nowUtc, Guid? evidenceId = null, TimelineEntryType type = TimelineEntryType.Other,
        StepEnvironment? environment = null, StepTiming? timing = null)
    {
        if (string.IsNullOrWhiteSpace(description))
            throw new ArgumentException("A description is required.");

        var normalisedTechnique = string.IsNullOrWhiteSpace(techniqueId) ? null : CaseTechnique.NormaliseId(techniqueId);

        if (actorEntityId is { } aid && Entities.All(e => e.Id != aid))
            throw new ArgumentException("The actor is not an entity on this case.");
        if (targetEntityId is { } tid && Entities.All(e => e.Id != tid))
            throw new ArgumentException("The target is not an entity on this case.");

        var entry = new TimelineEntry
        {
            CaseId = Id,
            Kind = TimelineKind.Event,
            // First-party attack steps categorise by tactic, so Type stays Other. A third-party/vendor case
            // has no adversary kill-chain in our estate (E-32): its event steps are vendor-disclosure
            // milestones instead, and the stage is carried in Type (Detection / Analysis / Communication / …).
            Type = type,
            Description = description.Trim(),
            Source = source,
            TechniqueId = normalisedTechnique,
            ActorEntityId = actorEntityId,
            TargetEntityId = targetEntityId,
            // Only a third-party case says where a step happened; an internal case's steps are all ours.
            Environment = Origin == CaseOrigin.ThirdParty ? environment : null,
            EvidenceId = evidenceId,
            CreatedBy = actor,
            CreatedAtUtc = nowUtc
        };
        foreach (var tactic in tactics.Distinct())
            entry.Tactics.Add(new EventStepTactic { TimelineEntryId = entry.Id, Tactic = tactic });

        ApplyTiming(entry, occurredAtUtc, timing, editing: false);
        TimelineEntries.Add(entry);
        Touch(actor, nowUtc);
        return entry;
    }

    // ---- ST-01: a step's time as stated, and its order among steps at the same time ----

    /// <summary>ST-03: sets the time, precision and place of a new event step built outside <see cref="AddEventStep"/>
    /// (the generic add an import uses), by the same rules.</summary>
    public void PlaceNewEventStep(TimelineEntry entry, DateTimeOffset occurredAtUtc, StepTiming? timing) =>
        ApplyTiming(entry, occurredAtUtc, timing, editing: false);

    private IEnumerable<TimelineEntry> EventStepsInOrder(TimelineEntry? except = null) =>
        TimelineEntries.Where(t => t.Kind == TimelineKind.Event && t.IsCurrent && t != except).InTimelineOrder();

    /// <summary>
    /// Sets an event step's time, precision and place from what was stated. A date is stored at 12:00 UTC on it; a
    /// step whose time wasn't stated takes the time of the step it follows (only as a sort key). When the time of a
    /// step changes, the not-stated steps placed directly after it move with it.
    /// </summary>
    private void ApplyTiming(TimelineEntry entry, DateTimeOffset occurredAtUtc, StepTiming? timing, bool editing)
    {
        var precision = timing?.Precision ?? TimePrecision.Exact;
        DateTimeOffset at;
        DateTimeOffset? until = null;
        Guid? after = null;
        var first = false;
        switch (precision)
        {
            case TimePrecision.Exact:
                at = occurredAtUtc;
                break;
            case TimePrecision.Day:
            case TimePrecision.OnOrBefore:
                at = StepTiming.DateAnchor(occurredAtUtc);
                break;
            case TimePrecision.Window:
                at = StepTiming.DateAnchor(occurredAtUtc);
                until = timing!.UntilUtc is { } u ? StepTiming.DateAnchor(u)
                    : throw new ArgumentException("Give the last date of the window.");
                if (until <= at) throw new ArgumentException("The window's last date must be after its first.");
                break;
            case TimePrecision.NotStated:
                if (timing!.AfterStepId is { } afterId)
                {
                    var prev = EventStepsInOrder(entry).FirstOrDefault(t => t.Id == afterId)
                        ?? throw new ArgumentException("The step it comes after isn't on this case.");
                    at = prev.OccurredAtUtc;
                    after = afterId;
                }
                else if (timing.First || !editing || entry.OccurredPrecision != TimePrecision.NotStated)
                {
                    // First (or, when nothing else is said, first too): before the earliest step, or the given time.
                    var earliest = EventStepsInOrder(entry).FirstOrDefault();
                    at = earliest?.OccurredAtUtc ?? occurredAtUtc;
                    first = earliest is not null;
                }
                else
                {
                    at = entry.OccurredAtUtc;   // editing a not-stated step without moving it: it stays where it is
                }
                break;
            default:
                throw new ArgumentException("Unknown time precision.");
        }

        var moved = !editing || at != entry.OccurredAtUtc || after is not null || first;
        // The not-stated steps directly after this one, which follow it when its time changes.
        var followers = editing && at != entry.OccurredAtUtc ? FollowersOf(entry) : [];

        entry.OccurredPrecision = precision == TimePrecision.Exact ? null : precision;
        entry.OccurredUntilUtc = until;
        if (!moved) { entry.OccurredAtUtc = at; return; }

        entry.OccurredAtUtc = at;
        if (after is { } a) PlaceAfter(entry, a);
        else if (first) PlaceFirst(entry);
        else PlaceLast(entry);

        var lead = entry;
        foreach (var f in followers)
        {
            f.OccurredAtUtc = at;
            PlaceAfter(f, lead.Id);
            lead = f;
        }
    }

    private List<TimelineEntry> FollowersOf(TimelineEntry entry)
    {
        var group = EventStepsInOrder().Where(t => t.OccurredAtUtc == entry.OccurredAtUtc).ToList();
        return group.SkipWhile(t => t != entry).Skip(1).TakeWhile(t => t.OccurredPrecision == TimePrecision.NotStated).ToList();
    }

    // The steps at the step's time, in order, without it.
    private List<TimelineEntry> TieGroup(TimelineEntry entry) =>
        EventStepsInOrder(entry).Where(t => t.OccurredAtUtc == entry.OccurredAtUtc).ToList();

    private static void Renumber(List<TimelineEntry> group)
    {
        for (var i = 0; i < group.Count; i++)
            if (group[i].StepOrder != i + 1) group[i].StepOrder = i + 1;
    }

    // Last at its time: the common case, so it changes nothing else (steps without an order sort by when recorded).
    private void PlaceLast(TimelineEntry entry)
    {
        var group = TieGroup(entry);
        entry.StepOrder = group.Count == 0 || group.All(t => t.StepOrder is null) ? null : group.Max(t => t.StepOrder ?? 0) + 1;
    }

    private void PlaceFirst(TimelineEntry entry)
    {
        var group = TieGroup(entry);
        group.Insert(0, entry);
        Renumber(group);
    }

    private void PlaceAfter(TimelineEntry entry, Guid afterId)
    {
        var group = TieGroup(entry);
        var i = group.FindIndex(t => t.Id == afterId);
        group.Insert(i < 0 ? group.Count : i + 1, entry);
        Renumber(group);
    }

    private void PlaceBefore(TimelineEntry entry, Guid beforeId)
    {
        var group = TieGroup(entry);
        var i = group.FindIndex(t => t.Id == beforeId);
        group.Insert(i < 0 ? 0 : i, entry);
        Renumber(group);
    }

    /// <summary>
    /// ST-01: moves an event step one place earlier or later. Steps at the same time swap; a step whose time wasn't
    /// stated takes its neighbour's time (as a sort key) to pass it. A step can't be moved past one whose stated time
    /// puts it elsewhere: its time has to change instead.
    /// </summary>
    public void MoveEventStep(Guid entryId, bool earlier, string actor, DateTimeOffset nowUtc)
    {
        // Among the attack steps (on a third-party case the disclosure milestones aren't part of the chain), the same
        // rule as the application's EventSteps.IsAttack.
        var steps = EventStepsInOrder().Where(t => Origin != CaseOrigin.ThirdParty || t.Tactics.Count > 0
            || !string.IsNullOrWhiteSpace(t.TechniqueId) || t.ActorEntityId is not null || t.TargetEntityId is not null
            || t.Environment is not null).ToList();
        var i = steps.FindIndex(t => t.Id == entryId);
        if (i < 0) throw new InvalidOperationException("Event step not found on this case.");
        var j = earlier ? i - 1 : i + 1;
        if (j < 0 || j >= steps.Count) return;   // already first or last
        var step = steps[i];
        var other = steps[j];

        if (other.OccurredAtUtc == step.OccurredAtUtc)
        {
            if (earlier) PlaceBefore(step, other.Id); else PlaceAfter(step, other.Id);
        }
        else if (step.OccurredPrecision == TimePrecision.NotStated)
        {
            step.OccurredAtUtc = other.OccurredAtUtc;
            if (earlier) PlaceBefore(step, other.Id); else PlaceAfter(step, other.Id);
        }
        else if (other.OccurredPrecision == TimePrecision.NotStated)
        {
            other.OccurredAtUtc = step.OccurredAtUtc;
            if (earlier) PlaceAfter(other, step.Id); else PlaceBefore(other, step.Id);
            other.ModifiedBy = actor;
            other.ModifiedAtUtc = nowUtc;
        }
        else
        {
            throw new InvalidOperationException("Its time puts it here. To move it, correct the step's time.");
        }
        step.ModifiedBy = actor;
        step.ModifiedAtUtc = nowUtc;
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// Tags a MITRE ATT&amp;CK technique on the case. Idempotent by technique ID: re-tagging the same
    /// ID updates its name/tactic rather than duplicating. The ID is validated and normalised.
    /// </summary>
    public CaseTechnique AddTechnique(string techniqueId, string name, MitreTactic tactic, string actor, DateTimeOffset nowUtc)
    {
        var id = CaseTechnique.NormaliseId(techniqueId);

        var existing = Techniques.FirstOrDefault(t => t.TechniqueId == id);
        if (existing is not null)
        {
            existing.Name = name?.Trim() ?? string.Empty;
            existing.Tactic = tactic;
            existing.ModifiedBy = actor;
            existing.ModifiedAtUtc = nowUtc;
            Touch(actor, nowUtc);
            return existing;
        }

        var technique = new CaseTechnique
        {
            CaseId = Id, TechniqueId = id, Name = name?.Trim() ?? string.Empty,
            Tactic = tactic, CreatedBy = actor, CreatedAtUtc = nowUtc
        };
        Techniques.Add(technique);
        Touch(actor, nowUtc);
        return technique;
    }

    /// <summary>
    /// CAP-34: records an outside party on the case (normalized and checked by <see cref="PartyDetails.Normalized"/>).
    /// </summary>
    public CaseParty AddParty(PartyDetails details, string actor, DateTimeOffset nowUtc)
    {
        var d = details.Normalized(nowUtc);
        var party = new CaseParty
        {
            CaseId = Id, Role = d.Role, Name = d.Name, Contact = d.Contact, Reference = d.Reference,
            EngagedAtUtc = d.EngagedAtUtc, Notes = d.Notes, CreatedBy = actor, CreatedAtUtc = nowUtc,
        };
        Parties.Add(party);
        Touch(actor, nowUtc);
        return party;
    }

    /// <summary>CAP-34: replaces what's recorded about one outside party. False when nothing changed.</summary>
    public bool EditParty(Guid partyId, PartyDetails details, string actor, DateTimeOffset nowUtc)
    {
        var party = Parties.FirstOrDefault(p => p.Id == partyId)
                    ?? throw new InvalidOperationException("That party isn't on this case any more.");
        if (!party.Set(details.Normalized(nowUtc))) return false;
        party.ModifiedBy = actor;
        party.ModifiedAtUtc = nowUtc;
        Touch(actor, nowUtc);
        return true;
    }

    /// <summary>CAP-34: takes an outside party off the case (a mis-entry); the audit trail keeps what it said. False when it
    /// was already gone.</summary>
    public bool RemoveParty(Guid partyId, string actor, DateTimeOffset nowUtc)
    {
        if (Parties.RemoveAll(p => p.Id == partyId) == 0) return false;
        Touch(actor, nowUtc);
        return true;
    }

    /// <summary>Removes a tagged ATT&amp;CK technique from the case.</summary>
    public void RemoveTechnique(Guid techniqueId, string actor, DateTimeOffset nowUtc)
    {
        var technique = Techniques.FirstOrDefault(t => t.Id == techniqueId);
        if (technique is null) return;

        Techniques.Remove(technique);
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// Edits a note by superseding the current version with a new one, preserving the prior text
    /// and its timestamp. Nothing is overwritten, so the record of what was known and when survives.
    /// </summary>
    public AnalystNote EditNote(Guid noteId, string newBody, string actor, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(newBody))
            throw new ArgumentException("Note body is required.");

        var current = Notes.FirstOrDefault(n => n.Id == noteId && n.IsCurrent)
            ?? throw new InvalidOperationException("Note not found or already superseded.");

        current.IsCurrent = false;
        var next = new AnalystNote
        {
            CaseId = Id, Body = newBody.Trim(), Version = current.Version + 1,
            SupersedesNoteId = current.Id, IsCurrent = true,
            CreatedBy = actor, CreatedAtUtc = nowUtc
        };
        Notes.Add(next);
        Touch(actor, nowUtc);
        return next;
    }

    /// <summary>
    /// Records the <b>regulatory-notification milestone</b> (PROD-07): the instant the reportable event was
    /// notified to regulators. Sets <see cref="ReportedAtUtc"/> (already part of the tamper-evident canonical),
    /// stopping the per-jurisdiction deadline countdown. Legal owns the actual filing and its per-regulator
    /// timing; the tool records that it happened. May be backdated (Legal often reports before it is entered
    /// here) but not set in the future or before the matter was detected. CAP-38: a whole-case time, for a case with no
    /// jurisdiction in play and no notice (CaseService records a notice per jurisdiction otherwise); every view reads it
    /// through <see cref="NoticeStanding"/>, as each jurisdiction then in play notified at that time.
    /// </summary>
    public void MarkReported(DateTimeOffset reportedAtUtc, string actor, DateTimeOffset nowUtc,
        IReadOnlyCollection<string>? jurisdictionsInPlay = null)
    {
        if (reportedAtUtc > nowUtc)
            throw new ArgumentException("The reported time can't be in the future.");
        if (DetectedAtUtc is { } detected && ToMinute(reportedAtUtc) < ToMinute(detected))
            throw new ArgumentException("The reported time can't be earlier than the detected time.");

        ReportedAtUtc = reportedAtUtc;
        // WF-11: recorded when the caller says what was in play; not said, it's left for the start-up back-fill.
        if (jurisdictionsInPlay is not null) FreezeJurisdictions(jurisdictionsInPlay);
        Touch(actor, nowUtc);
    }

    /// <summary>Clears the reported milestone (a mis-entry), reopening the notification countdown. Audited.</summary>
    public void ClearReported(string actor, DateTimeOffset nowUtc)
    {
        if (ReportedAtUtc is null && JurisdictionNotices.Count == 0) return;
        EnsureNotArchived("clear its notices");
        JurisdictionNotices.Clear();
        ReportedAtUtc = null;
        ReportedJurisdictions = null;   // WF-11
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// BUG-555: a case reported as a whole while nothing was in play goes back to unreported when an element added brings
    /// a regulator in. Unlike <see cref="ClearReported"/> (a mis-entry) it keeps <see cref="ReportedJurisdictions"/>, so
    /// removing that element is judged against what was kept, and a later admin change doesn't apply to the case. A kept
    /// value from before its elements were recorded gets <paramref name="elementsBefore"/> (the elements before the edit),
    /// or an added one couldn't be told apart. The reported time isn't kept: it has to be recorded again.
    /// </summary>
    public void Unreport(IEnumerable<string> elementsBefore, string actor, DateTimeOffset nowUtc)
    {
        if (ReportedAtUtc is null) return;
        EnsureNotArchived("change its report");
        ReportedAtUtc = null;
        // Too long to hold them: today's settings apply, as before.
        if (ReportedJurisdictions is { } kept && KeptElementKeys(kept) is null)
            ReportedJurisdictions = WithElements(kept, elementsBefore);
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// BUG-09: records when one regulator was notified (or corrects the time). Validated like the reported time.
    /// Call <see cref="ReportedFromNotices"/> afterwards, with the jurisdictions in play. CAP-07: <paramref name="details"/>,
    /// when given, records how it was notified too (the caller checks its evidence file is on the case); not given, a
    /// corrected notice keeps what it had.
    /// </summary>
    public JurisdictionNotice RecordNotice(string jurisdiction, DateTimeOffset notifiedAtUtc, string actor, DateTimeOffset nowUtc,
        NoticeDetails? details = null)
    {
        var how = details?.Normalized();   // CAP-07: refused before anything changes
        var code = (jurisdiction ?? "").Trim().ToUpperInvariant();
        if (code.Length == 0) throw new ArgumentException("Say which jurisdiction was notified.");
        if (code.Length > JurisdictionNotice.MaxJurisdictionLength) throw new ArgumentException("That jurisdiction code is too long.");
        if (notifiedAtUtc > nowUtc) throw new ArgumentException("The notice time can't be in the future.");
        if (DetectedAtUtc is { } detected && ToMinute(notifiedAtUtc) < ToMinute(detected))
            throw new ArgumentException("The notice time can't be earlier than the detected time.");

        var notice = JurisdictionNotices.FirstOrDefault(n => n.Jurisdiction == code);
        if (notice is null)
        {
            // BUG-404: a code with "," or ";" would read back as two codes, or split the kept "codes;elements" value.
            if (code.IndexOfAny(CodeSeparators) >= 0) throw new ArgumentException("A jurisdiction code can't contain a comma or semicolon.");
            notice = new JurisdictionNotice { CaseId = Id, Jurisdiction = code, NotifiedAtUtc = notifiedAtUtc, CreatedBy = actor, CreatedAtUtc = nowUtc };
            JurisdictionNotices.Add(notice);
        }
        else notice.NotifiedAtUtc = notifiedAtUtc;
        if (how is not null) notice.SetDetails(how);
        Touch(actor, nowUtc);
        return notice;
    }

    /// <summary>
    /// CAP-07: records how one regulator was notified (the method, reference, who gave it, the file holding it), on the
    /// notice already recorded for that code; its time doesn't move. The caller checks the evidence file is on the case.
    /// False when nothing changed.
    /// </summary>
    public bool SetNoticeDetails(string jurisdiction, NoticeDetails details, string actor, DateTimeOffset nowUtc)
    {
        var code = (jurisdiction ?? "").Trim().ToUpperInvariant();
        var notice = JurisdictionNotices.FirstOrDefault(n => n.Jurisdiction == code)
                     ?? throw new InvalidOperationException("That regulator has no notice recorded. Record the notice first.");
        if (!notice.SetDetails(details)) return false;
        Touch(actor, nowUtc);
        return true;
    }

    /// <summary>
    /// BUG-104: a case reported as a whole (no notice per jurisdiction) covered <paramref name="codes"/>, which become
    /// notices at the reported time. BUG-406: each is credited to <paramref name="recordedBy"/> and dated
    /// <paramref name="recordedAtUtc"/> (who recorded the report, and when), not to the edit that converted it, so it
    /// isn't new work by the editor on the timeline, in the handoff or the brief's "since".
    /// </summary>
    public void NoticesFromWholeReport(IEnumerable<string> codes, string recordedBy, DateTimeOffset recordedAtUtc,
        string actor, DateTimeOffset nowUtc)
    {
        if (ReportedAtUtc is not { } reported || JurisdictionNotices.Count > 0) return;
        foreach (var code in codes)
        {
            var n = RecordNotice(code, reported, actor, nowUtc);
            n.CreatedBy = recordedBy;
            n.CreatedAtUtc = recordedAtUtc;
        }
    }

    /// <summary>BUG-09: removes one regulator's notice (a mis-entry).</summary>
    public void RemoveNotice(string jurisdiction, string actor, DateTimeOffset nowUtc)
    {
        // BUG-190: with another notice left, the reported time follows the notices, so this restarts that clock.
        EnsureNotArchived("remove a notice");
        var code = (jurisdiction ?? "").Trim().ToUpperInvariant();
        if (JurisdictionNotices.RemoveAll(n => n.Jurisdiction == code) > 0) Touch(actor, nowUtc);
    }

    /// <summary>
    /// BUG-09: the reported time follows the notices: the time the last jurisdiction in play was notified, or none
    /// while any is outstanding (so the reminders, the close gate and archiving keep watching). A case reported before
    /// notices were recorded per jurisdiction has none, and keeps its reported time.
    /// </summary>
    public void ReportedFromNotices(IReadOnlyCollection<string> jurisdictionsInPlay, string actor, DateTimeOffset nowUtc)
    {
        if (JurisdictionNotices.Count == 0) return;
        // CAP-38: by the one reading every view uses (BUG-428: a legacy "NY;CA" notice counts for both). BUG-104: with nothing
        // in play any more (the data elements re-scoped), the notices already made still stand.
        var standing = NoticeStanding.Of(jurisdictionsInPlay, JurisdictionNotices.Select(n => (n.Jurisdiction, n.NotifiedAtUtc)), null);
        var reported = standing.ReportedAtUtc;
        if (reported == ReportedAtUtc) return;
        ReportedAtUtc = reported;
        // WF-11: what was in play when it became reported (the notices themselves when nothing is in play any more).
        FreezeJurisdictions(jurisdictionsInPlay.Count > 0 ? jurisdictionsInPlay : standing.Notices.Keys);
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// S-08: limits the case to need-to-know — its incident commander, its assigned team, and roles cleared for
    /// restricted cases. Audited (the field diff, with any reason, lands in the hash chain).
    /// </summary>
    public void Restrict(string actor, DateTimeOffset nowUtc)
    {
        if (IsRestricted) return;
        IsRestricted = true;
        Touch(actor, nowUtc);
    }

    /// <summary>S-08: lifts the need-to-know restriction, opening the case to everyone with case access.</summary>
    public void LiftRestriction(string actor, DateTimeOffset nowUtc)
    {
        if (!IsRestricted) return;
        IsRestricted = false;
        Touch(actor, nowUtc);
    }

    /// <summary>Places a legal hold, blocking archival/retention purge until it is released.</summary>
    public void PlaceLegalHold(string actor, DateTimeOffset nowUtc)
    {
        if (LegalHold) return;
        LegalHold = true;
        Touch(actor, nowUtc);
    }

    /// <summary>Releases a legal hold so the case may be archived/purged per policy.</summary>
    public void ReleaseLegalHold(string actor, DateTimeOffset nowUtc)
    {
        if (!LegalHold) return;
        LegalHold = false;
        ClearLegalHoldReleaseRequest();
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// F-12: asks for the legal hold to be released, pending a second person's approval. The reason is required
    /// (it's what the approver weighs). A newer request replaces an older pending one.
    /// </summary>
    public void RequestLegalHoldRelease(string reason, string actor, DateTimeOffset nowUtc)
    {
        if (!LegalHold) throw new InvalidOperationException("There is no legal hold on this case to release.");
        reason = (reason ?? "").Trim();
        if (reason.Length == 0) throw new ArgumentException("Give a reason for releasing the legal hold.");
        if (reason.Length > 1000) throw new ArgumentException("Keep the reason to 1,000 characters or fewer.");
        LegalHoldReleaseRequestedBy = actor;
        LegalHoldReleaseRequestedAtUtc = nowUtc;
        LegalHoldReleaseReason = reason;
        Touch(actor, nowUtc);
    }

    /// <summary>F-12: a second person approves the pending request, which releases the hold. Never the requester.</summary>
    public void ApproveLegalHoldRelease(string approver, DateTimeOffset nowUtc)
    {
        if (!LegalHold || !LegalHoldReleasePending)
            throw new InvalidOperationException("There is no pending request to release this legal hold.");
        if (string.Equals(approver, LegalHoldReleaseRequestedBy, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Two-person control: someone other than the requester must approve the release.");
        ReleaseLegalHold(approver, nowUtc);
    }

    /// <summary>F-12: withdraws a pending release request; the hold stays in force.</summary>
    public void CancelLegalHoldReleaseRequest(string actor, DateTimeOffset nowUtc)
    {
        if (!LegalHoldReleasePending) return;
        ClearLegalHoldReleaseRequest();
        Touch(actor, nowUtc);
    }

    private void ClearLegalHoldReleaseRequest()
    {
        LegalHoldReleaseRequestedBy = null;
        LegalHoldReleaseRequestedAtUtc = null;
        LegalHoldReleaseReason = null;
    }

    /// <summary>
    /// Sets (or clears, with null) the case's report profile (E-28). A reporting preference — audited by
    /// the save interceptor but out of the tamper-evident canonical, so it never re-baselines the row hash.
    /// </summary>
    public void SetReportProfile(Guid? profileId, string actor, DateTimeOffset nowUtc)
    {
        if (ReportProfileId == profileId) return;
        ReportProfileId = profileId;
        Touch(actor, nowUtc);
    }

    /// <summary>CAP-36: sets (or clears, with null) the owning team. Audited by the save interceptor and in the row hash.</summary>
    public void SetTeam(Guid? teamId, string actor, DateTimeOffset nowUtc)
    {
        if (TeamId == teamId) return;
        TeamId = teamId;
        Touch(actor, nowUtc);
    }

    /// <summary>CAP-36 (C9): the team editor's stamp, the team as the editor was opened with it ("" for none).</summary>
    public string TeamConcurrencyStamp() => TeamId?.ToString("N") ?? "";

    /// <summary>Archives the case. Refused while a legal hold is in force.</summary>
    public void Archive(string actor, DateTimeOffset nowUtc)
    {
        if (LegalHold)
            throw new InvalidOperationException("This case is under legal hold and can't be archived. Release the hold first.");
        if (IsArchived) return;
        IsArchived = true;
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// BUG-150: an archived case gets no deadline reminders and isn't counted on the dashboard (BUG-10 refuses to archive
    /// one whose clock is running). So what can start or re-arm a notification clock (classification, materiality,
    /// the impact assessment, clearing a notice) isn't changed while it's archived: restore it first.
    /// </summary>
    private void EnsureNotArchived(string what)
    {
        if (IsArchived)
            throw new InvalidOperationException($"This case is archived. Restore it from the archive to {what}: an archived case " +
                                                "gets no deadline reminders, so a change that could start its notification clock waits until it's restored.");
    }

    /// <summary>Restores an archived case to active status.</summary>
    public void Unarchive(string actor, DateTimeOffset nowUtc)
    {
        if (!IsArchived) return;
        IsArchived = false;
        Touch(actor, nowUtc);
    }

    /// <summary>Removes an entity and any relationships that reference it.</summary>
    public void RemoveEntity(Guid entityId, string actor, DateTimeOffset nowUtc)
    {
        var entity = Entities.FirstOrDefault(e => e.Id == entityId);
        if (entity is null) return;
        // BUG-108: an attack step that names it as actor or target would silently lose that (or the save would fail on
        // the foreign key), so the steps are changed first.
        var named = TimelineEntries.Count(t => !t.IsRetracted && (t.ActorEntityId == entityId || t.TargetEntityId == entityId));
        // BUG-413: a retracted step can't be changed, and it keeps saying what it said, so the entity it names stays.
        if (named == 0 && TimelineEntries.Any(t => t.IsRetracted && (t.ActorEntityId == entityId || t.TargetEntityId == entityId)))
            throw new InvalidOperationException(
                "A retracted attack step names this entity as actor or target, so it stays on the case: the retracted step " +
                "keeps reading as it did. Set its verdict to Benign instead if it's not part of the incident.");
        if (named > 0)
            throw new InvalidOperationException(
                $"{(named == 1 ? "An attack step names" : $"{named} attack steps name")} this entity as actor or target. " +
                "Change the step first, so the attack record keeps saying who did what to what.");

        // A task about it stays, no longer pointing at it.
        var about = $"{ActionItem.AboutEntity}:{entityId}";
        foreach (var t in ActionItems.Where(a => string.Equals(a.AboutRef, about, StringComparison.OrdinalIgnoreCase)))
        {
            t.AboutRef = null;
            t.ModifiedBy = actor;
            t.ModifiedAtUtc = nowUtc;
        }

        EntityRelationships.RemoveAll(r => r.SourceEntityId == entityId || r.TargetEntityId == entityId);
        EntityLayouts.RemoveAll(l => l.EntityId == entityId);
        Entities.Remove(entity);
        Touch(actor, nowUtc);
    }

    /// <summary>Creates a directed relationship between two of this case's entities.</summary>
    public EntityRelationship LinkEntities(Guid sourceEntityId, Guid targetEntityId, EntityRelationshipType type,
        string? description, string actor, DateTimeOffset nowUtc)
    {
        if (sourceEntityId == targetEntityId)
            throw new ArgumentException("An entity can't be related to itself.");
        if (Entities.All(e => e.Id != sourceEntityId) || Entities.All(e => e.Id != targetEntityId))
            throw new ArgumentException("Both entities must belong to this case.");

        var existing = EntityRelationships.FirstOrDefault(r =>
            r.SourceEntityId == sourceEntityId && r.TargetEntityId == targetEntityId && r.Type == type);
        if (existing is not null) return existing;

        var rel = new EntityRelationship
        {
            CaseId = Id, SourceEntityId = sourceEntityId, TargetEntityId = targetEntityId,
            Type = type, Description = description, CreatedBy = actor, CreatedAtUtc = nowUtc
        };
        EntityRelationships.Add(rel);
        Touch(actor, nowUtc);
        return rel;
    }

    /// <summary>
    /// INV-49: corrects a relationship in place — its type, its description, or its direction (pass the two entities
    /// swapped). One audited update rather than a remove and a re-add. Both ends must still be this case's entities,
    /// and it can't become a duplicate of another relationship.
    /// </summary>
    public void EditRelationship(Guid relationshipId, Guid sourceEntityId, Guid targetEntityId, EntityRelationshipType type,
        string? description, string actor, DateTimeOffset nowUtc)
    {
        var rel = EntityRelationships.FirstOrDefault(r => r.Id == relationshipId)
                  ?? throw new ArgumentException("That relationship is no longer on this case.");
        if (sourceEntityId == targetEntityId)
            throw new ArgumentException("An entity can't be related to itself.");
        if (Entities.All(e => e.Id != sourceEntityId) || Entities.All(e => e.Id != targetEntityId))
            throw new ArgumentException("Both entities must belong to this case.");
        if (EntityRelationships.Any(r => r.Id != relationshipId && r.SourceEntityId == sourceEntityId
                                         && r.TargetEntityId == targetEntityId && r.Type == type))
            throw new ArgumentException("That relationship already exists.");

        description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        if (rel.SourceEntityId == sourceEntityId && rel.TargetEntityId == targetEntityId && rel.Type == type
            && rel.Description == description) return;

        rel.SourceEntityId = sourceEntityId;
        rel.TargetEntityId = targetEntityId;
        rel.Type = type;
        rel.Description = description;
        rel.ModifiedBy = actor;
        rel.ModifiedAtUtc = nowUtc;
        Touch(actor, nowUtc);
    }

    /// <summary>Removes a relationship between entities (leaves the entities themselves intact).</summary>
    public void Unlink(Guid relationshipId, string actor, DateTimeOffset nowUtc)
    {
        var rel = EntityRelationships.FirstOrDefault(r => r.Id == relationshipId);
        if (rel is null) return;

        EntityRelationships.Remove(rel);
        Touch(actor, nowUtc);
    }

    /// <summary>
    /// INV-05b: corrects when an already-recorded transition happened. Append-only: a
    /// <see cref="TransitionTimeCorrection"/> records the old and new time and why; the change record's effective
    /// time is updated so every reader sees it, and its recorded time never moves. The new time must still be in
    /// order with the changes of the same kind made before and after it (in the order they were recorded), not in
    /// the future, and not before detection. Re-dating the change that set Contained, Resolved or Closed moves
    /// that milestone with it. The opening classification and severity can't be re-dated: they are the case's
    /// starting point, stamped when it was opened.
    /// </summary>
    public TransitionTimeCorrection CorrectTransitionTime(TransitionKind kind, Guid changeId,
        DateTimeOffset newEffectiveUtc, string reason, string actor, DateTimeOffset nowUtc)
    {
        reason = (reason ?? "").Trim();
        if (reason.Length == 0)
            throw new ArgumentException("Give a reason for correcting when this happened.");
        if (reason.Length > 2000)
            throw new ArgumentException("Keep the reason to 2,000 characters or fewer.");

        // The changes of this kind that can be re-dated, in the order they were made.
        var changes = kind switch
        {
            TransitionKind.Classification => ClassificationChanges
                .Where(x => x.From is not null || x.ChangedAtUtc > CreatedAtUtc)
                .Select(x => (x.Id, x.ChangedAtUtc, x.EffectiveAt, Set: (Action<DateTimeOffset?>)(v => x.EffectiveAtUtc = v), To: (CasePhase?)null)),
            TransitionKind.Phase => StatusChanges.Where(x => x.From is not null)
                .Select(x => (x.Id, x.ChangedAtUtc, x.EffectiveAt, Set: (Action<DateTimeOffset?>)(v => x.EffectiveAtUtc = v), To: (CasePhase?)x.To)),
            TransitionKind.Severity => SeverityChanges.Where(x => x.From is not null)
                .Select(x => (x.Id, x.ChangedAtUtc, x.EffectiveAt, Set: (Action<DateTimeOffset?>)(v => x.EffectiveAtUtc = v), To: (CasePhase?)null)),
            // BUG-414: an entity's verdicts are ordered among themselves (another entity's verdicts don't constrain them).
            TransitionKind.Verdict => VerdictChanges
                .Where(x => VerdictChanges.FirstOrDefault(v => v.Id == changeId) is { } target && x.EntityId == target.EntityId)
                .Select(x => (x.Id, x.ChangedAtUtc, x.EffectiveAt, Set: (Action<DateTimeOffset?>)(v => x.EffectiveAtUtc = v), To: (CasePhase?)null)),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        var ordered = changes.OrderBy(x => x.ChangedAtUtc).ToList();
        var i = ordered.FindIndex(x => x.Id == changeId);
        if (i < 0)
            throw new InvalidOperationException("That change isn't on this case, or it's the opening state, which can't be re-dated.");

        var target = ordered[i];
        var what = kind switch
        {
            TransitionKind.Phase => "phase", TransitionKind.Severity => "severity", TransitionKind.Verdict => "verdict", _ => "classification"
        };
        if (newEffectiveUtc > nowUtc)
            throw new ArgumentException($"The {what} change can't be dated in the future.");
        if (DetectedAtUtc is { } detected && ToMinute(newEffectiveUtc) < ToMinute(detected))
            throw new ArgumentException($"The {what} change can't be dated before the case was detected.");
        // WF-52: neighbours are compared to the minute; a time in a neighbour's minute is held just after (or before) that
        // neighbour, a tick apart, so the two never tie and every reader orders them the same way.
        if (i > 0 && ToMinute(newEffectiveUtc) < ToMinute(ordered[i - 1].EffectiveAt))
            throw new ArgumentException(
                $"The {what} change can't be dated before the {what} change made before it ({ordered[i - 1].EffectiveAt.UtcDateTime:yyyy-MM-dd HH:mm} UTC).");
        if (i < ordered.Count - 1 && ToMinute(newEffectiveUtc) > ToMinute(ordered[i + 1].EffectiveAt))
            throw new ArgumentException(
                $"The {what} change can't be dated after the {what} change made after it ({ordered[i + 1].EffectiveAt.UtcDateTime:yyyy-MM-dd HH:mm} UTC).");
        if (i > 0 && newEffectiveUtc <= ordered[i - 1].EffectiveAt) newEffectiveUtc = ordered[i - 1].EffectiveAt.AddTicks(1);
        if (i < ordered.Count - 1 && newEffectiveUtc >= ordered[i + 1].EffectiveAt) newEffectiveUtc = ordered[i + 1].EffectiveAt.AddTicks(-1);

        var old = target.EffectiveAt;
        if (newEffectiveUtc == old)
            throw new ArgumentException("That's already when it happened.");

        // The milestone this phase change set moves with it. BUG-210: a move past Containment that recorded it as not needed
        // set the contained time (the decision) to its own time, so that moves too.
        var (contained, resolved, closed) = (ContainedAtUtc, ResolvedAtUtc, ClosedAtUtc);
        switch (target.To)
        {
            case CasePhase.Containment when contained == old: contained = newEffectiveUtc; break;
            case CasePhase.Recovery when resolved == old: resolved = newEffectiveUtc; break;
            case CasePhase.Closed when closed == old: closed = newEffectiveUtc; break;
        }
        if (target.To is CasePhase.Eradication or CasePhase.Recovery or CasePhase.PostIncident
            && ContainmentNotNeededReason is not null && contained == old)
            contained = newEffectiveUtc;
        // REV-11: only when this correction moves one of them, so a case already out of order doesn't block every other fix.
        if ((contained != ContainedAtUtc || resolved != ResolvedAtUtc)
            && ContainmentNotNeededReason is null && contained is { } c && resolved is { } r && r < c)
            throw new ArgumentException("That would date the resolution before the containment.");
        // BUG-230: a move that came after the case was contained (or resolved) can't be re-dated to before it. A skip
        // move states those times itself (BUG-165/208), and ChangePhase refuses a stated time after the move; re-dating
        // the move before it would undo that check. A move that was already earlier (a close before a later reopen) can
        // still be corrected.
        var at = newEffectiveUtc;
        if (target.To is CasePhase.Eradication or CasePhase.Recovery or CasePhase.PostIncident or CasePhase.Closed
            && contained is { } cAt && old >= cAt && at < cAt)
            throw new ArgumentException($"This move came after the case was contained ({cAt.UtcDateTime:yyyy-MM-dd HH:mm} UTC), " +
                "so it can't be dated before that.");
        if (target.To is CasePhase.PostIncident or CasePhase.Closed && resolved is { } rAt && old >= rAt && at < rAt)
            throw new ArgumentException($"This move came after the case was resolved ({rAt.UtcDateTime:yyyy-MM-dd HH:mm} UTC), " +
                "so it can't be dated before that.");

        target.Set(newEffectiveUtc == target.ChangedAtUtc ? null : newEffectiveUtc);
        (ContainedAtUtc, ResolvedAtUtc, ClosedAtUtc) = (contained, resolved, closed);

        var correction = new TransitionTimeCorrection
        {
            CaseId = Id, Kind = kind, ChangeId = changeId, FromEffectiveUtc = old, ToEffectiveUtc = newEffectiveUtc,
            Reason = reason, CreatedBy = actor, CreatedAtUtc = nowUtc
        };
        TimeCorrections.Add(correction);
        Touch(actor, nowUtc);
        return correction;
    }

    /// <summary>
    /// INV-05: validates when a transition happened, for one recorded after the fact. Not in the future, not
    /// before the case was detected, and not before the previous change of the same kind (the opening state
    /// doesn't count: a case is often filed after the first moves were made). Returns the time to store, or
    /// null when it is the recorded time, so an ordinary change looks exactly as it always has.
    /// </summary>
    private DateTimeOffset? CheckEffective(DateTimeOffset? effectiveAtUtc, DateTimeOffset nowUtc, string what,
        IEnumerable<DateTimeOffset> earlierChanges)
    {
        if (effectiveAtUtc is not { } at || at == nowUtc) return null;
        if (at > nowUtc)
            throw new ArgumentException($"The {what} change can't be dated in the future.");
        if (DetectedAtUtc is { } detected && ToMinute(at) < ToMinute(detected))
            throw new ArgumentException($"The {what} change can't be dated before the case was detected.");
        // WF-52: compared to the minute, as the picker gives (REV-16 did the same for the detected time). A change dated in
        // the previous one's minute is recorded a tick after that change, so it sorts after it and never ties.
        var earlier = earlierChanges.ToList();
        if (earlier.Where(x => ToMinute(x) > ToMinute(at)).OrderByDescending(x => x).FirstOrDefault() is { } later && later != default)
            throw new ArgumentException(
                $"The {what} change can't be dated before the previous {what} change ({later.UtcDateTime:yyyy-MM-dd HH:mm} UTC).");
        var latest = earlier.Where(x => x >= at).DefaultIfEmpty(default).Max();
        return latest != default ? latest.AddTicks(1) : at;
    }

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    /// <summary>
    /// INV-09: saves a new version of the case brief, superseding the current one (the prior version is kept,
    /// with its time and author). A version must say something, and each part is capped in length. INV-36: the
    /// first part is the case summary, so this also sets <see cref="Summary"/>.
    /// </summary>
    /// <returns>The new version, or null when the written parts are unchanged: saving the same text again makes no
    /// version (use <see cref="ConfirmBrief"/> to say it still stands). The next steps are a snapshot of the tasks,
    /// not written, so they don't count as a change.</returns>
    /// <param name="appended">WF-30: CaseBrief added this version on its own (see <see cref="CaseBrief.Appended"/>).</param>
    public CaseBrief? ReviseBrief(string? summary, string? workingAssessment, string? known, string? openQuestions,
        string? nextSteps, string actor, DateTimeOffset nowUtc, bool appended = false)
    {
        if (Briefs.FirstOrDefault(b => b.IsCurrent) is { } current
            && Clean(summary) == current.Summary && Clean(workingAssessment) == current.WorkingAssessment
            && Clean(known) == current.Known && Clean(openQuestions) == current.OpenQuestions
            && new[] { current.Summary, current.WorkingAssessment, current.Known, current.OpenQuestions }.Any(p => p is not null))
            return null;
        var next = AddBriefVersion(summary, workingAssessment, known, openQuestions, nextSteps, actor, nowUtc,
            requireContent: true, appended: appended);
        Touch(actor, nowUtc);
        return next;
    }

    /// <summary>
    /// Confirms the current brief still stands, without a new version: records who and when on it, and the "changes
    /// since" count starts again from now.
    /// </summary>
    public CaseBrief ConfirmBrief(string actor, DateTimeOffset nowUtc)
    {
        var current = Briefs.FirstOrDefault(b => b.IsCurrent)
                      ?? throw new InvalidOperationException("There's no brief to confirm yet. Write one first.");
        current.ConfirmedAtUtc = nowUtc;
        current.ConfirmedBy = actor;
        Touch(actor, nowUtc);
        return current;
    }

    /// <summary>
    /// INV-36: the summary written when the case is opened, recorded as brief version 1 so the summary's history
    /// starts there. Does nothing when there's no summary.
    /// </summary>
    public void SetInitialSummary(string? summary, string actor, DateTimeOffset nowUtc)
    {
        if (Clean(summary) is null) return;
        AddBriefVersion(summary, null, null, null, null, actor, nowUtc, requireContent: true);
    }

    /// <summary>
    /// INV-25: follows up one of the brief's open questions as a task, so the question and the work on it are
    /// linked. The question stays in the brief until someone revises it; the task says where it came from.
    /// Refused when an open task already follows up the same question.
    /// </summary>
    public ActionItem RaiseTaskFromQuestion(string question, string actor, DateTimeOffset nowUtc)
    {
        var title = QuestionTaskTitle(question) ?? throw new ArgumentException("Say what the question is.");
        var brief = Briefs.FirstOrDefault(b => b.IsCurrent)
                    ?? throw new InvalidOperationException("The case has no brief to raise a question from.");
        if (ActionItems.Any(t => t.IsOpen && t.RaisedFromBriefId is not null
                                 && string.Equals(t.Title, title, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("An open task already follows up that question.");

        var task = new ActionItem
        {
            CaseId = Id, Title = title, Description = $"Raised from an open question in the brief (v{brief.Version}).",
            RaisedFromBriefId = brief.Id, CreatedBy = actor, CreatedAtUtc = nowUtc
        };
        ActionItems.Add(task);
        Touch(actor, nowUtc);
        return task;
    }

    /// <summary>
    /// BUG-298: the title of the task that follows up a brief question (its plain text), cut to a task title's length: what
    /// a raised task is called, and so what pairs a question with it. A question longer than a title was matched on its
    /// full text, so it never paired, and following it up again was refused as a duplicate.
    /// </summary>
    public static string? QuestionTaskTitle(string? question) =>
        Clean(question) is not { } t ? null
        : t.Length > ActionItem.MaxTitleLength ? t[..(ActionItem.MaxTitleLength - 1)] + "…" : t;

    /// <summary>BUG-298: the tasks raised from the brief that follow up <paramref name="question"/> (its plain text).</summary>
    public IEnumerable<ActionItem> TasksFollowingUp(string question) =>
        QuestionTaskTitle(question) is not { } title ? []
        : ActionItems.Where(t => t.RaisedFromBriefId is not null && string.Equals(t.Title, title, StringComparison.OrdinalIgnoreCase));

    // A new brief version (superseding the current one) that also sets the case summary. A summary edit made
    // outside the brief can clear the summary, so it may record a version with nothing in it.
    private CaseBrief AddBriefVersion(string? summary, string? workingAssessment, string? known,
        string? openQuestions, string? nextSteps, string actor, DateTimeOffset nowUtc, bool requireContent, bool appended = false)
    {
        var next = new CaseBrief
        {
            CaseId = Id, Summary = Clean(summary), WorkingAssessment = Clean(workingAssessment), Known = Clean(known),
            OpenQuestions = Clean(openQuestions), NextSteps = Clean(nextSteps), CreatedBy = actor, CreatedAtUtc = nowUtc,
            Appended = appended
        };
        // INV-25: the next steps are recorded, not written, so they don't count as saying something.
        if (requireContent && new[] { next.Summary, next.WorkingAssessment, next.Known, next.OpenQuestions }.All(p => p is null))
            throw new ArgumentException("Write at least one part of the brief.");
        if (new[] { next.Summary, next.WorkingAssessment, next.Known, next.OpenQuestions }
                .Any(p => p is { Length: > CaseBrief.MaxPartLength }))
            throw new ArgumentException($"Keep each part of the brief to {CaseBrief.MaxPartLength:N0} characters or fewer.");
        // BUG-263: the next steps are a snapshot of the tasks, which nobody can shorten, so they're cut rather than refused.
        if (next.NextSteps is { Length: > CaseBrief.MaxPartLength } steps) next.NextSteps = steps[..CaseBrief.MaxPartLength];

        if (Briefs.FirstOrDefault(b => b.IsCurrent) is { } current)
        {
            current.IsCurrent = false;
            next.Version = current.Version + 1;
            next.SupersedesBriefId = current.Id;
        }
        Briefs.Add(next);
        Summary = next.Summary;
        return next;
    }

    private void Touch(string actor, DateTimeOffset nowUtc)
    {
        ModifiedBy = actor;
        ModifiedAtUtc = nowUtc;
    }

    // --- Optimistic-concurrency stamps (FR-06) --------------------------------------------------
    // A stable signature of just the fields a single editor governs, so a save can detect that another
    // author changed those same fields since the editor was opened and refuse to silently overwrite them.
    // Scoped per editor (not the whole row's ModifiedAtUtc) so an unrelated change — a severity edit, a new
    // assignment — never false-conflicts with a details edit. Unit separator (U+001F) can't occur in the text.
    private const char StampSep = '';

    /// <summary>Signature of the "Details" editor's fields (title, summary, detection id, data types,
    /// impacted assets, and the two intake timestamps). See <see cref="UpdateDetails"/>.</summary>
    public string DetailsConcurrencyStamp() => string.Join(StampSep,
        Title, Summary, DetectionCaseId, DataTypesInvolved, ImpactedAssets,
        DetectedAtUtc?.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture) ?? "",
        OccurredAtUtc?.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture) ?? "");

    /// <summary>Signature of the structured "Impact assessment" editor's fields (affected count, the
    /// data-element key set, and jurisdictions). See <see cref="SetImpactAssessment"/>.</summary>
    public string ImpactConcurrencyStamp() => string.Join(StampSep,
        AffectedIndividualsCount?.ToString(CultureInfo.InvariantCulture) ?? "",
        string.Join(',', DataElements.Select(d => d.ElementKey).OrderBy(k => k, StringComparer.Ordinal)),
        AffectedStates);

    /// <summary>Signature of the "Legal referral" editor's fields (referral state, contact, relevance note).
    /// See <see cref="ReferToLegal"/>. REL-02: extends the FR-06 optimistic-concurrency check to this
    /// think-time modal so a concurrent referral edit isn't silently clobbered.</summary>
    public string LegalReferralConcurrencyStamp() => string.Join(StampSep,
        LegalReferral.IsReferred ? "1" : "0",
        LegalReferral.ReferredToContact, LegalReferral.RegulatoryRelevanceNote);

    /// <summary>Signature of the "Materiality determination" editor's fields (status, decision-maker,
    /// decided-on, rationale). See <see cref="RecordMateriality"/>. REL-02: extends the FR-06
    /// optimistic-concurrency check to this think-time modal (which carries a free-text rationale).</summary>
    public string MaterialityConcurrencyStamp() => string.Join(StampSep,
        ((int)Materiality.Status).ToString(CultureInfo.InvariantCulture),
        Materiality.DecisionMaker,
        Materiality.DecidedOnUtc?.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture) ?? "",
        Materiality.Rationale);

    public string BuildCanonicalContent() => string.Join('|',
        Canonical.Text(CaseNumber), Canonical.Text(Title), Classification is { } cls ? ((int)cls).ToString(CultureInfo.InvariantCulture) : "", (int)Phase, (int)Severity, (int)Origin,
        Canonical.Text(Summary), Canonical.Text(ImpactedAssets), Canonical.Text(DataTypesInvolved), Canonical.Text(DetectionCaseId),
        AffectedIndividualsCount, string.Join(',', DataElements.Select(d => d.ElementKey).OrderBy(k => k, StringComparer.Ordinal)), AffectedStates,
        ThirdParty?.ToCanonical(), LegalReferral.ToCanonical(), Materiality.ToCanonical(),
        IncidentCommander, IsRestricted, IsArchived, LegalHold, IsExercise,
        OccurredAtUtc?.ToString("o"), DetectedAtUtc?.ToString("o"), ReportedAtUtc?.ToString("o"),
        ContainedAtUtc?.ToString("o"), ResolvedAtUtc?.ToString("o"), ClosedAtUtc?.ToString("o"),
        CreatedBy, CreatedAtUtc.ToString("o"))
        // HR-01: the outcome only when one is recorded, so existing rows keep their exact hash.
        + (OutcomeKey is { Length: > 0 } outcome ? "|outcome|" + outcome : "")
        // BUG-165: likewise a containment-not-needed decision.
        + (ContainmentNotNeededReason is { } why ? "|containmentnotneeded|" + Canonical.Text(why) : "")
        // BUG-631: from format 4, the jurisdictions kept in play when it was reported (which regulators it owes).
        + Canonical.Since(4, ReportedJurisdictions is not null, () => "|reportedin|" + Canonical.Text(ReportedJurisdictions))
        // BUG-632: and a pending legal-hold release request, whose requester can't be the one who approves it.
        + Canonical.Since(4, LegalHoldReleaseRequestedBy is not null || LegalHoldReleaseRequestedAtUtc is not null || LegalHoldReleaseReason is not null,
            () => "|holdrelease|" + Canonical.Text(LegalHoldReleaseRequestedBy) + "|" + Canonical.Time(LegalHoldReleaseRequestedAtUtc)
                  + "|" + Canonical.Text(LegalHoldReleaseReason))
        // CAP-36: from format 5, the owning team, only when there is one (a case without a team keeps its exact hash).
        + Canonical.Since(5, TeamId is not null, () => "|team|" + TeamId!.Value.ToString("N"));

    public static string FormatCaseNumber(int year, int sequence, string descriptiveName)
        => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{year:0000}-{sequence:00}_{descriptiveName}");

    /// <summary>
    /// The Complex Event number: a "CE-" prefix + the creation date + slug (e.g.
    /// <c>CE-2026-08-23_Odd_Beaconing</c>), so intake items never look like IRP-ladder cases and there is
    /// no sequence to reuse. A <paramref name="disambiguator"/> above 1 appends "-N" for the rare case of a
    /// second Complex Event with the same descriptor on the same day.
    /// </summary>
    public static string FormatComplexEventNumber(DateTimeOffset date, string descriptiveName, int disambiguator = 1)
    {
        // BUG-59: a Gregorian date on any server culture.
        var day = date.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        return disambiguator <= 1
            ? $"CE-{day}_{descriptiveName}"
            : string.Create(System.Globalization.CultureInfo.InvariantCulture, $"CE-{day}_{descriptiveName}-{disambiguator}");
    }

    /// <summary>Whether a materiality determination can be recorded: an Incident or Breach, or a case downgraded from
    /// one that already carries a determination (BUG-59).</summary>
    public bool MaterialityApplies => Classification is Domain.Enums.Classification.Incident or Domain.Enums.Classification.Breach
        || (Classification == Domain.Enums.Classification.AdverseEvent && Materiality.Status != MaterialityStatus.Undetermined);

    /// <summary>Turns free text into an identifier-safe slug for the case number.</summary>
    public static string Slug(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "Case";
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (var ch in s.Trim())
        {
            if (char.IsLetterOrDigit(ch)) sb.Append(ch);
            else if (ch is ' ' or '-' or '_') sb.Append('_');
        }
        var slug = sb.ToString();
        while (slug.Contains("__")) slug = slug.Replace("__", "_");
        slug = slug.Trim('_');
        return slug.Length == 0 ? "Case" : slug;
    }
}
