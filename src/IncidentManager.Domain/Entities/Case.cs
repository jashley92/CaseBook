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
    // two-person release on). Audited like any change, but deliberately outside the row-hash canonical: it is a
    // workflow state, not case content, and adding it there would re-baseline every existing case's hash.
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

    // --- Lifecycle timestamps (for MTTD/MTTR/containment metrics) ---
    public DateTimeOffset? OccurredAtUtc { get; set; }
    public DateTimeOffset? DetectedAtUtc { get; set; }
    public DateTimeOffset? ReportedAtUtc { get; set; }
    public DateTimeOffset? ContainedAtUtc { get; set; }
    public DateTimeOffset? ResolvedAtUtc { get; set; }
    public DateTimeOffset? ClosedAtUtc { get; set; }

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

    /// <summary>Saved graph node positions (cosmetic; not audited/hashed).</summary>
    public List<EntityLayout> EntityLayouts { get; set; } = new();

    private Case() { } // EF

    /// <summary>Opens a new case, seeding the initial classification and status history. A null
    /// <paramref name="classification"/> opens the case as a <b>Complex Event</b> (pre-triage intake);
    /// it enters the ladder later via <see cref="Reclassify"/>.</summary>
    public static Case Open(int year, int sequence, string descriptiveName, string title,
        Classification? classification, Severity severity, CaseOrigin origin,
        string actor, DateTimeOffset nowUtc, bool isExercise = false)
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
            ? FormatComplexEventNumber(nowUtc, c.DescriptiveName)
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
    public void ChangePhase(CasePhase to, string? reason, string actor, DateTimeOffset nowUtc,
        DateTimeOffset? effectiveAtUtc = null)
    {
        if (to == Phase) return;

        var effective = CheckEffective(effectiveAtUtc, nowUtc, "phase",
            StatusChanges.Where(x => x.From is not null).Select(x => x.EffectiveAt));
        var at = effective ?? nowUtc;

        var from = Phase;
        Phase = to;
        StatusChanges.Add(new StatusChange
        {
            CaseId = Id, From = from, To = to, Reason = reason, ChangedBy = actor, ChangedAtUtc = nowUtc,
            EffectiveAtUtc = effective
        });

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
    /// Reopens a closed case (E-27): moves it back to the phase it held before closure (or Recovery if that
    /// can't be determined), clears <see cref="ClosedAtUtc"/>, and records the transition with the caller's
    /// reason. A first-class, reason-captured lifecycle action — closing again re-runs the close stage gate.
    /// </summary>
    public void Reopen(string reason, string actor, DateTimeOffset nowUtc)
    {
        if (Phase != CasePhase.Closed)
            throw new InvalidOperationException("Only a closed case can be reopened.");
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("A reason is required to reopen a case.");

        // Return to the phase it was in when it closed, so the lifecycle reads truthfully.
        var priorPhase = StatusChanges
            .Where(s => s.To == CasePhase.Closed && s.From is { } f && f != CasePhase.Closed)
            .OrderByDescending(s => s.ChangedAtUtc)
            .Select(s => s.From!.Value)
            .DefaultIfEmpty(CasePhase.Recovery)
            .First();

        ChangePhase(priorPhase, reason.Trim(), actor, nowUtc);
    }

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
        if (occurredAtUtc is { } occurred && occurred < detectedAtUtc.AddYears(-MaxDwellYears))
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
        }

        Title = title.Trim();
        // INV-36: a changed summary is a new brief version, so every summary the case has had stays readable.
        if (Clean(summary) != Clean(Summary))
        {
            var cur = Briefs.FirstOrDefault(b => b.IsCurrent);
            AddBriefVersion(summary, cur?.WorkingAssessment, cur?.Known, cur?.OpenQuestions, cur?.NextSteps,
                actor, nowUtc, requireContent: false);
        }
        DetectionCaseId = detectionCaseId;
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

        AffectedIndividualsCount = affectedIndividualsCount;

        var desired = dataElementKeys.Distinct(StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal);
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

        if (role == CaseAssignmentRole.IncidentCommander)
        {
            foreach (var other in Assignments.Where(a => a.UserId != userId && a.Role == CaseAssignmentRole.IncidentCommander))
                other.Role = CaseAssignmentRole.Analyst;
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
        if (IncidentCommander == userId) IncidentCommander = null;
        Touch(actor, nowUtc);
    }

    /// <summary>Records a Legal/Privacy referral (capture only &mdash; deadlines are Legal's responsibility).</summary>
    public void ReferToLegal(string referredBy, string? contact, string? relevanceNote, DateTimeOffset nowUtc)
    {
        LegalReferral = new LegalReferral
        {
            IsReferred = true, ReferredAtUtc = nowUtc, ReferredBy = referredBy,
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
        if (Classification is null or Domain.Enums.Classification.AdverseEvent)
            throw new InvalidOperationException("Materiality is determined only for Incidents and Breaches.");
        if (decidedOnUtc is { } future && future > nowUtc)
            throw new ArgumentException("The decision date can't be in the future.");

        if (status is MaterialityStatus.Material or MaterialityStatus.NotMaterial)
        {
            if (string.IsNullOrWhiteSpace(decisionMaker))
                throw new ArgumentException("A final determination must record who made the decision.");
            if (string.IsNullOrWhiteSpace(rationale))
                throw new ArgumentException("A final determination must record the rationale.");
            if (decidedOnUtc is null)
                throw new ArgumentException("A final determination must record the decision date.");
        }

        var from = Materiality.Status;
        Materiality = new MaterialityDetermination
        {
            Status = status,
            DecisionMaker = string.IsNullOrWhiteSpace(decisionMaker) ? null : decisionMaker.Trim(),
            DecidedOnUtc = decidedOnUtc,
            Rationale = string.IsNullOrWhiteSpace(rationale) ? null : rationale.Trim(),
            RecordedBy = actor,
            RecordedAtUtc = nowUtc
        };

        // History captures genuine status transitions (the audit chain records provenance-only edits via the
        // case row's canonical), mirroring how classification/severity changes are recorded.
        if (from != status)
            MaterialityChanges.Add(new MaterialityChange
            {
                CaseId = Id, From = from, To = status,
                DecisionMaker = Materiality.DecisionMaker, DecidedOnUtc = decidedOnUtc,
                Rationale = Materiality.Rationale, ChangedBy = actor, ChangedAtUtc = nowUtc
            });

        Touch(actor, nowUtc);
    }

    /// <summary>
    /// Adds an entity/IOC (account, host, IP, hash, URL…). Idempotent by (type, value): a
    /// repeat of the same observable updates its label/disposition/details rather than duplicating.
    /// </summary>
    public CaseEntity AddEntity(EntityType type, string value, string? label, EntityDisposition disposition,
        string? description, string? source, string actor, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("An entity value is required.");

        // Refang defanged IOC notation on entry so correlation (E-08), links (E-05) and the pushed
        // feed (E-13) all match on canonical values — and so this dedup catches "1.1.1[.]1" == "1.1.1.1".
        var v = IocObservable.Normalize(type, value);
        var existing = Entities.FirstOrDefault(e => e.Type == type &&
            string.Equals(e.Value, v, StringComparison.OrdinalIgnoreCase));
        if (existing is not null)
        {
            existing.Label = label;
            existing.Disposition = disposition;
            existing.Description = description;
            existing.Source = source;
            existing.ModifiedBy = actor;
            existing.ModifiedAtUtc = nowUtc;
            Touch(actor, nowUtc);
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
        EntityDisposition disposition, string? description, string? source, string actor, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("An entity value is required.");

        var entity = Entities.FirstOrDefault(e => e.Id == entityId)
            ?? throw new InvalidOperationException("Entity not found on this case.");

        var v = IocObservable.Normalize(type, value);
        // Don't let an edit collapse this entity onto a different one of the same type+value.
        if (Entities.Any(e => e.Id != entityId && e.Type == type &&
                string.Equals(e.Value, v, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Another entity with the same type and value already exists on this case.");

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
        string actor, DateTimeOffset nowUtc, TimelineEntryType type = TimelineEntryType.Other)
    {
        if (string.IsNullOrWhiteSpace(description))
            throw new ArgumentException("A description is required.");

        var entry = TimelineEntries.FirstOrDefault(t => t.Id == entryId && t.Kind == TimelineKind.Event)
            ?? throw new InvalidOperationException("Event step not found on this case.");

        var normalisedTechnique = string.IsNullOrWhiteSpace(techniqueId) ? null : CaseTechnique.NormaliseId(techniqueId);

        if (actorEntityId is { } aid && Entities.All(e => e.Id != aid))
            throw new ArgumentException("The actor is not an entity on this case.");
        if (targetEntityId is { } tid && Entities.All(e => e.Id != tid))
            throw new ArgumentException("The target is not an entity on this case.");

        entry.OccurredAtUtc = occurredAtUtc;
        entry.Type = type;   // vendor-disclosure stage for third-party cases (E-32); Other for first-party
        entry.Description = description.Trim();
        entry.Source = source;
        entry.TechniqueId = normalisedTechnique;
        entry.ActorEntityId = actorEntityId;
        entry.TargetEntityId = targetEntityId;
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
        string actor, DateTimeOffset nowUtc, Guid? evidenceId = null, TimelineEntryType type = TimelineEntryType.Other)
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
            OccurredAtUtc = occurredAtUtc,
            Description = description.Trim(),
            Source = source,
            TechniqueId = normalisedTechnique,
            ActorEntityId = actorEntityId,
            TargetEntityId = targetEntityId,
            EvidenceId = evidenceId,
            CreatedBy = actor,
            CreatedAtUtc = nowUtc
        };
        foreach (var tactic in tactics.Distinct())
            entry.Tactics.Add(new EventStepTactic { TimelineEntryId = entry.Id, Tactic = tactic });

        TimelineEntries.Add(entry);
        Touch(actor, nowUtc);
        return entry;
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
    /// here) but not set in the future or before the matter was detected.
    /// </summary>
    public void MarkReported(DateTimeOffset reportedAtUtc, string actor, DateTimeOffset nowUtc)
    {
        if (reportedAtUtc > nowUtc)
            throw new ArgumentException("The reported time can't be in the future.");
        if (DetectedAtUtc is { } detected && reportedAtUtc < detected)
            throw new ArgumentException("The reported time can't be earlier than the detected time.");

        ReportedAtUtc = reportedAtUtc;
        Touch(actor, nowUtc);
    }

    /// <summary>Clears the reported milestone (a mis-entry), reopening the notification countdown. Audited.</summary>
    public void ClearReported(string actor, DateTimeOffset nowUtc)
    {
        if (ReportedAtUtc is null) return;
        ReportedAtUtc = null;
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

    /// <summary>Archives the case. Refused while a legal hold is in force.</summary>
    public void Archive(string actor, DateTimeOffset nowUtc)
    {
        if (LegalHold)
            throw new InvalidOperationException("This case is under legal hold and can't be archived. Release the hold first.");
        if (IsArchived) return;
        IsArchived = true;
        Touch(actor, nowUtc);
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
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        var ordered = changes.OrderBy(x => x.ChangedAtUtc).ToList();
        var i = ordered.FindIndex(x => x.Id == changeId);
        if (i < 0)
            throw new InvalidOperationException("That change isn't on this case, or it's the opening state, which can't be re-dated.");

        var target = ordered[i];
        var what = kind switch { TransitionKind.Phase => "phase", TransitionKind.Severity => "severity", _ => "classification" };
        if (newEffectiveUtc > nowUtc)
            throw new ArgumentException($"The {what} change can't be dated in the future.");
        if (DetectedAtUtc is { } detected && newEffectiveUtc < detected)
            throw new ArgumentException($"The {what} change can't be dated before the case was detected.");
        if (i > 0 && newEffectiveUtc < ordered[i - 1].EffectiveAt)
            throw new ArgumentException(
                $"The {what} change can't be dated before the {what} change made before it ({ordered[i - 1].EffectiveAt.UtcDateTime:yyyy-MM-dd HH:mm} UTC).");
        if (i < ordered.Count - 1 && newEffectiveUtc > ordered[i + 1].EffectiveAt)
            throw new ArgumentException(
                $"The {what} change can't be dated after the {what} change made after it ({ordered[i + 1].EffectiveAt.UtcDateTime:yyyy-MM-dd HH:mm} UTC).");

        var old = target.EffectiveAt;
        if (newEffectiveUtc == old)
            throw new ArgumentException("That's already when it happened.");

        target.Set(newEffectiveUtc == target.ChangedAtUtc ? null : newEffectiveUtc);

        // The milestone this phase change set moves with it.
        switch (target.To)
        {
            case CasePhase.Containment when ContainedAtUtc == old: ContainedAtUtc = newEffectiveUtc; break;
            case CasePhase.Recovery when ResolvedAtUtc == old: ResolvedAtUtc = newEffectiveUtc; break;
            case CasePhase.Closed when ClosedAtUtc == old: ClosedAtUtc = newEffectiveUtc; break;
        }

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
        if (DetectedAtUtc is { } detected && at < detected)
            throw new ArgumentException($"The {what} change can't be dated before the case was detected.");
        if (earlierChanges.Where(x => x > at).OrderByDescending(x => x).FirstOrDefault() is { } later && later != default)
            throw new ArgumentException(
                $"The {what} change can't be dated before the previous {what} change ({later.UtcDateTime:yyyy-MM-dd HH:mm} UTC).");
        return at;
    }

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    /// <summary>
    /// INV-09: saves a new version of the case brief, superseding the current one (the prior version is kept,
    /// with its time and author). A version must say something, and each part is capped in length. INV-36: the
    /// first part is the case summary, so this also sets <see cref="Summary"/>.
    /// </summary>
    public CaseBrief ReviseBrief(string? summary, string? workingAssessment, string? known, string? openQuestions,
        string? nextSteps, string actor, DateTimeOffset nowUtc)
    {
        var next = AddBriefVersion(summary, workingAssessment, known, openQuestions, nextSteps, actor, nowUtc,
            requireContent: true);
        Touch(actor, nowUtc);
        return next;
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
        var title = Clean(question) ?? throw new ArgumentException("Say what the question is.");
        if (title.Length > ActionItem.MaxTitleLength) title = title[..(ActionItem.MaxTitleLength - 1)] + "…";
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

    // A new brief version (superseding the current one) that also sets the case summary. A summary edit made
    // outside the brief can clear the summary, so it may record a version with nothing in it.
    private CaseBrief AddBriefVersion(string? summary, string? workingAssessment, string? known,
        string? openQuestions, string? nextSteps, string actor, DateTimeOffset nowUtc, bool requireContent)
    {
        var next = new CaseBrief
        {
            CaseId = Id, Summary = Clean(summary), WorkingAssessment = Clean(workingAssessment), Known = Clean(known),
            OpenQuestions = Clean(openQuestions), NextSteps = Clean(nextSteps), CreatedBy = actor, CreatedAtUtc = nowUtc
        };
        // INV-25: the next steps are recorded, not written, so they don't count as saying something.
        if (requireContent && new[] { next.Summary, next.WorkingAssessment, next.Known, next.OpenQuestions }.All(p => p is null))
            throw new ArgumentException("Write at least one part of the brief.");
        if (new[] { next.Summary, next.WorkingAssessment, next.Known, next.OpenQuestions, next.NextSteps }
                .Any(p => p is { Length: > CaseBrief.MaxPartLength }))
            throw new ArgumentException($"Keep each part of the brief to {CaseBrief.MaxPartLength:N0} characters or fewer.");

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
        CaseNumber, Title, Classification is { } cls ? ((int)cls).ToString(CultureInfo.InvariantCulture) : "", (int)Phase, (int)Severity, (int)Origin,
        Summary, ImpactedAssets, DataTypesInvolved, DetectionCaseId,
        AffectedIndividualsCount, string.Join(',', DataElements.Select(d => d.ElementKey).OrderBy(k => k, StringComparer.Ordinal)), AffectedStates,
        ThirdParty?.ToCanonical(), LegalReferral.ToCanonical(), Materiality.ToCanonical(),
        IncidentCommander, IsRestricted, IsArchived, LegalHold, IsExercise,
        OccurredAtUtc?.ToString("o"), DetectedAtUtc?.ToString("o"), ReportedAtUtc?.ToString("o"),
        ContainedAtUtc?.ToString("o"), ResolvedAtUtc?.ToString("o"), ClosedAtUtc?.ToString("o"),
        CreatedBy, CreatedAtUtc.ToString("o"));

    public static string FormatCaseNumber(int year, int sequence, string descriptiveName)
        => $"{year:0000}-{sequence:00}_{descriptiveName}";

    /// <summary>
    /// The Complex Event number: a "CE-" prefix + the creation date + slug (e.g.
    /// <c>CE-2026-08-23_Odd_Beaconing</c>), so intake items never look like IRP-ladder cases and there is
    /// no sequence to reuse. A <paramref name="disambiguator"/> above 1 appends "-N" for the rare case of a
    /// second Complex Event with the same descriptor on the same day.
    /// </summary>
    public static string FormatComplexEventNumber(DateTimeOffset date, string descriptiveName, int disambiguator = 1)
        => disambiguator <= 1
            ? $"CE-{date:yyyy-MM-dd}_{descriptiveName}"
            : $"CE-{date:yyyy-MM-dd}_{descriptiveName}-{disambiguator}";

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
