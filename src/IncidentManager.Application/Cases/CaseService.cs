using System.Collections.Immutable;
using FluentValidation;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Cases;

/// <summary>A saved graph node position for one entity (cosmetic view state).</summary>
public sealed record EntityPosition(Guid EntityId, double X, double Y);

/// <summary>An entity on this case that also appears on another case the user can see.</summary>
public sealed record EntityOverlap(Guid EntityId, Guid OtherCaseId, string OtherCaseNumber);

/// <summary>A case related to the one in view (E-14), resolved to the "other" case's summary.</summary>
public sealed record CaseLinkView(
    Guid LinkId, Guid OtherCaseId, string OtherCaseNumber, string OtherTitle,
    Classification? OtherClassification, CasePhase OtherPhase, Domain.Enums.Severity OtherSeverity,
    CaseLinkType Type, bool Outgoing, string? Description, DateTimeOffset CreatedAtUtc, string CreatedBy);

/// <summary>A visible case that can be linked to the one in view (picker option, E-14).</summary>
public sealed record LinkableCase(Guid Id, string CaseNumber, string Title, Classification? Classification, CasePhase Phase);

/// <summary>
/// A visible <em>open</em> case whose entities already include one or more of the indicators being
/// entered on a new case — surfaced before filing so a campaign isn't fragmented across cases (E-23).
/// </summary>
public sealed record CaseIocMatch(Guid CaseId, string CaseNumber, string Title, Classification? Classification,
    CasePhase Phase, IReadOnlyList<string> Indicators);

/// <summary>
/// Use cases for the case aggregate. Reads are access-scoped to the current user; writes go
/// through the domain model so classification/lifecycle history is always recorded, and are
/// captured by the audit-chain interceptor on save.
/// </summary>
public sealed class CaseService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ICaseNumberGenerator _caseNumbers;
    private readonly IValidator<CreateCaseRequest> _createValidator;
    private readonly ICaseNotifications _notifications;
    private readonly IStageGateEvaluator _gates;
    private readonly Sla.ISlaTargetsProvider _sla;
    private readonly Security.ISecurityEventSink? _siem;

    public CaseService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        ICaseNumberGenerator caseNumbers, IValidator<CreateCaseRequest> createValidator,
        ICaseNotifications notifications, IStageGateEvaluator gates, Sla.ISlaTargetsProvider sla,
        Security.ISecurityEventSink? siem = null)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _caseNumbers = caseNumbers;
        _createValidator = createValidator;
        _notifications = notifications;
        _gates = gates;
        _sla = sla;
        _siem = siem;
    }

    /// <summary>Applies need-to-know scoping to a case query for the current user.</summary>
    private IQueryable<Case> Scoped(IQueryable<Case> query) => query.ForUser(_user);

    /// <summary>
    /// Whether the current user may view the case with this number, honouring need-to-know scoping.
    /// Used by the scoped audit-export endpoint (E-24) before it releases a case's audit trail.
    /// </summary>
    public async Task<bool> CanViewAsync(string caseNumber, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await Scoped(db.Cases.AsNoTracking()).AnyAsync(c => c.CaseNumber == caseNumber, ct);
    }

    public async Task<CasePage> ListAsync(CaseFilter filter, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var q = Scoped(db.Cases.AsNoTracking());

        if (!filter.IncludeClosed) q = q.Where(c => c.Phase != CasePhase.Closed && !c.IsArchived);
        if (filter.Classification is { } cl) q = q.Where(c => c.Classification == cl);
        if (filter.Phase is { } ph) q = q.Where(c => c.Phase == ph);
        if (filter.MinSeverity is { } sev) q = q.Where(c => c.Severity >= sev);
        if (filter.Origin is { } origin) q = q.Where(c => c.Origin == origin);

        // Overdue and opened-month are date comparisons that don't translate on SQLite, so resolve
        // the matching case ids in memory (small, on-prem data set) and narrow the query by id.
        if (filter.OverdueOnly)
        {
            var now = _clock.UtcNow;
            var open = await db.ActionItems.AsNoTracking()
                .Where(a => a.DueAtUtc != null
                            && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled)
                .Select(a => new { a.CaseId, a.DueAtUtc })
                .ToListAsync(ct);
            var overdueIds = open.Where(x => x.DueAtUtc!.Value < now).Select(x => x.CaseId).Distinct().ToList();
            q = q.Where(c => overdueIds.Contains(c.Id));
        }

        // SLA at-risk/breached is a per-severity time comparison against the administered targets, so
        // resolve the matching ids in memory (same pattern as overdue) and narrow the query by id.
        if (filter.SlaAtRiskOnly)
        {
            var now = _clock.UtcNow;
            var targets = _sla.Current;
            var rows = await q
                .Select(c => new { c.Id, c.Severity, c.Phase, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc })
                .ToListAsync(ct);
            var flaggedIds = rows.Where(r => Sla.SlaPolicy
                    .Evaluate(r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc, targets, now)
                    .NeedsAttention)
                .Select(r => r.Id).ToList();
            q = q.Where(c => flaggedIds.Contains(c.Id));
        }

        if (filter is { OpenedYear: { } oy, OpenedMonth: { } om })
        {
            var start = new DateTimeOffset(oy, om, 1, 0, 0, 0, TimeSpan.Zero);
            var end = start.AddMonths(1);
            var dated = await q.Select(c => new { c.Id, c.CreatedAtUtc }).ToListAsync(ct);
            var monthIds = dated.Where(x => x.CreatedAtUtc >= start && x.CreatedAtUtc < end)
                .Select(x => x.Id).ToList();
            q = q.Where(c => monthIds.Contains(c.Id));
        }
        if (filter.OnlyMine)
        {
            var uid = _user.UserId;
            q = q.Where(c => c.IncidentCommander == uid || c.Assignments.Any(a => a.UserId == uid));
        }
        if (filter.UnassignedOnly)
        {
            // No active (IC/Analyst) assignee — mirrors the team-workload unassigned queue (E-25).
            q = q.Where(c => !c.Assignments.Any(a => a.Role != CaseAssignmentRole.Observer));
        }
        else if (!string.IsNullOrEmpty(filter.AssigneeUserId))
        {
            var aid = filter.AssigneeUserId;
            q = q.Where(c => c.Assignments.Any(a => a.UserId == aid && a.Role != CaseAssignmentRole.Observer));
        }
        if (!string.IsNullOrWhiteSpace(filter.Search))
        {
            // Lower both sides so the match is case-insensitive regardless of the database's collation
            // (SQLite and SQL Server both default to CI, but this makes it explicit and provider-safe).
            // This runs inside an EF Core expression tree translated to SQL: ToLower() maps to the SQL
            // LOWER() function, whereas ToLowerInvariant() and the StringComparison overloads of
            // Contains() have no SQL translation and would throw at runtime — so the culture analyzers
            // (CA1304/CA1311/CA1862) are false positives here and their suggested fixes must not be applied.
#pragma warning disable CA1304, CA1311, CA1862 // EF Core translates ToLower()/Contains() to SQL; culture overloads don't translate.
            var s = filter.Search.Trim().ToLower();
            // Match across the case's own fields and its IOCs and notes, so analysts can find a case
            // by an indicator or a note as well as by number/title.
            q = q.Where(c =>
                c.CaseNumber.ToLower().Contains(s) ||
                c.Title.ToLower().Contains(s) ||
                (c.Summary != null && c.Summary.ToLower().Contains(s)) ||
                c.Entities.Any(e => e.Value.ToLower().Contains(s) || (e.Label != null && e.Label.ToLower().Contains(s))) ||
                c.Notes.Any(n => n.IsCurrent && n.Body.ToLower().Contains(s)));
#pragma warning restore CA1304, CA1311, CA1862
        }

        var total = await q.CountAsync(ct);
        var page = filter.Page < 1 ? 1 : filter.Page;
        var size = filter.PageSize < 1 ? 25 : filter.PageSize;

        var items = await q
            .OrderByDescending(c => c.CreatedAtUtc)
            .Skip((page - 1) * size)
            .Take(size)
            .Select(c => new CaseListItem(
                c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, c.Severity, c.Origin,
                c.IsRestricted, c.LegalReferral.IsReferred, c.CreatedAtUtc, c.IncidentCommander,
                c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc))
            .ToListAsync(ct);

        return new CasePage(items, total, page, size);
    }

    /// <summary>Loads a case with all detail for the workspace, enforcing access scoping.</summary>
    public async Task<Case?> GetDetailAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await Scoped(db.Cases.AsNoTracking())
            .Include(x => x.ClassificationChanges)
            .Include(x => x.StatusChanges)
            .Include(x => x.SeverityChanges)
            .Include(x => x.TimelineEntries).ThenInclude(t => t.Tactics)
            .Include(x => x.Notes)
            .Include(x => x.Evidence)
            .Include(x => x.ActionItems)
            .Include(x => x.Assignments)
            .Include(x => x.Entities)
            .Include(x => x.EntityRelationships)
            .Include(x => x.EntityLayouts)
            .Include(x => x.Techniques)
            .Include(x => x.DataElements)
            .Include(x => x.Reports)
            .FirstOrDefaultAsync(x => x.Id == id, ct);
        return c;
    }

    /// <summary>The active data-element reference set (X-03), in display order — the options the impact
    /// assessment offers. Archived elements are excluded from new selection but still resolve for display.</summary>
    public async Task<IReadOnlyList<DataElement>> ListActiveDataElementsAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.DataElements.AsNoTracking()
            .Where(e => e.IsActive)
            .OrderBy(e => e.SortOrder).ThenBy(e => e.Label)
            .ToListAsync(ct);
    }

    /// <summary>Resolves data-element labels by stable key (X-03) for display — includes archived elements so
    /// a case that already references a since-archived element still shows its label.</summary>
    public async Task<IReadOnlyDictionary<string, string>> DataElementLabelsAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.DataElements.AsNoTracking().ToDictionaryAsync(e => e.Key, e => e.Label, ct);
    }

    public async Task<Case> CreateAsync(CreateCaseRequest request, CancellationToken ct = default)
    {
        await _createValidator.ValidateAndThrowAsync(request, ct);

        var now = _clock.UtcNow;
        var year = now.Year;
        var custom = NormalizeCaseNumber(request.CaseNumber);

        // Retry on the rare auto-sequence collision (the unique CaseNumber / per-scheme sequence indexes
        // are the guard). A fresh context per attempt so a failed save's audit entry never lingers into the
        // retry. A custom number is fixed, so it isn't retried — a duplicate surfaces as a friendly error.
        for (var attempt = 0; ; attempt++)
        {
            using var db = _factory.CreateDbContext();

            if (custom is not null && await db.Cases.AnyAsync(x => x.CaseNumber == custom, ct))
                throw new InvalidOperationException($"Case number '{custom}' is already in use.");

            // IRP items draw a per-year sequence (advanced by the attempt offset so a retry moves past a
            // taken number); Complex Events are date-numbered (no sequence) and disambiguate with a "-N"
            // suffix on the rare same-day/same-descriptor clash; custom numbers are fixed.
            var isComplexEvent = request.Classification is null;
            var seq = (custom is null && !isComplexEvent)
                ? await _caseNumbers.NextSequenceAsync(year, ct) + attempt
                : 0;
            var c = Case.Open(year, seq, request.DescriptiveName, request.Title,
                request.Classification, request.Severity, request.Origin, _user.UserId, now);
            if (custom is not null) c.AssignCustomNumber(custom, _user.UserId, now);
            else if (isComplexEvent && attempt > 0) c.SetComplexEventNumber(now, attempt + 1);

            c.Summary = request.Summary;
            c.DetectionCaseId = request.DetectionCaseId;
            c.DataTypesInvolved = request.DataTypesInvolved;
            c.ImpactedAssets = request.ImpactedAssets;
            if (request.Origin == CaseOrigin.ThirdParty)
            {
                c.ThirdParty = new ThirdPartyDetails
                {
                    VendorName = request.VendorName ?? string.Empty,
                    VendorContact = request.VendorContact,
                    VendorReference = request.VendorReference
                };
            }

            db.Cases.Add(c);
            try
            {
                await db.SaveChangesAsync(ct);
                return c;
            }
            catch (DbUpdateException) when (custom is null && attempt < 20)
            {
                // Discard this attempt's context (and its rolled-back audit entry) and retry with a higher seq.
            }
            catch (DbUpdateException) when (custom is not null)
            {
                throw new InvalidOperationException($"Case number '{custom}' is already in use.");
            }
        }
    }

    /// <summary>Trims/validates an analyst-supplied case number; null when none was given.</summary>
    private static string? NormalizeCaseNumber(string? raw)
    {
        var v = raw?.Trim();
        if (string.IsNullOrEmpty(v)) return null;
        if (v.Length > 200)
            throw new InvalidOperationException("A case number must be 200 characters or fewer.");
        return v;
    }

    /// <summary>
    /// Changes a case's number to an explicit, analyst-chosen value (rename). Enforces uniqueness across
    /// all cases; the change is captured by the audit chain (the number is part of the canonical hash).
    /// </summary>
    public async Task RenumberAsync(Guid id, string newNumber, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);

        var n = NormalizeCaseNumber(newNumber)
            ?? throw new InvalidOperationException("A case number is required.");
        if (n == c.CaseNumber) return;

        if (await db.Cases.AnyAsync(x => x.Id != id && x.CaseNumber == n, ct))
            throw new InvalidOperationException($"Case number '{n}' is already in use.");

        c.AssignCustomNumber(n, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    private static async Task<Case> LoadTrackedAsync(IAppDbContext db, Guid id, CancellationToken ct)
    {
        var c = await db.Cases
            .Include(x => x.ClassificationChanges)
            .Include(x => x.StatusChanges)
            .Include(x => x.SeverityChanges)
            .Include(x => x.TimelineEntries).ThenInclude(t => t.Tactics)
            .Include(x => x.Notes)
            .Include(x => x.ActionItems)
            .Include(x => x.Assignments)
            .Include(x => x.Entities)
            .Include(x => x.EntityRelationships)
            .Include(x => x.EntityLayouts)
            .Include(x => x.Techniques)
            .Include(x => x.DataElements)
            .FirstOrDefaultAsync(x => x.Id == id, ct)
            ?? throw new InvalidOperationException($"Case {id} not found.");
        return c;
    }

    public async Task ReclassifyAsync(Guid id, Classification to, string reason,
        IReadOnlySet<Guid>? attestedRequirementIds = null, string? overrideJustification = null,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var from = c.Classification;

        // Gate only promotions/escalations (up the ladder or off intake) — de-escalations aren't gated.
        if ((from is null || to > from) && StageGateTriggers.ForClassification(to) is { } trigger)
            await ApplyGateAsync(db, c, trigger, attestedRequirementIds, overrideJustification, reason, ct);

        var now = _clock.UtcNow;
        c.Reclassify(to, reason, _user.UserId, now);

        // Promotion off the Complex Event intake ladder → renumber into the IRP scheme (unless the analyst
        // pinned a custom number). Advance past any already-used number for the year (defensive against a
        // custom number matching the auto-format), then save once; a true concurrent collision is caught by
        // the per-scheme unique index (rare — the action can simply be retried).
        if (from is null && !c.HasCustomNumber)
        {
            var seq = await _caseNumbers.NextSequenceAsync(c.Year, ct);
            while (await db.Cases.AnyAsync(x => x.CaseNumber == Case.FormatCaseNumber(c.Year, seq, c.DescriptiveName), ct))
                seq++;
            c.RenumberToIrp(seq, _user.UserId, now);
        }

        await db.SaveChangesAsync(ct);
        await _notifications.OnReclassifiedAsync(c, from, to, ct);

        // F-18: a breach escalation is a notable governance signal for the SOC stream.
        if (to == Classification.Breach && from != Classification.Breach)
            _siem?.Emit(Security.SecurityEvents.BreachEscalated(_user.UserId, _user.UserPrincipalName, c.CaseNumber));
    }

    public async Task ChangePhaseAsync(Guid id, CasePhase to, string? reason,
        IReadOnlySet<Guid>? attestedRequirementIds = null, string? overrideJustification = null,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);

        if (to == CasePhase.Closed && c.Phase != CasePhase.Closed)
            await ApplyGateAsync(db, c, StageGateTrigger.CloseCase, attestedRequirementIds, overrideJustification, reason, ct);

        c.ChangePhase(to, reason, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Reopens a closed case (E-27) with a required reason: returns it to its pre-closure phase and clears
    /// the closure timestamp so MTTR / dashboard math stays correct. Audited via the change interceptor.
    /// </summary>
    public async Task ReopenAsync(Guid id, string reason, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("A reason is required to reopen a case.", nameof(reason));

        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.Reopen(reason, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Evaluates the active gate for a transition (read-only) — for the workspace readiness view.</summary>
    public async Task<GateEvaluation> EvaluateGateAsync(Guid id, StageGateTrigger trigger, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await _gates.EvaluateAsync(db, id, trigger, ct);
    }

    /// <summary>
    /// Enforces the stage gate for a transition: evaluates blocking requirements against the case plus the
    /// analyst's attestations, blocks (throws) when any are unmet and no override justification is given,
    /// and records a tamper-evident <c>GatePassage</c> capturing the outcome (including any override).
    /// </summary>
    private async Task ApplyGateAsync(IAppDbContext db, Case c, StageGateTrigger trigger,
        IReadOnlySet<Guid>? attestedIds, string? overrideJustification, string? reason, CancellationToken ct)
    {
        var eval = await _gates.EvaluateAsync(db, c.Id, trigger, ct);
        if (!eval.GateExists) return;

        var attested = attestedIds ?? (IReadOnlySet<Guid>)ImmutableHashSet<Guid>.Empty;
        var unmet = eval.UnmetBlocking(attested);
        var overridden = unmet.Count > 0;

        if (overridden && string.IsNullOrWhiteSpace(overrideJustification))
            throw new GateNotSatisfiedException(trigger, eval.GateName, unmet);

        // A gate can require a minimum-length rationale. It applies to the transition reason, and — when the
        // move is being forced past unmet requirements — to the override justification too.
        if (eval.RequiresCommentary)
        {
            var min = eval.CommentaryMinLength;
            if ((reason?.Trim().Length ?? 0) < min)
                throw new InvalidOperationException(
                    $"Gate '{eval.GateName}' requires a reason of at least {min} characters.");
            if (overridden && (overrideJustification?.Trim().Length ?? 0) < min)
                throw new InvalidOperationException(
                    $"Gate '{eval.GateName}' requires an override justification of at least {min} characters.");
        }

        var detail = GateDetail.Summarize(eval, attested);
        // The reason is the analyst's rationale for the transition; keep it on the passage so the gate
        // record is self-contained for an examiner.
        c.RecordGatePassage(trigger, overridden, overrideJustification, reason, detail, _user.UserId, _clock.UtcNow);
    }

    public async Task ReferToLegalAsync(Guid id, string? contact, string? relevanceNote, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.ReferToLegal(_user.UserId, contact, relevanceNote, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task ChangeSeverityAsync(Guid id, Domain.Enums.Severity severity, string? reason = null,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.ChangeSeverity(severity, reason, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task UpdateDetailsAsync(Guid id, string title, string? summary, string? detectionCaseId,
        string? dataTypesInvolved, string? impactedAssets, DateTimeOffset detectedAtUtc, DateTimeOffset? occurredAtUtc,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.UpdateDetails(title, summary, detectionCaseId, dataTypesInvolved, impactedAssets,
            detectedAtUtc, occurredAtUtc, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Records the structured impact assessment (affected count, data-element taxonomy, jurisdictions). E-12.
    /// Data elements are supplied as stable <c>DataElement.Key</c>s (X-03).</summary>
    public async Task UpdateImpactAssessmentAsync(Guid id, int? affectedIndividualsCount,
        IEnumerable<string> dataElementKeys, string? affectedStates, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.SetImpactAssessment(affectedIndividualsCount, dataElementKeys, affectedStates, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task AssignAsync(Guid id, string userId, string displayName, CaseAssignmentRole role,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.Assign(userId, displayName, role, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);

        // E-03b: tell the assignee (out of band; never fails the assignment).
        await _notifications.OnAssignedAsync(c, userId, displayName, role, _user.UserId, ct);
    }

    public async Task UnassignAsync(Guid id, string userId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.Unassign(userId, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task AddTimelineEntryAsync(Guid id, TimelineKind kind, TimelineEntryType type,
        DateTimeOffset occurredAtUtc, string description, string? source, Guid? evidenceId = null,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c.Id, Kind = kind, Type = type, OccurredAtUtc = occurredAtUtc, Description = description,
            Source = source, EvidenceId = evidenceId, CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
        });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Adds an Event-timeline step (the attack narrative): one or more MITRE ATT&amp;CK tactics, an
    /// optional technique, and actor &rarr; target attribution to entities already on the case.
    /// </summary>
    public async Task AddEventStepAsync(Guid id, DateTimeOffset occurredAtUtc, IEnumerable<MitreTactic> tactics,
        string? techniqueId, Guid? actorEntityId, Guid? targetEntityId, string description, string? source,
        Guid? evidenceId = null, TimelineEntryType type = TimelineEntryType.Other, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.AddEventStep(occurredAtUtc, tactics, techniqueId, actorEntityId, targetEntityId, description, source,
            _user.UserId, _clock.UtcNow, evidenceId, type);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Corrects an Event-timeline step in place (attack narrative facts change during an investigation).
    /// The optional <paramref name="reason"/> is recorded on the audit entry.
    /// </summary>
    public async Task EditEventStepAsync(Guid id, Guid entryId, DateTimeOffset occurredAtUtc,
        IEnumerable<MitreTactic> tactics, string? techniqueId, Guid? actorEntityId, Guid? targetEntityId,
        string description, string? source, string? reason = null,
        TimelineEntryType type = TimelineEntryType.Other, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.EditEventStep(entryId, occurredAtUtc, tactics, techniqueId, actorEntityId, targetEntityId, description,
            source, _user.UserId, _clock.UtcNow, type);
        db.PendingChangeReason = reason;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Edits an Investigation-timeline entry, superseding it with a new version (prior kept). The optional
    /// <paramref name="reason"/> is recorded on the audit entry.
    /// </summary>
    public async Task EditInvestigationEntryAsync(Guid id, Guid entryId, TimelineEntryType type,
        DateTimeOffset occurredAtUtc, string description, string? source, string? reason = null,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.EditInvestigationEntry(entryId, type, occurredAtUtc, description, source, _user.UserId, _clock.UtcNow);
        db.PendingChangeReason = reason;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Finds this case's IOCs/entities that also appear on <em>other</em> cases the user is allowed to
    /// see (same type + value), so analysts can pivot on a shared indicator. Exact-value match.
    /// </summary>
    public async Task<IReadOnlyList<EntityOverlap>> FindEntityOverlapsAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var mine = await db.CaseEntities.AsNoTracking()
            .Where(e => e.CaseId == caseId)
            .Select(e => new { e.Id, e.Type, e.Value })
            .ToListAsync(ct);
        if (mine.Count == 0) return Array.Empty<EntityOverlap>();

        var values = mine.Select(m => m.Value).Distinct().ToList();

        var others = await (
            from e in db.CaseEntities.AsNoTracking()
            where e.CaseId != caseId && values.Contains(e.Value)
            join c in Scoped(db.Cases.AsNoTracking()) on e.CaseId equals c.Id
            select new { e.Type, e.Value, OtherCaseId = c.Id, c.CaseNumber }
        ).ToListAsync(ct);

        var result = new List<EntityOverlap>();
        foreach (var m in mine)
        {
            var matches = others
                .Where(o => o.Type == m.Type && string.Equals(o.Value, m.Value, StringComparison.OrdinalIgnoreCase))
                .Select(o => (o.OtherCaseId, o.CaseNumber))
                .Distinct();
            foreach (var (ocid, ocn) in matches)
                result.Add(new EntityOverlap(m.Id, ocid, ocn));
        }
        return result;
    }

    /// <summary>
    /// E-23: given the raw indicators an analyst is entering on a <em>new</em> case, returns the visible
    /// <b>open</b> cases whose entities already include any of them — so a duplicate or same-campaign case
    /// surfaces before filing. Indicators are refanged (a defanged paste matches a live stored value) and
    /// matched case-insensitively on value alone (type-agnostic — an IP is an IP). Need-to-know scoped, and
    /// closed/archived cases are excluded (only live investigations are worth relating to at intake).
    /// </summary>
    public async Task<IReadOnlyList<CaseIocMatch>> FindOpenCaseMatchesForIocsAsync(
        IEnumerable<string> rawIndicators, CancellationToken ct = default)
    {
        // Refang + trim, drop blanks, dedupe by lowercased value.
        var wanted = (rawIndicators ?? Enumerable.Empty<string>())
            .Select(r => Domain.Observables.IocObservable.Refang(r))
            .Where(v => v.Length > 0)
            .GroupBy(v => v.ToLowerInvariant())
            .Select(g => g.Key)
            .ToList();
        if (wanted.Count == 0) return Array.Empty<CaseIocMatch>();

        using var db = _factory.CreateDbContext();
        // e.Value.ToLower() runs in an EF Core query translated to SQL LOWER(); ToLowerInvariant() has
        // no SQL translation and would throw. The 'wanted' keys were already invariant-lowered in memory
        // above, so both sides match. CA1304/CA1311 are false positives in this expression-tree context.
#pragma warning disable CA1304, CA1311 // EF Core translates ToLower() to SQL; the invariant overload doesn't translate.
        var hits = await (
            from e in db.CaseEntities.AsNoTracking()
            join c in Scoped(db.Cases.AsNoTracking()) on e.CaseId equals c.Id
            where c.Phase != CasePhase.Closed && !c.IsArchived && wanted.Contains(e.Value.ToLower())
            select new { c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, e.Value }
        ).ToListAsync(ct);
#pragma warning restore CA1304, CA1311

        return hits
            .GroupBy(h => new { h.Id, h.CaseNumber, h.Title, h.Classification, h.Phase })
            .Select(g => new CaseIocMatch(g.Key.Id, g.Key.CaseNumber, g.Key.Title, g.Key.Classification,
                g.Key.Phase, g.Select(x => x.Value).Distinct().ToList()))
            .OrderByDescending(m => m.Indicators.Count)
            .ThenBy(m => m.CaseNumber)
            .ToList();
    }

    public async Task<Guid> AddEntityAsync(Guid id, EntityType type, string value, string? label,
        EntityDisposition disposition, string? description, string? source, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var entity = c.AddEntity(type, value, label, disposition, description, source, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        return entity.Id;
    }

    /// <summary>
    /// Corrects an existing IOC/entity in place (e.g. a mis-typed value or a re-assessed disposition).
    /// The optional <paramref name="reason"/> is recorded on the audit entry.
    /// </summary>
    public async Task EditEntityAsync(Guid id, Guid entityId, EntityType type, string value, string? label,
        EntityDisposition disposition, string? description, string? source, string? reason = null,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.EditEntity(entityId, type, value, label, disposition, description, source, _user.UserId, _clock.UtcNow);
        db.PendingChangeReason = reason;
        await db.SaveChangesAsync(ct);
    }

    public async Task RemoveEntityAsync(Guid id, Guid entityId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.RemoveEntity(entityId, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task LinkEntitiesAsync(Guid id, Guid sourceEntityId, Guid targetEntityId,
        EntityRelationshipType type, string? description, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.LinkEntities(sourceEntityId, targetEntityId, type, description, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task UnlinkAsync(Guid id, Guid relationshipId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.Unlink(relationshipId, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    // ── Case linking / campaign grouping (E-14) ─────────────────────────────────────────────────

    /// <summary>
    /// Links two cases with a typed relationship (E-14). Both cases must be visible to the caller;
    /// a pair can only be linked once (either direction). Returns the new link id, or null if the
    /// pair is already linked. Self-links are rejected.
    /// </summary>
    public async Task<Guid?> LinkCaseAsync(Guid caseId, Guid relatedCaseId, CaseLinkType type,
        string? description, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        if (caseId == relatedCaseId) throw new ArgumentException("A case cannot be linked to itself.");

        // Need-to-know: both ends must be visible to the caller.
        var visible = await Scoped(db.Cases.AsNoTracking())
            .Where(c => c.Id == caseId || c.Id == relatedCaseId)
            .Select(c => c.Id).ToListAsync(ct);
        if (!visible.Contains(caseId) || !visible.Contains(relatedCaseId))
            throw new InvalidOperationException("Both cases must exist and be visible to you.");

        // One link per pair, regardless of direction — keeps the relationship unambiguous.
        var already = await db.CaseLinks.AsNoTracking().AnyAsync(l =>
            (l.CaseId == caseId && l.RelatedCaseId == relatedCaseId) ||
            (l.CaseId == relatedCaseId && l.RelatedCaseId == caseId), ct);
        if (already) return null;

        var link = new CaseLink
        {
            CaseId = caseId,
            RelatedCaseId = relatedCaseId,
            Type = type,
            Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
            CreatedBy = _user.UserId,
            CreatedAtUtc = _clock.UtcNow
        };
        db.CaseLinks.Add(link);
        await db.SaveChangesAsync(ct);
        return link.Id;
    }

    /// <summary>Removes a case link. No-op unless the link touches <paramref name="caseId"/> and the caller can see it.</summary>
    public async Task RemoveCaseLinkAsync(Guid caseId, Guid linkId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var link = await db.CaseLinks.FirstOrDefaultAsync(l => l.Id == linkId, ct);
        if (link is null || (link.CaseId != caseId && link.RelatedCaseId != caseId)) return;

        var canSee = await Scoped(db.Cases.AsNoTracking())
            .AnyAsync(c => c.Id == link.CaseId || c.Id == link.RelatedCaseId, ct);
        if (!canSee) return;

        db.CaseLinks.Remove(link);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Related cases for the one in view, from either side of the link. The "other" case is resolved
    /// through need-to-know scoping, so a link to a case the caller can't see is silently omitted.
    /// </summary>
    public async Task<IReadOnlyList<CaseLinkView>> GetCaseLinksAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var links = await db.CaseLinks.AsNoTracking()
            .Where(l => l.CaseId == caseId || l.RelatedCaseId == caseId)
            .ToListAsync(ct);
        if (links.Count == 0) return Array.Empty<CaseLinkView>();

        var otherIds = links.Select(l => l.CaseId == caseId ? l.RelatedCaseId : l.CaseId).Distinct().ToList();
        var others = await Scoped(db.Cases.AsNoTracking())
            .Where(c => otherIds.Contains(c.Id))
            .Select(c => new { c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, c.Severity })
            .ToDictionaryAsync(c => c.Id, ct);

        var result = new List<CaseLinkView>();
        foreach (var l in links)
        {
            var outgoing = l.CaseId == caseId;
            var otherId = outgoing ? l.RelatedCaseId : l.CaseId;
            if (!others.TryGetValue(otherId, out var o)) continue; // other case not visible → hide
            result.Add(new CaseLinkView(l.Id, o.Id, o.CaseNumber, o.Title, o.Classification, o.Phase,
                o.Severity, l.Type, outgoing, l.Description, l.CreatedAtUtc, l.CreatedBy));
        }
        return result.OrderBy(r => r.OtherCaseNumber, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// Visible cases that can be linked to the one in view: excludes itself and any case already
    /// linked (either direction). Optional contains-match on case number or title. (E-14 picker.)
    /// </summary>
    public async Task<IReadOnlyList<LinkableCase>> SearchLinkableCasesAsync(Guid caseId, string? query,
        int take = 10, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var linked = await db.CaseLinks.AsNoTracking()
            .Where(l => l.CaseId == caseId || l.RelatedCaseId == caseId)
            .Select(l => l.CaseId == caseId ? l.RelatedCaseId : l.CaseId)
            .ToListAsync(ct);

        var q = Scoped(db.Cases.AsNoTracking()).Where(c => c.Id != caseId);
        if (linked.Count > 0) q = q.Where(c => !linked.Contains(c.Id));
        if (!string.IsNullOrWhiteSpace(query))
        {
            var term = query.Trim();
            q = q.Where(c => c.CaseNumber.Contains(term) || c.Title.Contains(term));
        }

        return await q.OrderByDescending(c => c.CreatedAtUtc).Take(take)
            .Select(c => new LinkableCase(c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase))
            .ToListAsync(ct);
    }

    public async Task<Guid> AddTechniqueAsync(Guid id, string techniqueId, string name, MitreTactic tactic,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var technique = c.AddTechnique(techniqueId, name, tactic, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        return technique.Id;
    }

    public async Task RemoveTechniqueAsync(Guid id, Guid techniqueId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.RemoveTechnique(techniqueId, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Upserts saved graph node positions for a case. Cosmetic view state written straight to
    /// its own table (not via the aggregate), so it is neither audited nor hash-chained.
    /// </summary>
    public async Task SaveGraphLayoutAsync(Guid caseId, IReadOnlyList<EntityPosition> positions, CancellationToken ct = default)
    {
        if (positions.Count == 0) return;

        using var db = _factory.CreateDbContext();

        // Only persist for cases the current user is allowed to see.
        var visible = await Scoped(db.Cases.AsNoTracking()).AnyAsync(c => c.Id == caseId, ct);
        if (!visible) return;

        var validIds = (await db.CaseEntities.AsNoTracking()
            .Where(e => e.CaseId == caseId).Select(e => e.Id).ToListAsync(ct)).ToHashSet();

        var existing = await db.EntityLayouts.Where(l => l.CaseId == caseId).ToListAsync(ct);
        var byEntity = existing.ToDictionary(l => l.EntityId);

        foreach (var p in positions)
        {
            if (!validIds.Contains(p.EntityId)) continue;
            if (byEntity.TryGetValue(p.EntityId, out var row)) { row.X = p.X; row.Y = p.Y; }
            else db.EntityLayouts.Add(new EntityLayout { CaseId = caseId, EntityId = p.EntityId, X = p.X, Y = p.Y });
        }
        await db.SaveChangesAsync(ct);
    }

    public async Task AddNoteAsync(Guid id, string body, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.Notes.Add(new AnalystNote
        {
            CaseId = c.Id, Body = body, CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
        });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Edits a note, superseding the current version with a new one (no destructive overwrite).</summary>
    public async Task EditNoteAsync(Guid id, Guid noteId, string newBody, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.EditNote(noteId, newBody, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Places or releases a legal hold on the case (blocks archival while held).</summary>
    public async Task SetLegalHoldAsync(Guid id, bool held, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        if (held) c.PlaceLegalHold(_user.UserId, _clock.UtcNow);
        else c.ReleaseLegalHold(_user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        _siem?.Emit(Security.SecurityEvents.LegalHold(held, _user.UserId, _user.UserPrincipalName, c.CaseNumber));
    }

    /// <summary>
    /// Sets (or clears, with null) the case's report profile (E-28) — the named section layout its reports
    /// and in-app preview use. Audited; falls back to the global default when cleared or the profile is gone.
    /// </summary>
    public async Task SetReportProfileAsync(Guid id, Guid? profileId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.SetReportProfile(profileId, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Archives or restores the case. Archiving is refused while a legal hold is in force.</summary>
    public async Task SetArchivedAsync(Guid id, bool archived, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        if (archived) c.Archive(_user.UserId, _clock.UtcNow);
        else c.Unarchive(_user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task AddActionItemAsync(Guid id, string title, string? owner, DateTimeOffset? dueAtUtc,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.ActionItems.Add(new ActionItem
        {
            CaseId = c.Id, Title = title, Owner = owner, DueAtUtc = dueAtUtc,
            CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
        });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Seeds a case template's playbook steps (E-06) as action items on a case the caller can see.
    /// <paramref name="stepIds"/> optionally narrows to a subset (the Apply-playbook dialog lets an analyst
    /// uncheck steps); null seeds them all. Each item's owner is the step's owner hint when set, else the
    /// case owner (the incident commander), else <paramref name="defaultOwner"/> — the fallback the Apply
    /// dialog collects when the case has no owner yet, so a playbook doesn't silently create a wall of
    /// unassigned tasks (U-45). Any still-empty owner is left Unassigned. Due dates are computed from now plus
    /// the step's hour offset so a mid-case apply isn't instantly overdue. Returns the number seeded.
    /// </summary>
    public async Task<int> ApplyTemplateAsync(Guid caseId, Guid templateId, IReadOnlyCollection<Guid>? stepIds = null,
        string? defaultOwner = null, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();

        // Scope the case so a caller can't seed items onto a case they can't see.
        if (!await Scoped(db.Cases.AsNoTracking()).AnyAsync(x => x.Id == caseId, ct))
            throw new InvalidOperationException("Case not found or not accessible.");

        var template = await db.CaseTemplates.AsNoTracking()
            .Include(t => t.Steps)
            .FirstOrDefaultAsync(t => t.Id == templateId, ct)
            ?? throw new InvalidOperationException("Template not found.");

        var c = await LoadTrackedAsync(db, caseId, ct);
        var now = _clock.UtcNow;

        var steps = template.Steps.OrderBy(s => s.Order).AsEnumerable();
        if (stepIds is not null)
        {
            var wanted = stepIds.ToHashSet();
            steps = steps.Where(s => wanted.Contains(s.Id));
        }

        // The fallback owner for steps with no hint: the case owner if one exists, else the default the Apply
        // dialog collected (U-45). Trimmed to null so a blank never becomes a stored empty owner.
        var fallbackOwner = string.IsNullOrWhiteSpace(c.IncidentCommander)
            ? (string.IsNullOrWhiteSpace(defaultOwner) ? null : defaultOwner.Trim())
            : c.IncidentCommander;

        var seeded = 0;
        foreach (var s in steps)
        {
            var owner = string.IsNullOrWhiteSpace(s.OwnerHint) ? fallbackOwner : s.OwnerHint.Trim();
            c.ActionItems.Add(new ActionItem
            {
                CaseId = c.Id,
                Title = s.Title,
                Description = s.Description,
                Owner = owner,
                DueAtUtc = s.DueOffsetHours is { } h ? now.AddHours(h) : null,
                CreatedBy = _user.UserId,
                CreatedAtUtc = now
            });
            seeded++;
        }

        if (seeded > 0) await db.SaveChangesAsync(ct);
        return seeded;
    }

    public async Task SetActionItemStatusAsync(Guid caseId, Guid actionItemId, ActionItemStatus status,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        var item = c.ActionItems.FirstOrDefault(a => a.Id == actionItemId)
                   ?? throw new InvalidOperationException("Action item not found.");
        item.Status = status;
        item.ModifiedBy = _user.UserId;
        item.ModifiedAtUtc = _clock.UtcNow;
        if (status == ActionItemStatus.Done) item.CompletedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }
}
