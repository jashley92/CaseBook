using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using FluentValidation;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using IncidentManager.Application.Common;

namespace IncidentManager.Application.Cases;

/// <summary>A saved graph node position for one entity (cosmetic view state).</summary>
public sealed record EntityPosition(Guid EntityId, double X, double Y);

/// <summary>
/// An entity on this case that also appears on another case the user can see. HR-03: with what that case is and how it
/// ended: its title, phase, the verdict it reached there, and, once closed, when, its outcome and its closing line
/// (the closing brief's conclusion, else the close's reason).
/// </summary>
public sealed record EntityOverlap(Guid EntityId, Guid OtherCaseId, string OtherCaseNumber,
    string OtherTitle = "", CasePhase OtherPhase = CasePhase.New, EntityDisposition DispositionThere = EntityDisposition.Unknown,
    DateTimeOffset? ClosedAtUtc = null, string? OutcomeKey = null, string? ClosingLine = null, Classification? OtherClassification = null)
{
    public bool IsClosed => OtherPhase == CasePhase.Closed;
}

/// <summary>
/// CAP-28: an indicator on another case the user can see that's possibly related to <paramref name="Indicator"/> (one of
/// this case's, or one being entered): not the same value, but the same registrable domain, /24 or /48, or email domain
/// (<see cref="Key"/>). A suggestion, never a link.
/// </summary>
public sealed record RelatedIndicator(string Indicator, EntityType OtherType, string OtherValue, Guid OtherCaseId,
    string OtherCaseNumber, string OtherTitle, CasePhase OtherPhase, EntityDisposition DispositionThere,
    IncidentManager.Domain.Observables.RelatedKey Key)
{
    public bool IsClosed => OtherPhase == CasePhase.Closed;

    /// <summary>Why it's suggested: "same registrable domain evil.example".</summary>
    public string Why => Key.Describe();
}

/// <summary>
/// CAP-28 review: the possibly related indicators found, and whether a shared part had more candidates than were read
/// (<see cref="CaseService.RelatedScanLimit"/>, newest cases first): then "none" means none among the newest checked, and
/// the panel says so rather than that nothing is related.
/// </summary>
public sealed class RelatedIndicators(IReadOnlyList<RelatedIndicator> items, bool scanLimitHit) : IReadOnlyList<RelatedIndicator>
{
    public static readonly RelatedIndicators None = new([], false);

    /// <summary>A shared part had at least <see cref="CaseService.RelatedScanLimit"/> candidates; only the newest were checked.</summary>
    public bool ScanLimitHit { get; } = scanLimitHit;

    public int Count => items.Count;
    public RelatedIndicator this[int index] => items[index];
    public IEnumerator<RelatedIndicator> GetEnumerator() => items.GetEnumerator();
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>
/// HR-03: a visible <em>closed</em> case whose entities include indicators being entered on a new case: what it concluded,
/// when, and the verdict each shared indicator reached there. Shown at intake as "seen before", beside the open matches.
/// </summary>
public sealed record CaseHistoryMatch(Guid CaseId, string CaseNumber, string Title, Classification? Classification,
    DateTimeOffset? ClosedAtUtc, string? OutcomeKey, string? ClosingLine,
    IReadOnlyList<(string Value, EntityDisposition Disposition)> Indicators);

/// <summary>
/// CAP-24: a vendor's earlier cases the user can see, shown at intake as "Seen before": how many, how many are still
/// open, and the most recently closed one with how it ended (null when none has closed).
/// </summary>
public sealed record VendorHistory(string Vendor, int Cases, int Open, CaseHistoryMatch? LastClosed);

/// <summary>A case related to the one in view (E-14), resolved to the "other" case's summary.</summary>
public sealed record CaseLinkView(
    Guid LinkId, Guid OtherCaseId, string OtherCaseNumber, string OtherTitle,
    Classification? OtherClassification, CasePhase OtherPhase, Domain.Enums.Severity OtherSeverity,
    CaseLinkType Type, bool Outgoing, string? Description, DateTimeOffset CreatedAtUtc, string CreatedBy);

/// <summary>A visible case that can be linked to the one in view (picker option, E-14).</summary>
public sealed record LinkableCase(Guid Id, string CaseNumber, string Title, Classification? Classification, CasePhase Phase);

/// <summary>PROD-11: what superseding a duplicate did — the kept case, indicators copied, and whether a link was added.</summary>
public sealed record SupersedeResult(Guid PrimaryCaseId, string PrimaryCaseNumber, int IndicatorsCopied, bool LinkAdded);

/// <summary>
/// A visible <em>open</em> case whose entities already include one or more of the indicators being
/// entered on a new case — surfaced before filing so a campaign isn't fragmented across cases (E-23).
/// </summary>
public sealed record CaseIocMatch(Guid CaseId, string CaseNumber, string Title, Classification? Classification,
    CasePhase Phase, IReadOnlyList<string> Indicators);

/// <summary>
/// A visible <em>open</em> case that shares one or more indicators with the case in view and is <b>not yet
/// linked</b> to it — surfaced mid-investigation as a suggestion to relate the two (PROD-40). Purely a
/// suggestion: a human decides whether (and how) to link.
/// </summary>
public sealed record RelatedCaseSuggestion(Guid CaseId, string CaseNumber, string Title,
    Classification? Classification, CasePhase Phase, IReadOnlyList<string> SharedIndicators);

/// <summary>
/// Use cases for the case aggregate. Reads are access-scoped to the current user; writes go
/// through the domain model so classification/lifecycle history is always recorded, and are
/// captured by the audit-chain interceptor on save.
/// </summary>
public sealed class CaseService
{
    private readonly IOrganizationTimeZone? _zone;
    private readonly IExerciseEscalationPolicy? _exercise;   // BUG-100
    private readonly Notifications.IDeadlineReminderTracker? _deadlineReminders;   // BUG-156
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ICaseNumberGenerator _caseNumbers;
    private readonly IValidator<CreateCaseRequest> _createValidator;
    private readonly ICaseNotifications _notifications;
    private readonly IStageGateEvaluator _gates;
    private readonly Sla.ISlaTargetsProvider _sla;
    private readonly Security.ISecurityEventSink? _siem;
    private readonly Compliance.INotificationDeadlineSettingsProvider? _notifySettings;
    private readonly Admin.NotificationRuleService? _notifyRules;

    private readonly Microsoft.Extensions.Options.IOptionsMonitor<LegalHoldOptions>? _legalHold;
    private readonly IUserDirectory? _users;
    private readonly IRoleDirectory? _roles;

    /// <summary>F-12: whether releasing a legal hold needs a second approver (admin setting, off by default).</summary>
    public bool LegalHoldReleaseNeedsSecondApprover => _legalHold?.CurrentValue.RequireSecondApprover ?? false;

    public CaseService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        ICaseNumberGenerator caseNumbers, IValidator<CreateCaseRequest> createValidator,
        ICaseNotifications notifications, IStageGateEvaluator gates, Sla.ISlaTargetsProvider sla,
        Security.ISecurityEventSink? siem = null,
        Microsoft.Extensions.Options.IOptionsMonitor<LegalHoldOptions>? legalHold = null,
        Compliance.INotificationDeadlineSettingsProvider? notifySettings = null,
        Admin.NotificationRuleService? notifyRules = null,
        IOrganizationTimeZone? zone = null,
        IUserDirectory? users = null,
        IRoleDirectory? roles = null,
        IExerciseEscalationPolicy? exercise = null,
        Notifications.IDeadlineReminderTracker? deadlineReminders = null,
        IEvidenceStore? evidenceStore = null,
        Accounts.AccountDirectoryService? accounts = null,
        Notifications.ReminderAudience? audience = null,
        Microsoft.Extensions.Options.IOptionsMonitor<Evidence.EvidenceStorageOptions>? evidenceLimits = null,
        Evidence.EvidencePackageTickets? evidencePackages = null)
    {
        _evidencePackages = evidencePackages;
        _evidenceLimits = evidenceLimits;
        _audience = audience;
        _accounts = accounts;
        _evidenceStore = evidenceStore;
        _deadlineReminders = deadlineReminders;
        _exercise = exercise;
        _zone = zone;
        _users = users;
        _roles = roles;
        _legalHold = legalHold;
        _notifySettings = notifySettings;
        _notifyRules = notifyRules;
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

    private readonly IEvidenceStore? _evidenceStore;   // WF-31
    private readonly Microsoft.Extensions.Options.IOptionsMonitor<Evidence.EvidenceStorageOptions>? _evidenceLimits;   // PROD-55
    private readonly Evidence.EvidencePackageTickets? _evidencePackages;   // CAP-12
    private readonly Accounts.AccountDirectoryService? _accounts;   // BUG-416
    private readonly Notifications.ReminderAudience? _audience;   // BUG-596/597

    /// <summary>
    /// BUG-596/597: of <paramref name="userIds"/>, the people a notification about <paramref name="c"/> may go to: active
    /// and entitled now (the directory of record where it can say, else the mirror) and able to see a restricted case,
    /// as the reminder scans judge it (BUG-377). An assignment email went to a no-role user or a leaver, and a mention or
    /// handoff to someone the directory had disabled, because only the mirror's roles were checked, or nothing at all.
    /// </summary>
    private Task<List<string>> RecipientsAsync(Case c, IEnumerable<string> userIds, CancellationToken ct) =>
        (_audience ?? new Notifications.ReminderAudience(_users, _roles)).RecipientsAsync(userIds, c.IsRestricted,
            c.IncidentCommander, c.Assignments.Select(a => a.UserId).ToList(), ct);

    /// <summary>
    /// WF-31: a screenshot pasted into the composer, stored as evidence with the entry it illustrates. CAP-26: or any other
    /// file pasted or dropped there: one whose type isn't an image is stored the same way and cited by the entry
    /// (<see cref="IsCitedFile"/>) instead of shown as its screenshot.
    /// </summary>
    public sealed record Screenshot(string FileName, string ContentType, byte[] Bytes, string? Description = "Pasted into the timeline")
    {
        /// <summary>CAP-26: not an image by the type it came with, so it's cited rather than shown; an image keeps the
        /// screenshot path exactly as before.</summary>
        public bool IsCitedFile => !ContentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>CAP-26: what the composer says of a file it attaches that isn't an image.</summary>
    public const string AttachedFromTimeline = "Attached from the timeline";

    /// <summary>
    /// WF-31: stores <paramref name="shot"/> and records it as evidence on the case, linked to <paramref name="entry"/>, in
    /// the same save as the entry. Called once the entry has passed every check, so a refused entry leaves no evidence
    /// (which can't be removed once recorded). Returns the stored path, to discard if the save itself fails. CAP-26: a file
    /// that isn't an image is cited by the entry (as <see cref="CiteEvidenceAsync"/> records it), and is first held to what
    /// an Evidence tab upload is: the same file already on the case (not withdrawn) is refused before a byte is stored
    /// (PROD-59). It carries no collection details (CAP-08); they're recorded later from its evidence panel.
    /// </summary>
    private async Task<string?> AttachScreenshotAsync(IAppDbContext db, Guid caseId, TimelineEntry entry, Screenshot? shot,
        CancellationToken ct)
    {
        if (shot is null) return null;
        if (_evidenceStore is null) throw new InvalidOperationException("Screenshots can't be stored on this server.");
        if (shot.FileName.Length > Evidence.EvidenceService.MaxFileNameLength)
            throw new ArgumentException($"That file name is longer than {Evidence.EvidenceService.MaxFileNameLength} characters.");
        if (shot.IsCitedFile)
        {
            var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(shot.Bytes)).ToLowerInvariant();
            var already = await db.Evidence.AsNoTracking()   // stored as lowercase hex, as the store writes it
                .Where(e => e.CaseId == caseId && e.Sha256 == sha && e.WithdrawnAtUtc == null)
                .OrderBy(e => e.CreatedAtUtc).Select(e => new { e.OriginalFileName, e.CreatedAtUtc }).FirstOrDefaultAsync(ct);
            if (already is not null)
                throw new ArgumentException(Evidence.EvidenceService.AlreadyEvidence(already.OriginalFileName, already.CreatedAtUtc) +
                    " It wasn't stored again. Remove it here, save the entry, then cite that copy with Cite evidence.");
        }
        // PROD-55: a pasted screenshot is evidence, so it counts against the same limits as an upload.
        await Evidence.EvidenceRoom.CheckAsync(db, _evidenceStore, _evidenceLimits?.CurrentValue ?? new(), shot.Bytes.LongLength, ct: ct);
        await using var content = new MemoryStream(shot.Bytes, writable: false);
        var stored = await _evidenceStore.SaveAsync(caseId, content, ct);
        var now = _clock.UtcNow;
        var evidence = new Domain.Entities.Evidence
        {
            CaseId = caseId, OriginalFileName = shot.FileName,
            ContentType = string.IsNullOrWhiteSpace(shot.ContentType) ? "application/octet-stream" : shot.ContentType,
            SizeBytes = stored.SizeBytes, Sha256 = stored.Sha256, StoragePath = stored.StoragePath, Description = shot.Description,
            CreatedBy = _user.UserId, CreatedAtUtc = now
        };
        evidence.CustodyEvents.Add(new ChainOfCustodyEvent
        {
            EvidenceId = evidence.Id, AtUtc = now, Actor = _user.UserId,
            Action = "Uploaded", Details = $"{stored.SizeBytes} bytes; sha256={stored.Sha256}"
        });
        db.Evidence.Add(evidence);
        if (shot.IsCitedFile)   // CAP-26: "Evidence: file.csv" on the entry, as a citation made later reads
            db.EvidenceCitations.Add(new EvidenceCitation { CaseId = caseId, TimelineEntryId = entry.Id, EvidenceId = evidence.Id });
        else entry.EvidenceId = evidence.Id;
        return stored.StoragePath;
    }

    // WF-31: the save that records a screenshot with its entry; a failed save leaves no file without a record (BUG-206).
    private async Task SaveWithScreenshotAsync(IAppDbContext db, string? storedPath, CancellationToken ct)
    {
        try { await db.SaveChangesAsync(ct); }
        catch
        {
            if (storedPath is not null) await _evidenceStore!.DiscardUnrecordedAsync(storedPath);
            throw;
        }
    }

    /// <summary>Applies need-to-know scoping to a case query for the current user.</summary>
    private IQueryable<Case> Scoped(IQueryable<Case> query) => query.ForUser(_user);

    // BUG-46: a read keyed by a case id answers only for a case the caller can see (callers scope today; this holds
    // if one doesn't).
    private Task<bool> CanSeeAsync(IAppDbContext db, Guid caseId, CancellationToken ct) =>
        Scoped(db.Cases.AsNoTracking()).AnyAsync(c => c.Id == caseId, ct);

    /// <summary>
    /// F-21: the write-authorization backstop. Every mutating use case calls this on entry; the caller's
    /// method name (via <see cref="CallerMemberNameAttribute"/>) is looked up in the single reviewed
    /// <see cref="CaseActionPermissions.Required"/> table and the caller's held permissions are checked.
    /// Fails <b>closed</b>: a mutation with no table entry throws, so a newly added write can never ship
    /// unguarded. This runs behind the Blazor UI gates — defense-in-depth, and the guarantee any future
    /// non-UI caller inherits for free. Reads never call it (they carry no entry); their access is
    /// governed by need-to-know data scoping in the query layer instead.
    /// </summary>
    private void Require([CallerMemberName] string action = "")
    {
        if (!CaseActionPermissions.Required.TryGetValue(action, out var permission))
            throw new InvalidOperationException(
                $"No case-action permission is defined for '{action}'. Add it to {nameof(CaseActionPermissions)}.");
        if (!_user.Has(permission))
        {
            _siem?.Emit(Security.SecurityEvents.ActionRefused(_user.UserId, _user.UserPrincipalName, permission, $"CaseService.{action}"));
            throw new ForbiddenException(permission, action);
        }
    }

    /// <summary>
    /// Whether the current user may view the case with this number, honouring need-to-know scoping.
    /// Used by the scoped audit-export endpoint (E-24) before it releases a case's audit trail.
    /// </summary>
    public async Task<bool> CanViewAsync(string caseNumber, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await Scoped(db.Cases.AsNoTracking()).AnyAsync(c => c.CaseNumber == caseNumber, ct);
    }

    /// <summary>
    /// FR-22: whether a custom case number is free, so intake / renumber can flag a collision as the user
    /// types instead of only on submit. Uniqueness is global (unscoped) — a number must not collide even
    /// with a case the user can't see — matching the enforcement in CreateAsync / RenumberAsync. A blank
    /// number is "available" (it auto-generates); an over-long one is not. <paramref name="exceptCaseId"/>
    /// excludes the case being renumbered from the check.
    /// </summary>
    /// <summary>
    /// Resolves a case number from a readable link (/cases/2026-124_Insider_Data_Access) to the case id, need-to-know
    /// scoped. An exact match wins. Otherwise the year-sequence prefix alone ("2026-124") resolves when exactly one
    /// visible case carries it, since that's how people quote case numbers in chat and tickets.
    /// </summary>
    public async Task<Guid?> FindIdByNumberAsync(string? caseNumber, CancellationToken ct = default)
    {
        var n = caseNumber?.Trim();
        if (string.IsNullOrEmpty(n)) return null;
        using var db = _factory.CreateDbContext();
        var visible = Scoped(db.Cases.AsNoTracking());
        var exact = await visible.Where(c => c.CaseNumber == n).Select(c => (Guid?)c.Id).FirstOrDefaultAsync(ct);
        if (exact is not null) return exact;
        var prefixed = await visible.Where(c => c.CaseNumber.StartsWith(n + "_")).Select(c => c.Id).Take(2).ToListAsync(ct);
        return prefixed.Count == 1 ? prefixed[0] : null;
    }

    public async Task<bool> IsCaseNumberAvailableAsync(string? caseNumber, Guid? exceptCaseId = null, CancellationToken ct = default)
    {
        var n = caseNumber?.Trim();
        if (string.IsNullOrEmpty(n)) return true;
        if (n.Length > 200) return false;
        using var db = _factory.CreateDbContext();
        return !await NumberTakenAsync(db, n, exceptCaseId, ct);
    }

    /// <summary>
    /// Whether <paramref name="number"/> belongs to a case other than <paramref name="caseId"/>: another case has it, or
    /// the audit trail holds entries under it that aren't this case's. BUG-145: audit entries keep the number a case had
    /// when they were written, and the Audit tab, its export and the activity feed find them by number, so a number freed
    /// by a renumber can't be taken by another case (it would show the first case's history, restricted or not).
    /// </summary>
    private static async Task<bool> NumberTakenAsync(IAppDbContext db, string number, Guid? caseId, CancellationToken ct)
    {
        if (await db.Cases.AnyAsync(x => (caseId == null || x.Id != caseId) && x.CaseNumber == number, ct)) return true;
        var own = caseId?.ToString();
        if (own is not null && await db.AuditLog.AnyAsync(a => a.CaseNumber == number && a.EntityType == "Case" && a.EntityId == own, ct))
            return false;   // this case's own former number
        return await db.AuditLog.AnyAsync(a => a.CaseNumber == number, ct);
    }

    private static string NumberTakenMessage(string number) =>
        $"Case number '{number}' is already in use, or was used before by another case (its audit trail keeps it).";

    /// <summary>
    /// CAP-17 review: every case the list's filter matches, in the list's order, up to <paramref name="limit"/>, and whether
    /// more matched: the CSV export. The ids are read in one query, so a case that changes while the export reads can't move
    /// from a page not yet read to one already read and be missed; then the rows by id, <paramref name="chunk"/> at a time.
    /// The SLA order is ranked once, not once a page. A case the caller can no longer see by the time its rows are read is
    /// left out. <paramref name="afterChunk"/> runs after each chunk (tests: to change a case under the export).
    /// </summary>
    internal async Task<(IReadOnlyList<CaseListItem> Items, bool Truncated)> ListAllAsync(CaseFilter filter, int limit, int chunk,
        Func<int, Task>? afterChunk = null, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var q = await FilteredAsync(db, filter, ct);
        limit = Math.Max(0, limit);
        var ids = filter.Sort == CaseSort.Sla
            ? await SlaOrderedIdsAsync(q, filter.SortDescending, 0, limit + 1, ct)
            : await Ordered(db, q, filter.Sort, filter.SortDescending).Select(c => c.Id).Take(limit + 1).ToListAsync(ct);
        var truncated = ids.Count > limit;
        if (truncated) ids.RemoveRange(limit, ids.Count - limit);

        var items = new List<CaseListItem>(ids.Count);
        var size = Math.Max(1, chunk);
        for (var i = 0; i < ids.Count; i += size)
        {
            var part = ids.GetRange(i, Math.Min(size, ids.Count - i));
            var rows = (await Scoped(db.Cases.AsNoTracking()).Where(c => part.Contains(c.Id)).Select(ListItem).ToListAsync(ct))
                .ToDictionary(r => r.Id);
            items.AddRange(part.Where(rows.ContainsKey).Select(id => rows[id]));
            if (afterChunk is not null) await afterChunk(i / size + 1);
        }
        return (items, truncated);
    }

    // The cases the list's filter matches, need-to-know scoped (ForUser), unordered: the list and its export (CAP-17).
    private async Task<IQueryable<Case>> FilteredAsync(IAppDbContext db, CaseFilter filter, CancellationToken ct)
    {
        var q = Scoped(db.Cases.AsNoTracking());

        // BUG-57: the notification-deadline filter keeps closed cases (closing doesn't answer a regulator, INV-43), so
        // it lists what the dashboard counts; it leaves out archived ones itself.
        if (!filter.IncludeClosed && string.IsNullOrEmpty(filter.OutcomeKey) && !filter.NotifyDeadlineOnly)
            q = q.Where(c => c.Phase != CasePhase.Closed && !c.IsArchived);
        if (filter.OutcomeKey is { Length: > 0 } outcomeKey) q = q.Where(c => c.OutcomeKey == outcomeKey);   // HR-01
        // PROD-43: tabletop/exercise cases stay out of the working queue unless explicitly requested.
        if (!filter.IncludeExercises) q = q.ExcludingExercises();
        if (filter.Classification is { } cl) q = q.Where(c => c.Classification == cl);
        if (filter.Phase is { } ph) q = q.Where(c => c.Phase == ph);
        if (filter.MinSeverity is { } sev) q = q.Where(c => c.Severity >= sev);
        if (filter.Origin is { } origin) q = q.Where(c => c.Origin == origin);
        if (filter.Vendor?.Trim() is { Length: > 0 } vendor) q = VendorCases(q, vendor.ToLowerInvariant());   // CAP-24
        // CAP-36: a team narrows what need-to-know let through (q is already Scoped); it never widens it.
        if (!string.IsNullOrWhiteSpace(filter.TeamKey)) q = q.InTeam(await TeamScope.ResolveAsync(db, filter.TeamKey, ct));
        // UX-10: SOC/IC roll-up of Legal obligations across the queue (Legal doesn't use the app).
        if (filter.ReferredOnly) q = q.Where(c => c.LegalReferral.IsReferred);
        if (filter.OnHoldOnly) q = q.Where(c => c.LegalHold);

        // F-08: a date comparison against a value translates on both providers (SQLite stores ticks), so this runs
        // in the database.
        if (filter.OverdueOnly)
        {
            var now = _clock.UtcNow;
            q = q.Where(c => c.ActionItems.Any(a => a.DueAtUtc != null && a.DueAtUtc < now
                && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled));
        }

        // SLA at-risk/breached against the administered targets, as a database filter (F-08: SlaQueries restates
        // SlaPolicy.Evaluate, including Breach-specific targets, as on the list's SLA badge). A closed case's clocks
        // have stopped, so it never needs attention.
        if (filter.SlaAtRiskOnly)
        {
            var now = _clock.UtcNow;
            var targets = _sla.Current;
            q = q.Where(c => c.Phase != CasePhase.Closed)
                 .Where(Sla.SlaQueries.NeedsAttention(targets, now));
        }

        if (filter.NotifyDeadlineOnly)
        {
            // Same evaluation as the dashboard's notification figures, so a click-through lists exactly those cases
            // (closed ones included — INV-43).
            var ids = new List<Guid>();
            if (_notifySettings?.Current is { Enabled: true } nd && _notifyRules is not null)
            {
                var ruleSet = await _notifyRules.LoadRuleSetAsync(nd.DefaultWindowHours, ct);
                var heads = await Compliance.NotificationDeadlineService.OpenHeadlinesAsync(
                    db, q.Where(c => !c.IsArchived), nd, ruleSet, _clock.UtcNow, ct);
                ids = heads.Where(h => h.Value.State is Sla.SlaState.Breached or Sla.SlaState.AtRisk)
                    .Select(h => h.Key).ToList();
            }
            q = q.Where(c => ids.Contains(c.Id));
        }

        // The dashboard trend's month drill-in: the same calendar month, in the organization's reporting time zone.
        // BUG-475: a month outside years 2..9998 is ignored, as the page does. 9999-12 has no next month and year 1
        // starts before DateTime.MinValue in UTC east of Greenwich, so either would throw.
        if (filter is { OpenedYear: int oy and >= 2 and <= 9998, OpenedMonth: int om and >= 1 and <= 12 })
        {
            var zone = _zone?.Current ?? TimeZoneInfo.Utc;
            var start = ZonedMonths.StartUtc(oy, om, zone);
            var next = new DateTime(oy, om, 1).AddMonths(1);
            var end = ZonedMonths.StartUtc(next.Year, next.Month, zone);
            q = q.Where(c => c.CreatedAtUtc >= start && c.CreatedAtUtc < end);
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
            // by an indicator or a note as well as by number/title. HR-09: and across the record itself (timeline
            // entries and decisions, the brief, tasks and their results, the review, phase reasons), so an old case
            // can be found by what happened in it.
            q = q.Where(SearchMatch(db, s, unlinkedOnly: false));
            // BUG-273: as in Find (WF-84), a word that could be part of a link's hidden target (entity:, evidence:, a GUID's
            // hex) counts only where the reader sees it. Cases it matches in text without links stand; the rest (matched
            // only in text holding a link) are read back, at most HiddenText.MaxRecheck, and kept only when it shows.
            if (Search.HiddenText.CouldBeHidden(s))
            {
                var plain = q.Where(SearchMatch(db, s, unlinkedOnly: true)).Select(c => c.Id);
                var linkedOnly = await q.Where(c => !plain.Contains(c.Id)).OrderByDescending(c => c.CreatedAtUtc)
                    .Select(c => c.Id).Take(Search.HiddenText.MaxRecheck).ToListAsync(ct);
                if (linkedOnly.Count > 0)
                {
                    var shown = await CasesShowingAsync(db, linkedOnly, s, ct);
                    var hidden = linkedOnly.Where(id => !shown.Contains(id)).ToList();
                    q = q.Where(c => !hidden.Contains(c.Id));
                }
            }
#pragma warning restore CA1304, CA1311, CA1862
        }
        return q;
    }

    public async Task<CasePage> ListAsync(CaseFilter filter, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var q = await FilteredAsync(db, filter, ct);

        var total = await q.CountAsync(ct);
        var page = filter.Page < 1 ? 1 : filter.Page;
        var size = filter.PageSize < 1 ? 25 : filter.PageSize;
        // BUG-281: a page past the end is an empty page, never an overflowed (negative) offset, which SQL Server refuses.
        if ((long)(page - 1) * size > int.MaxValue) page = int.MaxValue / size;

        List<CaseListItem> items;
        if (filter.Sort == CaseSort.Sla)
        {
            // SLA position is a per-severity time calculation against the administered targets, so it's ranked in
            // memory (as the at-risk filter is) and only the page's rows are then loaded.
            var pageIds = await SlaOrderedIdsAsync(q, filter.SortDescending, (page - 1) * size, size, ct);
            var rows = await q.Where(c => pageIds.Contains(c.Id)).Select(ListItem).ToListAsync(ct);
            items = rows.OrderBy(r => pageIds.IndexOf(r.Id)).ToList();
        }
        else
        {
            items = await Ordered(db, q, filter.Sort, filter.SortDescending)
                .Skip((page - 1) * size)
                .Take(size)
                .Select(ListItem)
                .ToListAsync(ct);
        }

        var matches = string.IsNullOrWhiteSpace(filter.Search) || items.Count == 0 ? null
            : await SearchMatchesAsync(db, items, filter.Search.Trim(), ct);
        return new CasePage(items, total, page, size, matches);
    }

    /// <summary>
    /// HR-09: for each case on a search page, where the term matched when it isn't in the number, title or summary:
    /// the first of an entity, a note, a timeline entry or decision, the brief, a task, a task comment or result, a phase
    /// reason, or the review, with a snippet around the match.
    /// </summary>
    private async Task<Dictionary<Guid, string>> SearchMatchesAsync(IAppDbContext db, IReadOnlyList<CaseListItem> items,
        string term, CancellationToken ct)
    {
        var ids = items.Where(i => !i.CaseNumber.Contains(term, StringComparison.OrdinalIgnoreCase)
                                   && !i.Title.Contains(term, StringComparison.OrdinalIgnoreCase)).Select(i => i.Id).ToList();
        var result = new Dictionary<Guid, string>();
        if (ids.Count == 0) return result;
        var summaries = await db.Cases.AsNoTracking().Where(c => ids.Contains(c.Id)).Select(c => new { c.Id, c.Summary }).ToListAsync(ct);
        ids = ids.Where(id => summaries.FirstOrDefault(x => x.Id == id)?.Summary?.Contains(term, StringComparison.OrdinalIgnoreCase) != true).ToList();
        if (ids.Count == 0) return result;

        // Candidates in display priority; the first that contains the term wins. Loaded per page (at most a page of cases).
        var candidates = new List<(Guid CaseId, int Rank, string Where, DateTimeOffset? At, string Text, TimePrecision? Stated)>();
        foreach (var e in await db.CaseEntities.AsNoTracking().Where(e => ids.Contains(e.CaseId)).Select(e => new { e.CaseId, e.Value, e.Label }).ToListAsync(ct))
            candidates.Add((e.CaseId, 0, "entity", null, e.Label is null ? e.Value : $"{e.Label} ({e.Value})", null));
        foreach (var e in await db.TimelineEntries.AsNoTracking().Where(e => ids.Contains(e.CaseId) && e.IsCurrent)
                     .Select(e => new { e.CaseId, e.Type, e.OccurredAtUtc, e.OccurredPrecision, e.Description, e.Rationale }).ToListAsync(ct))
            candidates.Add((e.CaseId, 1, e.Type == TimelineEntryType.Decision ? "decision" : "timeline entry", e.OccurredAtUtc,
                Content.RichText.ToText(e.Description) + (e.Rationale is { } why ? " Why: " + why : ""), e.OccurredPrecision));
        foreach (var b in await db.CaseBriefs.AsNoTracking().Where(b => ids.Contains(b.CaseId) && b.IsCurrent)
                     .Select(b => new { b.CaseId, b.WorkingAssessment, b.Known, b.OpenQuestions }).ToListAsync(ct))
            candidates.Add((b.CaseId, 2, "brief", null, string.Join(" ", new[] { b.WorkingAssessment, b.Known, b.OpenQuestions }.Where(x => x is not null)), null));
        foreach (var n in await db.Notes.AsNoTracking().Where(n => ids.Contains(n.CaseId) && n.IsCurrent)
                     .Select(n => new { n.CaseId, n.CreatedAtUtc, n.Body }).ToListAsync(ct))
            candidates.Add((n.CaseId, 3, "note", n.CreatedAtUtc, Content.RichText.ToText(n.Body), null));
        foreach (var t in await db.ActionItems.AsNoTracking().Where(t => ids.Contains(t.CaseId)).Select(t => new { t.CaseId, t.Title }).ToListAsync(ct))
            candidates.Add((t.CaseId, 4, "task", null, t.Title, null));
        foreach (var x in await db.ActionItemComments.AsNoTracking().Where(x => ids.Contains(x.CaseId))
                     .Select(x => new { x.CaseId, x.CreatedAtUtc, x.Body }).ToListAsync(ct))
            candidates.Add((x.CaseId, 5, TaskResults.Parse(x.Body) is null ? "task comment" : "task result", x.CreatedAtUtc,
                TaskResults.Parse(x.Body) ?? x.Body, null));
        foreach (var x in await db.StatusChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId) && x.Reason != null)
                     .Select(x => new { x.CaseId, x.ChangedAtUtc, x.EffectiveAtUtc, x.Reason }).ToListAsync(ct))
            candidates.Add((x.CaseId, 6, "phase change", x.EffectiveAtUtc ?? x.ChangedAtUtc, x.Reason!, null));   // when it happened
        foreach (var r in await db.PostIncidentReviews.AsNoTracking().Where(r => ids.Contains(r.CaseId))
                     .Select(r => new { r.CaseId, r.WhatHappened, r.ContributingFactors, r.WhatWorkedWell, r.OpportunitiesToImprove }).ToListAsync(ct))
            candidates.Add((r.CaseId, 7, "post-incident review", null,
                string.Join(" ", new[] { r.WhatHappened, r.ContributingFactors, r.WhatWorkedWell, r.OpportunitiesToImprove }.Where(x => x is not null)), null));

        foreach (var g in candidates.Where(x => x.Text.Contains(term, StringComparison.OrdinalIgnoreCase)).GroupBy(x => x.CaseId))
        {
            var hit = g.OrderBy(x => x.Rank).ThenByDescending(x => x.At).First();
            result[g.Key] = $"{hit.Where}{SnippetDay(hit.At, hit.Stated)}: {Snippet(hit.Text, term)}";
        }
        return result;
    }

    // BUG-494: a match's day on the organisation's calendar (BUG-112/WF-15), not the UTC one. A step's stated date is a
    // calendar date (12:00 UTC) and prints as stored, as StepTime does; one whose time isn't stated has no day to give.
    private string SnippetDay(DateTimeOffset? at, TimePrecision? stated)
    {
        if (at is not { } t || stated == TimePrecision.NotStated) return "";
        var day = stated is TimePrecision.Day or TimePrecision.Window or TimePrecision.OnOrBefore ? t.UtcDateTime : OrgLocal(t).DateTime;
        return ", " + day.ToString("d MMM yyyy", System.Globalization.CultureInfo.InvariantCulture);
    }

    // A short window of text around the first occurrence of the term, on one line.
    private static string Snippet(string text, string term, int radius = 60)
    {
        var line = string.Join(' ', text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries));
        var i = line.IndexOf(term, StringComparison.OrdinalIgnoreCase);
        if (i < 0) return TaskResults.Excerpt(line, radius * 2);
        var start = Math.Max(0, i - radius);
        var end = Math.Min(line.Length, i + term.Length + radius);
        return (start > 0 ? "…" : "") + line[start..end].Trim() + (end < line.Length ? "…" : "");
    }

    // BUG-275: every order ends on the case id, so a page boundary between equal keys (two High cases in Triage) is the same
    // on every request: SQL Server's OFFSET over ties isn't deterministic, so rows repeated or went missing between pages.
    private static IQueryable<Case> Ordered(IAppDbContext db, IQueryable<Case> q, CaseSort sort, bool desc) =>
        OrderedBy(db, q, sort, desc).ThenBy(c => c.Id);

    private static IOrderedQueryable<Case> OrderedBy(IAppDbContext db, IQueryable<Case> q, CaseSort sort, bool desc) => sort switch
    {
        CaseSort.Severity => desc
            ? q.OrderByDescending(c => c.Severity).ThenByDescending(c => c.CreatedAtUtc)
            : q.OrderBy(c => c.Severity).ThenByDescending(c => c.CreatedAtUtc),
        CaseSort.Phase => desc
            ? q.OrderByDescending(c => c.Phase).ThenByDescending(c => c.Severity).ThenByDescending(c => c.CreatedAtUtc)
            : q.OrderBy(c => c.Phase).ThenByDescending(c => c.Severity).ThenByDescending(c => c.CreatedAtUtc),
        CaseSort.CaseNumber => desc ? q.OrderByDescending(c => c.CaseNumber) : q.OrderBy(c => c.CaseNumber),
        // REV-15: the latest work on the case, from its audit trail. The case row's own modified time doesn't move for a
        // note, a timeline entry, a task or a hand-off.
        // C18: CaseBook's upkeep isn't work on the case.
        CaseSort.Updated => desc
            ? q.OrderByDescending(c => db.AuditLog.Where(a => a.CaseNumber == c.CaseNumber && a.Reason != Integrity.IntegrityUpkeep.Reason)
                .Max(a => (DateTimeOffset?)a.AtUtc) ?? c.CreatedAtUtc)
            : q.OrderBy(c => db.AuditLog.Where(a => a.CaseNumber == c.CaseNumber && a.Reason != Integrity.IntegrityUpkeep.Reason)
                .Max(a => (DateTimeOffset?)a.AtUtc) ?? c.CreatedAtUtc),
        _ => desc ? q.OrderByDescending(c => c.CreatedAtUtc) : q.OrderBy(c => c.CreatedAtUtc),
    };

    // Running clocks first, by time left (most overdue first ascending); cases with no running clock follow,
    // newest first. Descending reverses the running clocks only.
    private async Task<List<Guid>> SlaOrderedIdsAsync(IQueryable<Case> q, bool desc, int skip, int take, CancellationToken ct)
    {
        var now = _clock.UtcNow;
        var targets = _sla.Current;
        var rows = await q
            .Select(c => new { c.Id, c.Severity, c.Phase, c.Classification, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc, c.CreatedAtUtc })
            .ToListAsync(ct);
        var ranked = rows.Select(r => new
        {
            r.Id,
            r.CreatedAtUtc,
            Status = Sla.SlaPolicy.Evaluate(r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc, targets, now, r.Classification)
        }).ToList();
        var running = ranked.Where(r => r.Status.IsActive && r.Status.Remaining is not null);
        // BUG-275: ties broken by the id, as the database orders are, so a page boundary doesn't move between requests.
        running = desc ? running.OrderByDescending(r => r.Status.Remaining).ThenBy(r => r.Id) : running.OrderBy(r => r.Status.Remaining).ThenBy(r => r.Id);
        var rest = ranked.Where(r => !(r.Status.IsActive && r.Status.Remaining is not null)).OrderByDescending(r => r.CreatedAtUtc).ThenBy(r => r.Id);
        return running.Concat(rest).Skip(skip).Take(take).Select(r => r.Id).ToList();
    }

    private static readonly System.Linq.Expressions.Expression<Func<Case, CaseListItem>> ListItem = c => new CaseListItem(
                c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, c.Severity, c.Origin,
                c.IsRestricted, c.LegalReferral.IsReferred, c.LegalHold, c.CreatedAtUtc, c.IncidentCommander,
                c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc, c.IsExercise,
                c.Assignments.Where(a => a.Role != CaseAssignmentRole.Observer)
                    .OrderBy(a => a.Role).ThenBy(a => a.AssignedAtUtc)
                    .Select(a => a.UserDisplayName).FirstOrDefault(),
                Math.Max(0, c.Assignments.Count(a => a.Role != CaseAssignmentRole.Observer) - 1),
                c.Assignments.Where(a => a.Role != CaseAssignmentRole.Observer)
                    .OrderBy(a => a.Role).ThenBy(a => a.AssignedAtUtc)
                    .Select(a => a.UserId).FirstOrDefault(),
                c.ContainmentNotNeededReason != null,
                c.ClosedAtUtc, c.ReportedAtUtc,   // CAP-17
                c.TeamId);   // CAP-36

    /// <summary>
    /// Design review P3: the case preview panel's summary, scoped like every read (null when the case doesn't exist
    /// or isn't visible). A handful of narrow queries instead of the workspace's full graph.
    /// </summary>
    public async Task<CasePreview?> GetPreviewAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var visible = Scoped(db.Cases.AsNoTracking());
        var head = await visible.Where(c => c.Id == id)
            .Select(c => new
            {
                c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, c.Severity, c.IsRestricted,
                Referred = c.LegalReferral.IsReferred, c.LegalHold, c.IsExercise, Materiality = c.Materiality.Status,
                c.CreatedAtUtc, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc, c.Summary,
                NotNeeded = c.ContainmentNotNeededReason != null
            })
            .FirstOrDefaultAsync(ct);
        if (head is null) return null;

        // Date ordering happens in memory (DateTimeOffset comparisons stay off SQLite, F-08).
        var open = await db.ActionItems.AsNoTracking()
            .Where(a => a.CaseId == id && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled)
            .Select(a => new CasePreviewTask(a.Title, a.Owner, a.DueAtUtc))
            .ToListAsync(ct);
        var next = open.OrderBy(a => a.DueAtUtc is null).ThenBy(a => a.DueAtUtc).FirstOrDefault();

        var entries = await db.TimelineEntries.AsNoTracking()
            .Where(e => e.CaseId == id && e.IsCurrent)
            .Select(e => new CasePreviewEntry(e.Description, e.OccurredAtUtc, e.Kind))
            .ToListAsync(ct);
        var latest = entries.MaxBy(e => e.OccurredAtUtc);

        var entities = await db.CaseEntities.AsNoTracking()
            .Where(e => e.CaseId == id)
            .Select(e => new { e.Id, e.Type, e.Value, e.Disposition })
            .ToListAsync(ct);
        var top = entities
            .OrderBy(e => e.Disposition switch
            {
                EntityDisposition.Malicious => 0, EntityDisposition.Compromised => 1, EntityDisposition.Suspicious => 2,
                EntityDisposition.Unknown => 3, _ => 4
            })
            .Take(5).ToList();
#pragma warning disable CA1304, CA1311, CA1862 // EF Core translates ToLower() to SQL LOWER(); culture overloads don't translate.
        var keys = top.Select(e => e.Value.ToLower()).Distinct().ToList();
        // BUG-505: only cases on the same side of the exercise line (WF-48): a live case counts no drill, and the reverse.
        var visibleIds = visible.Where(c => c.IsExercise == head.IsExercise).Select(c => c.Id);
        var shared = keys.Count == 0
            ? new Dictionary<string, int>()
            : (await db.CaseEntities.AsNoTracking()
                .Where(e => e.CaseId != id && visibleIds.Contains(e.CaseId) && keys.Contains(e.Value.ToLower()))
                .Select(e => new { Key = e.Value.ToLower(), e.CaseId })
                .ToListAsync(ct))
                .GroupBy(x => x.Key).ToDictionary(g => g.Key, g => g.Select(x => x.CaseId).Distinct().Count());
#pragma warning restore CA1304, CA1311, CA1862
        var indicators = top
            .Select(e => new CasePreviewIndicator(e.Id, e.Type, e.Value, e.Disposition,
                shared.GetValueOrDefault(e.Value.ToLowerInvariant())))
            .ToList();

        var team = await db.Assignments.AsNoTracking()
            .Where(a => a.CaseId == id && a.Role != CaseAssignmentRole.Observer)
            .OrderBy(a => a.Role).ThenBy(a => a.AssignedAtUtc)
            .Select(a => new CasePreviewPerson(a.UserDisplayName, a.Role))
            .ToListAsync(ct);

        return new CasePreview(head.Id, head.CaseNumber, head.Title, head.Classification, head.Phase, head.Severity,
            head.IsRestricted, head.Referred, head.LegalHold, head.IsExercise, head.Materiality,
            head.CreatedAtUtc, head.DetectedAtUtc, head.ContainedAtUtc, head.ResolvedAtUtc, head.Summary,
            open.Count, next, latest, indicators, entities.Count, team, head.NotNeeded);
    }

    /// <summary>
    /// HR-02: the latest recorded result of each task on a case (see <see cref="TaskResults"/>). Need-to-know scoped:
    /// a case the caller can't see has none.
    /// </summary>
    public async Task<IReadOnlyDictionary<Guid, TaskResult>> GetTaskResultsAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        if (!await Scoped(db.Cases.AsNoTracking()).AnyAsync(c => c.Id == caseId, ct))
            return new Dictionary<Guid, TaskResult>();
        var rows = await db.ActionItemComments.AsNoTracking()
            .Where(c => c.CaseId == caseId && c.Body.StartsWith(TaskResults.Prefix))
            .ToListAsync(ct);
        return TaskResults.Latest(rows);
    }

    /// <summary>Loads a case with all detail for the workspace, enforcing access scoping.</summary>
    public async Task<Case?> GetDetailAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        // S8733: eager-loading many independent collections in ONE query is a Cartesian explosion — the row
        // count is the product of every collection's size (e.g. notes × evidence × action items × entities …).
        // Split it into one correlated query per collection instead. This is a read-only AsNoTracking snapshot
        // for the workspace and the app is human-gated, so the minor cross-query consistency trade-off is moot.
        var c = await Scoped(db.Cases.AsNoTracking())
            .AsSplitQuery()
            .Include(x => x.ClassificationChanges)
            .Include(x => x.MaterialityChanges)
            .Include(x => x.StatusChanges)
            .Include(x => x.AssignmentChanges)   // INV-31
            .Include(x => x.VerdictChanges)      // HR-05
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
            .Include(x => x.GatePassages)   // INV-01: shown on the timeline as milestones
            .Include(x => x.TimeCorrections)  // INV-05b: the "time corrected" history on those milestones
            .Include(x => x.JurisdictionNotices)   // BUG-09: each regulator's notice, a milestone
            .Include(x => x.Parties)          // CAP-34: outside parties (Things › Connections)
            .Include(x => x.Briefs)           // INV-09: the case brief and its earlier versions
            .Include(x => x.Citations)        // INV-10: evidence cited by timeline entries
            .FirstOrDefaultAsync(x => x.Id == id, ct);
        return c;
    }

    /// <summary>
    /// RD-22: re-reads only the given parts of a workspace's case snapshot (from <see cref="GetDetailAsync"/>), in place,
    /// after a collaborator changed them. Returns false when the case is no longer visible to the caller (or
    /// <see cref="CaseRegions.Whole"/> was asked for): the caller re-reads the whole case instead.
    /// </summary>
    public async Task<bool> RefreshPartsAsync(Case snapshot, CaseRegions parts, CancellationToken ct = default)
    {
        if (parts.HasFlag(CaseRegions.Whole)) return false;
        using var db = _factory.CreateDbContext();
        var id = snapshot.Id;
        if (!await Scoped(db.Cases.AsNoTracking()).AnyAsync(c => c.Id == id, ct)) return false;

        if (parts.HasFlag(CaseRegions.Record))
            snapshot.TimelineEntries = await db.TimelineEntries.AsNoTracking().Include(t => t.Tactics).Where(t => t.CaseId == id).ToListAsync(ct);
        if (parts.HasFlag(CaseRegions.Record) || parts.HasFlag(CaseRegions.Evidence))
            snapshot.Citations = await db.Cases.AsNoTracking().Where(c => c.Id == id).SelectMany(c => c.Citations).ToListAsync(ct);
        if (parts.HasFlag(CaseRegions.Notes))
            snapshot.Notes = await db.Notes.AsNoTracking().Where(n => n.CaseId == id).ToListAsync(ct);
        if (parts.HasFlag(CaseRegions.Tasks))
            snapshot.ActionItems = await db.ActionItems.AsNoTracking().Where(t => t.CaseId == id).ToListAsync(ct);
        if (parts.HasFlag(CaseRegions.Things))
        {
            snapshot.Entities = await db.CaseEntities.AsNoTracking().Where(e => e.CaseId == id).ToListAsync(ct);
            snapshot.EntityRelationships = await db.EntityRelationships.AsNoTracking().Where(r => r.CaseId == id).ToListAsync(ct);
            snapshot.VerdictChanges = await db.EntityVerdictChanges.AsNoTracking().Where(v => v.CaseId == id).ToListAsync(ct);
            snapshot.Techniques = await db.CaseTechniques.AsNoTracking().Where(t => t.CaseId == id).ToListAsync(ct);
        }
        if (parts.HasFlag(CaseRegions.Evidence))
            snapshot.Evidence = await db.Evidence.AsNoTracking().Where(x => x.CaseId == id).ToListAsync(ct);
        if (parts.HasFlag(CaseRegions.Brief))
            snapshot.Briefs = await db.CaseBriefs.AsNoTracking().Where(b => b.CaseId == id).ToListAsync(ct);
        if (parts.HasFlag(CaseRegions.Paper))
            snapshot.Reports = await db.Reports.AsNoTracking().Where(r => r.CaseId == id).ToListAsync(ct);
        return true;
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
        Require();
        // REV-14: filing straight onto the ladder is a classification, as promoting a Complex Event is. Without it, a role
        // that can't escalate a case to Breach could file one as a Breach.
        if (request.Classification is not null && !_user.Has(Permission.ChangeClassification))
            throw new ForbiddenException(Permission.ChangeClassification, nameof(CreateAsync));
        await _createValidator.ValidateAndThrowAsync(request, ct);

        var now = _clock.UtcNow;
        // BUG-112: the number's year and a Complex Event's date are the organization's calendar, so a case opened at
        // 9 pm in New York on 31 December takes that year's number, not the next.
        var local = OrgLocal(now);
        var year = local.Year;
        var custom = NormalizeCaseNumber(request.CaseNumber);

        // FR-03: capture the detection time at intake (drives the SLA clock + dwell). Defaults to filing time
        // when omitted, and is validated exactly like the domain's UpdateDetails so a bad value is rejected
        // with the same friendly message rather than silently anchoring the SLA to the wrong instant.
        var detectedAtUtc = request.DetectedAtUtc ?? now;
        if (detectedAtUtc > now)
            throw new ArgumentException("The detected time can't be in the future.");
        if (request.OccurredAtUtc is { } occurred && occurred > detectedAtUtc)
            throw new ArgumentException("Activity can't begin after it was detected.");
        Case.EnsurePlausibleDwell(request.OccurredAtUtc, detectedAtUtc);
        if (request.TeamId is { } teamId)
        {
            using var check = _factory.CreateDbContext();
            await RequireActiveTeamAsync(check, teamId, ct);   // CAP-36
        }

        // Retry on the rare auto-sequence collision (the unique CaseNumber / per-scheme sequence indexes
        // are the guard). A fresh context per attempt so a failed save's audit entry never lingers into the
        // retry. A custom number is fixed, so it isn't retried — a duplicate surfaces as a friendly error.
        for (var attempt = 0; ; attempt++)
        {
            using var db = _factory.CreateDbContext();

            if (custom is not null && await NumberTakenAsync(db, custom, null, ct))
                throw new InvalidOperationException(NumberTakenMessage(custom));

            // IRP items draw a per-year sequence (advanced by the attempt offset so a retry moves past a
            // taken number); Complex Events are date-numbered (no sequence) and disambiguate with a "-N"
            // suffix on the rare same-day/same-descriptor clash; custom numbers are fixed.
            var isComplexEvent = request.Classification is null;
            var seq = (custom is null && !isComplexEvent)
                ? await _caseNumbers.NextSequenceAsync(year, ct) + attempt
                : 0;
            var c = Case.Open(year, seq, request.DescriptiveName, request.Title,
                request.Classification, request.Severity, request.Origin, _user.UserId, now,
                isExercise: request.IsExercise, numberDate: local);   // PROD-43: fixed at creation
            if (custom is not null) c.AssignCustomNumber(custom, _user.UserId, now);
            else if (isComplexEvent && attempt > 0) c.SetComplexEventNumber(local, attempt + 1);
            // BUG-307: nor a classified number the audit trail holds for another case (one a custom-numbered case had,
            // then gave up), as a promotion already checks (BUG-145): the trail is read by number, so the two would share it.
            else if (!isComplexEvent)
                while (await NumberTakenAsync(db, c.CaseNumber, c.Id, ct))
                    c.RenumberToIrp(c.Sequence + 1, _user.UserId, now);
            // BUG-53: a Complex Event's number is freed when it's promoted (renumbered), but its audit entries keep it,
            // and the activity feed, stale-case and closure checks read the audit trail by case number. A new Complex
            // Event never takes a number the trail already holds, so those entries can't attach to the wrong case.
            if (isComplexEvent && custom is null)
                for (var n = attempt + 2; await db.AuditLog.AnyAsync(a => a.CaseNumber == c.CaseNumber, ct); n++)
                    c.SetComplexEventNumber(local, n);

            c.SetInitialSummary(request.Summary, _user.UserId, now);   // INV-36: brief v1 holds it
            c.DetectionCaseId = request.DetectionCaseId?.Trim();   // CAP-14 review: trimmed, as the import matches it
            c.DataTypesInvolved = request.DataTypesInvolved;
            c.ImpactedAssets = request.ImpactedAssets;
            c.DetectedAtUtc = detectedAtUtc;          // FR-03: real detection time (Case.Open defaults it to now)
            c.OccurredAtUtc = request.OccurredAtUtc;
            if (request.TeamId is { } team) c.SetTeam(team, _user.UserId, now);   // CAP-36
            if (request.AssignToMe)
                c.Assign(_user.UserId, SelfDisplayName, CaseAssignmentRole.Analyst, _user.UserId, now);
            if (request.IsRestricted)
            {
                // S-08: keep the filer on a case they're restricting (they have no IC/assignment yet).
                if (!request.AssignToMe && !CaseRestrictionPolicy.KeepsAccess(_user, null, []))
                    c.Assign(_user.UserId, SelfDisplayName, CaseAssignmentRole.Analyst, _user.UserId, now);
                c.IsRestricted = true;
            }
            if (request.Origin == CaseOrigin.ThirdParty)
            {
                c.ThirdParty = new ThirdPartyDetails
                {
                    VendorName = request.VendorName ?? string.Empty,
                    VendorContact = request.VendorContact,
                    VendorReference = request.VendorReference
                };
            }

            // BUG-61: a case filed straight onto a rung passes the gates up to it, with the same ticks and override.
            if (request.Classification is { } cls)
                foreach (var trigger in StageGateTriggers.Climb(null, cls))
                    await ApplyGateAsync(db, c, trigger, request.AttestedRequirementIds, request.OverrideJustification,
                        // WF-98: the summary may be twice as long as a passage's commentary holds (8,000 vs 4,000).
                        request.OverrideJustification ?? (request.Summary is { } sum ? Clip(sum, 2000) : null), ct,
                        eval: await _gates.EvaluateNewAsync(db, c, trigger, request.PlannedEntityCount, request.PlannedDispositions, ct));

            db.Cases.Add(c);
            try
            {
                await db.SaveChangesAsync(ct);
                EmitLifecycle(c, (s, a, u) => Security.SecurityEvents.CaseCreated(s, c.Classification, c.Severity, a, u));   // CAP-06
                if (c.Classification == Classification.Breach)
                {
                    // Filed as a Breach: the same alerts as an escalation to one (Legal distribution, SIEM).
                    await _notifications.OnReclassifiedAsync(c, null, Classification.Breach, ct);
                    EmitBreachEscalated(c);
                }
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

    /// <summary>
    /// The case-list search: the case's own fields, its IOCs and notes, and the record itself (HR-09). With
    /// <paramref name="unlinkedOnly"/>, Markdown text counts only when it holds no link (BUG-273), so what it matches is
    /// certainly shown.
    /// </summary>
#pragma warning disable CA1304, CA1311, CA1862 // EF Core translates ToLower()/Contains() to SQL; culture overloads don't translate.
    private static System.Linq.Expressions.Expression<Func<Case, bool>> SearchMatch(IAppDbContext db, string s, bool unlinkedOnly)
    {
        const string link = Search.HiddenText.LinkMark;
        var comments = db.ActionItemComments;
        var reviews = db.PostIncidentReviews;
        return c =>
            c.CaseNumber.ToLower().Contains(s) ||
            c.Title.ToLower().Contains(s) ||
            (c.Summary != null && c.Summary.ToLower().Contains(s) && (!unlinkedOnly || !c.Summary.Contains(link))) ||
            c.Entities.Any(e => e.Value.ToLower().Contains(s) || (e.Label != null && e.Label.ToLower().Contains(s))) ||
            c.Notes.Any(n => n.IsCurrent && n.Body.ToLower().Contains(s) && (!unlinkedOnly || !n.Body.Contains(link))) ||
            c.TimelineEntries.Any(e => e.IsCurrent
                && ((e.Description.ToLower().Contains(s) && (!unlinkedOnly || !e.Description.Contains(link)))
                    || (e.Rationale != null && e.Rationale.ToLower().Contains(s) && (!unlinkedOnly || !e.Rationale.Contains(link))))) ||
            c.Briefs.Any(b => b.IsCurrent
                && ((b.WorkingAssessment != null && b.WorkingAssessment.ToLower().Contains(s) && (!unlinkedOnly || !b.WorkingAssessment.Contains(link)))
                    || (b.Known != null && b.Known.ToLower().Contains(s) && (!unlinkedOnly || !b.Known.Contains(link)))
                    || (b.OpenQuestions != null && b.OpenQuestions.ToLower().Contains(s) && (!unlinkedOnly || !b.OpenQuestions.Contains(link))))) ||
            c.ActionItems.Any(t => t.Title.ToLower().Contains(s)) ||
            comments.Any(x => x.CaseId == c.Id && x.Body.ToLower().Contains(s) && (!unlinkedOnly || !x.Body.Contains(link))) ||
            c.StatusChanges.Any(x => x.Reason != null && x.Reason.ToLower().Contains(s) && (!unlinkedOnly || !x.Reason.Contains(link))) ||
            reviews.Any(r => r.CaseId == c.Id && ((r.WhatHappened != null && r.WhatHappened.ToLower().Contains(s))
                                                  || (r.ContributingFactors != null && r.ContributingFactors.ToLower().Contains(s))
                                                  || (r.WhatWorkedWell != null && r.WhatWorkedWell.ToLower().Contains(s))
                                                  || (r.OpportunitiesToImprove != null && r.OpportunitiesToImprove.ToLower().Contains(s)))
                                             // Each field on its own: SQL Server cuts a concatenation of nvarchar(4000)s at 4,000.
                                             && (!unlinkedOnly || !((r.WhatHappened != null && r.WhatHappened.Contains(link))
                                                                    || (r.ContributingFactors != null && r.ContributingFactors.Contains(link))
                                                                    || (r.WhatWorkedWell != null && r.WhatWorkedWell.Contains(link))
                                                                    || (r.OpportunitiesToImprove != null && r.OpportunitiesToImprove.Contains(link)))));
    }

    // BUG-273: of these cases (each matched only in text holding a link), the ones where the word shows in that text.
    private static async Task<HashSet<Guid>> CasesShowingAsync(IAppDbContext db, List<Guid> ids, string s, CancellationToken ct)
    {
        const string link = Search.HiddenText.LinkMark;
        var texts = new List<(Guid CaseId, string? Text)>();
        texts.AddRange((await db.Cases.AsNoTracking().Where(c => ids.Contains(c.Id) && c.Summary != null && c.Summary.Contains(link))
            .Select(c => new { c.Id, c.Summary }).ToListAsync(ct)).Select(x => (x.Id, x.Summary)));
        texts.AddRange((await db.Notes.AsNoTracking().Where(n => n.IsCurrent && ids.Contains(n.CaseId) && n.Body.ToLower().Contains(s))
            .Select(n => new { n.CaseId, n.Body }).ToListAsync(ct)).Select(x => (x.CaseId, (string?)x.Body)));
        texts.AddRange((await db.TimelineEntries.AsNoTracking().Where(e => e.IsCurrent && ids.Contains(e.CaseId)
                && (e.Description.ToLower().Contains(s) || (e.Rationale != null && e.Rationale.ToLower().Contains(s))))
            .Select(e => new { e.CaseId, e.Description, e.Rationale }).ToListAsync(ct))
            .Select(x => (x.CaseId, Paragraphs(x.Description, x.Rationale))));
        texts.AddRange((await db.CaseBriefs.AsNoTracking().Where(b => b.IsCurrent && ids.Contains(b.CaseId))
            .Select(b => new { b.CaseId, b.WorkingAssessment, b.Known, b.OpenQuestions }).ToListAsync(ct))
            .Select(x => (x.CaseId, Paragraphs(x.WorkingAssessment, x.Known, x.OpenQuestions))));
        texts.AddRange((await db.ActionItemComments.AsNoTracking().Where(x => ids.Contains(x.CaseId) && x.Body.ToLower().Contains(s))
            .Select(x => new { x.CaseId, x.Body }).ToListAsync(ct)).Select(x => (x.CaseId, (string?)x.Body)));
        texts.AddRange((await db.StatusChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId) && x.Reason != null && x.Reason.ToLower().Contains(s))
            .Select(x => new { x.CaseId, x.Reason }).ToListAsync(ct)).Select(x => (x.CaseId, x.Reason)));
        texts.AddRange((await db.PostIncidentReviews.AsNoTracking().Where(r => ids.Contains(r.CaseId))
            .Select(r => new { r.CaseId, r.WhatHappened, r.ContributingFactors, r.WhatWorkedWell, r.OpportunitiesToImprove }).ToListAsync(ct))
            .Select(x => (x.CaseId, Paragraphs(x.WhatHappened, x.ContributingFactors, x.WhatWorkedWell, x.OpportunitiesToImprove))));
        string[] terms = [s];
        return texts.Where(t => Search.HiddenText.Shows(terms, null, t.Text)).Select(t => t.CaseId).ToHashSet();
    }

    // Separate Markdown parts as separate paragraphs, so one part's text doesn't run into the next's.
    private static string? Paragraphs(params string?[] parts) => string.Join("\n\n", parts.Where(p => p is not null));
#pragma warning restore CA1304, CA1311, CA1862

    /// <summary>BUG-112: <paramref name="utc"/> as the organization's wall clock (UTC when no zone is configured).</summary>
    private DateTimeOffset OrgLocal(DateTimeOffset utc) => _zone is null ? utc : TimeZoneInfo.ConvertTime(utc, _zone.Current);

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
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);

        var n = NormalizeCaseNumber(newNumber)
            ?? throw new InvalidOperationException("A case number is required.");
        if (n == c.CaseNumber) return;

        if (await NumberTakenAsync(db, n, id, ct))
            throw new InvalidOperationException(NumberTakenMessage(n));

        c.AssignCustomNumber(n, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    private async Task<Case> LoadTrackedAsync(IAppDbContext db, Guid id, CancellationToken ct)
    {
        // S-09: every write loads through need-to-know scoping, so a write can never reach a case the caller
        // can't see (e.g. someone removed from a restricted case while it's open, or a future non-UI caller).
        // Not-visible and not-found are the same answer, so the error leaks nothing.
        // S8733: same many-collection Cartesian explosion as GetDetailAsync. Split into one correlated query
        // per collection; EF stitches them onto the tracked root via the change tracker, and case work is
        // human-gated (one attributable act at a time) so the cross-query consistency trade-off is moot.
        var c = await Scoped(db.Cases)
            .AsSplitQuery()
            .Include(x => x.ClassificationChanges)
            .Include(x => x.MaterialityChanges)
            .Include(x => x.StatusChanges)
            .Include(x => x.AssignmentChanges)   // INV-31
            .Include(x => x.VerdictChanges)      // HR-05
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
            .Include(x => x.Citations)   // INV-10: moved with an edited entry; reconciled when citing
            .FirstOrDefaultAsync(x => x.Id == id, ct)
            ?? throw new InvalidOperationException("Case not found or not accessible.");
        return c;
    }

    /// <summary>INV-06: the details of a Decision entry — why, what else was considered, and who decided.</summary>
    public sealed record DecisionDetails(string Rationale, string? OptionsConsidered = null, string? DecidedBy = null);

    /// <summary>INV-05: a transition dated more than this far before it is recorded needs a reason, so the record
    /// says why it was entered late.</summary>
    public static readonly TimeSpan BackdateReasonThreshold = TimeSpan.FromHours(1);

    /// <summary>INV-05: true when <paramref name="effectiveAtUtc"/> is far enough in the past to need a reason.</summary>
    public static bool IsBackdated(DateTimeOffset? effectiveAtUtc, DateTimeOffset nowUtc) =>
        effectiveAtUtc is { } at && nowUtc - at > BackdateReasonThreshold;

    private void RequireReasonIfBackdated(DateTimeOffset? effectiveAtUtc, string? reason)
    {
        if (IsBackdated(effectiveAtUtc, _clock.UtcNow) && string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("Give a reason when recording a change more than an hour after it happened.");
    }

    public async Task ReclassifyAsync(Guid id, Classification to, string reason,
        IReadOnlySet<Guid>? attestedRequirementIds = null, string? overrideJustification = null,
        DateTimeOffset? effectiveAtUtc = null, CancellationToken ct = default)
    {
        // WF-53: two Complex Events promoted at once draw the same IRP sequence, and the second save hits the unique index.
        // As creation does, try again from a fresh read (the sequence moves on); a case someone else changed is refused
        // as a ConcurrentEditException, which this doesn't catch.
        Require();
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await ReclassifyOnceAsync(id, to, reason, attestedRequirementIds, overrideJustification, effectiveAtUtc, ct);
                return;
            }
            catch (DbUpdateException) when (attempt < 5) { }
        }
    }

    private async Task ReclassifyOnceAsync(Guid id, Classification to, string reason,
        IReadOnlySet<Guid>? attestedRequirementIds, string? overrideJustification,
        DateTimeOffset? effectiveAtUtc, CancellationToken ct)
    {
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var from = c.Classification;

        // Gate only promotions/escalations (up the ladder or off intake) — de-escalations aren't gated. BUG-60: every
        // rung climbed passes its own gate, so a jump to Breach passes the Incident gate too.
        if (from is null || to > from)
            foreach (var trigger in StageGateTriggers.Climb(from, to))
                await ApplyGateAsync(db, c, trigger, attestedRequirementIds, overrideJustification, reason, ct);

        var now = _clock.UtcNow;
        c.Reclassify(to, reason, _user.UserId, now, effectiveAtUtc);

        // Promotion off the Complex Event intake ladder → renumber into the IRP scheme (unless the analyst
        // pinned a custom number). Advance past any already-used number for the year (defensive against a
        // custom number matching the auto-format), then save once; a true concurrent collision is caught by
        // the per-scheme unique index (rare — the action can simply be retried).
        if (from is null && !c.HasCustomNumber)
        {
            var seq = await _caseNumbers.NextSequenceAsync(c.Year, ct);
            while (await NumberTakenAsync(db, Case.FormatCaseNumber(c.Year, seq, c.DescriptiveName), c.Id, ct))
                seq++;   // BUG-145: nor one the audit trail holds for another case
            c.RenumberToIrp(seq, _user.UserId, now);
        }

        await db.SaveChangesAsync(ct);
        await _notifications.OnReclassifiedAsync(c, from, to, ct);

        // F-18: a breach escalation is a notable governance signal for the SOC stream.
        if (to == Classification.Breach && from != Classification.Breach)
            EmitBreachEscalated(c);
        else if (to != from)   // CAP-06: every other reclassification
            EmitLifecycle(c, (s, a, u) => Security.SecurityEvents.CaseReclassified(s, from, to, a, u));
    }

    /// <summary>F-18's breach-escalation SIEM event. BUG-100: an exercise's is marked EXERCISE, or not sent when the
    /// organization keeps exercise escalations inside CaseBook.</summary>
    private void EmitBreachEscalated(Case c)
    {
        if (c.IsExercise && _exercise?.Mode == ExerciseEscalation.Skip) return;
        var e = Security.SecurityEvents.BreachEscalated(_user.UserId, _user.UserPrincipalName, c.CaseNumber);
        _siem?.Emit(c.IsExercise ? e with { Detail = ExerciseMarking.SiemDetail } : e);
    }

    /// <summary>CAP-06: a case-lifecycle SIEM event (5506-5513) for <paramref name="c"/> as saved, by the current user.
    /// Best effort: it never fails the action that was just saved.</summary>
    private void EmitLifecycle(Case c, Func<Security.CaseSubject, string, string?, Security.SecurityEvent> build) =>
        Security.SecurityEventEmit.EmitSafely(_siem, () => build(Security.CaseSubject.Of(c), _user.UserId, _user.UserPrincipalName));

    /// <summary>
    /// HR-01: what closing a case records: the outcome (a <c>CaseOutcome</c> key) and the closing brief: what happened
    /// (the summary) and what the team concluded (the working assessment's final version).
    /// </summary>
    public sealed record CaseClosing(string OutcomeKey, string Summary, string Conclusion);

    /// <param name="containment">BUG-165: when moving past Containment without it, when it was contained or why it
    /// wasn't needed.</param>
    /// <param name="resolvedAtUtc">BUG-208: when moving past Recovery without it, when it was resolved.</param>
    public async Task ChangePhaseAsync(Guid id, CasePhase to, string? reason,
        IReadOnlySet<Guid>? attestedRequirementIds = null, string? overrideJustification = null,
        DateTimeOffset? effectiveAtUtc = null, CaseClosing? closing = null, ContainmentDecision? containment = null,
        DateTimeOffset? resolvedAtUtc = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var now = _clock.UtcNow;
        var closingNow = to == CasePhase.Closed && c.Phase != CasePhase.Closed;
        // BUG-309: a close that someone else made first says so, rather than that an outcome needs a close.
        if (closing is not null && to == CasePhase.Closed && c.Phase == CasePhase.Closed)
            throw new InvalidOperationException("This case is already closed: someone closed it while you were writing. Reload to see how it was closed.");
        if (closing is not null && !closingNow)
            throw new ArgumentException("An outcome is recorded only when a case is closed.");

        string? outcomeKey = null;
        if (closingNow)
        {
            // HR-01: a case closes with a conclusion of record. The closing brief's conclusion stands in for the
            // transition reason when none is given separately.
            var (key, summary, conclusion) = await ValidateClosingAsync(db, closing, ct);
            outcomeKey = key;
            reason = string.IsNullOrWhiteSpace(reason) ? Clip(conclusion, 2000) : reason;
            RequireReasonIfBackdated(effectiveAtUtc, reason);
            await ApplyGateAsync(db, c, StageGateTrigger.CloseCase, attestedRequirementIds, overrideJustification, reason, ct,
                summaryProvided: true);   // the closing brief records the summary

            await db.CaseBriefs.Where(b => b.CaseId == id && b.IsCurrent).ToListAsync(ct);
            var current = c.Briefs.FirstOrDefault(b => b.IsCurrent);
            if (current is null || current.Summary != summary || current.WorkingAssessment != conclusion)
            {
                // Recorded at the same instant as the close, so the brief doesn't read as out of date because of it.
                var nextSteps = CaseNext.Snapshot(c, now, u => _users?.DisplayFor(u) ?? u);
                c.ReviseBrief(summary, conclusion, current?.Known, current?.OpenQuestions, nextSteps, _user.UserId, now);
            }
        }
        else RequireReasonIfBackdated(effectiveAtUtc, reason);

        var fromPhase = c.Phase;
        c.ChangePhase(to, reason, _user.UserId, now, effectiveAtUtc, outcomeKey,
            containment?.ContainedAtUtc, containment?.NotNeededReason, resolvedAtUtc);
        await db.SaveChangesAsync(ct);
        // CAP-06: a close says whether it went past unmet gate requirements (the passage just recorded; the case's earlier
        // passages aren't loaded).
        if (closingNow)
            EmitLifecycle(c, (s, a, u) => Security.SecurityEvents.CaseClosed(s, outcomeKey,
                c.GatePassages.Any(p => p.Trigger == StageGateTrigger.CloseCase && p.WasOverridden && p.PassedAtUtc >= now), a, u));
        else if (fromPhase == CasePhase.Closed && to != CasePhase.Closed)
            EmitLifecycle(c, Security.SecurityEvents.CaseReopened);   // BUG-62: leaving Closed is a reopen by another route
        else if (fromPhase != to)
            EmitLifecycle(c, (s, a, u) => Security.SecurityEvents.CasePhaseChanged(s, fromPhase, to, a, u));
    }

    /// <summary>BUG-165: for a case going past Containment without it: when it was contained, or why it wasn't needed.</summary>
    public sealed record ContainmentDecision(DateTimeOffset? ContainedAtUtc, string? NotNeededReason);

    private static async Task<(string Key, string Summary, string Conclusion)> ValidateClosingAsync(IAppDbContext db,
        CaseClosing? closing, CancellationToken ct)
    {
        if (closing is null)
            throw new ArgumentException("Record the outcome and what the team concluded to close the case.");
        var key = (closing.OutcomeKey ?? "").Trim();
        if (key.Length == 0) throw new ArgumentException("Choose an outcome to close the case.");
        if (!await db.CaseOutcomes.AsNoTracking().AnyAsync(o => o.Key == key && o.IsActive, ct))
            throw new ArgumentException("That outcome isn't available any more. Choose another.");
        var summary = (closing.Summary ?? "").Trim();
        var conclusion = (closing.Conclusion ?? "").Trim();
        if (summary.Length == 0) throw new ArgumentException("Say what happened to close the case.");
        if (conclusion.Length == 0) throw new ArgumentException("Say what the team concluded to close the case.");
        if (summary.Length > CaseBrief.MaxPartLength || conclusion.Length > CaseBrief.MaxPartLength)
            throw new ArgumentException($"Keep each part of the closing brief to {CaseBrief.MaxPartLength:N0} characters or fewer.");
        return (key, summary, conclusion);
    }

    private static string Clip(string text, int max) => text.Length <= max ? text : text[..(max - 1)] + "…";

    /// <summary>
    /// Reopens a closed case (E-27) with a required reason: returns it to its pre-closure phase and clears
    /// the closure timestamp so MTTR / dashboard math stays correct. Audited via the change interceptor.
    /// </summary>
    /// <param name="containment">WF-50: when the phase reopened to skips Containment, as for ChangePhaseAsync.</param>
    public async Task ReopenAsync(Guid id, string reason, ContainmentDecision? containment = null,
        DateTimeOffset? resolvedAtUtc = null, CancellationToken ct = default)
    {
        Require();
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("A reason is required to reopen a case.");

        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.Reopen(reason, _user.UserId, _clock.UtcNow, containment?.ContainedAtUtc, containment?.NotNeededReason, resolvedAtUtc);
        await db.SaveChangesAsync(ct);
        EmitLifecycle(c, Security.SecurityEvents.CaseReopened);   // CAP-06
    }

    /// <summary>Evaluates the active gate for a transition (read-only) — for the workspace readiness view.</summary>
    /// <param name="summaryProvided">HR-01: the transition records a summary itself (closing), which meets the summary check.</param>
    public async Task<GateEvaluation> EvaluateGateAsync(Guid id, StageGateTrigger trigger, bool summaryProvided = false,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        if (!await CanSeeAsync(db, id, ct)) return GateEvaluation.None(trigger);   // BUG-46
        return await _gates.EvaluateAsync(db, id, trigger, summaryProvided, ct);
    }

    /// <summary>BUG-60: the gates a reclassification to <paramref name="to"/> passes, as one checklist.</summary>
    public async Task<GateEvaluation> EvaluateClimbAsync(Guid id, Classification to, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var target = StageGateTriggers.ForClassification(to) ?? StageGateTrigger.PromoteToAdverseEvent;
        // REV-19: a case that's gone or not visible is no gate to pass, as EvaluateGateAsync answers (BUG-46), not a throw.
        var row = await db.Cases.AsNoTracking().ForUser(_user).Where(x => x.Id == id).Select(x => new { x.Classification }).FirstOrDefaultAsync(ct);
        if (row is null) return GateEvaluation.None(target);
        var from = row.Classification;
        if (from is not null && to <= from) return GateEvaluation.None(target);   // de-escalation isn't gated
        var gates = new List<GateEvaluation>();
        foreach (var t in StageGateTriggers.Climb(from, to)) gates.Add(await _gates.EvaluateAsync(db, id, t, false, ct));
        return GateEvaluation.Combine(gates, target);
    }

    /// <summary>
    /// BUG-61: the gates a case filed as <paramref name="request"/> would pass, judged from what the form holds (the
    /// summary, the indicators to be filed), as one checklist; null for a Complex Event, which no gate guards.
    /// </summary>
    public async Task<GateEvaluation?> EvaluateNewCaseGatesAsync(CreateCaseRequest request, CancellationToken ct = default)
    {
        if (request.Classification is not { } cls) return null;
        var now = _clock.UtcNow;
        var c = Case.Open(OrgLocal(now).Year, 0, string.IsNullOrWhiteSpace(request.DescriptiveName) ? "New case" : request.DescriptiveName,
            request.Title, cls, request.Severity, request.Origin, _user.UserId, now, request.IsExercise);
        c.SetInitialSummary(request.Summary, _user.UserId, now);
        c.DetectionCaseId = request.DetectionCaseId?.Trim();   // CAP-14 review: trimmed, as the import matches it
        using var db = _factory.CreateDbContext();
        var gates = new List<GateEvaluation>();
        foreach (var t in StageGateTriggers.Climb(null, cls))
            gates.Add(await _gates.EvaluateNewAsync(db, c, t, request.PlannedEntityCount, request.PlannedDispositions, ct));
        return GateEvaluation.Combine(gates, StageGateTriggers.ForClassification(cls)!.Value);
    }

    /// <summary>
    /// Enforces the stage gate for a transition: evaluates blocking requirements against the case plus the
    /// analyst's attestations, blocks (throws) when any are unmet and no override justification is given,
    /// and records a tamper-evident <c>GatePassage</c> capturing the outcome (including any override).
    /// </summary>
    private async Task ApplyGateAsync(IAppDbContext db, Case c, StageGateTrigger trigger,
        IReadOnlySet<Guid>? attestedIds, string? overrideJustification, string? reason, CancellationToken ct,
        bool summaryProvided = false, GateEvaluation? eval = null)
    {
        eval ??= await _gates.EvaluateAsync(db, c.Id, trigger, summaryProvided, ct);
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
            // overrideJustification is non-null here: line 497 already threw if the move was overridden
            // without one, so the earlier null-coalescing guard was unreachable (S2589).
            if (overridden && overrideJustification!.Trim().Length < min)
                throw new InvalidOperationException(
                    $"Gate '{eval.GateName}' requires an override justification of at least {min} characters.");
        }

        // WF-15: a date in "shown: …" is written as the checklist writes it (yyyy-MM-dd), on the organization's calendar,
        // not as a UTC "4 Oct 2026" the analyst never saw.
        var detail = GateDetail.Summarize(eval, attested,
            d => OrgLocal(d).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));
        if (trigger == StageGateTrigger.CloseCase && RecentDowngrade(c) is { } note) detail += note;
        // The reason is the analyst's rationale for the transition; keep it on the passage so the gate
        // record is self-contained for an examiner.
        c.RecordGatePassage(trigger, overridden, overrideJustification, reason, detail, _user.UserId, _clock.UtcNow);
    }

    /// <summary>WF-13: how long before closing a lowered classification is noted on the close gate's passage.</summary>
    public static readonly TimeSpan DowngradeNoteWindow = TimeSpan.FromDays(7);

    /// <summary>
    /// WF-13: the close gate judges the case as it stands, so a Breach lowered to Adverse Event just before closing skips
    /// the Incident- and Breach-only checks (lessons captured, notifications recorded). That stands (owner's decision:
    /// flag, don't block), but the passage says so, so an examiner reading "[MET]" sees the lowering beside it.
    /// </summary>
    private string? RecentDowngrade(Case c)
    {
        var now = _clock.UtcNow;
        // WF-69: judged by when the lowering was recorded (a backdated one still happened just now), and only while the
        // case stands below what it held in the window (lowered and raised back again, nothing was skipped).
        var recent = c.ClassificationChanges.Where(x => x.ChangedAtUtc >= now - DowngradeNoteWindow).ToList();
        var lowered = recent.Where(x => Rank(x.To) < Rank(x.From)).OrderByDescending(x => x.ChangedAtUtc).FirstOrDefault();
        if (lowered is null || Rank(c.Classification) >= recent.Max(x => Rank(x.From))) return null;
        var on = OrgLocal(lowered.ChangedAtUtc).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        return $" · Note: the classification was lowered from {Words(lowered.From)} to {Words(lowered.To)} on {on}, within " +
               $"{DowngradeNoteWindow.TotalDays:0} days of closing; the checks were judged on the current classification.";

        static int Rank(Classification? k) => k is null ? 0 : (int)k.Value + 1;
        static string Words(Classification? k) => k switch
        {
            null => "Complex Event", Classification.AdverseEvent => "Adverse Event", Classification v => v.ToString()
        };
    }

    /// <summary>Records (or edits) the Legal referral. BUG-519: with <paramref name="onlyIfNotReferred"/> (the bulk path), a
    /// case already referred keeps its referral and this returns false.</summary>
    public async Task<bool> ReferToLegalAsync(Guid id, string? contact, string? relevanceNote,
        string? expectedStamp = null, bool onlyIfNotReferred = false, CancellationToken ct = default)
    {
        Require();
        for (var attempt = 0; ; attempt++)
        {
            using var db = _factory.CreateDbContext();
            var c = await LoadTrackedAsync(db, id, ct);
            // BUG-519: judged on the case as it stands now, not the caller's list snapshot.
            if (onlyIfNotReferred && c.LegalReferral is { IsReferred: true }) return false;
            // REL-02: expected-value optimistic-concurrency (as on the details/impact editors). If the referral
            // fields changed since the modal was opened, refuse rather than silently clobbering the other author.
            if (expectedStamp is not null && c.LegalReferralConcurrencyStamp() != expectedStamp)
                throw new StaleEditException(c.LegalReferralConcurrencyStamp(),
                    "Someone else changed the Legal referral while you were editing. Reload and try again.");
            c.ReferToLegal(_user.UserId, contact, relevanceNote, _clock.UtcNow);
            try
            {
                await db.SaveChangesAsync(ct);
                return true;
            }
            // BUG-519: another save landed first (perhaps a referral); look again from a fresh read.
            catch (ConcurrentEditException) when (onlyIfNotReferred && attempt == 0) { }
        }
    }

    /// <summary>Records the regulatory-notification milestone (PROD-07): sets <c>ReportedAtUtc</c>, stopping the
    /// per-jurisdiction deadline countdown. Backdatable but not future / pre-detection (enforced in the domain).</summary>
    /// <summary>
    /// Records that regulators were notified. BUG-09: with jurisdictions in play, this records a notice for each one not
    /// yet notified (all at once); otherwise it sets the reported time directly, as before.
    /// </summary>
    /// <param name="expectedReportedAtUtc">BUG-594: the reported time the page showed (<c>Shown.Of(null)</c>: not reported).
    /// Given, the save is refused when it has changed since, so a stale page doesn't overwrite a colleague's time.</param>
    public async Task MarkReportedAsync(Guid id, DateTimeOffset reportedAtUtc, Shown<DateTimeOffset?>? expectedReportedAtUtc = null,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadWithNoticesAsync(db, id, ct);
        if (expectedReportedAtUtc is { } shown && shown.Value != c.ReportedAtUtc)
            throw new StaleEditException(Stamp(c.ReportedAtUtc),
                "Someone else recorded when regulators were notified while you were looking. Review it, then record yours again if it's still needed.");
        var now = _clock.UtcNow;
        var inPlay = await InPlayAsync(db, c, ct);
        if (inPlay.Count == 0) c.MarkReported(reportedAtUtc, _user.UserId, now, inPlay);
        else
        {
            // BUG-428: a legacy notice coded "NY;CA" already covers NY and CA, so neither gets a second notice.
            var noticed = Case.ByNoticeCode(c.JurisdictionNotices.Select(n => (n.Jurisdiction, n.NotifiedAtUtc)));
            foreach (var code in inPlay.Where(j => !noticed.ContainsKey(j)))
                c.RecordNotice(code, reportedAtUtc, _user.UserId, now);
            c.ReportedFromNotices(inPlay, _user.UserId, now);
        }
        await db.SaveChangesAsync(ct);
        EmitLifecycle(c, (s, a, u) => Security.SecurityEvents.CaseReported(s, null, a, u));   // CAP-06
        await FreezeNoticeDuesAsync(id, ct);   // WF-77
    }

    /// <summary>BUG-09: records (or corrects) when one regulator was notified; the case counts as reported once all in play are.</summary>
    /// <param name="expectedNotifiedAtUtc">BUG-594: when the page showed this regulator as notified (<c>Shown.Of(null)</c>:
    /// not yet). Given, the save is refused when that has changed since, so a stale page doesn't overwrite a colleague's
    /// notice (a notice coded "NY;CA" before v1.6.10 counts for NY and CA, as everywhere else, BUG-428).</param>
    /// <param name="details">CAP-07: how the regulator was notified (method, reference, who, the evidence file holding it),
    /// when known. Not given, a corrected notice keeps what it had.</param>
    public async Task RecordNoticeAsync(Guid id, string jurisdiction, DateTimeOffset notifiedAtUtc,
        Shown<DateTimeOffset?>? expectedNotifiedAtUtc = null, NoticeDetails? details = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadWithNoticesAsync(db, id, ct);
        await EnsureEvidenceOnCaseAsync(db, id, details?.EvidenceId, ct);   // CAP-07: a file on this (visible) case only
        if (expectedNotifiedAtUtc is { } shown)
        {
            var noticed = Case.ByNoticeCode(c.JurisdictionNotices.Select(n => (n.Jurisdiction, (DateTimeOffset?)n.NotifiedAtUtc)));
            var current = noticed.GetValueOrDefault(NoticeCode(jurisdiction));
            if (shown.Value != current)
                throw new StaleEditException(Stamp(current),
                    "Someone else recorded this regulator's notice while you were looking. Review it, then record yours again if it's still needed.");
        }
        var now = _clock.UtcNow;
        c.RecordNotice(jurisdiction, notifiedAtUtc, _user.UserId, now, details);
        c.ReportedFromNotices(await InPlayAsync(db, c, ct), _user.UserId, now);
        await db.SaveChangesAsync(ct);
        EmitLifecycle(c, (s, a, u) => Security.SecurityEvents.CaseReported(s, NoticeCode(jurisdiction), a, u));   // CAP-06
        await FreezeNoticeDuesAsync(id, ct);   // WF-77
    }

    /// <summary>
    /// CAP-07: records how one regulator was notified (method, reference, who gave it, the evidence file holding it) on its
    /// notice, without moving its time. Audited like the notice; the file must be on this case. No SIEM event: the notice
    /// itself sent one (5513), and these details change no clock.
    /// </summary>
    /// <param name="expectedStamp">FR-06 / REL-02: the details as the form showed them
    /// (<see cref="JurisdictionNotice.DetailsConcurrencyStamp"/>). Given, the save is refused when they changed since, or the
    /// notice was removed.</param>
    /// <returns>False when nothing changed, so nothing was saved.</returns>
    public async Task<bool> UpdateNoticeDetailsAsync(Guid id, string jurisdiction, NoticeDetails details, string? expectedStamp = null,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadWithNoticesAsync(db, id, ct);
        var code = NoticeCode(jurisdiction).ToUpperInvariant();
        var notice = c.JurisdictionNotices.FirstOrDefault(n => n.Jurisdiction == code);
        if (expectedStamp is not null && notice?.DetailsConcurrencyStamp() != expectedStamp)
            throw new StaleEditException(notice?.DetailsConcurrencyStamp() ?? "",
                notice is null
                    ? "Someone else removed this regulator's notice while you were editing it."
                    : "Someone else changed how this regulator was notified while you were editing. Review it, then save yours again if it's still needed.");
        await EnsureEvidenceOnCaseAsync(db, id, details.EvidenceId, ct);
        if (!c.SetNoticeDetails(code, details, _user.UserId, _clock.UtcNow)) return false;
        await db.SaveChangesAsync(ct);
        return true;
    }

    // BUG-594: a recorded time as a StaleEditException's stamp ("" for none).
    private static string Stamp(DateTimeOffset? at) => at?.ToString("o", System.Globalization.CultureInfo.InvariantCulture) ?? "";

    private static string NoticeCode(string? jurisdiction) => (jurisdiction ?? "").Trim();

    // WF-77: a new notice's deadline is kept as it stands when the notice is recorded, so its on-time outcome is fixed.
    private async Task FreezeNoticeDuesAsync(Guid id, CancellationToken ct)
    {
        if (_notifySettings is null || _notifyRules is null) return;
        // BUG-288: the notice is already saved; a failure here would report the save as failed. A due left unrecorded is
        // judged against the rules as they stand, and the start-up back-fill records it.
        try { await new Compliance.NotificationDeadlineService(_factory, _notifySettings, _notifyRules, _clock).FreezeNoticeDuesAsync(id, ct); }
        catch (Exception ex) when (ex is DbUpdateException or System.Data.Common.DbException or InvalidOperationException) { }
    }

    /// <summary>BUG-09: removes one regulator's notice (a mis-entry); its clock runs again.</summary>
    public async Task RemoveNoticeAsync(Guid id, string jurisdiction, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadWithNoticesAsync(db, id, ct);
        var now = _clock.UtcNow;
        var hadNotices = c.JurisdictionNotices.Count;
        c.RemoveNotice(jurisdiction, _user.UserId, now);
        var removed = c.JurisdictionNotices.Count < hadNotices;   // CAP-06 review: a stale page's second remove removes nothing
        var cleared = hadNotices > 0 && c.JurisdictionNotices.Count == 0;
        if (cleared) c.ClearReported(_user.UserId, now);
        else c.ReportedFromNotices(await InPlayAsync(db, c, ct), _user.UserId, now);
        await db.SaveChangesAsync(ct);
        if (removed) EmitLifecycle(c, (s, a, u) => Security.SecurityEvents.ReportedCleared(s, NoticeCode(jurisdiction), a, u));   // CAP-06
        // BUG-156: its clock runs again, so it's reminded again. BUG-619: only that regulator's, unless every notice went.
        if (cleared) _deadlineReminders?.ForgetCase(id);
        else
            foreach (var code in Compliance.NotificationDeadlineService.SplitCodes(jurisdiction))   // a legacy "NY;CA" notice
                _deadlineReminders?.ForgetJurisdiction(id, code);
    }

    // WF-11 / BUG-284: what's in play on a case: the jurisdictions kept since it was first reported when there are any,
    // else what its data elements bring in under today's settings.
    private static async Task<IReadOnlyList<string>> InPlayAsync(IAppDbContext db, Case c, CancellationToken ct) =>
        Case.KeptInPlay(c.ReportedJurisdictions, c.DataElements.Select(d => d.ElementKey).ToList(),
            Compliance.NotificationDeadlineService.Live(await Compliance.NotificationDeadlineService.ElementJurisdictionsAsync(db, ct)));

    private async Task<Case> LoadWithNoticesAsync(IAppDbContext db, Guid id, CancellationToken ct)
    {
        var c = await LoadTrackedAsync(db, id, ct);
        await db.JurisdictionNotices.Where(n => n.CaseId == id).ToListAsync(ct);   // tracked: fixes up c.JurisdictionNotices
        return c;
    }

    /// <summary>Clears the reported milestone (a mis-entry), reopening the notification countdown.</summary>
    public async Task ClearReportedAsync(Guid id, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadWithNoticesAsync(db, id, ct);
        var wasReported = c.ReportedAtUtc is not null || c.JurisdictionNotices.Count > 0;
        c.ClearReported(_user.UserId, _clock.UtcNow);   // BUG-09: and every jurisdiction's notice
        await db.SaveChangesAsync(ct);
        // CAP-06 review: only when something was taken back (a stale page's second clear changes nothing).
        if (wasReported) EmitLifecycle(c, (s, a, u) => Security.SecurityEvents.ReportedCleared(s, null, a, u));
        _deadlineReminders?.ForgetCase(id);   // BUG-156: its clock runs again, so it's reminded again
    }

    /// <summary>
    /// Records the materiality determination on a case (PROD-18). The decision may be the SOC's own or an
    /// external Legal/committee call, so <paramref name="decisionMaker"/> (the deciding authority) and
    /// <paramref name="decidedOnUtc"/> are captured distinctly from the recording user + timestamp. Allowed
    /// only on Incidents/Breaches; a final call requires decision-maker, date and rationale.
    /// </summary>
    public async Task RecordMaterialityAsync(Guid id, MaterialityStatus status, string? decisionMaker,
        DateTimeOffset? decidedOnUtc, string? rationale, string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        // REL-02: expected-value optimistic-concurrency (as on the details/impact editors). If the materiality
        // determination changed since the modal was opened, refuse rather than silently clobbering the rationale.
        if (expectedStamp is not null && c.MaterialityConcurrencyStamp() != expectedStamp)
            throw new StaleEditException(c.MaterialityConcurrencyStamp(),
                "Someone else changed the materiality determination while you were editing. Reload and try again.");
        c.RecordMateriality(status, decisionMaker, decidedOnUtc, rationale, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        EmitLifecycle(c, (s, a, u) => Security.SecurityEvents.MaterialityRecorded(s, status, a, u));   // CAP-06
    }

    /// <summary>
    /// INV-05b: corrects when an already-recorded classification, phase or severity change happened. Append-only:
    /// a hashed correction record keeps the old and new time and the reason, and the change's audited update
    /// carries the same reason. Re-dating a classification change needs the same permission as making one.
    /// </summary>
    public async Task CorrectTransitionTimeAsync(Guid id, TransitionKind kind, Guid changeId,
        DateTimeOffset happenedAtUtc, string reason, CancellationToken ct = default)
    {
        Require();
        if (kind == TransitionKind.Classification && !_user.Has(Permission.ChangeClassification))
            throw new ForbiddenException(Permission.ChangeClassification, nameof(CorrectTransitionTimeAsync));

        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.CorrectTransitionTime(kind, changeId, happenedAtUtc, reason, _user.UserId, _clock.UtcNow);
        db.PendingChangeReason = reason.Trim();   // the change row's audited update carries the reason too
        await db.SaveChangesAsync(ct);
    }

    public const string SeverityRaiseNeedsReason = "Say why the severity is going up; one line is enough.";

    public async Task ChangeSeverityAsync(Guid id, Domain.Enums.Severity severity, string? reason = null,
        DateTimeOffset? effectiveAtUtc = null, CancellationToken ct = default)
    {
        Require();
        RequireReasonIfBackdated(effectiveAtUtc, reason);
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        // HR-11: going up is a judgement a later reader will want explained (classification already asks for one).
        if (severity > c.Severity && string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException(SeverityRaiseNeedsReason);
        c.ChangeSeverity(severity, reason, _user.UserId, _clock.UtcNow, effectiveAtUtc);
        await db.SaveChangesAsync(ct);
    }

    public async Task UpdateDetailsAsync(Guid id, string title, string? summary, string? detectionCaseId,
        string? dataTypesInvolved, string? impactedAssets, DateTimeOffset detectedAtUtc, DateTimeOffset? occurredAtUtc,
        string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadWithNoticesAsync(db, id, ct);   // BUG-111: the detected time is checked against each notice
        // FR-06: expected-value optimistic-concurrency. If the details fields changed since the editor was
        // opened, refuse rather than silently clobbering the other author's edit (last-write-wins).
        if (expectedStamp is not null && c.DetailsConcurrencyStamp() != expectedStamp)
            throw new StaleEditException(c.DetailsConcurrencyStamp(),
                "Someone else changed these details while you were editing. Reload and try again.");
        // INV-36: a summary change is a new brief version, so the current one must be tracked here.
        await db.CaseBriefs.Where(b => b.CaseId == id && b.IsCurrent).ToListAsync(ct);
        c.UpdateDetails(title, summary, detectionCaseId, dataTypesInvolved, impactedAssets,
            detectedAtUtc, occurredAtUtc, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Records the structured impact assessment (affected count, data-element taxonomy, jurisdictions). E-12.
    /// Data elements are supplied as stable <c>DataElement.Key</c>s (X-03).</summary>
    public async Task UpdateImpactAssessmentAsync(Guid id, int? affectedIndividualsCount,
        IEnumerable<string> dataElementKeys, string? affectedStates, string? expectedStamp = null,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        // FR-06: expected-value optimistic-concurrency, as on the details editor.
        if (expectedStamp is not null && c.ImpactConcurrencyStamp() != expectedStamp)
            throw new StaleEditException(c.ImpactConcurrencyStamp(),
                "Someone else changed the impact assessment while you were editing. Reload and try again.");
        await db.JurisdictionNotices.Where(n => n.CaseId == id).ToListAsync(ct);
        var now = _clock.UtcNow;
        // WF-11: what a reported case covered is what was in play when it was reported, not today's admin settings (an
        // element given another jurisdiction since would otherwise become a notice, under this user's name, that never happened).
        var kept = c.ReportedJurisdictions;   // BUG-284: kept once reported, also while a later element is outstanding
        var keysBefore = c.DataElements.Select(d => d.ElementKey).ToList();
        var live = Compliance.NotificationDeadlineService.Live(await Compliance.NotificationDeadlineService.ElementJurisdictionsAsync(db, ct));
        var before = Case.KeptInPlay(kept, keysBefore, live, elementsIfUnknown: keysBefore);
        c.SetImpactAssessment(affectedIndividualsCount, dataElementKeys, affectedStates, _user.UserId, now);
        // WF-65: and for a reported case only an element added since it was reported brings in a jurisdiction; the elements
        // it had keep the ones kept at notice time (editing the count must not reopen it after an admin change), and
        // removing one added since takes its jurisdictions out again (BUG-284).
        var after = Case.KeptInPlay(kept, c.DataElements.Select(d => d.ElementKey).ToList(), live, elementsIfUnknown: keysBefore);
        var wasReported = c.ReportedAtUtc is not null;   // BUG-570: before the BUG-555 branch can unreport it
        // BUG-104: a case reported as a whole (no notice per jurisdiction: reported before notices were per jurisdiction,
        // or when none was in play) covered the jurisdictions in play then, and no others. Those become notices at that
        // time, so one that comes into play now is outstanding until its regulator is notified.
        if (c.JurisdictionNotices.Count == 0 && c.ReportedAtUtc is { } reported && after.Except(before, StringComparer.OrdinalIgnoreCase).Any())
        {
            // BUG-406: credited to whoever recorded the report, and dated when they did (the report's audit entry; the
            // reported time when there's none), not to this edit: it isn't new work in the handoff, brief or "since" views.
            var key = id.ToString();
            var field = "\"" + nameof(Case.ReportedAtUtc) + "\"";
            var recorded = await db.AuditLog.AsNoTracking()
                .Where(a => a.EntityType == nameof(Case) && a.EntityId == key && a.AfterJson != null && a.AfterJson.Contains(field))
                .OrderByDescending(a => a.Sequence).Select(a => new { a.Actor, a.AtUtc }).FirstOrDefaultAsync(ct);
            c.NoticesFromWholeReport(before, recorded?.Actor ?? "system", recorded?.AtUtc ?? reported, _user.UserId, now);
            // BUG-555: nothing was in play when it was reported; it's outstanding now, but keeps what was kept.
            if (c.JurisdictionNotices.Count == 0) c.Unreport(keysBefore, _user.UserId, now);
        }
        // BUG-09: a data element that brings a new jurisdiction into play reopens the report until that regulator is notified.
        c.ReportedFromNotices(after, _user.UserId, now);
        // BUG-618: still reported (with notices or as a whole), so an element added counts as had.
        c.KeepElementsWhileReported();
        await db.SaveChangesAsync(ct);
        await FreezeNoticeDuesAsync(id, ct);   // WF-77: notices a BUG-104 conversion recorded
        if (wasReported && c.ReportedAtUtc is null) _deadlineReminders?.ForgetCase(id);   // BUG-156: reminded again
    }

    public async Task AssignAsync(Guid id, string userId, string displayName, CaseAssignmentRole role,
        CancellationToken ct = default) => await AssignCoreAsync(id, userId, displayName, role, onlyIfAbsent: false, nameof(AssignAsync), notify: true, ct);

    /// <summary>
    /// REV-26: the Cases list's bulk assign. It adds the person where they aren't on the case yet, and leaves a case they
    /// are already on as it is: changing their role there could demote an incident commander, or (assigning them as an
    /// analyst where they're the IC) leave the case with none. False when they were already on it.
    /// </summary>
    public Task<bool> AddAssigneeAsync(Guid id, string userId, string displayName, CaseAssignmentRole role,
        CancellationToken ct = default) => AssignCoreAsync(id, userId, displayName, role, onlyIfAbsent: true, nameof(AddAssigneeAsync), notify: true, ct);

    /// <summary>
    /// CAP-35 review: an imported history's team, through the same guarded, audited assignment as
    /// <see cref="AssignAsync"/> (and its permission), told of it only when <paramref name="notify"/>: a closed historical
    /// case's team isn't emailed "you've been assigned" (CaseImportService decides).
    /// </summary>
    internal Task AssignImportedAsync(Guid id, string userId, string displayName, CaseAssignmentRole role, bool notify,
        CancellationToken ct = default) => AssignCoreAsync(id, userId, displayName, role, onlyIfAbsent: false, nameof(AssignAsync), notify, ct);

    private async Task<bool> AssignCoreAsync(Guid id, string userId, string displayName, CaseAssignmentRole role,
        bool onlyIfAbsent, string action, bool notify, CancellationToken ct)
    {
        Require(action);
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        if (onlyIfAbsent && c.Assignments.Any(a => a.UserId == userId)) return false;
        // BUG-128: on a restricted case the incident commander can lift the restriction, so naming one is held to those
        // who could lift it already: the current incident commander or someone cleared for restricted cases.
        if (c.IsRestricted && role == CaseAssignmentRole.IncidentCommander
            && !string.Equals(c.IncidentCommander, userId, StringComparison.Ordinal)
            && !CaseRestrictionPolicy.CanLift(_user, c.IncidentCommander))
            throw new InvalidOperationException(
                "On a restricted case, only the incident commander or someone cleared for restricted cases can name a new incident commander.");
        c.Assign(userId, displayName, role, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);

        // E-03b: tell the assignee (out of band; never fails the assignment). Not on a self-assignment (as before), and
        // only when they're entitled to the case (BUG-596).
        if (notify && !string.Equals(userId, _user.UserId, StringComparison.OrdinalIgnoreCase)
            && (await RecipientsAsync(c, [userId], ct)).Count > 0)
            await _notifications.OnAssignedAsync(c, userId, displayName, role, _user.UserId, ct);
        return true;
    }

    /// <summary>
    /// BUG-306: Team workload's rebalancing, in one save: <paramref name="toUserId"/> joins the case (someone already on
    /// it keeps their role, so an incident commander isn't demoted) and <paramref name="fromUserId"/> leaves it. When the
    /// one leaving was the incident commander, the one joining takes that seat, so the case isn't left without one. An
    /// observer joining in a working seat takes it (BUG-405). False when nothing changed.
    /// </summary>
    public async Task<bool> ReassignAsync(Guid id, string? fromUserId, string toUserId, string toDisplayName,
        CaseAssignmentRole role, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var now = _clock.UtcNow;
        var leaving = fromUserId is null ? null : c.Assignments.FirstOrDefault(a => a.UserId == fromUserId);
        var seat = leaving?.Role == CaseAssignmentRole.IncidentCommander ? CaseAssignmentRole.IncidentCommander : role;
        var namesCommander = seat == CaseAssignmentRole.IncidentCommander && c.IncidentCommander != toUserId;
        // BUG-128, as for any assignment: naming an IC on a restricted case is held to those who could lift it.
        if (c.IsRestricted && namesCommander && !CaseRestrictionPolicy.CanLift(_user, c.IncidentCommander))
            throw new InvalidOperationException(
                "On a restricted case, only the incident commander or someone cleared for restricted cases can name a new incident commander.");
        var joined = c.Assignments.All(a => a.UserId != toUserId);
        // BUG-405: an observer doesn't work the case, so one taking over joins the working seat (and is told), or the
        // case is left with nobody on it once the other leaves.
        var promoted = !joined && seat != CaseAssignmentRole.Observer
                       && c.Assignments.First(a => a.UserId == toUserId).Role == CaseAssignmentRole.Observer;
        if (joined || namesCommander || promoted)   // someone already working it changes role only to take the seat being left
            c.Assign(toUserId, toDisplayName, seat, _user.UserId, now);
        if (leaving is not null && fromUserId != toUserId) c.Unassign(leaving.UserId, _user.UserId, now);
        if (!joined && !namesCommander && !promoted && leaving is null) return false;   // nothing changed
        await db.SaveChangesAsync(ct);
        if ((joined || promoted) && !string.Equals(toUserId, _user.UserId, StringComparison.OrdinalIgnoreCase)
            && (await RecipientsAsync(c, [toUserId], ct)).Count > 0)   // BUG-596
            await _notifications.OnAssignedAsync(c, toUserId, toDisplayName, seat, _user.UserId, ct);
        return true;
    }

    public async Task UnassignAsync(Guid id, string userId, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.Unassign(userId, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    // BUG-05: an entry's attached file must be this case's evidence (a screenshot staged on another case mustn't link).
    // CAP-21: and one that stands: a withdrawn file isn't attached to an entry or named as a notice's file (CAP-07).
    private static async Task EnsureEvidenceOnCaseAsync(IAppDbContext db, Guid caseId, Guid? evidenceId, CancellationToken ct)
    {
        if (evidenceId is not { } eid) return;
        var withdrawn = await db.Evidence.Where(e => e.Id == eid && e.CaseId == caseId)
            .Select(e => (bool?)(e.WithdrawnAtUtc != null)).FirstOrDefaultAsync(ct)
            ?? throw new InvalidOperationException("Only evidence on this case can be attached to its record.");
        if (withdrawn) throw new InvalidOperationException("That file has been withdrawn from the case, so it can't be attached to its record.");
    }

    public async Task<Guid> AddTimelineEntryAsync(Guid id, TimelineKind kind, TimelineEntryType type,
        DateTimeOffset occurredAtUtc, string description, string? source, Guid? evidenceId = null,
        DecisionDetails? decision = null, bool imported = false, EntryFollowUps? followUps = null, StepTiming? timing = null,
        Screenshot? screenshot = null, CancellationToken ct = default)
    {
        Require();
        // BUG-119: the same rules as the composer: something to say, and an event step is one line.
        if (string.IsNullOrWhiteSpace(description)) throw new ArgumentException("Say what happened.");
        if (kind == TimelineKind.Event) description = Content.MarkdownService.OneLine(description);
        TimelineEntry.EnsureDecisionHasRationale(type, decision?.Rationale);
        followUps?.Validate();
        foreach (var t in followUps?.Tasks ?? []) CheckDue(t.DueAtUtc, t.Title.Trim());   // BUG-577
        using var linkGate = await LinkGateAsync(followUps?.LinkCaseId is not null, ct);   // BUG-525
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        await EnsureEvidenceOnCaseAsync(db, id, evidenceId, ct);
        var isDecision = type == TimelineEntryType.Decision;
        var entry = new TimelineEntry
        {
            CaseId = c.Id, Kind = kind, Type = type, OccurredAtUtc = occurredAtUtc, Description = description,
            Source = source, EvidenceId = evidenceId, CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow,
            Rationale = isDecision ? decision?.Rationale.Trim() : null,
            OptionsConsidered = isDecision && !string.IsNullOrWhiteSpace(decision?.OptionsConsidered) ? decision.OptionsConsidered.Trim() : null,
            DecidedBy = isDecision && !string.IsNullOrWhiteSpace(decision?.DecidedBy) ? decision.DecidedBy.Trim() : null,
            PromotedFrom = imported ? TimelineEntry.Imported : null   // INV-23
        };
        // ST-03: an event step takes its time as stated and its place in order, as in the composer.
        if (kind == TimelineKind.Event) c.PlaceNewEventStep(entry, occurredAtUtc, timing);
        c.TimelineEntries.Add(entry);
        if (followUps is not null) await ApplyFollowUpsAsync(db, c, entry, followUps, ct);
        var shot = await AttachScreenshotAsync(db, c.Id, entry, screenshot, ct);   // WF-31: only once the entry has passed
        await SaveWithScreenshotAsync(db, shot, ct);
        return entry.Id;
    }

    /// <summary>An imported timeline entry for <see cref="AddImportedTimelineEntriesAsync"/>. <paramref name="FollowsPrevious"/>:
    /// an event step whose time wasn't stated, placed after the step before it in the list (ST-03).</summary>
    public sealed record TimelineToAdd(TimelineKind Kind, TimelineEntryType Type, DateTimeOffset OccurredAtUtc,
        string Description, string? Source, DecisionDetails? Decision = null, StepTiming? Timing = null, bool FollowsPrevious = false);

    /// <summary>
    /// BUG-255: adds imported timeline entries in batches of <see cref="EntitiesPerSave"/> (one case load and one audited
    /// save each), not a whole-case reload, save and live publish per entry. Each is checked and placed exactly as
    /// <see cref="AddTimelineEntryAsync"/> places one; <paramref name="afterStepId"/> is the step the first not-stated one
    /// follows (null: first). <paramref name="saved"/> gets each batch's ids once it's saved, so a retry resumes.
    /// </summary>
    public async Task AddImportedTimelineEntriesAsync(Guid id, IReadOnlyList<TimelineToAdd> items, Guid? afterStepId,
        Action<IReadOnlyList<Guid>> saved, CancellationToken ct = default)
    {
        Require();
        var prev = afterStepId;
        foreach (var batch in items.Chunk(EntitiesPerSave))
        {
            using var db = _factory.CreateDbContext();
            var c = await LoadTrackedAsync(db, id, ct);
            var ids = new List<Guid>(batch.Length);
            // Steps at one time with no order of their own sort by when recorded; saved one at a time, that was document
            // order. In one save it's whatever order the rows go in, so each is recorded a tick after the one before.
            var recorded = _clock.UtcNow;
            foreach (var i in batch)
            {
                recorded = recorded.AddTicks(1);
                if (string.IsNullOrWhiteSpace(i.Description)) throw new ArgumentException("Say what happened.");
                var description = i.Kind == TimelineKind.Event ? Content.MarkdownService.OneLine(i.Description) : i.Description;
                TimelineEntry.EnsureDecisionHasRationale(i.Type, i.Decision?.Rationale);
                var isDecision = i.Type == TimelineEntryType.Decision;
                var entry = new TimelineEntry
                {
                    CaseId = c.Id, Kind = i.Kind, Type = i.Type, OccurredAtUtc = i.OccurredAtUtc, Description = description,
                    Source = i.Source, CreatedBy = _user.UserId, CreatedAtUtc = recorded,
                    Rationale = isDecision ? i.Decision?.Rationale.Trim() : null,
                    OptionsConsidered = isDecision && !string.IsNullOrWhiteSpace(i.Decision?.OptionsConsidered) ? i.Decision.OptionsConsidered.Trim() : null,
                    DecidedBy = isDecision && !string.IsNullOrWhiteSpace(i.Decision?.DecidedBy) ? i.Decision.DecidedBy.Trim() : null,
                    PromotedFrom = TimelineEntry.Imported   // INV-23
                };
                if (i.Kind == TimelineKind.Event)
                {
                    var timing = i.FollowsPrevious
                        ? prev is { } p ? new StepTiming(TimePrecision.NotStated, AfterStepId: p) : new StepTiming(TimePrecision.NotStated, First: true)
                        : i.Timing;
                    c.PlaceNewEventStep(entry, i.OccurredAtUtc, timing);
                    prev = entry.Id;
                }
                c.TimelineEntries.Add(entry);
                ids.Add(entry.Id);
            }
            await db.SaveChangesAsync(ct);
            saved(ids);
        }
    }

    /// <summary>
    /// RD-09: what the composer saves with an entry, in the same save: tasks about the entry (a decision's tasks read
    /// "carries out a decision"), a question for the brief (optionally followed up as a task), a line for the brief's
    /// Known, and a link to another case. The brief changes make one new brief version. CAP-23: and the open question a
    /// finding answers (<see cref="AnswerQuestionAsync"/>).
    /// </summary>
    private async Task ApplyFollowUpsAsync(IAppDbContext db, Case c, TimelineEntry entry, EntryFollowUps f, CancellationToken ct)
    {
        // CAP-23: first, so a brief version this save also makes snapshots the answered task as done.
        if (f.Answers is { } answers) await AnswerQuestionAsync(db, c, entry, answers, ct);

        foreach (var t in f.Tasks ?? [])
            c.ActionItems.Add(new ActionItem
            {
                CaseId = c.Id, Title = t.Title.Trim(), Owner = string.IsNullOrWhiteSpace(t.Owner) ? null : t.Owner.Trim(),
                Kind = t.Kind, DueAtUtc = t.DueAtUtc, AboutRef = $"{ActionItem.AboutEntry}:{entry.Id}",
                CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
            });

        var question = EntryFollowUps.Clean(f.Question);
        var known = EntryFollowUps.Clean(f.KnownLine);
        if (question is not null || known is not null)
        {
            await db.CaseBriefs.Where(b => b.CaseId == c.Id && b.IsCurrent).ToListAsync(ct);
            var cur = c.Briefs.FirstOrDefault(b => b.IsCurrent);
            if (question is not null && CaseNext.Questions(cur?.OpenQuestions)?.Any(x => string.Equals(x, question, StringComparison.OrdinalIgnoreCase)) == true)
                throw new InvalidOperationException("That question is already open in the brief.");
            string? Append(string? part, string? line) => line is null ? part
                : string.IsNullOrWhiteSpace(part) ? $"- {line}" : $"{part.TrimEnd()}\n- {line}";
            var nextSteps = CaseNext.Snapshot(c, _clock.UtcNow, u => _users?.DisplayFor(u) ?? u);
            c.ReviseBrief(c.Summary, cur?.WorkingAssessment, Append(cur?.Known, known), Append(cur?.OpenQuestions, question),
                nextSteps, _user.UserId, _clock.UtcNow, appended: true);   // WF-30
            // WF-25: titled as the brief pairs a question with its task (its plain text), as AddOpenQuestionAsync does; a
            // question with formatting or a tag otherwise never paired, and the brief kept offering a second task.
            if (question is not null && f.QuestionTask) c.RaiseTaskFromQuestion(Content.MarkdownService.PlainLine(question), _user.UserId, _clock.UtcNow);
        }

        if (f.LinkCaseId is { } other)
        {
            if (other == c.Id) throw new ArgumentException("A case can't be linked to itself.");
            var visible = await Scoped(db.Cases.AsNoTracking()).AnyAsync(x => x.Id == other, ct);
            if (!visible) throw new InvalidOperationException("The case to link must exist and be visible to you.");
            await EnsureSameSideAsync(db, c.Id, other, ct);
            // BUG-525: the caller holds the link gate (LinkGateAsync) from before this look through its save.
            if (!await LinkedAsync(db, c.Id, other, ct))
                db.CaseLinks.Add(new CaseLink
                {
                    CaseId = c.Id, RelatedCaseId = other, Type = f.LinkType, Description = null,
                    CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
                });
        }
    }

    /// <summary>
    /// CAP-23: a finding that answers one of the brief's open questions. The task following the question up (by the id
    /// the picker had, WF-25) is completed with the finding's text as its result (HR-02), or, when no task did, one is
    /// raised and completed (INV-25); the entry is linked to it (<see cref="TimelineEntry.ActionItemId"/>, as a result
    /// logged from Mark done is, INV-08). All in the entry's save (RD-09). Refused when the question was answered,
    /// followed up or closed by someone else since the picker showed it, so a second answer never overwrites the first.
    /// </summary>
    private async Task AnswerQuestionAsync(IAppDbContext db, Case c, TimelineEntry entry, QuestionAnswer a, CancellationToken ct)
    {
        if (entry.Kind != TimelineKind.Investigation || entry.Type is TimelineEntryType.Decision or TimelineEntryType.Handoff)
            throw new ArgumentException("Only a finding can answer an open question.");
        var text = entry.Description.Trim();
        if (text.Length > 8000 - TaskResults.Prefix.Length)   // BUG-105: the result is a comment of 8,000
            throw new ArgumentException($"Keep a finding that answers a question to {8000 - TaskResults.Prefix.Length:N0} characters or fewer.");
        var now = _clock.UtcNow;
        var at = entry.OccurredAtUtc < now ? entry.OccurredAtUtc : now;
        if (c.DetectedAtUtc is { } detected && Case.ToMinute(at) < Case.ToMinute(detected))   // REV-16, as Mark done
            throw new ArgumentException("A finding dated before the case was detected can't complete the question's task.");

        ActionItem task;
        if (a.TaskId is { } id)
        {
            task = c.ActionItems.FirstOrDefault(t => t.Id == id)
                   ?? throw new InvalidOperationException("The task for that question isn't on this case.");
            if (!task.FollowsUpQuestion) throw new InvalidOperationException("That task doesn't follow up a question in the brief.");
            if (task.Status == ActionItemStatus.Done)
                throw new InvalidOperationException(
                    $"{_users?.DisplayFor(task.CompletedBy) ?? task.CompletedBy} answered that question while you were writing. Your entry wasn't saved: read their answer, then save yours without it or with another question.");
            if (task.Status == ActionItemStatus.Cancelled)
                throw new InvalidOperationException("The task for that question was canceled while you were writing. Your entry wasn't saved: save it without the question, or reopen the task first.");
        }
        else
        {
            await db.CaseBriefs.Where(b => b.CaseId == c.Id && b.IsCurrent).ToListAsync(ct);
            var question = EntryFollowUps.Clean(a.Question) ?? throw new ArgumentException("Choose the question the finding answers.");
            var offered = OpenQuestionAnswers.Answerable(c).FirstOrDefault(q => string.Equals(q.Question, question, StringComparison.OrdinalIgnoreCase));
            if (offered is null)
                throw new InvalidOperationException(
                    c.TasksFollowingUp(Content.MarkdownService.PlainLine(question)).Any(t => t.Status == ActionItemStatus.Done)
                        ? "Someone answered that question while you were writing. Your entry wasn't saved: read their answer, then save yours without it or with another question."
                        : "That question is no longer open in the brief. Your entry wasn't saved: save it without the question, or with another one.");
            // Someone followed it up meanwhile: their task is the one to complete, so pick it again rather than add a second.
            if (offered.TaskId is not null)
                throw new InvalidOperationException("Someone followed that question up with a task while you were writing. Your entry wasn't saved: pick the question again, then save.");
            task = c.RaiseTaskFromQuestion(Content.MarkdownService.PlainLine(question), _user.UserId, now);
        }

        task.Status = ActionItemStatus.Done;
        task.CompletedAtUtc = at;
        task.CompletedBy = _user.UserId;
        task.CompletionRecordedAtUtc = now;   // BUG-364
        task.ModifiedBy = _user.UserId;
        task.ModifiedAtUtc = now;
        db.ActionItemComments.Add(new ActionItemComment
        {
            ActionItemId = task.Id, CaseId = c.Id, Body = TaskResults.Body(text), CreatedBy = _user.UserId, CreatedAtUtc = now
        });
        entry.ActionItemId = task.Id;
    }

    /// <summary>
    /// Adds an Event-timeline step (the attack narrative): one or more MITRE ATT&amp;CK tactics, an
    /// optional technique, and actor &rarr; target attribution to entities already on the case.
    /// </summary>
    public async Task<Guid> AddEventStepAsync(Guid id, DateTimeOffset occurredAtUtc, IEnumerable<MitreTactic> tactics,
        string? techniqueId, Guid? actorEntityId, Guid? targetEntityId, string description, string? source,
        Guid? evidenceId = null, TimelineEntryType type = TimelineEntryType.Other, EntryFollowUps? followUps = null,
        StepEnvironment? environment = null, StepTiming? timing = null, Screenshot? screenshot = null, CancellationToken ct = default)
    {
        Require();
        followUps?.Validate();
        foreach (var t in followUps?.Tasks ?? []) CheckDue(t.DueAtUtc, t.Title.Trim());   // BUG-577
        using var linkGate = await LinkGateAsync(followUps?.LinkCaseId is not null, ct);   // BUG-525
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        await EnsureEvidenceOnCaseAsync(db, id, evidenceId, ct);
        // One-line field: inline Markdown only, so the step reads as one line in tables and the attack-chain diagram.
        var step = c.AddEventStep(occurredAtUtc, tactics, techniqueId, actorEntityId, targetEntityId, Content.MarkdownService.OneLine(description), source,
            _user.UserId, _clock.UtcNow, evidenceId, type, environment, timing);
        if (followUps is not null) await ApplyFollowUpsAsync(db, c, step, followUps, ct);
        var shot = await AttachScreenshotAsync(db, c.Id, step, screenshot, ct);   // WF-31
        await SaveWithScreenshotAsync(db, shot, ct);
        return step.Id;
    }

    /// <summary>
    /// Corrects an Event-timeline step in place (attack narrative facts change during an investigation).
    /// The optional <paramref name="reason"/> is recorded on the audit entry.
    /// </summary>
    /// BUG-196: <paramref name="expectedStamp"/> is the step's row hash when the editor opened (empty for one without);
    /// a step someone changed since is refused with <see cref="StaleEditException"/>. Null skips the check.
    public async Task EditEventStepAsync(Guid id, Guid entryId, DateTimeOffset occurredAtUtc,
        IEnumerable<MitreTactic> tactics, string? techniqueId, Guid? actorEntityId, Guid? targetEntityId,
        string description, string? source, string? reason = null,
        TimelineEntryType type = TimelineEntryType.Other, StepEnvironment? environment = null, StepTiming? timing = null,
        string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        if (expectedStamp is not null && c.TimelineEntries.FirstOrDefault(e => e.Id == entryId) is { } step
            && !string.Equals(step.RowHash ?? "", expectedStamp, StringComparison.Ordinal))
            throw new StaleEditException(step.RowHash ?? "", "Someone changed this step since you opened it, so your edit " +
                "wasn't saved. It has been reloaded with their change; make yours again.");
        c.EditEventStep(entryId, occurredAtUtc, tactics, techniqueId, actorEntityId, targetEntityId, Content.MarkdownService.OneLine(description),
            source, _user.UserId, _clock.UtcNow, type, environment, timing);
        db.PendingChangeReason = reason;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>ST-01: moves an event step one place earlier or later among the steps (see <see cref="Case.MoveEventStep"/>).</summary>
    public async Task MoveEventStepAsync(Guid id, Guid entryId, bool earlier, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.MoveEventStep(entryId, earlier, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// BUG-413: takes a wrong timeline entry off the record, with a reason; nothing is deleted (see
    /// <see cref="Case.RetractTimelineEntry"/>). <paramref name="expectedStamp"/> is the entry's row hash when the person
    /// opened the dialog; an entry someone changed since is refused with <see cref="StaleEditException"/>. Null skips it.
    /// </summary>
    public async Task RetractTimelineEntryAsync(Guid id, Guid entryId, string reason, string? expectedStamp = null,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        if (expectedStamp is not null && c.TimelineEntries.FirstOrDefault(e => e.Id == entryId) is { } entry
            && !string.Equals(entry.RowHash ?? "", expectedStamp, StringComparison.Ordinal))
            throw new StaleEditException(entry.RowHash ?? "", "Someone changed this entry since you opened it, so it wasn't " +
                "retracted. It has been reloaded with their change; look again before retracting it.");
        c.RetractTimelineEntry(entryId, reason, _user.UserId, _clock.UtcNow);
        db.PendingChangeReason = reason?.Trim();
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Edits an Investigation-timeline entry, superseding it with a new version (prior kept). The optional
    /// <paramref name="reason"/> is recorded on the audit entry.
    /// </summary>
    public async Task EditInvestigationEntryAsync(Guid id, Guid entryId, TimelineEntryType type,
        DateTimeOffset occurredAtUtc, string description, string? source, string? reason = null,
        DecisionDetails? decision = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.EditInvestigationEntry(entryId, type, occurredAtUtc, description, source, _user.UserId, _clock.UtcNow,
            decision?.Rationale, decision?.OptionsConsidered, decision?.DecidedBy);
        db.PendingChangeReason = reason;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Finds this case's IOCs/entities that also appear on <em>other</em> cases the user is allowed to
    /// see (same type + value), so analysts can pivot on a shared indicator. Exact-value match.
    /// </summary>
    /// <param name="entityId">BUG-254: just this entity's overlaps (the entity panel), not the whole case's.</param>
    public async Task<IReadOnlyList<EntityOverlap>> FindEntityOverlapsAsync(Guid caseId, Guid? entityId = null,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        if (!await CanSeeAsync(db, caseId, ct)) return Array.Empty<EntityOverlap>();   // BUG-46
        if (await IsExerciseAsync(db, caseId, ct)) return Array.Empty<EntityOverlap>();   // WF-48: a drill correlates with no live case
        var mine = await db.CaseEntities.AsNoTracking()
            .Where(e => e.CaseId == caseId && (entityId == null || e.Id == entityId))
            .Select(e => new { e.Id, e.Type, e.Value })
            .ToListAsync(ct);
        if (mine.Count == 0) return Array.Empty<EntityOverlap>();

        // HR-03: compare values ignoring case on every provider (SQLite's IN is case-sensitive).
        var values = mine.Select(m => m.Value.ToLowerInvariant()).Distinct().ToList();

#pragma warning disable CA1304, CA1311 // EF Core translates ToLower() to SQL LOWER(); the invariant overload doesn't translate.
        var others = await (
            from e in db.CaseEntities.AsNoTracking()
            where e.CaseId != caseId && values.Contains(e.Value.ToLower())
            join c in Scoped(db.Cases.AsNoTracking()).ExcludingExercises() on e.CaseId equals c.Id
            select new { e.Type, e.Value, e.Disposition, OtherCaseId = c.Id, c.CaseNumber, c.Title, c.Phase, c.Classification,
                c.ClosedAtUtc, c.OutcomeKey }
        ).ToListAsync(ct);
#pragma warning restore CA1304, CA1311
        var closing = await ClosingLinesAsync(db, others.Where(o => o.Phase == CasePhase.Closed).Select(o => o.OtherCaseId), ct);

        // BUG-254: looked up by (family, value), not by scanning every other occurrence for each of this case's entities
        // (a 1,000-indicator case against 20,000 shared occurrences was 20 million comparisons per load).
        var byKey = others.ToLookup(o => (Domain.Observables.IocObservable.MatchFamily(o.Type), o.Value.ToLowerInvariant()));
        var result = new List<EntityOverlap>();
        foreach (var m in mine)
        {
            // HR-03: the same observable across types in one family (an account and an email address with one value).
            var matches = byKey[(Domain.Observables.IocObservable.MatchFamily(m.Type), m.Value.ToLowerInvariant())]
                .GroupBy(o => o.OtherCaseId);
            foreach (var g in matches)
            {
                var o = g.OrderByDescending(x => Intel.IndicatorService.Severity(x.Disposition)).First();
                result.Add(new EntityOverlap(m.Id, o.OtherCaseId, o.CaseNumber, o.Title, o.Phase, o.Disposition,
                    o.Phase == CasePhase.Closed ? o.ClosedAtUtc : null, o.Phase == CasePhase.Closed ? o.OutcomeKey : null,
                    closing.GetValueOrDefault(o.OtherCaseId), o.Classification));
            }
        }
        return result;
    }

    /// <summary>CAP-28: at most this many shared parts (domains, /24s, email domains) are looked up per check.</summary>
    public const int RelatedKeyLimit = 50;

    /// <summary>CAP-28: each shared part reads at most this many candidate indicators, newest cases first (C10).</summary>
    public const int RelatedScanLimit = 500;

    /// <summary>CAP-28: at most this many possibly related indicators are listed per indicator.</summary>
    public const int RelatedPerIndicator = 20;

    /// <summary>
    /// CAP-28: the indicators on <em>other</em> cases the user can see that are possibly related to this case's (or just
    /// <paramref name="entityId"/>'s) by the fixed rules of <see cref="Domain.Observables.RelatedObservables"/>: the same
    /// registrable domain, /24 or /48, or email domain, never the identical value (that's <see cref="FindEntityOverlapsAsync"/>).
    /// Need-to-know scoped; exercises take part in none. Suggestions only: nothing is linked, and nothing counts toward a
    /// gate or the Desk (A4).
    /// </summary>
    public async Task<RelatedIndicators> FindRelatedIndicatorsAsync(Guid caseId, Guid? entityId = null,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        if (!await CanSeeAsync(db, caseId, ct)) return RelatedIndicators.None;   // BUG-46
        if (await IsExerciseAsync(db, caseId, ct)) return RelatedIndicators.None;   // WF-48
        var mine = await db.CaseEntities.AsNoTracking()
            .Where(e => e.CaseId == caseId && (entityId == null || e.Id == entityId))
            .Select(e => new { e.Type, e.Value }).ToListAsync(ct);
        return await RelatedAsync(db, mine.Select(m => (m.Type, m.Value)).ToList(), caseId, ct);
    }

    /// <summary>
    /// CAP-28: the indicators possibly related to those being entered on a new case (detected and normalized as they'll
    /// be filed), on the cases the user can see, by the rules of <see cref="FindRelatedIndicatorsAsync"/>.
    /// </summary>
    public async Task<RelatedIndicators> FindRelatedIndicatorsForIocsAsync(IEnumerable<string> rawIndicators,
        CancellationToken ct = default)
    {
        var mine = (rawIndicators ?? Enumerable.Empty<string>())
            .Select(r => Domain.Observables.IocObservable.DetectType(r) is var t ? (t, Domain.Observables.IocObservable.Normalize(t, r)) : default)
            .Where(m => m.Item2.Length > 0)
            .ToList();
        if (mine.Count == 0) return RelatedIndicators.None;
        using var db = _factory.CreateDbContext();
        return await RelatedAsync(db, mine, null, ct);
    }

    // CAP-28: one bounded query per shared part (a LIKE that narrows; the rule itself is checked here, in one place, C2),
    // joined to the cases the user can see, exercises left out.
    private async Task<RelatedIndicators> RelatedAsync(IAppDbContext db, IReadOnlyList<(EntityType Type, string Value)> mine,
        Guid? notCaseId, CancellationToken ct)
    {
        var keyed = mine.Select(m => (m.Type, m.Value, Key: Domain.Observables.RelatedObservables.KeyOf(m.Type, m.Value)))
            .Where(m => m.Key is not null).Select(m => (m.Type, m.Value, Key: m.Key!.Value)).ToList();
        if (keyed.Count == 0) return RelatedIndicators.None;

        var found = new List<(Domain.Observables.RelatedKey Key, Guid CaseId, string CaseNumber, string Title, CasePhase Phase,
            EntityType Type, string Value, EntityDisposition Disposition)>();
        var limitHit = false;
        foreach (var key in keyed.Select(k => k.Key).Distinct().Take(RelatedKeyLimit))
        {
            var types = Domain.Observables.RelatedObservables.TypesFor(key.Rule).ToList();
            var direct = types[0];
            var (pDirect, pDirect2, pIn1, pIn2, pIn3) = RelatedPatterns(key);
            // CAP-28 review: this check's own values are left out in SQL, so copies of them on newer cases (an exact match,
            // never a suggestion) can't fill the scan and hide an older related one. They're read apart, below.
            var own = keyed.Where(k => k.Key == key).Select(k => k.Value.Trim().ToLowerInvariant()).Distinct().ToList();
#pragma warning disable CA1304, CA1311 // EF Core translates ToLower() to SQL LOWER(); the invariant overload doesn't translate.
            var candidates =
                from e in db.CaseEntities.AsNoTracking()
                where types.Contains(e.Type) && (notCaseId == null || e.CaseId != notCaseId)
                join c in Scoped(db.Cases.AsNoTracking()).ExcludingExercises() on e.CaseId equals c.Id
                select new { e.Type, e.Value, e.Disposition, c.Id, c.CaseNumber, c.Title, c.Phase, c.CreatedAtUtc };
            var rows = await candidates
                .Where(x => !own.Contains(x.Value.ToLower())
                    && ((x.Type == direct && (EF.Functions.Like(x.Value.ToLower(), pDirect, LikeEscape)
                            || EF.Functions.Like(x.Value.ToLower(), pDirect2, LikeEscape)))
                        || (x.Type != direct && (EF.Functions.Like(x.Value.ToLower(), pIn1, LikeEscape)
                            || EF.Functions.Like(x.Value.ToLower(), pIn2, LikeEscape)
                            || EF.Functions.Like(x.Value.ToLower(), pIn3, LikeEscape)))))
                .OrderByDescending(x => x.CreatedAtUtc).Take(RelatedScanLimit).ToListAsync(ct);
            limitHit |= rows.Count >= RelatedScanLimit;
            // Another of this check's values with the same part (evil.example beside portal.evil.example) is related to
            // the rest, so its copies elsewhere are read too, bounded the same way.
            if (own.Count > 1)
            {
                var copies = await candidates.Where(x => own.Contains(x.Value.ToLower()))
                    .OrderByDescending(x => x.CreatedAtUtc).Take(RelatedScanLimit).ToListAsync(ct);
                limitHit |= copies.Count >= RelatedScanLimit;
                rows.AddRange(copies);
            }
#pragma warning restore CA1304, CA1311
            found.AddRange(rows.Where(r => Domain.Observables.RelatedObservables.KeyOf(r.Type, r.Value) == key)
                .Select(r => (key, r.Id, r.CaseNumber, r.Title, r.Phase, r.Type, r.Value, r.Disposition)));
        }

        var result = new List<RelatedIndicator>();
        foreach (var m in keyed.DistinctBy(m => (Domain.Observables.IocObservable.MatchFamily(m.Type), m.Value.ToLowerInvariant())))
        {
            result.AddRange(found
                .Where(f => f.Key == m.Key && Domain.Observables.RelatedObservables.AreRelated(m.Type, m.Value, f.Type, f.Value))
                .DistinctBy(f => (f.CaseId, f.Value.ToLowerInvariant()))
                .Take(RelatedPerIndicator)
                .Select(f => new RelatedIndicator(m.Value, f.Type, f.Value, f.CaseId, f.CaseNumber, f.Title, f.Phase, f.Disposition, m.Key)));
        }
        return new RelatedIndicators(result, limitHit);
    }

    private const string LikeEscape = "\\";

    // CAP-28: the LIKEs that narrow to values that can share the part (lowercase; wildcards in the part escaped): two for
    // the key's own type (a domain, an IP address, an email address), three for the type that carries it (a URL, an account).
    private static (string Direct, string Direct2, string In1, string In2, string In3) RelatedPatterns(Domain.Observables.RelatedKey key)
    {
        static string Esc(string s) => s.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_").Replace("[", "\\[");
        switch (key.Rule)
        {
            case Domain.Observables.RelatedRule.Ipv4Slash24:
            {
                // CAP-28 review: anchored. "%1.2.3.%" also read 11.2.3.4 and 201.2.3.9, which could fill the scan. An address
                // is stored as a dotted quad; in a URL it follows the "//", a userinfo "@" or a mapped "[::ffff:". R1: an
                // address stored before v1.5.3 (BUG-176, no backfill) can still be IPv4-mapped ("::ffff:1.2.3.4").
                var p = Esc(key.Shared) + ".%";
                return (p, "%:" + p, "%/" + p, "%@" + p, "%:" + p);
            }
            case Domain.Observables.RelatedRule.Ipv6Slash48:
            {
                // CAP-28 review: the /48's hextets up to the first zero one narrow, not only the first (2001:db8:0::5 is
                // "2001:db8::5" canonically). R1: an address isn't always stored canonically (a URL's never is, and an
                // IpAddress stored before v1.5.3 may not be, BUG-176), so a hextet shorter than four may carry leading
                // zeros ("0db8"), and a zero one may be written out rather than compressed; the exact rule filters after.
                // A URL carries the address in brackets.
                var lead = string.Concat(key.Shared.Split(':').TakeWhile(h => h != "0")
                    .Select(h => (h.Length < 4 ? "%" : "") + Esc(h) + ":"));
                var inUrl = "%\\[" + lead + "%";
                var direct = lead.Length == 0 ? "%:%" : lead + "%";
                return (direct, direct, inUrl, inUrl, inUrl);
            }
            case Domain.Observables.RelatedRule.EmailDomain:
            {
                var p = $"%@{Esc(key.Shared)}";
                return (p, p, p, p, p);
            }
            default:
            {
                var p = $"%{Esc(key.Shared)}%";
                return (p, p, p, p, p);
            }
        }
    }

    /// <summary>
    /// HR-03: one line on how each closed case ended: its closing brief's conclusion (the working assessment of the brief
    /// as it stood at the latest close, when it closed with an outcome), else the reason given when it closed.
    /// </summary>
    private static async Task<Dictionary<Guid, string>> ClosingLinesAsync(IAppDbContext db, IEnumerable<Guid> caseIds,
        CancellationToken ct)
    {
        var ids = caseIds.Distinct().ToList();
        if (ids.Count == 0) return [];
        var withOutcome = await db.Cases.AsNoTracking().Where(c => ids.Contains(c.Id) && c.OutcomeKey != null)
            .Select(c => c.Id).ToListAsync(ct);
        // BUG-527 sibling: the brief as it stood at the latest close (Case.ClosingBrief, BUG-310), not a revision since.
        var briefs = await db.CaseBriefs.AsNoTracking()
            .Where(b => withOutcome.Contains(b.CaseId))
            .Select(b => new { b.CaseId, b.Version, b.CreatedAtUtc, b.WorkingAssessment }).ToListAsync(ct);
        var closes = await db.StatusChanges.AsNoTracking()
            .Where(s => ids.Contains(s.CaseId) && s.To == CasePhase.Closed)
            .Select(s => new { s.CaseId, s.Reason, s.ChangedAtUtc }).ToListAsync(ct);
        var lines = new Dictionary<Guid, string>();
        foreach (var id in ids)
        {
            var close = closes.Where(s => s.CaseId == id).MaxBy(s => s.ChangedAtUtc);
            var assessment = close is null ? null
                : briefs.Where(b => b.CaseId == id && b.CreatedAtUtc <= close.ChangedAtUtc).MaxBy(b => b.Version)?.WorkingAssessment;
            // BUG-527 sibling: the brief is Markdown; the line is shown as plain text.
            var line = (string.IsNullOrWhiteSpace(assessment) ? null : Content.RichText.ToText(assessment))
                       ?? closes.Where(s => s.CaseId == id && s.Reason != null).MaxBy(s => s.ChangedAtUtc)?.Reason;
            if (!string.IsNullOrWhiteSpace(line)) lines[id] = TaskResults.Excerpt(line, 220);
        }
        return lines;
    }

    /// <summary>
    /// HR-03: given the raw indicators an analyst is entering on a new case, the visible <b>closed</b> cases that already
    /// recorded any of them, with how each ended and the verdict each indicator reached there: "seen before". Matched like
    /// <see cref="FindOpenCaseMatchesForIocsAsync"/> (refanged, value only, ignoring case); need-to-know scoped;
    /// exercises excluded. Most recently closed first.
    /// </summary>
    public async Task<IReadOnlyList<CaseHistoryMatch>> FindCaseHistoryForIocsAsync(
        IEnumerable<string> rawIndicators, CancellationToken ct = default)
    {
        var wanted = (rawIndicators ?? Enumerable.Empty<string>())
            .Select(r => Domain.Observables.IocObservable.Refang(r))
            .Where(v => v.Length > 0)
            .Select(v => v.ToLowerInvariant())
            .Distinct()
            .ToList();
        if (wanted.Count == 0) return Array.Empty<CaseHistoryMatch>();

        using var db = _factory.CreateDbContext();
#pragma warning disable CA1304, CA1311 // EF Core translates ToLower() to SQL LOWER(); the invariant overload doesn't translate.
        var hits = await (
            from e in db.CaseEntities.AsNoTracking()
            join c in Scoped(db.Cases.AsNoTracking()).ExcludingExercises() on e.CaseId equals c.Id
            where c.Phase == CasePhase.Closed && wanted.Contains(e.Value.ToLower())
            select new { c.Id, c.CaseNumber, c.Title, c.Classification, c.ClosedAtUtc, c.OutcomeKey, e.Value, e.Disposition }
        ).ToListAsync(ct);
#pragma warning restore CA1304, CA1311
        var closing = await ClosingLinesAsync(db, hits.Select(h => h.Id), ct);

        return hits
            .GroupBy(h => h.Id)
            .Select(g =>
            {
                var f = g.First();
                return new CaseHistoryMatch(f.Id, f.CaseNumber, f.Title, f.Classification, f.ClosedAtUtc, f.OutcomeKey,
                    closing.GetValueOrDefault(f.Id),
                    g.GroupBy(x => x.Value, StringComparer.OrdinalIgnoreCase)
                        .Select(v => (v.First().Value, v.Select(x => x.Disposition).MaxBy(Intel.IndicatorService.Severity)))
                        .ToList());
            })
            .OrderByDescending(m => m.ClosedAtUtc)
            .ToList();
    }

    /// <summary>CAP-24: at most this many vendor names are offered to pick from.</summary>
    public const int VendorNameLimit = 500;

    /// <summary>
    /// CAP-24: the vendor names on third-party cases the user can see (<c>ForUser</c>, so a restricted case outside their
    /// need-to-know never names its vendor), exercises left out, for the New case form to offer. Trimmed, one per name
    /// ignoring case (spelled as most of its cases spell it, else as the latest does), A–Z, at most
    /// <see cref="VendorNameLimit"/>, from the latest <see cref="VendorCaseScan"/> vendor cases. A suggestion only: the
    /// stored value stays free text.
    /// </summary>
    public async Task<IReadOnlyList<string>> ListVendorNamesAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var rows = await Scoped(db.Cases.AsNoTracking()).ExcludingExercises()
            .Where(c => c.Origin == CaseOrigin.ThirdParty && c.ThirdParty != null && c.ThirdParty.VendorName != "")
            .OrderByDescending(c => c.CreatedAtUtc).Take(VendorCaseScan)
            .Select(c => c.ThirdParty!.VendorName)
            .ToListAsync(ct);
        return rows.Select(n => n.Trim()).Where(n => n.Length > 0)
            .GroupBy(n => n, StringComparer.OrdinalIgnoreCase)
            .Select(SpelledAsMost)
            .Order(StringComparer.OrdinalIgnoreCase)
            .Take(VendorNameLimit)
            .ToList();
    }

    /// <summary>CAP-24: the vendor list reads at most this many of the latest vendor cases (C10: a bounded query).</summary>
    public const int VendorCaseScan = 5000;

    // CAP-24: one vendor's spellings (newest first): the commonest, ties going to the newest.
    private static string SpelledAsMost(IEnumerable<string> newestFirst) =>
        newestFirst.Select((n, i) => (n, i)).GroupBy(x => x.n, StringComparer.Ordinal)
            .OrderByDescending(g => g.Count()).ThenBy(g => g.Min(x => x.i)).First().Key;

    /// <summary>
    /// CAP-24: what the user can see of a vendor's earlier cases, for the New case form's "Seen before" line: how many
    /// (and how many are still open), and the most recently closed one with its outcome and closing line, as HR-03 shows
    /// an indicator's. Matched on the trimmed name ignoring case; need-to-know scoped; exercises and the cases of other
    /// origins left out. Null when the name is blank or no visible case names it.
    /// </summary>
    public async Task<VendorHistory?> FindVendorHistoryAsync(string? vendorName, CancellationToken ct = default)
    {
        var wanted = (vendorName ?? "").Trim().ToLowerInvariant();
        if (wanted.Length == 0) return null;

        using var db = _factory.CreateDbContext();
#pragma warning disable CA1304, CA1311 // EF Core translates ToLower() to SQL LOWER(); the invariant overload doesn't translate.
        var rows = await VendorCases(Scoped(db.Cases.AsNoTracking()).ExcludingExercises(), wanted)
            .OrderByDescending(c => c.CreatedAtUtc)
            .Select(c => new { c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, c.ClosedAtUtc, c.OutcomeKey,
                Vendor = c.ThirdParty!.VendorName })
            .ToListAsync(ct);
#pragma warning restore CA1304, CA1311
        if (rows.Count == 0) return null;

        var last = rows.Where(r => r.Phase == CasePhase.Closed).MaxBy(r => r.ClosedAtUtc);
        CaseHistoryMatch? lastClosed = null;
        if (last is not null)
        {
            var closing = await ClosingLinesAsync(db, [last.Id], ct);
            lastClosed = new CaseHistoryMatch(last.Id, last.CaseNumber, last.Title, last.Classification, last.ClosedAtUtc,
                last.OutcomeKey, closing.GetValueOrDefault(last.Id), []);
        }
        return new VendorHistory(SpelledAsMost(rows.Select(r => r.Vendor.Trim())), rows.Count, rows.Count(r => r.Phase != CasePhase.Closed), lastClosed);
    }

    // CAP-24: the third-party cases naming a vendor (trimmed, ignoring case; wanted is already trimmed and lowered). One
    // rule for the "Seen before" count and the case list's vendor filter it links to (C2).
#pragma warning disable CA1304, CA1311, CA1862 // EF Core translates ToLower() to SQL LOWER(); the culture overloads don't translate.
    internal static IQueryable<Case> VendorCases(IQueryable<Case> q, string wanted) =>
        q.Where(c => c.Origin == CaseOrigin.ThirdParty && c.ThirdParty != null && c.ThirdParty.VendorName.Trim().ToLower() == wanted);
#pragma warning restore CA1304, CA1311, CA1862

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
            join c in Scoped(db.Cases.AsNoTracking()).ExcludingExercises() on e.CaseId equals c.Id
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

    /// <summary>
    /// PROD-40: given the case in view, the visible <b>open</b> cases that share one or more of its indicators
    /// and are <b>not already linked</b> to it — a mid-investigation "these look related, link them?" surface
    /// (the in-case cousin of the at-intake <see cref="FindOpenCaseMatchesForIocsAsync"/>). Matched
    /// case-insensitively on the stored (already-refanged) indicator value alone (type-agnostic — an IP is an
    /// IP). Need-to-know scoped; closed/archived and already-linked cases are excluded. Suggestion only — it
    /// never creates a link.
    /// </summary>
    public async Task<IReadOnlyList<RelatedCaseSuggestion>> FindRelatedOpenCasesAsync(
        Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        if (!await CanSeeAsync(db, caseId, ct)) return Array.Empty<RelatedCaseSuggestion>();   // BUG-46
        if (await IsExerciseAsync(db, caseId, ct)) return Array.Empty<RelatedCaseSuggestion>();   // WF-48

        var mine = await db.CaseEntities.AsNoTracking()
            .Where(e => e.CaseId == caseId)
            .Select(e => e.Value)
            .ToListAsync(ct);
        if (mine.Count == 0) return Array.Empty<RelatedCaseSuggestion>();
        var wanted = mine.Select(v => v.ToLowerInvariant()).Distinct().ToList();

        // Cases already linked to this one (either direction) shouldn't be re-suggested.
        var linked = await db.CaseLinks.AsNoTracking()
            .Where(l => l.CaseId == caseId || l.RelatedCaseId == caseId)
            .Select(l => l.CaseId == caseId ? l.RelatedCaseId : l.CaseId)
            .ToListAsync(ct);

        // e.Value.ToLower() translates to SQL LOWER(); the invariant overload does not (see the E-23 matcher).
#pragma warning disable CA1304, CA1311
        var hits = await (
            from e in db.CaseEntities.AsNoTracking()
            join c in Scoped(db.Cases.AsNoTracking()).ExcludingExercises() on e.CaseId equals c.Id
            where c.Id != caseId && c.Phase != CasePhase.Closed && !c.IsArchived
                  && wanted.Contains(e.Value.ToLower())
            select new { c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, e.Value }
        ).ToListAsync(ct);
#pragma warning restore CA1304, CA1311

        return hits
            .Where(h => !linked.Contains(h.Id))
            .GroupBy(h => new { h.Id, h.CaseNumber, h.Title, h.Classification, h.Phase })
            .Select(g => new RelatedCaseSuggestion(g.Key.Id, g.Key.CaseNumber, g.Key.Title,
                g.Key.Classification, g.Key.Phase, g.Select(x => x.Value).Distinct().ToList()))
            .OrderByDescending(s => s.SharedIndicators.Count)
            .ThenBy(s => s.CaseNumber, StringComparer.Ordinal)
            .ToList();
    }

    // BUG-416: an account added to the case is looked up in the directory and its details kept (best effort).
    private async Task CaptureAccountsAsync(Guid id, IEnumerable<CaseEntity> added,
        Accounts.AccountDirectoryService.CaptureAllowance capture, CancellationToken ct)
    {
        var ids = added.Where(e => Accounts.AccountDirectoryService.IsAccountType(e.Type)).Select(e => e.Id).ToList();
        if (ids.Count > 0 && _accounts is not null) await _accounts.CaptureOnAddAsync(id, ids, capture, ct);
    }

    public async Task<Guid> AddEntityAsync(Guid id, EntityType type, string value, string? label,
        EntityDisposition disposition, string? description, string? source, CancellationToken ct = default)
        => (await AddOrMatchEntityAsync(id, type, value, label, disposition, description, source, ct)).Id;

    /// <summary>
    /// What adding an entity did (HR-04): added it, or found it already on the case. When it was already there,
    /// <see cref="Disposition"/> is the verdict the case keeps, which may differ from the one asked for: adding never
    /// overwrites a recorded verdict.
    /// </summary>
    /// <param name="VerdictChanged">WF-29: it was already here as Unknown and took the verdict it was added with.</param>
    public sealed record EntityAddResult(Guid Id, bool AlreadyOnCase, EntityDisposition Disposition, string? Label,
        bool VerdictChanged = false);

    /// <summary>Adds an entity, or reports that it's already on the case (HR-04). See <see cref="Case.AddEntity"/>.</summary>
    public async Task<EntityAddResult> AddOrMatchEntityAsync(Guid id, EntityType type, string value, string? label,
        EntityDisposition disposition, string? description, string? source, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var before = c.FindEntity(type, value)?.Disposition;
        var entity = c.AddEntity(type, value, label, disposition, description, source, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        if (before is null) await CaptureAccountsAsync(id, [entity], new Accounts.AccountDirectoryService.CaptureAllowance(), ct);   // BUG-416
        return new EntityAddResult(entity.Id, before is not null, entity.Disposition, entity.Label,
            before is { } was && was != entity.Disposition);
    }

    /// <summary>One indicator for <see cref="AddOrMatchEntitiesAsync"/>; <see cref="Tlp"/> only ever raises a marking.</summary>
    public sealed record EntityToAdd(EntityType Type, string Value, string? Label, EntityDisposition Disposition,
        string? Description, string? Source, TlpLevel? Tlp = null);

    /// <summary>BUG-202: how many indicators one audited save takes.</summary>
    public const int EntitiesPerSave = 200;

    /// <summary>
    /// BUG-202: adds (or matches) many indicators, loading the case once per <see cref="EntitiesPerSave"/> and saving each
    /// batch as one audited change, rather than reloading the whole case and saving once per indicator. Matching is the
    /// same as <see cref="AddOrMatchEntityAsync"/>, so a retry after a failure part-way adds nothing twice. A marking
    /// (BUG-152) is kept, and only ever raises the one an indicator already has.
    /// </summary>
    /// <param name="promotedReason">WF-29: recorded on an Unknown indicator that takes the verdict it's pasted with.</param>
    public Task<IReadOnlyList<EntityAddResult>> AddOrMatchEntitiesAsync(Guid id, IReadOnlyList<EntityToAdd> items,
        string? promotedReason = null, CancellationToken ct = default) =>
        AddOrMatchEntitiesAsync(id, items, promotedReason, new Accounts.AccountDirectoryService.CaptureAllowance(), ct);

    /// <summary>BUG-420: the same, with the directory lookups of the accounts added taken from <paramref name="capture"/>.</summary>
    internal async Task<IReadOnlyList<EntityAddResult>> AddOrMatchEntitiesAsync(Guid id, IReadOnlyList<EntityToAdd> items,
        string? promotedReason, Accounts.AccountDirectoryService.CaptureAllowance capture, CancellationToken ct)
    {
        Require();
        var results = new List<EntityAddResult>(items.Count);
        foreach (var batch in items.Chunk(EntitiesPerSave))
        {
            using var db = _factory.CreateDbContext();
            var c = await LoadTrackedAsync(db, id, ct);
            var now = _clock.UtcNow;
            var added = new List<CaseEntity>();
            foreach (var i in batch)
            {
                var before = c.FindEntity(i.Type, i.Value)?.Disposition;
                var existed = before is not null;
                var entity = c.AddEntity(i.Type, i.Value, i.Label, i.Disposition, i.Description, i.Source, _user.UserId, now, promotedReason);
                if (i.Tlp is { } tlp && (!existed || entity.Tlp is not { } had || had < tlp))
                    c.SetEntityTlp(entity.Id, tlp, _user.UserId, now);
                results.Add(new EntityAddResult(entity.Id, existed, entity.Disposition, entity.Label,
                    before is { } was && was != entity.Disposition));
                if (!existed) added.Add(entity);
            }
            await db.SaveChangesAsync(ct);
            // BUG-416: the accounts just added, as the directory has them now. BUG-429: once each batch is saved, so a later
            // batch failing (and a retry matching these as already on the case) doesn't leave them without a snapshot.
            await CaptureAccountsAsync(id, added, capture, ct);
        }
        return results;
    }

    /// <summary>
    /// Corrects an existing IOC/entity in place (e.g. a mis-typed value or a re-assessed disposition).
    /// The optional <paramref name="reason"/> is recorded on the audit entry. BUG-234: <paramref name="expectedStamp"/> is
    /// the entity's row hash when the editor opened; one someone changed since (a colleague's verdict) is refused with
    /// <see cref="StaleEditException"/> rather than written back over. Null skips the check.
    /// </summary>
    public async Task EditEntityAsync(Guid id, Guid entityId, EntityType type, string value, string? label,
        EntityDisposition disposition, string? description, string? source, string? reason = null,
        string? expectedStamp = null, DateTimeOffset? determinedAtUtc = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        if (expectedStamp is not null && c.Entities.FirstOrDefault(e => e.Id == entityId) is { } current
            && !string.Equals(current.RowHash ?? "", expectedStamp, StringComparison.Ordinal))
            throw new StaleEditException(current.RowHash ?? "", "Someone changed this entity since you opened it, so your " +
                "edit wasn't saved (it would have undone theirs). It now shows their version; make your change again.");
        // HR-05: marking something Malicious or Compromised is a finding; say why, in a line.
        if (c.Entities.FirstOrDefault(e => e.Id == entityId) is { } before && before.Disposition != disposition
            && disposition is EntityDisposition.Malicious or EntityDisposition.Compromised && string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException($"Say why it's {(disposition == EntityDisposition.Malicious ? "malicious" : "compromised")}: the reason is kept with the verdict.");
        if (reason is { Length: > 2000 }) throw new ArgumentException("Keep the reason to 2,000 characters or fewer.");
        // BUG-414: a verdict reached earlier than it's recorded; only meaningful when the verdict changes.
        var verdictChanges = c.Entities.FirstOrDefault(e => e.Id == entityId) is { } was && was.Disposition != disposition;
        if (verdictChanges) RequireReasonIfBackdated(determinedAtUtc, reason);
        c.EditEntity(entityId, type, value, label, disposition, description, source, _user.UserId, _clock.UtcNow, reason,
            verdictChanges ? determinedAtUtc : null);
        db.PendingChangeReason = reason;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// BUG-234: records a verdict alone, keeping the entity's other fields as they are now (the panel's copy may be
    /// older). <paramref name="expectedDisposition"/> is the verdict the person saw; if someone has changed it since,
    /// the change is refused rather than recorded as a move from a verdict that's no longer there.
    /// </summary>
    public async Task SetEntityVerdictAsync(Guid id, Guid entityId, EntityDisposition disposition, string? reason,
        EntityDisposition expectedDisposition, DateTimeOffset? determinedAtUtc = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var e = c.Entities.FirstOrDefault(x => x.Id == entityId)
            ?? throw new InvalidOperationException("That entity is no longer on the case.");
        if (e.Disposition != expectedDisposition)
            throw new StaleEditException(e.RowHash ?? "", $"Someone set this to {e.Disposition} since you opened it, so your " +
                "verdict wasn't recorded. Look again, then record yours.");
        if (e.Disposition != disposition && disposition is EntityDisposition.Malicious or EntityDisposition.Compromised
            && string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException($"Say why it's {(disposition == EntityDisposition.Malicious ? "malicious" : "compromised")}: the reason is kept with the verdict.");
        if (reason is { Length: > 2000 }) throw new ArgumentException("Keep the reason to 2,000 characters or fewer.");
        if (e.Disposition != disposition) RequireReasonIfBackdated(determinedAtUtc, reason);   // BUG-414
        c.EditEntity(entityId, e.Type, e.Value, e.Label, disposition, e.Description, e.Source, _user.UserId, _clock.UtcNow, reason,
            e.Disposition != disposition ? determinedAtUtc : null);
        db.PendingChangeReason = reason;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>CAP-02: how many entities one assessment takes (the most a paste or an IOC file adds at once).</summary>
    public const int MaxEntitiesPerAssessment = Import.IocImportConverter.MaxIndicators;

    /// <summary>
    /// CAP-02: records one verdict on several of a case's entities at once, as <see cref="SetEntityVerdictAsync"/> records
    /// it on one: each one that changes gets its own <see cref="EntityVerdictChange"/> and timeline milestone (HR-05), with
    /// the same reason and "when determined". The rules are the single verdict's: a reason for Malicious or Compromised and
    /// for a time more than an hour back, the time checked against each entity's own earlier verdicts (BUG-414).
    /// <paramref name="expected"/> holds the verdict each one showed when they were picked; if someone has changed any of
    /// them since, nothing is recorded (BUG-234). One save: an id that isn't on this case, or a time one entity refuses,
    /// records none of them. Returns how many changed (one already at the verdict is left as it is). All on one case, so
    /// no E-18 cross-case metering applies.
    /// </summary>
    public async Task<int> AssessEntitiesAsync(Guid id, IReadOnlyCollection<Guid> entityIds, EntityDisposition disposition,
        string? reason, IReadOnlyDictionary<Guid, EntityDisposition>? expected = null, DateTimeOffset? determinedAtUtc = null,
        CancellationToken ct = default)
    {
        Require();
        var ids = entityIds.Distinct().ToList();
        if (ids.Count == 0) throw new ArgumentException("Pick at least one entity to assess.");
        if (ids.Count > MaxEntitiesPerAssessment)
            throw new ArgumentException($"Assess up to {MaxEntitiesPerAssessment:N0} entities at a time.");
        if (reason is { Length: > 2000 }) throw new ArgumentException("Keep the reason to 2,000 characters or fewer.");
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var entities = c.Entities.ToDictionary(e => e.Id);
        if (ids.Any(e => !entities.ContainsKey(e)))
            throw new InvalidOperationException("Some of those entities are no longer on this case. Look again, then assess them.");
        var picked = ids.Select(e => entities[e]).ToList();
        if (expected is not null && picked.FirstOrDefault(e => expected.TryGetValue(e.Id, out var seen) && seen != e.Disposition) is { } moved)
            throw new StaleEditException(moved.RowHash ?? "", $"Someone set {moved.Label ?? moved.Value} to {moved.Disposition} since " +
                "you picked it, so no verdicts were recorded. Look again, then record yours.");
        var changing = picked.Where(e => e.Disposition != disposition).ToList();
        if (changing.Count == 0) return 0;
        if (disposition is EntityDisposition.Malicious or EntityDisposition.Compromised && string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException($"Say why they're {(disposition == EntityDisposition.Malicious ? "malicious" : "compromised")}: the reason is kept with each verdict.");
        RequireReasonIfBackdated(determinedAtUtc, reason);   // BUG-414
        var now = _clock.UtcNow;
        foreach (var e in changing)
            c.EditEntity(e.Id, e.Type, e.Value, e.Label, disposition, e.Description, e.Source, _user.UserId, now, reason, determinedAtUtc);
        db.PendingChangeReason = reason;
        await db.SaveChangesAsync(ct);
        return changing.Count;
    }

    /// <summary>BUG-152: an indicator's own TLP marking (null when it has none, or isn't on a case the caller can see).</summary>
    public async Task<TlpLevel?> EntityTlpAsync(Guid id, Guid entityId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var visible = Scoped(db.Cases.AsNoTracking()).Where(c => c.Id == id).Select(c => c.Id);
        return await db.CaseEntities.AsNoTracking().Where(e => e.Id == entityId && visible.Contains(e.CaseId))
            .Select(e => e.Tlp).FirstOrDefaultAsync(ct);
    }

    /// <summary>PROD-45: sets or clears (null) an indicator's TLP sharing marking.</summary>
    public async Task SetEntityTlpAsync(Guid id, Guid entityId, TlpLevel? tlp, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.SetEntityTlp(entityId, tlp, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>INV-32: pins an entity to (or unpins it from) the case context panel.</summary>
    public async Task SetEntityPinnedAsync(Guid id, Guid entityId, bool pinned, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.SetEntityPinned(entityId, pinned, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task RemoveEntityAsync(Guid id, Guid entityId, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.RemoveEntity(entityId, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task LinkEntitiesAsync(Guid id, Guid sourceEntityId, Guid targetEntityId,
        EntityRelationshipType type, string? description, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.LinkEntities(sourceEntityId, targetEntityId, type, description, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>INV-49: change a relationship's type, description or direction as one audited update.</summary>
    public async Task EditRelationshipAsync(Guid id, Guid relationshipId, Guid sourceEntityId, Guid targetEntityId,
        EntityRelationshipType type, string? description, string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        // BUG-234: as for entities, a relationship someone changed since the editor opened isn't written back over.
        if (expectedStamp is not null && c.EntityRelationships.FirstOrDefault(r => r.Id == relationshipId) is { } current
            && !string.Equals(current.RowHash ?? "", expectedStamp, StringComparison.Ordinal))
            throw new StaleEditException(current.RowHash ?? "", "Someone changed this relationship since you opened it, so " +
                "your edit wasn't saved. It now shows their version; make your change again.");
        c.EditRelationship(relationshipId, sourceEntityId, targetEntityId, type, description, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task UnlinkAsync(Guid id, Guid relationshipId, CancellationToken ct = default)
    {
        Require();
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
    private static Task<bool> IsExerciseAsync(IAppDbContext db, Guid caseId, CancellationToken ct) =>
        db.Cases.AsNoTracking().Where(c => c.Id == caseId).Select(c => c.IsExercise).FirstOrDefaultAsync(ct);

    /// <summary>
    /// WF-48: an exercise and a live case are never linked or superseded into each other (owner's decision). Superseding
    /// copied a drill's malicious indicators into a live case and its pushed IOC feed, and a live case superseded into a
    /// drill went on in a case left out of every reminder and dashboard.
    /// </summary>
    private static async Task EnsureSameSideAsync(IAppDbContext db, Guid a, Guid b, CancellationToken ct)
    {
        var sides = await db.Cases.AsNoTracking().Where(c => c.Id == a || c.Id == b).Select(c => c.IsExercise).Distinct().ToListAsync(ct);
        if (sides.Count > 1)
            throw new InvalidOperationException("An exercise case and a live case can't be linked or superseded into each other.");
    }

    public async Task<Guid?> LinkCaseAsync(Guid caseId, Guid relatedCaseId, CaseLinkType type,
        string? description, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        if (caseId == relatedCaseId) throw new ArgumentException("A case can't be linked to itself.");

        // Need-to-know: both ends must be visible to the caller.
        var visible = await Scoped(db.Cases.AsNoTracking())
            .Where(c => c.Id == caseId || c.Id == relatedCaseId)
            .Select(c => c.Id).ToListAsync(ct);
        if (!visible.Contains(caseId) || !visible.Contains(relatedCaseId))
            throw new InvalidOperationException("Both cases must exist and be visible to you.");
        await EnsureSameSideAsync(db, caseId, relatedCaseId, ct);

        using var gate = await LinkGateAsync(true, ct);   // BUG-525
        // One link per pair, regardless of direction — keeps the relationship unambiguous.
        if (await LinkedAsync(db, caseId, relatedCaseId, ct)) return null;

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
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException)
        {
            // BUG-525: a link added past the gate (another process) hits the unique index. The pair is linked, as asked.
            using var fresh = _factory.CreateDbContext();
            if (await LinkedAsync(fresh, caseId, relatedCaseId, ct)) return null;
            throw;
        }
        return link.Id;
    }

    // BUG-525: whether two cases are linked, either way round.
    private static Task<bool> LinkedAsync(IAppDbContext db, Guid a, Guid b, CancellationToken ct) =>
        db.CaseLinks.AsNoTracking().AnyAsync(l => (l.CaseId == a && l.RelatedCaseId == b) || (l.CaseId == b && l.RelatedCaseId == a), ct);

    // BUG-525: linking is a look, then an insert. One at a time (the app runs as one instance, as WF-40), so two people
    // linking the same two cases at once, either way round, can't both find no link and both add one. Taken after the
    // other checks and held through the save; nothing under it waits on another link.
    private static readonly SemaphoreSlim LinkGate = new(1, 1);

    private static async Task<IDisposable?> LinkGateAsync(bool needed, CancellationToken ct)
    {
        if (!needed) return null;
        await LinkGate.WaitAsync(ct);
        return new LinkGateHeld();
    }

    private sealed class LinkGateHeld : IDisposable
    {
        private int _released;
        public void Dispose() { if (Interlocked.Exchange(ref _released, 1) == 0) LinkGate.Release(); }
    }

    /// <summary>
    /// PROD-11: supersedes a duplicate case by the case work continues on. Records the <c>DuplicateOf</c> link
    /// (duplicate → primary) when the pair isn't already linked, optionally copies the duplicate's indicators that
    /// the primary doesn't have yet (source noted as copied from the duplicate; existing ones are never
    /// overwritten), and adds a cross-referencing note to both cases with the reason — one save, so it all lands
    /// or none of it does. It deliberately does <b>not</b> close the duplicate: closing stays a separate human act
    /// through the normal close gate. Both cases must be visible to the caller.
    /// </summary>
    /// <summary>
    /// BUG-129: superseding a restricted case into one that isn't puts its number (in the note) and, when copied, its
    /// indicators in front of everyone who can see the kept case. BUG-160: so does superseding it into a restricted case
    /// with a different team, and superseding any case into a restricted one puts the kept case's number in the
    /// duplicate's note, in front of the duplicate's audience. What would be exposed, so the dialog can warn and ask for
    /// a tick; null when nothing would.
    /// </summary>
    public async Task<SupersedeExposure?> SupersedeExposureAsync(Guid duplicateId, Guid primaryId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var cases = await Scoped(db.Cases.AsNoTracking()).Where(c => c.Id == duplicateId || c.Id == primaryId)
            .Select(c => new { c.Id, c.IsRestricted, c.IncidentCommander, Team = c.Assignments.Select(a => a.UserId).ToList() })
            .ToListAsync(ct);
        if (cases.FirstOrDefault(c => c.Id == duplicateId) is not { } dup || cases.FirstOrDefault(c => c.Id == primaryId) is not { } primary)
            return null;
        var dupValues = await db.CaseEntities.AsNoTracking().Where(e => e.CaseId == duplicateId).Select(e => new { e.Type, e.Value }).ToListAsync(ct);
        var have = await db.CaseEntities.AsNoTracking().Where(e => e.CaseId == primaryId).Select(e => new { e.Type, e.Value }).ToListAsync(ct);
        var copied = dupValues.Count(d => !have.Any(p => p.Type == d.Type && string.Equals(p.Value, d.Value, StringComparison.OrdinalIgnoreCase)));
        return Exposure(dup.IsRestricted, dup.IncidentCommander, dup.Team, primary.IsRestricted, primary.IncidentCommander, primary.Team, copied);
    }

    /// <summary>BUG-160: what superseding would show to people who can't see the case it comes from.</summary>
    public sealed record SupersedeExposure(bool DuplicateExposed, bool KeptNumberExposed, int IndicatorsCopied);

    // A restricted case's audience is its team (plus everyone cleared to see restricted cases, the same for both), so
    // what goes from one case to the other is exposed unless the other's audience is no wider: restricted, with a team
    // inside this one's.
    private static SupersedeExposure? Exposure(bool dupRestricted, string? dupIc, IEnumerable<string> dupTeam,
        bool primaryRestricted, string? primaryIc, IEnumerable<string> primaryTeam, int copied)
    {
        static HashSet<string> TeamOf(string? ic, IEnumerable<string> team) =>
            team.Append(ic ?? "").Where(u => u.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var dupPeople = TeamOf(dupIc, dupTeam);
        var primaryPeople = TeamOf(primaryIc, primaryTeam);
        var dupExposed = dupRestricted && (!primaryRestricted || !primaryPeople.IsSubsetOf(dupPeople));
        var keptExposed = primaryRestricted && (!dupRestricted || !dupPeople.IsSubsetOf(primaryPeople));
        return dupExposed || keptExposed ? new SupersedeExposure(dupExposed, keptExposed, copied) : null;
    }

    /// <param name="acknowledgeExposure">BUG-129/160: the caller confirmed what <see cref="SupersedeExposureAsync"/> said
    /// would be seen by people who can't see the case it comes from.</param>
    public async Task<SupersedeResult> SupersedeAsync(Guid duplicateId, Guid primaryId, bool copyIndicators, string reason,
        bool acknowledgeExposure = false, CancellationToken ct = default)
    {
        Require();
        if (duplicateId == primaryId) throw new ArgumentException("A case can't supersede itself.");
        reason = (reason ?? "").Trim();
        if (reason.Length == 0) throw new ArgumentException("Say why this case is a duplicate.");

        using var db = _factory.CreateDbContext();
        var visible = await Scoped(db.Cases.AsNoTracking())
            .Where(c => c.Id == duplicateId || c.Id == primaryId).Select(c => c.Id).ToListAsync(ct);
        if (!visible.Contains(duplicateId) || !visible.Contains(primaryId))
            throw new InvalidOperationException("Both cases must exist and be visible to you.");

        await EnsureSameSideAsync(db, duplicateId, primaryId, ct);
        var dup = await LoadTrackedAsync(db, duplicateId, ct);
        var primary = await LoadTrackedAsync(db, primaryId, ct);
        // BUG-114: as the docs and the workspace say, neither case may be closed (reopen it first).
        if (dup.Phase == CasePhase.Closed || primary.Phase == CasePhase.Closed)
            throw new InvalidOperationException("A closed case can't supersede or be superseded. Reopen it first.");
        if (!acknowledgeExposure && Exposure(dup.IsRestricted, dup.IncidentCommander, dup.Assignments.Select(a => a.UserId),
                primary.IsRestricted, primary.IncidentCommander, primary.Assignments.Select(a => a.UserId), 0) is { } exposed)
            throw new InvalidOperationException(exposed.DuplicateExposed
                ? $"This case is restricted, and not everyone who can see {primary.CaseNumber} can see it. Confirm that its number" +
                  (copyIndicators ? " and indicators" : "") + " may be seen by everyone who can see that case."
                : $"{primary.CaseNumber} is restricted, and not everyone who can see this case can see it. Confirm that its number " +
                  "may be seen, in this case's note, by everyone who can see this case.");
        // BUG-313: a duplicate is a duplicate of one case. Superseding it again into another left it a duplicate of both,
        // with a note on each; the existing "Duplicate of" link is removed first (from the case's Links) to change it.
        var otherPrimaries = db.CaseLinks.AsNoTracking()
            .Where(l => l.CaseId == duplicateId && l.Type == CaseLinkType.DuplicateOf && l.RelatedCaseId != primaryId)
            .Select(l => l.RelatedCaseId);
        if (await otherPrimaries.AnyAsync(ct))
        {
            // Named only when the caller can see it (need-to-know).
            var shown = await Scoped(db.Cases.AsNoTracking()).Where(c => otherPrimaries.Contains(c.Id)).Select(c => c.CaseNumber).FirstOrDefaultAsync(ct);
            throw new InvalidOperationException($"This case is already superseded as a duplicate of {shown ?? "another case"}. " +
                "Remove that link first to supersede it into another case.");
        }
        var now = _clock.UtcNow;

        var copied = 0;
        var added = new List<CaseEntity>();
        if (copyIndicators)
        {
            foreach (var e in dup.Entities.OrderBy(e => e.CreatedAtUtc))
            {
                var have = primary.Entities.Any(p => p.Type == e.Type && string.Equals(p.Value, e.Value, StringComparison.OrdinalIgnoreCase));
                if (have) continue;
                var isNew = primary.FindEntity(e.Type, e.Value) is null;
                var source = $"Copied from {dup.CaseNumber}" + (string.IsNullOrWhiteSpace(e.Source) ? "" : $" ({e.Source})");
                var copy = primary.AddEntity(e.Type, e.Value, e.Label, e.Disposition, e.Description,
                    source.Length > 200 ? source[..200] : source, _user.UserId, now);
                copy.Tlp = e.Tlp;   // BUG-106: the sharing marking travels with the indicator
                if (isNew) added.Add(copy);
                copied++;
            }
        }

        dup.Notes.Add(new AnalystNote
        {
            CaseId = dup.Id, CreatedBy = _user.UserId, CreatedAtUtc = now,
            Body = $"**Superseded by {primary.CaseNumber}.** Work continues on that case.\n\nReason: {reason}",
        });
        primary.Notes.Add(new AnalystNote
        {
            CaseId = primary.Id, CreatedBy = _user.UserId, CreatedAtUtc = now,
            Body = $"**Supersedes duplicate {dup.CaseNumber}.**" + (copyIndicators ? $" {Plural.Of(copied, "indicator")} copied across." : "")
                   + $"\n\nReason: {reason}",
        });

        bool linked;
        // BUG-525: the pair's links are read and changed under the link gate, through the save, as LinkCaseAsync does.
        using (await LinkGateAsync(true, ct))
        {
            // A "Related to" link between the two becomes "Duplicate of". BUG-161: a "Part of campaign" link stays: the
            // campaign views walk those links, so removing it would drop cases linked through the duplicate out of the campaign.
            var existing = await db.CaseLinks.Where(l =>
                (l.CaseId == duplicateId && l.RelatedCaseId == primaryId) || (l.CaseId == primaryId && l.RelatedCaseId == duplicateId))
                .ToListAsync(ct);
            linked = existing.Any(l => l.Type == CaseLinkType.DuplicateOf && l.CaseId == duplicateId);
            db.CaseLinks.RemoveRange(existing.Where(l => l.Type != CaseLinkType.PartOfCampaign
                && !(l.Type == CaseLinkType.DuplicateOf && l.CaseId == duplicateId)));
            if (!linked)
                db.CaseLinks.Add(new CaseLink
                {
                    CaseId = duplicateId, RelatedCaseId = primaryId, Type = CaseLinkType.DuplicateOf,
                    Description = reason.Length > 500 ? reason[..500] : reason, CreatedBy = _user.UserId, CreatedAtUtc = now
                });

            await db.SaveChangesAsync(ct);
        }
        // BUG-493: the accounts copied across get their "as added" directory snapshot on the kept case, as any add does
        // (BUG-416); best effort, once the supersede is saved.
        await CaptureAccountsAsync(primary.Id, added, new Accounts.AccountDirectoryService.CaptureAllowance(), ct);
        return new SupersedeResult(primary.Id, primary.CaseNumber, copied, !linked);
    }

    /// <summary>Removes a case link. No-op unless the link touches <paramref name="caseId"/> and the caller can see both
    /// ends (BUG-47: as linking requires).</summary>
    public async Task RemoveCaseLinkAsync(Guid caseId, Guid linkId, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var link = await db.CaseLinks.FirstOrDefaultAsync(l => l.Id == linkId, ct);
        if (link is null || (link.CaseId != caseId && link.RelatedCaseId != caseId)) return;

        var visible = await Scoped(db.Cases.AsNoTracking())
            .CountAsync(c => c.Id == link.CaseId || c.Id == link.RelatedCaseId, ct);
        if (visible < 2) return;

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
        if (!await CanSeeAsync(db, caseId, ct)) return Array.Empty<CaseLinkView>();   // BUG-46
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

        // WF-48: only cases on the same side of the exercise boundary.
        var drill = await db.Cases.AsNoTracking().Where(c => c.Id == caseId).Select(c => c.IsExercise).FirstOrDefaultAsync(ct);
        var q = Scoped(db.Cases.AsNoTracking()).Where(c => c.Id != caseId && c.IsExercise == drill);
        if (linked.Count > 0) q = q.Where(c => !linked.Contains(c.Id));
        if (!string.IsNullOrWhiteSpace(query))
        {
            // BUG-51: ignoring case on every provider (SQLite's LIKE via Contains is case-sensitive for non-ASCII and
            // instr() is case-sensitive outright). ToLower() translates to SQL LOWER(); the invariant overload doesn't.
            var term = query.Trim().ToLowerInvariant();
#pragma warning disable CA1304, CA1311, CA1862
            q = q.Where(c => c.CaseNumber.ToLower().Contains(term) || c.Title.ToLower().Contains(term));
#pragma warning restore CA1304, CA1311, CA1862
        }

        return await q.OrderByDescending(c => c.CreatedAtUtc).Take(take)
            .Select(c => new LinkableCase(c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase))
            .ToListAsync(ct);
    }

    public async Task<Guid> AddTechniqueAsync(Guid id, string techniqueId, string name, MitreTactic tactic,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var technique = c.AddTechnique(techniqueId, name, tactic, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        return technique.Id;
    }

    public async Task RemoveTechniqueAsync(Guid id, Guid techniqueId, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.RemoveTechnique(techniqueId, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// CAP-34: records an outside party on the case (counsel, a forensics firm, the insurer, law enforcement, a regulator's
    /// contact) with its reference and when it was engaged. Facts only (ADR 0012). Audited and hash-chained; need-to-know
    /// applies (the case loads through <see cref="LoadTrackedAsync"/>).
    /// </summary>
    public async Task<Guid> AddPartyAsync(Guid caseId, PartyDetails details, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadWithPartiesAsync(db, caseId, ct);
        var party = c.AddParty(details, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        return party.Id;
    }

    /// <summary>CAP-34: replaces what's recorded about one outside party.</summary>
    /// <param name="expectedStamp">C9: the party's <see cref="CaseParty.RowHash"/> as the form opened with it (empty for one
    /// without). Given, the save is refused when the party changed or was removed since.</param>
    /// <returns>False when nothing changed, so nothing was saved.</returns>
    public async Task<bool> UpdatePartyAsync(Guid caseId, Guid partyId, PartyDetails details, string? expectedStamp = null,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadWithPartiesAsync(db, caseId, ct);
        var party = c.Parties.FirstOrDefault(p => p.Id == partyId);
        if (expectedStamp is not null && (party?.RowHash ?? "") != expectedStamp)
            throw new StaleEditException(party?.RowHash ?? "", party is null
                ? "Someone else removed this party while you were editing it."
                : "Someone else changed this party while you were editing. Review it, then save yours again if it's still needed.");
        if (!c.EditParty(partyId, details, _user.UserId, _clock.UtcNow)) return false;
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>CAP-34: takes an outside party off the case (a mis-entry); the audit trail keeps what it said.</summary>
    /// <param name="expectedStamp">C9: the party's row hash as the page showed it. Given, a party changed since is refused,
    /// so a stale page doesn't remove what a colleague just corrected.</param>
    public async Task RemovePartyAsync(Guid caseId, Guid partyId, string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadWithPartiesAsync(db, caseId, ct);
        if (c.Parties.FirstOrDefault(p => p.Id == partyId) is not { } party) return;   // already gone
        if (expectedStamp is not null && (party.RowHash ?? "") != expectedStamp)
            throw new StaleEditException(party.RowHash ?? "",
                "Someone else changed this party since you opened the case, so it wasn't removed. Look at it again first.");
        if (c.RemoveParty(partyId, _user.UserId, _clock.UtcNow)) await db.SaveChangesAsync(ct);
    }

    // CAP-34: the case (need-to-know scoped) with its parties tracked.
    private async Task<Case> LoadWithPartiesAsync(IAppDbContext db, Guid id, CancellationToken ct)
    {
        var c = await LoadTrackedAsync(db, id, ct);
        await db.CaseParties.Where(p => p.CaseId == id).ToListAsync(ct);   // tracked: fixes up c.Parties
        return c;
    }

    /// <summary>
    /// Upserts saved graph node positions for a case. Cosmetic view state written straight to
    /// its own table (not via the aggregate), so it is neither audited nor hash-chained.
    /// </summary>
    public async Task SaveGraphLayoutAsync(Guid caseId, IReadOnlyList<EntityPosition> positions, CancellationToken ct = default)
    {
        Require();
        if (positions.Count == 0) return;

        // BUG-512: two saves for a new entity (two tabs, two quick drags) both find no row and both insert; the second hits
        // the unique EntityId index. As BUG-368, that one goes again from a fresh read and updates the row that won. So does
        // one whose row (or entity) was removed meanwhile.
        for (var attempt = 0; ; attempt++)
        {
            using var db = _factory.CreateDbContext();

            // Only persist for cases the current user is allowed to see.
            var visible = await Scoped(db.Cases.AsNoTracking()).AnyAsync(c => c.Id == caseId, ct);
            if (!visible) return;

            var validIds = (await db.CaseEntities.AsNoTracking()
                .Where(e => e.CaseId == caseId).Select(e => e.Id).ToListAsync(ct)).ToHashSet();

            var existing = await db.EntityLayouts.Where(l => l.CaseId == caseId).ToListAsync(ct);
            var byEntity = existing.ToDictionary(l => l.EntityId);

            var adding = false;
            foreach (var p in positions)
            {
                if (!validIds.Contains(p.EntityId)) continue;
                if (byEntity.TryGetValue(p.EntityId, out var row)) { row.X = p.X; row.Y = p.Y; }
                else
                {
                    // An entity listed twice takes its last position, not a second row.
                    db.EntityLayouts.Add(byEntity[p.EntityId] = new EntityLayout { CaseId = caseId, EntityId = p.EntityId, X = p.X, Y = p.Y });
                    adding = true;
                }
            }
            try
            {
                await db.SaveChangesAsync(ct);
                return;
            }
            catch (Exception ex) when (attempt == 0 && (ex is ConcurrentEditException || (adding && ex is DbUpdateException)))
            { /* lost the insert race (or a row went meanwhile): go again from what's there now */ }
        }
    }

    /// <summary>
    /// S-13 / INV-37: the people who may be @mentioned in this case's notes — everyone who can see it except the caller.
    /// On a restricted case that's its incident commander, team and cleared roles, so a mention never reaches someone
    /// outside it. Also the people a handoff can go to.
    /// </summary>
    public async Task<IReadOnlyList<UserSummary>> MentionableAsync(Guid caseId, CancellationToken ct = default)
    {
        if (_users is null) return [];
        using var db = _factory.CreateDbContext();
        var c = await Scoped(db.Cases.AsNoTracking()).Where(x => x.Id == caseId)
            .Select(x => new { x.IsRestricted, x.IncidentCommander, Team = x.Assignments.Select(a => a.UserId).ToList() })
            .FirstOrDefaultAsync(ct);
        if (c is null) return [];
        return _users.All()
            .Where(u => !string.Equals(u.UserId, _user.UserId, StringComparison.OrdinalIgnoreCase))
            .Where(u => _roles is null || CaseAudience.CanSee(c.IsRestricted, c.IncidentCommander, c.Team, u, _roles))
            .ToList();
    }

    // De-dupes the picked mentions, drops the author, and (S-13 backstop) anyone who can't see the case, so a note
    // excerpt never reaches someone outside a restricted case's audience.
    private List<string> CleanMentions(Case c, IReadOnlyCollection<string>? mentionUserIds)
    {
        var mentions = (mentionUserIds ?? [])
            .Where(id => !string.IsNullOrWhiteSpace(id) && !string.Equals(id, _user.UserId, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (_roles is not null && _users is not null && mentions.Count > 0)
        {
            var team = c.Assignments.Select(a => a.UserId).ToList();
            mentions = mentions.Where(id => CaseAudience.CanSee(c.IsRestricted, c.IncidentCommander, team, _users.Resolve(id), _roles)).ToList();
        }
        return mentions;
    }

    /// <summary>Adds a note. INV-37: the people it @mentions are notified, with a link to it.</summary>
    public async Task AddNoteAsync(Guid id, string body, IReadOnlyCollection<string>? mentionUserIds = null,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var mentions = CleanMentions(c, mentionUserIds);
        var note = new AnalystNote
        {
            CaseId = c.Id, Body = body, MentionsCsv = string.Join(',', mentions),
            CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
        };
        c.Notes.Add(note);
        await db.SaveChangesAsync(ct);
        // BUG-597: the note records everyone it mentions; only those the directory still entitles are emailed.
        if (mentions.Count > 0 && await RecipientsAsync(c, mentions, ct) is { Count: > 0 } notify)
            await _notifications.OnMentionedAsync(c, _user.UserId, notify, note.Body, note.Id, ct);
    }

    /// <summary>
    /// Edits a note, superseding the current version with a new one (no destructive overwrite). INV-37: the new version
    /// records its mentions; only people it mentions that the previous version didn't are notified, so fixing a typo
    /// doesn't email everyone again.
    /// </summary>
    public async Task EditNoteAsync(Guid id, Guid noteId, string newBody, IReadOnlyCollection<string>? mentionUserIds = null,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        var before = c.Notes.FirstOrDefault(n => n.Id == noteId)?.Mentions ?? [];
        var mentions = CleanMentions(c, mentionUserIds);
        var next = c.EditNote(noteId, newBody, _user.UserId, _clock.UtcNow);
        next.MentionsCsv = string.Join(',', mentions);
        await db.SaveChangesAsync(ct);
        var added = mentions.Where(m => !before.Contains(m, StringComparer.OrdinalIgnoreCase)).ToList();
        if (added.Count > 0 && await RecipientsAsync(c, added, ct) is { Count: > 0 } notify)   // BUG-597
            await _notifications.OnMentionedAsync(c, _user.UserId, notify, next.Body, next.Id, ct);
    }

    /// <summary>
    /// Places or releases a legal hold on the case (blocks archival while held). Releasing needs a reason (S-15),
    /// recorded on the audit entry; a reason given when placing is recorded too.
    /// </summary>
    public async Task SetLegalHoldAsync(Guid id, bool held, string? reason = null, CancellationToken ct = default)
    {
        Require();
        reason = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim();
        if (reason is { Length: > 1000 }) throw new ArgumentException("Keep the reason to 1000 characters or fewer.");
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        // BUG-312: already in that state (a double click, a stale menu): nothing changes, so nothing is said to the SIEM.
        if (c.LegalHold == held) return;
        if (held) c.PlaceLegalHold(_user.UserId, _clock.UtcNow);
        else
        {
            // F-12: with two-person release on, a single person can't lift a hold; they request it instead.
            if (c.LegalHold && LegalHoldReleaseNeedsSecondApprover)
                throw new InvalidOperationException(
                    "Releasing a legal hold needs a second approver. Request the release, and someone else with Manage Legal approves it.");
            if (c.LegalHold && reason is null)
                throw new ArgumentException("Say why the legal hold is being released.");
            c.ReleaseLegalHold(_user.UserId, _clock.UtcNow);
        }
        db.PendingChangeReason = reason;
        await db.SaveChangesAsync(ct);
        _siem?.Emit(Security.SecurityEvents.LegalHold(held, _user.UserId, _user.UserPrincipalName, c.CaseNumber));
    }

    /// <summary>F-12: asks for the legal hold to be released, with a reason, pending a second person's approval.</summary>
    public async Task RequestLegalHoldReleaseAsync(Guid id, string reason, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.RequestLegalHoldRelease(reason, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>F-12: approves a pending release (never by the requester), which lifts the hold.</summary>
    public async Task ApproveLegalHoldReleaseAsync(Guid id, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.ApproveLegalHoldRelease(_user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        _siem?.Emit(Security.SecurityEvents.LegalHold(false, _user.UserId, _user.UserPrincipalName, c.CaseNumber));
    }

    /// <summary>
    /// S-08: restricts the case to need-to-know, or lifts the restriction. Restricting needs only edit rights; if the
    /// caller wouldn't otherwise keep sight of the case they're added to its team as an analyst, so nobody locks
    /// themselves out mid-investigation. Lifting opens the case to everyone with case access, so it's limited to the
    /// incident commander or a cleared role (<see cref="CaseRestrictionPolicy.CanLift"/>) and needs a reason. The
    /// change and reason land in the audit chain and the SIEM stream.
    /// </summary>
    public async Task SetRestrictedAsync(Guid id, bool restricted, string? reason, CancellationToken ct = default)
    {
        Require();
        reason = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim();
        if (reason is { Length: > 1000 }) throw new ArgumentException("Keep the reason to 1000 characters or fewer.");

        using var db = _factory.CreateDbContext();
        if (!await Scoped(db.Cases.AsNoTracking()).AnyAsync(x => x.Id == id, ct))
            throw new InvalidOperationException("Case not found or not accessible.");
        var c = await LoadTrackedAsync(db, id, ct);
        if (c.IsRestricted == restricted) return;

        var now = _clock.UtcNow;
        if (restricted)
        {
            if (!CaseRestrictionPolicy.KeepsAccess(_user, c.IncidentCommander, c.Assignments.Select(a => a.UserId)))
                c.Assign(_user.UserId, SelfDisplayName, CaseAssignmentRole.Analyst, _user.UserId, now);
            c.Restrict(_user.UserId, now);
        }
        else
        {
            if (!CaseRestrictionPolicy.CanLift(_user, c.IncidentCommander))
                throw new InvalidOperationException(
                    "Only the case's incident commander or a role cleared for restricted cases can lift the restriction.");
            if (reason is null) throw new ArgumentException("Say why the restriction is being lifted.");
            c.LiftRestriction(_user.UserId, now);
        }

        db.PendingChangeReason = reason;
        await db.SaveChangesAsync(ct);
        _siem?.Emit(Security.SecurityEvents.CaseRestriction(restricted, _user.UserId, _user.UserPrincipalName, c.CaseNumber));
    }

    /// <summary>
    /// S-08: the roles whose holders see every restricted case (ViewAllCases or ViewRestricted), for the case's
    /// "who can see this" line. Includes custom roles.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetRestrictedClearanceRolesAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var roles = await db.Roles.AsNoTracking().ToListAsync(ct);
        return roles
            .Where(r => r.GetPermissions() is var p && (p.Contains(Permission.ViewAllCases) || p.Contains(Permission.ViewRestricted)))
            .Select(r => r.Name)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private string SelfDisplayName => string.IsNullOrWhiteSpace(_user.DisplayName) ? _user.UserId : _user.DisplayName;

    /// <summary>F-12: withdraws a pending release request; the hold stays.</summary>
    public async Task CancelLegalHoldReleaseAsync(Guid id, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.CancelLegalHoldReleaseRequest(_user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Sets (or clears, with null) the case's report profile (E-28) — the named section layout its reports
    /// and in-app preview use. Audited; falls back to the global default when cleared or the profile is gone.
    /// </summary>
    public async Task SetReportProfileAsync(Guid id, Guid? profileId, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.SetReportProfile(profileId, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// CAP-36: sets (or clears, with null) the team that owns the case: an active team. Audited, and in the row hash. Teams
    /// route and filter only, so this never changes who can see the case. <paramref name="expectedStamp"/> is
    /// <see cref="Case.TeamConcurrencyStamp"/> as the editor opened (C9): a team changed since is refused.
    /// </summary>
    public async Task SetTeamAsync(Guid id, Guid? teamId, string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        if (expectedStamp is not null && c.TeamConcurrencyStamp() != expectedStamp)
            throw new StaleEditException(c.TeamConcurrencyStamp(),
                "Someone else changed this case's team while you were editing. Reload and try again.");
        if (c.TeamId == teamId) return;
        if (teamId is { } t) await RequireActiveTeamAsync(db, t, ct);
        c.SetTeam(teamId, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    // CAP-36: a case takes an active team only (a retired one stays on the cases that name it, but isn't given to more).
    private static async Task RequireActiveTeamAsync(IAppDbContext db, Guid teamId, CancellationToken ct)
    {
        var team = await db.Teams.AsNoTracking().Where(t => t.Id == teamId).Select(t => new { t.Name, t.IsActive }).FirstOrDefaultAsync(ct)
                   ?? throw new InvalidOperationException("That team no longer exists. Reload the page and choose another.");
        if (!team.IsActive)
            throw new InvalidOperationException($"The team \"{team.Name}\" is retired, so it can't be given a case. Choose another.");
    }

    /// <summary>Archives or restores the case. Archiving is refused while a legal hold is in force.</summary>
    public Task SetArchivedAsync(Guid id, bool archived, CancellationToken ct = default) =>
        SetArchivedAsync(id, archived, closedBeforeUtc: null, ct);

    /// <summary>
    /// As <see cref="SetArchivedAsync(Guid, bool, CancellationToken)"/>. CAP-10 review: with <paramref name="closedBeforeUtc"/>
    /// (the retention review's batch), a case is archived only if the row it loads is still closed before that instant and
    /// not archived; one reopened (or archived) since the review was read is refused with
    /// <see cref="Compliance.CaseNoLongerDueException"/> and left as it is.
    /// </summary>
    internal async Task SetArchivedAsync(Guid id, bool archived, DateTimeOffset? closedBeforeUtc, CancellationToken ct)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        if (archived && closedBeforeUtc is { } cutoff
            && (c.IsArchived || c.Phase != CasePhase.Closed || c.ClosedAtUtc is not { } closed || closed >= cutoff))
            throw new Compliance.CaseNoLongerDueException();
        // BUG-10: archiving drops a case from the deadline scan and the "awaiting report" count, so a case whose
        // notification clock is running can't be archived until the notice is recorded (INV-43). Drills are exempt.
        if (archived && !c.IsArchived && !c.IsExercise && c.ReportedAtUtc is null
            && _notifySettings is not null && _notifyRules is not null
            && (await new Compliance.NotificationDeadlineService(_factory, _notifySettings, _notifyRules, _clock)
                .EvaluateAsync(id, ct)).HasClock)
            throw new InvalidOperationException("This case has a regulatory notification deadline running and no notice recorded. " +
                "Record when regulators were notified before archiving it, so the deadline isn't silenced.");
        var wasArchived = c.IsArchived;
        if (archived) c.Archive(_user.UserId, _clock.UtcNow);
        else c.Unarchive(_user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        if (wasArchived != archived) EmitLifecycle(c, (s, a, u) => Security.SecurityEvents.CaseArchived(s, archived, a, u));   // CAP-06
    }

    /// <summary>
    /// Adds a task. INV-28: <paramref name="about"/> optionally says what it's about ("entity:&lt;id&gt;",
    /// "evidence:&lt;id&gt;" or "entry:&lt;id&gt;"), which must be on this case; an entry is stored as its first version so
    /// the link survives edits.
    /// </summary>
    public async Task AddActionItemAsync(Guid id, string title, string? owner, DateTimeOffset? dueAtUtc,
        TaskKind kind = TaskKind.General, string? about = null, CancellationToken ct = default)
    {
        Require();
        title = (title ?? "").Trim();
        if (title.Length == 0) throw new ArgumentException("Say what needs doing.");
        if (title.Length > ActionItem.MaxTitleLength)
            throw new ArgumentException($"Keep the task to {ActionItem.MaxTitleLength} characters or fewer.");
        owner = CleanTaskOwner(owner);
        CheckDue(dueAtUtc);   // BUG-577
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, id, ct);
        c.ActionItems.Add(new ActionItem
        {
            CaseId = c.Id, Title = title, Owner = owner, DueAtUtc = dueAtUtc, Kind = kind,
            AboutRef = await ResolveAboutAsync(db, c, about, ct),
            CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
        });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>BUG-255: adds imported tasks in batches (one case load and one audited save each), checked as
    /// <see cref="AddActionItemAsync"/> checks one. <paramref name="saved"/> gets each batch's count once it's saved.</summary>
    public async Task AddImportedActionItemsAsync(Guid id, IReadOnlyList<(string Title, string? Owner, DateTimeOffset? DueAtUtc)> items,
        Action<int> saved, CancellationToken ct = default)
    {
        Require();
        // BUG-577: every due checked before the first batch is saved, so a bad one doesn't leave the import half done.
        foreach (var (rawTitle, _, due) in items) CheckDue(due, (rawTitle ?? "").Trim());
        foreach (var batch in items.Chunk(EntitiesPerSave))
        {
            using var db = _factory.CreateDbContext();
            var c = await LoadTrackedAsync(db, id, ct);
            foreach (var (rawTitle, rawOwner, due) in batch)
            {
                var title = (rawTitle ?? "").Trim();
                if (title.Length == 0) throw new ArgumentException("Say what needs doing.");
                if (title.Length > ActionItem.MaxTitleLength)
                    throw new ArgumentException($"Keep the task to {ActionItem.MaxTitleLength} characters or fewer.");
                c.ActionItems.Add(new ActionItem
                {
                    CaseId = c.Id, Title = title, Owner = CleanTaskOwner(rawOwner), DueAtUtc = due,
                    CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
                });
            }
            await db.SaveChangesAsync(ct);
            saved(batch.Length);
        }
    }

    // INV-28: checks what a task is about is on this case, and anchors a timeline entry at its first version.
    private static async Task<string?> ResolveAboutAsync(IAppDbContext db, Case c, string? about, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(about)) return null;
        var parts = about.Split(':', 2);
        if (parts.Length != 2 || !Guid.TryParse(parts[1], out var target))
            throw new ArgumentException("That isn't something a task can be about.");
        switch (parts[0])
        {
            case ActionItem.AboutEntity when c.Entities.Any(e => e.Id == target):
                return $"{ActionItem.AboutEntity}:{target}";
            // CAP-21 review: not a withdrawn file; it's off the case's record (its panel offers no task either).
            case ActionItem.AboutEvidence when await db.Evidence.AnyAsync(e => e.Id == target && e.CaseId == c.Id && e.WithdrawnAtUtc == null, ct):
                return $"{ActionItem.AboutEvidence}:{target}";
            case ActionItem.AboutEntry when c.TimelineEntries.FirstOrDefault(e => e.Id == target) is { } entry:
                var first = entry;
                while (first.SupersedesEntryId is { } prior && c.TimelineEntries.FirstOrDefault(e => e.Id == prior) is { } p) first = p;
                return $"{ActionItem.AboutEntry}:{first.Id}";
            // HR-17: a note, anchored at its first version like an entry, so the link survives edits.
            case ActionItem.AboutNote when await db.Notes.AsNoTracking().AnyAsync(n => n.Id == target && n.CaseId == c.Id, ct):
                var root = target;
                for (var guard = 0; guard < 100 && await db.Notes.AsNoTracking().Where(n => n.Id == root).Select(n => n.SupersedesNoteId).FirstOrDefaultAsync(ct) is { } prior; guard++)
                    root = prior;
                return $"{ActionItem.AboutNote}:{root}";
            default:
                throw new InvalidOperationException("What the task is about isn't on this case.");
        }
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
        Require();
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
                DueAtUtc = s.DueOffsetHours is { } h and > 0 ? now.AddHours(Math.Min(h, CaseTemplateStep.MaxDueOffsetHours)) : null,   // BUG-267
                Kind = s.Kind,   // INV-28: the step's kind of work
                CreatedBy = _user.UserId,
                CreatedAtUtc = now
            });
            seeded++;
        }

        if (seeded > 0) await db.SaveChangesAsync(ct);
        return seeded;
    }

    /// <summary>
    /// INV-15: records a handoff on the investigation timeline — where the case stands, what's done and what's open —
    /// to the person taking it on, and optionally hands them the caller's open tasks on this case. INV-37: with
    /// <paramref name="notify"/>, the recipient is emailed the handoff (only if they can see the case, S-13).
    /// Returns the number of tasks reassigned.
    /// </summary>
    public async Task<int> HandOffAsync(Guid caseId, string toUserId, string body, bool reassignMyOpenTasks,
        bool notify = false, CancellationToken ct = default)
    {
        Require();
        var text = (body ?? "").Trim();
        if (string.IsNullOrWhiteSpace(toUserId)) throw new ArgumentException("Choose who you're handing the case to.");
        if (string.Equals(toUserId, _user.UserId, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Choose someone other than yourself.");
        if (text.Length == 0) throw new ArgumentException("Say where the case stands.");
        if (text.Length > 8000) throw new ArgumentException("Keep the handoff to 8,000 characters or fewer.");

        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        // BUG-48: the person taking the case on (and the tasks handed to them) must be able to open it.
        if (_roles is not null && _users is not null && c.IsRestricted
            && !CaseAudience.CanSee(c.IsRestricted, c.IncidentCommander, c.Assignments.Select(a => a.UserId).ToList(), _users.Resolve(toUserId), _roles))
            throw new InvalidOperationException(
                "That person can't see this restricted case. Add them to the team first, then hand it off.");
        var now = _clock.UtcNow;
        c.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c.Id, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Handoff, OccurredAtUtc = now,
            Description = text, Source = "Handoff", CreatedBy = _user.UserId, CreatedAtUtc = now,
            HandedToUserId = toUserId.Trim()   // CAP-20 review: the card finds the recipient by id, not by the name in the text
        });
        var moved = 0;
        if (reassignMyOpenTasks)
            foreach (var t in c.ActionItems.Where(t => t.IsOpen && Work.TaskOwner.IsMine(t.Owner, _user)))   // REV-17: every task My Work shows as mine
            {
                t.Owner = toUserId;
                t.ModifiedBy = _user.UserId;
                t.ModifiedAtUtc = now;
                moved++;
            }
        await db.SaveChangesAsync(ct);
        // BUG-597: emailed only when the directory still entitles them (the check above is the mirror's, as the picker).
        if (notify && CleanMentions(c, [toUserId]).Count > 0 && (await RecipientsAsync(c, [toUserId], ct)).Count > 0)
            await _notifications.OnHandedOffAsync(c, _user.UserId, toUserId, text, ct);
        return moved;
    }

    /// <summary>
    /// CAP-08: records when, where from and by whom an evidence file was collected, after it was uploaded (from the
    /// evidence panel). The file itself stays as it is (R3, C3): these are facts about its acquisition, so they may be
    /// set, corrected or cleared, each change an audited update of the record (the audit trail keeps what they were) that
    /// its row hash then covers. The time follows the upload's rules (<see cref="Domain.Entities.Evidence.CheckCollection"/>), with the
    /// upload time as its latest. Need-to-know applies: a file on a case the caller can't see is "not found".
    /// </summary>
    /// <param name="expectedCollection">The collection the editor opened with. Given, the save is refused when it has
    /// changed since, so a stale panel doesn't overwrite a colleague's correction.</param>
    /// <returns>False when nothing changed, so nothing was saved.</returns>
    public async Task<bool> RecordEvidenceCollectionAsync(Guid caseId, Guid evidenceId, Evidence.EvidenceCollection collection,
        Evidence.EvidenceCollection? expectedCollection = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var times = await Scoped(db.Cases.AsNoTracking()).Where(c => c.Id == caseId)
                        .Select(c => new { c.OccurredAtUtc, c.DetectedAtUtc }).FirstOrDefaultAsync(ct)
                    ?? throw new InvalidOperationException("Case not found or not accessible.");
        var ev = await db.Evidence.FirstOrDefaultAsync(e => e.Id == evidenceId && e.CaseId == caseId, ct)
                 ?? throw new InvalidOperationException("That evidence isn't on this case.");
        if (ev.IsWithdrawn) throw new InvalidOperationException("That file has been withdrawn, so how it was collected stays as it was.");   // CAP-21
        var current = Evidence.EvidenceCollection.Of(ev);
        if (expectedCollection is not null && expectedCollection != current)
            throw new StaleEditException(Evidence.EvidenceCollection.Line(current.AtUtc, current.From, current.By),
                "Someone else changed how this file was collected while you were editing. Review it, then save yours again if it's still needed.");
        var now = _clock.UtcNow;
        var (at, from, by) = Domain.Entities.Evidence.CheckCollection(collection.AtUtc, collection.From, collection.By, now,
            times.OccurredAtUtc ?? times.DetectedAtUtc, ev.CreatedAtUtc);
        if (at == ev.CollectedAtUtc && from == ev.CollectedFrom && by == ev.CollectedBy) return false;
        (ev.CollectedAtUtc, ev.CollectedFrom, ev.CollectedBy) = (at, from, by);
        ev.ModifiedBy = _user.UserId;
        ev.ModifiedAtUtc = now;
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>
    /// CAP-21: withdraws an evidence file filed on the wrong case, with a reason. Nothing is deleted (R3): the bytes, the
    /// hash and the chain of custody stay, a "Withdrawn" custody event records why, and the file can still be downloaded
    /// for the record (each download logged as before). It leaves the case report, the gates' evidence count, citing and
    /// evidence packages (CAP-12), and its "Evidence added" milestone becomes "Evidence withdrawn". Final, as a retraction
    /// is (BUG-413). Refused while a regulator's notice names it as the file holding the notice (CAP-07), or a current
    /// timeline entry shows it as its screenshot, so nothing on the record points at a withdrawn file: change the notice,
    /// or retract the entry, first. Audited (the reason is the audit entry's), and sent to the SIEM (5516).
    /// </summary>
    /// <param name="expectedStamp">The file's row hash when the dialog opened (empty for one without). Given, a file whose
    /// record changed since is refused with <see cref="StaleEditException"/>.</param>
    /// <exception cref="ConcurrentEditException">The case changed while this was checked (a notice or an entry may name
    /// the file now, or it was withdrawn alongside); nothing was saved.</exception>
    public async Task WithdrawEvidenceAsync(Guid caseId, Guid evidenceId, string reason, string? expectedStamp = null,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        // CAP-21 review: the case is tracked, so this save checks and renews its edit version (BUG-113) as a notice naming
        // the file, an entry showing it, a citation of it or a second withdrawal does: of two made from the same reads, the
        // later is refused (ConcurrentEditException) rather than both passing the checks below.
        var head = await Scoped(db.Cases).FirstOrDefaultAsync(c => c.Id == caseId, ct)
                   ?? throw new InvalidOperationException("Case not found or not accessible.");
        var subject = new Security.CaseSubject(head.CaseNumber, head.DetectionCaseId, head.IsExercise);
        var ev = await db.Evidence.FirstOrDefaultAsync(e => e.Id == evidenceId && e.CaseId == caseId, ct)
                 ?? throw new InvalidOperationException("That evidence isn't on this case.");
        if (expectedStamp is not null && !string.Equals(ev.RowHash ?? "", expectedStamp, StringComparison.Ordinal))
            throw new StaleEditException(ev.RowHash ?? "", "Someone changed this file's record since you opened it, so it wasn't " +
                "withdrawn. Look at it again before withdrawing it.");
        if (await db.JurisdictionNotices.AnyAsync(n => n.CaseId == caseId && n.EvidenceId == evidenceId, ct))
            throw new InvalidOperationException("A regulator's notice names this file as the one holding the notice. Change that notice's file first.");
        if (await db.TimelineEntries.AnyAsync(t => t.CaseId == caseId && t.EvidenceId == evidenceId && t.IsCurrent, ct))
            throw new InvalidOperationException("This file is the screenshot on a timeline entry. Retract that entry first if it belongs to another case too.");
        ev.Withdraw(reason, _user.UserId, _clock.UtcNow);
        db.PendingChangeReason = reason?.Trim();
        await db.SaveChangesAsync(ct);
        Security.SecurityEventEmit.EmitSafely(_siem,
            () => Security.SecurityEvents.EvidenceWithdrawn(subject, ev.Id, _user.UserId, _user.UserPrincipalName));
    }

    /// <summary>
    /// CAP-12: prepares a package of a case's evidence for hand-over: the files picked (every file that stands when none
    /// are named; a withdrawn one is refused, CAP-21), and who it's for, how and why, named once. Checks the permission, the
    /// case (need-to-know), that each file is on it, and the package's size (<see cref="Evidence.EvidencePackage.CheckSize"/>),
    /// and returns a ticket for the download (<c>/evidence/package/{ticket}</c>), so nothing picked or typed goes in a
    /// URL. Records nothing: the download records the transfer as begun before its first byte, then how far it got
    /// (<see cref="Evidence.EvidenceService.RecordPackageBegunAsync"/>, CAP-12 review).
    /// </summary>
    public async Task<Evidence.EvidencePackageStaged> StageEvidencePackageAsync(Guid caseId, IReadOnlyCollection<Guid>? evidenceIds,
        string recipient, string? method, string purpose, CancellationToken ct = default)
    {
        Require();
        if (_evidencePackages is null) throw new InvalidOperationException("Evidence packages aren't available on this server.");
        var handOver = Evidence.EvidenceHandOver.Checked(recipient, method, purpose);
        using var db = _factory.CreateDbContext();
        if (!await CanSeeAsync(db, caseId, ct)) throw new InvalidOperationException("Case not found or not accessible.");
        var files = await db.Evidence.AsNoTracking().Where(e => e.CaseId == caseId)
            .Select(e => new { e.Id, e.SizeBytes, e.CreatedAtUtc, Withdrawn = e.WithdrawnAtUtc != null }).ToListAsync(ct);
        var picked = evidenceIds is null
            ? files.Where(f => !f.Withdrawn).ToList()
            : evidenceIds.Distinct().Select(id => files.FirstOrDefault(f => f.Id == id)
                                                  ?? throw new InvalidOperationException("Only evidence on this case can be packaged.")).ToList();
        if (picked.Any(f => f.Withdrawn)) throw new InvalidOperationException("A withdrawn file can't be packaged.");
        var bytes = picked.Sum(f => f.SizeBytes);
        Evidence.EvidencePackage.CheckSize(picked.Count, bytes, _evidenceLimits?.CurrentValue ?? new());
        var now = _clock.UtcNow;
        var ticket = _evidencePackages.Stage(_user.UserId, caseId,
            picked.OrderBy(f => f.CreatedAtUtc).Select(f => f.Id).ToList(), handOver, now);
        return new Evidence.EvidencePackageStaged(ticket, picked.Count, bytes, now + Evidence.EvidencePackageTickets.Lifetime);
    }

    /// <summary>INV-10: sets which evidence a timeline entry cites (replacing its current set).</summary>
    /// <param name="openedWith">BUG-297: the entry's citations when the picker opened. Given, only what changed since then
    /// is applied (files ticked are added, files unticked removed), so a citation a colleague added meanwhile stays.</param>
    public async Task CiteEvidenceAsync(Guid caseId, Guid entryId, IReadOnlyCollection<Guid> evidenceIds,
        IReadOnlyCollection<Guid>? openedWith = null, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        // Evidence isn't in the tracked load; bring in just the ids the domain checks against.
        await db.Evidence.Where(e => e.CaseId == caseId).ToListAsync(ct);
        if (openedWith is not null)
        {
            var now = c.Citations.Where(x => x.TimelineEntryId == entryId).Select(x => x.EvidenceId).ToHashSet();
            now.ExceptWith(openedWith.Except(evidenceIds));
            now.UnionWith(evidenceIds.Except(openedWith));
            evidenceIds = now;
        }
        c.SetCitations(entryId, evidenceIds, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// INV-09: saves a new version of the case brief. <paramref name="expectedCurrentId"/> is the version the
    /// editor opened from (null for the first brief); if someone saved a newer one meanwhile the save is refused
    /// (FR-06 style), so neither author's understanding is silently overwritten. INV-25: the next steps are the
    /// case's open tasks, recorded with the version as they stand, not written as text.
    /// </summary>
    /// <returns>False when nothing written changed, so no version was saved.</returns>
    public async Task<bool> ReviseBriefAsync(Guid caseId, Guid? expectedCurrentId, string? summary, string? workingAssessment,
        string? known, string? openQuestions, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        // Tracked in this context, so EF attaches it to c.Briefs (only the current version is needed).
        await db.CaseBriefs.Where(b => b.CaseId == caseId && b.IsCurrent).ToListAsync(ct);
        var currentId = c.Briefs.FirstOrDefault(b => b.IsCurrent)?.Id;
        if (currentId != expectedCurrentId)
        {
            // BUG-595: versions CaseBook appended meanwhile (a question, a Known line, WF-30) are merged in, not refused:
            // refused, the editor's next save dropped them.
            var merged = await MergeAppendedAsync(db, caseId, expectedCurrentId, [summary, workingAssessment, known, openQuestions], ct)
                         ?? throw new StaleEditException(currentId?.ToString() ?? "",
                             "Someone else saved a newer version of the brief while you were editing. Your text is still here; review theirs, then save again to replace it.");
            (summary, workingAssessment, known, openQuestions) = (merged[0], merged[1], merged[2], merged[3]);
        }
        var nextSteps = CaseNext.Snapshot(c, _clock.UtcNow, u => _users?.DisplayFor(u) ?? u);
        if (c.ReviseBrief(summary, workingAssessment, known, openQuestions, nextSteps, _user.UserId, _clock.UtcNow) is null)
            return false;
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>
    /// BUG-595: the editor's parts (summary, assessment, known, questions) with what was added since the version it opened
    /// from, when every version since is one CaseBook appended (WF-30): a part the editor left alone takes the part as it
    /// stands; in Known and Open questions, the lines appended meanwhile are added after the editor's text. Null when a
    /// version since was a revision, or a part both changed otherwise (a summary edit in the details): that's refused.
    /// </summary>
    private static async Task<string?[]?> MergeAppendedAsync(IAppDbContext db, Guid caseId, Guid? openedFrom, string?[] mine,
        CancellationToken ct)
    {
        var versions = (await db.CaseBriefs.AsNoTracking().Where(b => b.CaseId == caseId).ToListAsync(ct)).ToDictionary(b => b.Id);
        var current = versions.Values.FirstOrDefault(b => b.IsCurrent);
        Domain.Entities.CaseBrief? opened = null;
        for (var b = current; b is not null && b.Id != openedFrom; b = b.SupersedesBriefId is { } prev ? versions.GetValueOrDefault(prev) : null)
        {
            if (!b.Appended) return null;
            if (b.SupersedesBriefId is null && openedFrom is not null) return null;   // the version opened from isn't in the chain
        }
        if (current is null) return null;
        if (openedFrom is not null && !versions.TryGetValue(openedFrom.Value, out opened)) return null;
        string?[] baseParts = [opened?.Summary, opened?.WorkingAssessment, opened?.Known, opened?.OpenQuestions];
        string?[] nowParts = [current.Summary, current.WorkingAssessment, current.Known, current.OpenQuestions];
        var result = new string?[4];
        for (var i = 0; i < 4; i++)
        {
            var (was, now, edited) = (baseParts[i], nowParts[i], Clean(mine[i]));
            if (now == was) result[i] = mine[i];
            else if (edited == was) result[i] = now;
            else if (i >= 2 && now is not null && (was is null || now.StartsWith(was + "\n", StringComparison.Ordinal)))
            {
                var lines = (edited ?? "").Split('\n').Select(l => l.Trim()).ToHashSet(StringComparer.Ordinal);
                var added = now[(was?.Length ?? 0)..].Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Where(l => !lines.Contains(l));
                result[i] = string.Join('\n', new[] { edited }.Concat(added).Where(p => !string.IsNullOrEmpty(p)));
            }
            else return null;
        }
        return result;

        static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
    }

    /// <summary>Confirms the current brief still stands without changing it (no new version). Refused when someone saved
    /// a newer version since the caller looked, so what's confirmed is what they read.</summary>
    public async Task ConfirmBriefAsync(Guid caseId, Guid expectedCurrentId, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        await db.CaseBriefs.Where(b => b.CaseId == caseId && b.IsCurrent).ToListAsync(ct);
        var currentId = c.Briefs.FirstOrDefault(b => b.IsCurrent)?.Id;
        if (currentId != expectedCurrentId)
            throw new StaleEditException(currentId?.ToString() ?? "",
                "Someone saved a newer version of the brief. Read it, then confirm that one.");
        c.ConfirmBrief(_user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>INV-25: follows up one of the brief's open questions as a task (unowned, general; the analyst
    /// fills in the rest on the Tasks tab).</summary>
    /// <summary>
    /// RD-07: the composer's Question mode. Adds a question to the brief's open questions (a new brief version, so the
    /// earlier one stays readable) and, when <paramref name="followUp"/> is set, raises the task that follows it up, in
    /// one save. The question goes on its own list line, so it can be answered there when the task is done.
    /// </summary>
    public async Task AddOpenQuestionAsync(Guid caseId, string question, bool followUp, CancellationToken ct = default)
    {
        Require();
        var q = Content.MarkdownService.OneLine(question);
        if (q.StartsWith("- ", StringComparison.Ordinal)) q = q[2..].Trim();
        if (q.Length == 0) throw new ArgumentException("Write the question.");
        if (EntryFollowUps.TypedLength(q) > ActionItem.MaxTitleLength)   // BUG-481: as typed, not with its [[tags]] expanded
            throw new ArgumentException($"Keep the question to {ActionItem.MaxTitleLength} characters or fewer.");
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        await db.CaseBriefs.Where(b => b.CaseId == caseId && b.IsCurrent).ToListAsync(ct);
        var cur = c.Briefs.FirstOrDefault(b => b.IsCurrent);
        if (CaseNext.Questions(cur?.OpenQuestions)?.Any(x => string.Equals(x, q, StringComparison.OrdinalIgnoreCase)) == true)
            throw new InvalidOperationException("That question is already open in the brief.");
        var open = string.IsNullOrWhiteSpace(cur?.OpenQuestions) ? $"- {q}" : $"{cur!.OpenQuestions!.TrimEnd()}\n- {q}";
        var nextSteps = CaseNext.Snapshot(c, _clock.UtcNow, u => _users?.DisplayFor(u) ?? u);
        c.ReviseBrief(c.Summary, cur?.WorkingAssessment, cur?.Known, open, nextSteps, _user.UserId, _clock.UtcNow, appended: true);   // WF-30
        // The task's title is the question as plain text, which is how the brief pairs each question with its task.
        if (followUp) c.RaiseTaskFromQuestion(Content.MarkdownService.PlainLine(q), _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    public async Task RaiseTaskFromQuestionAsync(Guid caseId, string question, CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        await db.CaseBriefs.Where(b => b.CaseId == caseId && b.IsCurrent).ToListAsync(ct);
        c.RaiseTaskFromQuestion(question, _user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// INV-07: puts a note or a task comment on the investigation timeline, so it isn't
    /// retyped. <paramref name="sourceRef"/> is "note:&lt;id&gt;" or "taskcomment:&lt;id&gt;" and must be
    /// on this case; the new entry keeps it, and its <c>Source</c> names the kind. The text may be edited on the
    /// way (the source itself is unchanged). A Decision can't be made this way: it needs its why.
    /// </summary>
    public async Task PromoteToTimelineAsync(Guid caseId, string sourceRef, TimelineEntryType type,
        DateTimeOffset occurredAtUtc, string text, CancellationToken ct = default)
    {
        Require();
        var body = (text ?? "").Trim();
        if (body.Length == 0) throw new ArgumentException("There's nothing to add to the timeline.");
        if (body.Length > 8000) throw new ArgumentException("Keep the entry to 8,000 characters or fewer.");
        if (type == TimelineEntryType.Decision)
            throw new ArgumentException("Record a decision as a Decision entry on the timeline, with why it was made.");
        if (occurredAtUtc > _clock.UtcNow) throw new ArgumentException("The entry can't be dated in the future.");

        var parts = (sourceRef ?? "").Split(':', 2);
        if (parts.Length != 2 || !Guid.TryParse(parts[1], out var sourceId))
            throw new ArgumentException("That isn't something that can be added to the timeline.");

        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        var label = parts[0] switch
        {
            "note" when c.Notes.Any(n => n.Id == sourceId) => "Note",
            "taskcomment" when await db.ActionItemComments.AnyAsync(x => x.Id == sourceId && x.CaseId == caseId, ct) => "Task comment",
            _ => throw new InvalidOperationException("That note or comment isn't on this case.")
        };

        c.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c.Id, Kind = TimelineKind.Investigation, Type = type, OccurredAtUtc = occurredAtUtc,
            Description = body, Source = label, PromotedFrom = $"{parts[0]}:{sourceId}",
            CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
        });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// INV-08: completes a task, optionally recording its result. The time it was completed may be earlier than
    /// now (tasks are often ticked off after the fact) but not in the future or before the case was detected.
    /// A result is kept on the task as a comment and, when <paramref name="logAs"/> is given, also put on the
    /// investigation timeline as an entry of that type, dated at completion and linked to the task — so the
    /// work is written once. One save, one audited unit.
    /// </summary>
    /// <param name="knownLine">RD-10: a line to add to the brief's Known in the same save (a new brief version).</param>
    public async Task CompleteActionItemAsync(Guid caseId, Guid actionItemId, DateTimeOffset? completedAtUtc,
        string? result, TimelineEntryType? logAs, string? doneBy = null, string? knownLine = null, CancellationToken ct = default)
    {
        Require();
        var known = EntryFollowUps.Clean(knownLine);
        if (known is not null && EntryFollowUps.TypedLength(known) > 2000)   // BUG-481
            throw new ArgumentException("Keep the line for Known to 2,000 characters or fewer.");
        var text = string.IsNullOrWhiteSpace(result) ? null : result.Trim();
        var by = string.IsNullOrWhiteSpace(doneBy) ? _user.UserId : doneBy.Trim();
        if (by.Length > 200) throw new ArgumentException("Keep \"done by\" to 200 characters or fewer.");
        // BUG-105: the result is kept as "Result: <text>" in a comment column of 8,000.
        if (text is not null && text.Length > 8000 - TaskResults.Prefix.Length)
            throw new ArgumentException($"Keep the result to {8000 - TaskResults.Prefix.Length:N0} characters or fewer.");
        if (logAs is not null && text is null)
            throw new ArgumentException("Describe the result to add it to the timeline.");
        if (logAs == TimelineEntryType.Decision)
            throw new ArgumentException("Record a decision as a Decision entry on the timeline, with why it was made.");

        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        var item = c.ActionItems.FirstOrDefault(a => a.Id == actionItemId)
                   ?? throw new InvalidOperationException("Task not found.");
        // BUG-49: completing records who and when; doing it again would overwrite that and add a second result.
        if (item.Status == ActionItemStatus.Done) throw new InvalidOperationException("This task is already done.");
        if (item.Status == ActionItemStatus.Cancelled)
            throw new InvalidOperationException("This task was cancelled. Reopen it to mark it done.");
        // HR-02: a task that follows up a question in the brief is done when the question has an answer.
        if (item.FollowsUpQuestion && text is null)
            await EnsureQuestionAnsweredAsync(db, item, ct);
        var now = _clock.UtcNow;
        var at = completedAtUtc ?? now;
        if (at > now) throw new ArgumentException("A task can't be completed in the future.");
        if (c.DetectedAtUtc is { } detected && Case.ToMinute(at) < Case.ToMinute(detected))   // REV-16
            throw new ArgumentException("A task can't be completed before the case was detected.");

        item.Status = ActionItemStatus.Done;
        item.CompletedAtUtc = at;
        item.CompletedBy = by;
        item.CompletionRecordedAtUtc = now;   // BUG-364
        item.ModifiedBy = _user.UserId;
        item.ModifiedAtUtc = now;

        if (text is not null)
        {
            db.ActionItemComments.Add(new ActionItemComment
            {
                ActionItemId = item.Id, CaseId = c.Id, Body = TaskResults.Body(text), CreatedBy = _user.UserId, CreatedAtUtc = now
            });
            if (logAs is { } type)
                c.TimelineEntries.Add(new TimelineEntry
                {
                    CaseId = c.Id, Kind = TimelineKind.Investigation, Type = type, OccurredAtUtc = at,
                    Description = text, Source = TaskSource(item.Title), ActionItemId = item.Id,
                    CreatedBy = _user.UserId, CreatedAtUtc = now
                });
        }
        if (known is not null)
        {
            await db.CaseBriefs.Where(b => b.CaseId == c.Id && b.IsCurrent).ToListAsync(ct);
            var cur = c.Briefs.FirstOrDefault(b => b.IsCurrent);
            var newKnown = string.IsNullOrWhiteSpace(cur?.Known) ? $"- {known}" : $"{cur!.Known!.TrimEnd()}\n- {known}";
            c.ReviseBrief(c.Summary, cur?.WorkingAssessment, newKnown, cur?.OpenQuestions,
                CaseNext.Snapshot(c, now, u => _users?.DisplayFor(u) ?? u), _user.UserId, now, appended: true);   // WF-30
        }
        await db.SaveChangesAsync(ct);
    }

    // BUG-105: a timeline entry's source is 200 characters and a task title up to 400; the entry links to the task.
    private static string TaskSource(string title)
    {
        var source = $"Task: {title}";
        return source.Length <= 200 ? source : source[..199] + "…";
    }

    private const string QuestionNeedsAnswer =
        "This task follows up a question in the brief. Say what was found to mark it done.";

    // HR-02: a status change can't complete a question's task without an answer. An answer recorded before (the task
    // was reopened since) still counts; otherwise "Mark done" is the way to give one.
    private static async Task EnsureQuestionAnsweredAsync(IAppDbContext db, ActionItem item, CancellationToken ct)
    {
        if (!item.FollowsUpQuestion) return;
        var answered = await db.ActionItemComments.AsNoTracking()
            .AnyAsync(c => c.ActionItemId == item.Id && c.Body.StartsWith(TaskResults.Prefix), ct);
        if (!answered) throw new InvalidOperationException(QuestionNeedsAnswer);
    }

    public async Task SetActionItemStatusAsync(Guid caseId, Guid actionItemId, ActionItemStatus status,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        var item = c.ActionItems.FirstOrDefault(a => a.Id == actionItemId)
                   ?? throw new InvalidOperationException("Task not found.");
        // BUG-109: no change, nothing to record; Done again would overwrite who completed it and when.
        if (item.Status == status) return;
        // REV-23: as CompleteActionItemAsync refuses it. A cancellation (with its reason) isn't undone by marking done.
        if (status == ActionItemStatus.Done && item.Status == ActionItemStatus.Cancelled)
            throw new InvalidOperationException($"\"{item.Title}\" was cancelled. Reopen it to mark it done.");
        if (status == ActionItemStatus.Done)
            await EnsureQuestionAnsweredAsync(db, item, ct);
        item.Status = status;
        item.ModifiedBy = _user.UserId;
        item.ModifiedAtUtc = _clock.UtcNow;
        // Completed only while Done — reopening a task (back to Open/InProgress/Blocked) clears the
        // completion timestamp so it re-enters the open queues and metrics stay accurate.
        item.CompletedAtUtc = status == ActionItemStatus.Done ? _clock.UtcNow : null;
        item.CompletedBy = status == ActionItemStatus.Done ? _user.UserId : null;   // HR-02
        item.CompletionRecordedAtUtc = item.CompletedAtUtc;   // BUG-364
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// A map of a case's entity ids to a short display label (its friendly label, else its value). Used by
    /// the Audit tab to resolve reference fields (a timeline entry's Actor/Target) from an opaque GUID to a
    /// human name. Read-only and gated by case visibility (need-to-know); empty when the case isn't accessible.
    /// </summary>
    public async Task<IReadOnlyDictionary<Guid, string>> GetEntityLabelsAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        if (!await Scoped(db.Cases.AsNoTracking()).AnyAsync(x => x.Id == caseId, ct))
            return new Dictionary<Guid, string>();

        var rows = await db.CaseEntities.AsNoTracking()
            .Where(e => e.CaseId == caseId)
            .Select(e => new { e.Id, e.Label, e.Value })
            .ToListAsync(ct);

        return rows.ToDictionary(
            r => r.Id,
            r => string.IsNullOrWhiteSpace(r.Label) ? r.Value : $"{r.Label} ({r.Value})");
    }

    /// <summary>
    /// Edits a task's fields in one audited change (title, owner, due date, status, description) — the
    /// consolidated edit behind the Tasks tab's Edit button. Owner is a directory id, a free-text external
    /// name, or null/blank for Unassigned; a status away from Done clears the completion timestamp. Captured
    /// by the audit trail (before → after) like any structured-record edit.
    /// </summary>
    /// <param name="cancelReason">HR-17: when this edit cancels the task, why (optional); kept as a "Cancelled: …" comment
    /// on the task, so a later reader knows it was dropped on purpose.</param>
    /// <summary>
    /// Edits a task. BUG-196: <paramref name="expectedStamp"/> is the task's row hash as the editor (or the row) showed it
    /// (empty for a task without one); every field is written from the form, so if someone changed the task since, the
    /// edit is refused with <see cref="StaleEditException"/> rather than silently undoing their change (a completion, an
    /// owner). Null skips the check.
    /// </summary>
    public async Task UpdateActionItemAsync(Guid caseId, Guid actionItemId, string title, string? owner,
        DateTimeOffset? dueAtUtc, ActionItemStatus status, string? description, TaskKind? kind = null,
        string? cancelReason = null, string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        var cleanTitle = (title ?? "").Trim();
        if (string.IsNullOrWhiteSpace(cleanTitle)) throw new ArgumentException("A task needs a title.");
        // BUG-50: the same limits as adding a task (and the columns), so an edit can't fail on save.
        if (cleanTitle.Length > ActionItem.MaxTitleLength)
            throw new ArgumentException($"Keep the task to {ActionItem.MaxTitleLength} characters or fewer.");
        var cleanOwner = CleanTaskOwner(owner);
        var cleanDescription = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        if (cleanDescription is { Length: > ActionItem.MaxDescriptionLength })
            throw new ArgumentException($"Keep the description to {ActionItem.MaxDescriptionLength:N0} characters or fewer.");

        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        var item = c.ActionItems.FirstOrDefault(a => a.Id == actionItemId)
                   ?? throw new InvalidOperationException("Task not found.");
        if (expectedStamp is not null && !string.Equals(item.RowHash ?? "", expectedStamp, StringComparison.Ordinal))
            throw new StaleEditException(item.RowHash ?? "", "Someone changed this task since you opened it, so your edit " +
                "wasn't saved. It has been reloaded with their change; make yours again.");

        // BUG-577: a due being set is bounded; one stored before the bound, left as it was, doesn't stop other edits.
        if (dueAtUtc != item.DueAtUtc) CheckDue(dueAtUtc);
        var wasStatus = item.Status;
        // BUG-304 (owner's decision): Edit follows the same rule as Complete and the status buttons (REV-23): a cancelled
        // task is reopened before it's marked done, so its result and who completed it are recorded as for any other.
        if (status == ActionItemStatus.Done && wasStatus == ActionItemStatus.Cancelled)
            throw new InvalidOperationException($"\"{item.Title}\" was cancelled. Reopen it to mark it done.");
        item.Title = cleanTitle;
        item.Owner = cleanOwner;
        item.DueAtUtc = dueAtUtc;
        item.Description = cleanDescription;
        if (status == ActionItemStatus.Done && item.Status != ActionItemStatus.Done)
            await EnsureQuestionAnsweredAsync(db, item, ct);
        item.CompletedBy = status == ActionItemStatus.Done ? (item.Status == ActionItemStatus.Done ? item.CompletedBy : _user.UserId) : null;   // HR-02
        item.Status = status;
        item.CompletedAtUtc = status == ActionItemStatus.Done ? (item.CompletedAtUtc ?? _clock.UtcNow) : null;
        // BUG-364: kept while it stays done, set when it becomes done, cleared when it leaves.
        item.CompletionRecordedAtUtc = status != ActionItemStatus.Done ? null
            : wasStatus == ActionItemStatus.Done ? item.CompletionRecordedAtUtc : _clock.UtcNow;
        if (kind is { } k) item.Kind = k;
        item.ModifiedBy = _user.UserId;
        item.ModifiedAtUtc = _clock.UtcNow;
        if (status == ActionItemStatus.Cancelled && wasStatus != ActionItemStatus.Cancelled && !string.IsNullOrWhiteSpace(cancelReason))
        {
            var why = cancelReason.Trim();
            if (why.Length > 2000) throw new ArgumentException("Keep the reason to 2,000 characters or fewer.");
            db.ActionItemComments.Add(new ActionItemComment
            {
                ActionItemId = item.Id, CaseId = c.Id, Body = CancelledPrefix + why, CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
            });
        }
        await db.SaveChangesAsync(ct);
    }

    // A task's owner: a directory id or an external name, null for Unassigned. BUG-50: within the column.
    private static string? CleanTaskOwner(string? owner)
    {
        var o = string.IsNullOrWhiteSpace(owner) ? null : owner.Trim();
        if (o is { Length: > ActionItem.MaxOwnerLength })
            throw new ArgumentException($"Keep the owner to {ActionItem.MaxOwnerLength} characters or fewer.");
        return o;
    }

    /// <summary>BUG-577: the earliest and latest due a task takes (years 2 to 9998, as BUG-475's month filter). A due
    /// typed as 9999-12-31 sat at the end of the calendar, where the agenda, the feed and the reminders add to it.</summary>
    public static readonly DateTimeOffset EarliestDueUtc = new(2, 1, 1, 0, 0, 0, TimeSpan.Zero);
    public static readonly DateTimeOffset LatestDueUtc = new(9998, 12, 31, 23, 59, 59, TimeSpan.Zero);

    private static void CheckDue(DateTimeOffset? dueAtUtc, string? title = null)
    {
        if (dueAtUtc is { } due && (due < EarliestDueUtc || due > LatestDueUtc))
            throw new ArgumentException((title is null ? "That due date" : $"The due date of \"{title}\"")
                + " is outside the range a task can take (the years 2 to 9998). Pick another date.");
    }

    /// <summary>HR-17: how a cancelled task's reason is kept (a task comment).</summary>
    public const string CancelledPrefix = "Cancelled: ";

    /// <summary>Reassigns a task's owner. A directory user id or free-text external name, or null/blank
    /// to leave it Unassigned. Change is audited/hash-chained like any other edit.</summary>
    public async Task SetActionItemOwnerAsync(Guid caseId, Guid actionItemId, string? owner,
        CancellationToken ct = default)
    {
        Require();
        using var db = _factory.CreateDbContext();
        var c = await LoadTrackedAsync(db, caseId, ct);
        var item = c.ActionItems.FirstOrDefault(a => a.Id == actionItemId)
                   ?? throw new InvalidOperationException("Task not found.");
        item.Owner = CleanTaskOwner(owner);
        item.ModifiedBy = _user.UserId;
        item.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }
}
