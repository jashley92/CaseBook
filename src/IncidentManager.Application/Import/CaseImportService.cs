using System.Globalization;
using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using IncidentManager.Application.Common;

namespace IncidentManager.Application.Import;

/// <summary>
/// PROD-31: ingests a structured <see cref="CaseImportDocument"/> into a new or existing case as a
/// human-confirmed draft. Parsing and preview-building are pure (and treat the document as untrusted:
/// validate, clamp, fall back on unknown enums, dedupe), so they unit-test without a database. Apply
/// resolves/creates the target and then reuses the already-guarded, already-audited <see cref="CaseService"/>
/// write methods — so the F-21 permission checks and the audit/hash chain come for free. Each write is its
/// own transaction/chain-append (there is no atomic multi-write), so apply is <b>resume-safe</b> like
/// <c>CreateCase.Submit</c>: it records what it has applied on the preview and skips it on a retry.
/// </summary>
public sealed class CaseImportService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly CaseService _cases;

    private readonly IAuditWriter? _audit;   // WF-18

    // CAP-01: who's told when a submission arrives, and the open pages' badges. CAP-06: the SIEM.
    private readonly ICaseNotifications? _notifications;
    private readonly IUserDirectory? _users;
    private readonly IRoleDirectory? _roles;
    private readonly Notifications.ReminderAudience? _audience;
    private readonly PendingImportSignal? _signal;
    private readonly ISecurityEventSink? _siem;
    private readonly ILogger<CaseImportService>? _log;   // CAP-01 review: the reviewers' notice, told in the background

    public CaseImportService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, CaseService cases,
        IAuditWriter? audit = null, ICaseNotifications? notifications = null, IUserDirectory? users = null,
        IRoleDirectory? roles = null, Notifications.ReminderAudience? audience = null, PendingImportSignal? signal = null,
        ISecurityEventSink? siem = null, ILogger<CaseImportService>? log = null)
    {
        _log = log;
        _audit = audit;
        _factory = factory;
        _user = user;
        _clock = clock;
        _cases = cases;
        _notifications = notifications;
        _users = users;
        _roles = roles;
        _audience = audience;
        _signal = signal;
        _siem = siem;
    }

    // Defensive caps for untrusted text — matched to the create validator where one exists.
    private const int MaxTitle = 300;
    private const int MaxDescriptiveName = 120;
    private const int MaxSummary = 8000;
    private const int MaxDescription = 8000;
    // BUG-02: the limits below match the database columns, which SQL Server enforces (SQLite doesn't).
    private const int MaxEntityDescription = 4000;
    private const int MaxSource = 200;
    private const int MaxValue = 2000;   // BUG-175: CaseEntities.Value

    /// <summary>BUG-202: the most of each a document can carry (indicators as for an IOC file).</summary>
    public const int MaxEntities = IocImportConverter.MaxIndicators, MaxTimelineEntries = 1000, MaxActionItems = 500;

    private static string? TooMany(CaseImportDocument doc)
    {
        string? Over(int? count, int max, string what) => count > max
            ? $"This document has {count:N0} {what}; one import takes up to {max:N0}, so a reviewer can check what's applied. Split it into several documents."
            : null;
        return Over(doc.Entities?.Count, MaxEntities, "indicators")
               ?? Over(doc.Timeline?.Count, MaxTimelineEntries, "timeline entries")
               ?? Over(doc.ActionItems?.Count, MaxActionItems, "tasks");
    }
    private const int MaxLabel = 300;
    private const int MaxOwner = 200;

    /// <summary>The longest reject reason (<c>PendingImports.DecisionNote</c>) and queue summary (<c>.Summary</c>).</summary>
    public const int MaxDecisionNoteLength = 2000, MaxQueueSummaryLength = 300;

    /// <summary>Parses import JSON, guarding format and schema version. Never throws on bad input — returns a
    /// friendly <see cref="CaseImportParse.Error"/> instead, so the UI/API can show it.</summary>
    /// <param name="unzonedIn">BUG-636: the zone of times written without an offset when the document doesn't name one
    /// (<c>timeZone</c>). The API leaves it null, so such times are UTC as the schema says; the import page passes the
    /// zone the reviewer picked.</param>
    public static CaseImportParse Parse(string? json, TimeZoneInfo? unzonedIn = null)
    {
        if (string.IsNullOrWhiteSpace(json))
            return CaseImportParse.Fail("Paste or upload a case-import document first.");

        // BUG-636: the document's own zone, read first, wins over the one the caller offers.
        var zone = unzonedIn ?? TimeZoneInfo.Utc;
        if (StatedTimeZone(json) is { } stated)
        {
            if (!TimeZoneInfo.TryFindSystemTimeZoneById(stated, out var named))
                return CaseImportParse.Fail($"Unknown \"timeZone\": \"{stated}\". Use a zone id such as America/New_York, Europe/London or UTC.");
            zone = named;
        }
        var times = new CaseImportJson.UtcUnlessStated(zone);
        // CA1869: deliberately per parse: the converter records which times this document wrote without a zone
        // (UnzonedTimes), so a shared options instance would mix documents' state across concurrent parses.
#pragma warning disable CA1869
        var options = new JsonSerializerOptions(CaseImportJson.Options);
#pragma warning restore CA1869
        options.Converters.Clear();
        options.Converters.Add(times);

        CaseImportDocument? doc;
        try
        {
            doc = JsonSerializer.Deserialize<CaseImportDocument>(json, options);
        }
        catch (JsonException ex)
        {
            return CaseImportParse.Fail(IocImportConverter.InvalidJson(ex));
        }

        if (doc is null)
            return CaseImportParse.Fail("This isn't a case-import document.");
        if (!string.Equals(doc.Format, CaseImportJson.FormatTag, StringComparison.Ordinal))
            return CaseImportParse.Fail(
                $"This isn't a CaseBook case-import document (expected \"format\": \"{CaseImportJson.FormatTag}\").");
        if (doc.SchemaVersion is { } v && v > CaseImportJson.CurrentSchemaVersion)
            return CaseImportParse.Fail(
                $"This document is schema v{v}, newer than this app supports (v{CaseImportJson.CurrentSchemaVersion}). Upgrade CaseBook first.");
        // BUG-202: the same limits a reviewer can check by eye; a bigger set is split across documents.
        if (TooMany(doc) is { } tooMany) return CaseImportParse.Fail(tooMany);

        if (FoldTimeNames(doc) is { } clash) return CaseImportParse.Fail(clash);   // BUG-663
        return CaseImportParse.Success(doc) with { UnzonedTimes = times.Unzoned, UnzonedZone = zone };
    }

    /// <summary>
    /// BUG-663: each time may be written under its preferred name (occurredAt, occurredUntil, detectedAt, dueAt) or the
    /// v1 one ending in "Utc". The preferred one is copied onto the old property, which the rest of the import reads. A
    /// document that gives both for the same time is refused, so there's no doubt which counts.
    /// </summary>
    private static string? FoldTimeNames(CaseImportDocument doc)
    {
        static string? Fold(DateTimeOffset? preferred, DateTimeOffset? legacy, string name, string where, Action<DateTimeOffset?> set)
        {
            if (preferred is null) return null;
            if (legacy is not null)
                return $"{where} gives both \"{name}\" and \"{name}Utc\". Give one: \"{name}\" (\"{name}Utc\" is its old name).";
            set(preferred);
            return null;
        }

        if (doc.Target?.NewCase is { } nc)
        {
            if (Fold(nc.DetectedAt, nc.DetectedAtUtc, "detectedAt", "The new case", v => nc.DetectedAtUtc = v) is { } e1) return e1;
            if (Fold(nc.OccurredAt, nc.OccurredAtUtc, "occurredAt", "The new case", v => nc.OccurredAtUtc = v) is { } e2) return e2;
        }
        for (var i = 0; i < (doc.Timeline?.Count ?? 0); i++)
        {
            if (doc.Timeline![i] is not { } t) continue;   // a null row is skipped (and counted) later
            var where = $"Timeline entry {i + 1}";
            if (Fold(t.OccurredAt, t.OccurredAtUtc, "occurredAt", where, v => t.OccurredAtUtc = v) is { } e3) return e3;
            if (Fold(t.OccurredUntil, t.OccurredUntilUtc, "occurredUntil", where, v => t.OccurredUntilUtc = v) is { } e4) return e4;
        }
        for (var i = 0; i < (doc.ActionItems?.Count ?? 0); i++)
        {
            if (doc.ActionItems![i] is not { } a) continue;
            if (Fold(a.DueAt, a.DueAtUtc, "dueAt", $"Task {i + 1}", v => a.DueAtUtc = v) is { } e5) return e5;
        }
        return null;
    }

    // The top-level "timeZone", if the document has one (null when it doesn't, or isn't JSON; Deserialize reports that).
    private static string? StatedTimeZone(string json)
    {
        try
        {
            using var d = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            if (d.RootElement.ValueKind != JsonValueKind.Object) return null;
            foreach (var p in d.RootElement.EnumerateObject())
                if (string.Equals(p.Name, "timeZone", StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.String)
                    return string.IsNullOrWhiteSpace(p.Value.GetString()) ? null : p.Value.GetString()!.Trim();
            return null;
        }
        catch (JsonException) { return null; }
    }

    /// <summary>
    /// Builds the editable preview. When <paramref name="intoCaseId"/> (or the document's target case) resolves
    /// to a case the user can see, the target is that existing case; otherwise a new case is prepared from the
    /// document. Row validation/clamping is pure (<see cref="BuildPreviewCore"/>); only target resolution hits
    /// the database (need-to-know scoped).
    /// </summary>
    public Task<CaseImportPreview> BuildPreviewAsync(CaseImportDocument doc, Guid? intoCaseId = null,
        CancellationToken ct = default) => PreviewAsync(doc, intoCaseId, resolveDetection: true, ct);

    /// <param name="resolveDetection">CAP-14: false for a submission's own preview (the API's response and the queued row):
    /// a detection case id is resolved under the reviewer when it's reviewed, never under the producer's token, whose view of
    /// the cases isn't the reviewer's (the BUG-279 lesson). The preview then names it in <see cref="CaseImportPreview.DetectionCaseId"/>.</param>
    private async Task<CaseImportPreview> PreviewAsync(CaseImportDocument doc, Guid? intoCaseId, bool resolveDetection,
        CancellationToken ct)
    {
        var preview = BuildPreviewCore(doc, _clock.UtcNow);
        // BUG-542: REV-14, as CreateCase offers it: a rung this user can't file is dropped here, so the import page and the
        // API's preview agree, and Apply doesn't fail as Forbidden. A reviewer previews a queued one again under their role.
        if (preview.NewCase is { Classification: { } cls } nc && !_user.Has(Permission.ChangeClassification))
        {
            nc.Classification = null;
            var label = Admin.TaxonomyCatalog.DefaultLabel("Classification", cls.ToString());
            preview.Warnings.Add($"The document files this as {label}, a classification your role can't file, so it's prepared as " +
                                 "a Complex Event. Someone who can change a case's classification promotes it onto the ladder.");
        }

        var existingId = intoCaseId ?? doc.Target?.CaseId;
        if (existingId is { } id)
        {
            var found = await ResolveCaseAsync(id, ct);
            if (found is { } c)
            {
                preview.TargetKind = CaseImportTargetKind.ExistingCase;
                preview.ExistingCaseId = c.Id;
                preview.ExistingCaseNumber = c.CaseNumber;
                preview.ExistingTitle = c.Title;
                // Keep NewCase populated so the UI can toggle back to a new-case target without a rebuild.
            }
            else
            {
                preview.Warnings.Add("The target case wasn't found or isn't visible to you, so a new case was prepared instead.");
            }
        }
        else if (DetectionTarget(doc, preview.Warnings) is { } detection)
        {
            if (resolveDetection) await ResolveDetectionAsync(preview, detection, ct);
            else
            {
                preview.DetectionCaseId = detection;
                preview.Warnings.Add($"This adds to the open case carrying detection case id \"{detection}\". Which case that is is " +
                                     "decided when it's reviewed, among the cases the reviewer can see; with none, a new case is prepared.");
            }
        }

        // CAP-35: the team is matched to the directory, and the outcome checked, as it's reviewed. A history belongs to the
        // new case it describes: one going into an existing case (by id, or by detection case id, CAP-14) leaves it out.
        if (preview.HasHistory || preview.Outcome is not null)
        {
            ResolveTeam(preview);
            await CheckOutcomeAsync(preview, ct);
            if (preview.TargetKind == CaseImportTargetKind.ExistingCase)
                preview.Warnings.Add("The document's history, outcome and team describe a new case, so they aren't applied to an " +
                                     "existing one. Choose a new case as the target to import them.");
        }
        return preview;
    }

    /// <summary>CAP-14: the most cases one detection case id is matched against; past it, the reviewer is told there are more.</summary>
    private const int MaxDetectionMatches = 5;

    // CAP-14: the document's target.detectionCaseId, trimmed; null when there's none, or one longer than any case can carry.
    private static string? DetectionTarget(CaseImportDocument doc, List<string>? warnings = null)
    {
        var d = doc.Target?.DetectionCaseId?.Trim();
        if (string.IsNullOrEmpty(d)) return null;
        if (d.Length <= CaseImportSchema.MaxDetectionCaseId) return d;
        warnings?.Add($"The target's detection case id is longer than {CaseImportSchema.MaxDetectionCaseId} characters, so no case " +
                      "carries it. It was ignored.");
        return null;
    }

    // CAP-14: the one open case carrying the id becomes the target. None leaves the new case the document describes; several
    // leave the choice to the reviewer, naming them. All as the current user (the reviewer) sees cases.
    private async Task ResolveDetectionAsync(CaseImportPreview preview, string detection, CancellationToken ct)
    {
        var matches = await FindOpenByDetectionIdAsync(detection, ct);
        if (matches.Count == 1)
        {
            preview.TargetKind = CaseImportTargetKind.ExistingCase;
            (preview.ExistingCaseId, preview.ExistingCaseNumber, preview.ExistingTitle) = matches[0];
            return;
        }
        if (matches.Count == 0)
        {
            preview.Warnings.Add($"No open case you can see carries detection case id \"{detection}\", so a new case was prepared. " +
                                 "If it belongs in a case, choose that case as the target.");
            return;
        }
        preview.TargetKind = CaseImportTargetKind.ExistingCase;
        var named = string.Join(", ", matches.Take(MaxDetectionMatches).Select(m => m.CaseNumber));
        preview.Warnings.Add($"More than one open case you can see carries detection case id \"{detection}\" ({named}" +
                             (matches.Count > MaxDetectionMatches ? ", and more" : "") + "). Choose the case to add to.");
    }

    /// <summary>
    /// CAP-14: the open (not closed, not archived) cases the current user can see that carry <paramref name="detectionCaseId"/>
    /// as their detection case id, compared as <see cref="SameDetectionId"/> does on either database; at most one more than
    /// <see cref="MaxDetectionMatches"/>.
    /// </summary>
    public async Task<IReadOnlyList<(Guid Id, string CaseNumber, string Title)>> FindOpenByDetectionIdAsync(string detectionCaseId,
        CancellationToken ct = default)
    {
        var detection = detectionCaseId.Trim();
        if (detection.Length == 0) return [];
        // CAP-14 review: the database narrows, then SameDetectionId decides, so SQLite, SQL Server and CheckTargetAsync agree.
        // Trimmed of spaces on both sides (an id saved before CaseService trimmed it can carry a stray space; SQL Server's =
        // ignores a trailing one and SQLite's doesn't; SQL TRIM strips U+0020 only, as SameDetectionId does). SQLite's upper()
        // folds ASCII only and SQL Server's folds Unicode, so the key is offered both ways: each database's own fold of a
        // matching id equals one of them.
        var ascii = AsciiUpper(detection);
        var full = detection.ToUpperInvariant();
        using var db = _factory.CreateDbContext();
#pragma warning disable CA1304, CA1311, CA1862 // UPPER() in SQL; the culture overloads don't translate
        var found = await db.Cases.AsNoTracking().ForUser(_user)
            .Where(c => c.Phase != CasePhase.Closed && !c.IsArchived && c.DetectionCaseId != null
                        && (c.DetectionCaseId.Trim().ToUpper() == ascii || c.DetectionCaseId.Trim().ToUpper() == full))
#pragma warning restore CA1304, CA1311, CA1862
            .OrderBy(c => c.CaseNumber)
            .Select(c => new { c.Id, c.CaseNumber, c.Title, c.DetectionCaseId })
            .Take(MaxDetectionCandidates)
            .ToListAsync(ct);
        return found.Where(c => SameDetectionId(c.DetectionCaseId, detection))
            .Take(MaxDetectionMatches + 1)
            .Select(c => (c.Id, c.CaseNumber, c.Title)).ToList();
    }

    // CAP-14 review: what the database's narrowing may return before SameDetectionId decides (bounded, C10; a looser fold
    // on SQL Server can let a near-miss through, never drop a match).
    private const int MaxDetectionCandidates = 50;

    /// <summary>
    /// CAP-14 review: whether two detection case ids are the same id: trimmed of spaces, ASCII letters compared without regard
    /// to case, every other character exactly (as SQLite's <c>upper()</c> folds, so the database and this agree on both providers).
    /// </summary>
    /// <remarks>
    /// Only U+0020 is trimmed, because that is all SQL <c>TRIM</c> strips on either database, so an id stored with other
    /// whitespace at an end (a no-break space, a tab) matches on neither path. Every write path trims all whitespace, so only an
    /// old row can carry one; normalising those rows instead would change Case's canonical hash (it includes the detection
    /// case id), so they are left as written and simply don't match until the case's details are saved again.
    /// </remarks>
    public static bool SameDetectionId(string? a, string? b) =>
        a is not null && b is not null && string.Equals(AsciiUpper(a.Trim(' ')), AsciiUpper(b.Trim(' ')), StringComparison.Ordinal);

    private static string AsciiUpper(string s) => string.Create(s.Length, s, static (span, src) =>
    {
        for (var i = 0; i < src.Length; i++) span[i] = char.IsAsciiLetterLower(src[i]) ? (char)(src[i] - 32) : src[i];
    });

    /// <summary>
    /// CAP-14: why the document's target can't be used, or null. <c>target.caseId</c> and <c>target.detectionCaseId</c> given
    /// together must name the same case, so one that carries a different detection case id (or none) is refused, before
    /// anything is queued or previewed. A case id the caller can't see isn't judged here: it previews as a new case, as before
    /// (BUG-279), and its detection case id goes with it.
    /// </summary>
    public async Task<string?> CheckTargetAsync(CaseImportDocument doc, CancellationToken ct = default)
    {
        if (doc.Target?.CaseId is not { } id || DetectionTarget(doc) is not { } detection) return null;
        using var db = _factory.CreateDbContext();
        var target = await db.Cases.AsNoTracking().ForUser(_user).Where(c => c.Id == id)
            .Select(c => new { c.CaseNumber, c.DetectionCaseId }).FirstOrDefaultAsync(ct);
        if (target is null || SameDetectionId(target.DetectionCaseId, detection)) return null;   // CAP-14 review: as FindOpenByDetectionIdAsync
        return $"target.caseId and target.detectionCaseId name different cases: {target.CaseNumber} carries " +
               (string.IsNullOrWhiteSpace(target.DetectionCaseId) ? "no detection case id" : $"detection case id \"{target.DetectionCaseId.Trim()}\"") +
               $", not \"{detection}\". Give one of them.";
    }

    /// <summary>
    /// CAP-35: why a v2 document's history can't be applied (out of order, before detection, in the future, a close
    /// without its outcome), or null. The API refuses such a document before queueing it, so the producer hears at once.
    /// </summary>
    public string? CheckHistory(CaseImportDocument doc) => BuildPreviewCore(doc, _clock.UtcNow).HistoryProblem;

    /// <summary>Resolves a case the current user is allowed to see, by id — for the existing-case target.</summary>
    public async Task<(Guid Id, string CaseNumber, string Title)?> ResolveCaseAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var c = await db.Cases.AsNoTracking().ForUser(_user)
            .Where(x => x.Id == id)
            .Select(x => new { x.Id, x.CaseNumber, x.Title })
            .FirstOrDefaultAsync(ct);
        return c is null ? null : (c.Id, c.CaseNumber, c.Title);
    }

    /// <summary>Resolves a visible case by its case number — for entering an existing target on the import page.</summary>
    public async Task<(Guid Id, string CaseNumber, string Title)?> ResolveCaseByNumberAsync(string caseNumber,
        CancellationToken ct = default)
    {
        var n = caseNumber?.Trim();
        if (string.IsNullOrEmpty(n)) return null;
        using var db = _factory.CreateDbContext();
        var c = await db.Cases.AsNoTracking().ForUser(_user)
            .Where(x => x.CaseNumber == n)
            .Select(x => new { x.Id, x.CaseNumber, x.Title })
            .FirstOrDefaultAsync(ct);
        return c is null ? null : (c.Id, c.CaseNumber, c.Title);
    }

    /// <summary>
    /// Applies the confirmed preview: creates the case if the target is new, then writes each included item via
    /// <see cref="CaseService"/>. Resume-safe — records progress on the preview so a retry after a mid-apply
    /// failure never duplicates. Provenance (<see cref="CaseImportPreview.Origin"/> or a row's own source) is
    /// stamped on imported entities and timeline entries.
    /// </summary>
    /// <param name="pendingImportId">CAP-06: the queued submission being applied, named in the SIEM event; null for a
    /// document pasted or uploaded on the Import page.</param>
    public async Task<CaseImportResult> ApplyAsync(CaseImportPreview p, Guid? pendingImportId = null, CancellationToken ct = default)
    {
        // INV-18: checked before anything is written, so a missing why can't leave a half-applied import.
        if (p.Timeline.Any(t => t.Include && t.Type == TimelineEntryType.Decision && string.IsNullOrWhiteSpace(t.Rationale)))
            throw new ArgumentException("A decision on the timeline needs its why. Add it, or change the entry's type.");
        // CAP-35: a history that breaks R4's checks is refused before anything is written.
        if (p.TargetKind == CaseImportTargetKind.NewCase && p.HistoryProblem is { } historyProblem)
            throw new ArgumentException(historyProblem);
        // CAP-35 review: and checked again as of now, by the domain's own rules and against the close gate as it stands, so a
        // gate tightened (or a minute passed) since the preview refuses here rather than leaving a half-applied case.
        if (p.TargetKind == CaseImportTargetKind.NewCase && p.History.Any(h => !h.Applied) && p.NewCase?.DetectedAtUtc is { } detectedAt
            && (ReplayHistory(p.History, detectedAt, _clock.UtcNow) ?? await CloseGateProblemAsync(p, ct)) is { } nowRefused)
            throw new ArgumentException(nowRefused);

        Guid caseId;
        string caseNumber;
        var created = false;

        if (p.TargetKind == CaseImportTargetKind.ExistingCase)
        {
            caseId = p.ExistingCaseId ?? throw new InvalidOperationException("No target case was selected.");
            caseNumber = p.ExistingCaseNumber ?? string.Empty;
        }
        else
        {
            var req = p.NewCase ?? throw new InvalidOperationException("New-case details are required.");
            if (p.CreatedCaseId is null)
            {
                var c = await _cases.CreateAsync(req, ct);   // validates + is F-21 guarded + audited
                p.CreatedCaseId = c.Id;
                p.ExistingCaseNumber = c.CaseNumber;         // reuse for the result/label
                created = true;
            }
            caseId = p.CreatedCaseId.Value;
            caseNumber = p.ExistingCaseNumber ?? string.Empty;
        }

        var origin = string.IsNullOrWhiteSpace(p.Origin) ? null : p.Origin.Trim();

        var notes = 0;
        if (p.IncludeSummary && !p.SummaryApplied && !string.IsNullOrWhiteSpace(p.Summary))
        {
            await _cases.AddNoteAsync(caseId, p.Summary!, ct: ct);
            p.SummaryApplied = true;
        }
        if (p.SummaryApplied) notes = 1;

        var timeline = 0;
        Guid? lastStep = null;   // ST-03: a step with no stated time follows the step before it in the document
        // BUG-118: a not-stated step that opens the document, on a case with no steps yet, is placed by the earliest time
        // the document does state, not by when it's imported (which would put it after the steps it comes before).
        // BUG-174: as each will be stored: a date-only step at its date's anchor (12:00 UTC), not the time the document wrote.
        var firstStated = p.Timeline.Where(x => x.Include && x.Kind == TimelineKind.Event && x.Precision != TimePrecision.NotStated)
            .Select(x => (DateTimeOffset?)(x.Precision is TimePrecision.Day or TimePrecision.OnOrBefore or TimePrecision.Window
                ? StepTiming.DateAnchor(x.OccurredAtUtc) : x.OccurredAtUtc)).Min();
        // BUG-255: in batches (one case load and one audited save each), not a whole-case reload, save and live publish per
        // entry. The rows still to apply keep their order; a not-stated step follows the step before it in the document.
        var included = p.Timeline.Where(t => t.Include).ToList();
        var pending = new List<(ImportTimelineRow Row, CaseService.TimelineToAdd Item)>();
        var stepBefore = false;   // a step before this one (applied last time, or pending) for a not-stated one to follow
        foreach (var t in included)
        {
            // BUG-15: on a retry, a step applied last time is still the one the next not-stated step follows.
            if (t.Applied)
            {
                if (pending.Count == 0 && t.Kind == TimelineKind.Event && t.AppliedId is { } before) lastStep = before;
                if (t.Kind == TimelineKind.Event) stepBefore = true;
                continue;
            }
            var precision = t.Kind == TimelineKind.Event ? t.Precision : TimePrecision.Exact;
            StepTiming? timing = precision switch
            {
                TimePrecision.Exact => null,
                TimePrecision.Window => new StepTiming(TimePrecision.Window, t.OccurredUntilUtc),
                TimePrecision.NotStated => null,   // placed after the step before it, in the batch
                _ => new StepTiming(precision)
            };
            var when = precision == TimePrecision.NotStated && !stepBefore && firstStated is { } earliest
                ? earliest : t.OccurredAtUtc;
            pending.Add((t, new CaseService.TimelineToAdd(t.Kind, t.Type, when, t.Description, t.Source ?? origin,
                t.Type == TimelineEntryType.Decision ? new CaseService.DecisionDetails(t.Rationale ?? "", t.OptionsConsidered, t.DecidedBy) : null,
                timing, FollowsPrevious: precision == TimePrecision.NotStated)));
            if (t.Kind == TimelineKind.Event) stepBefore = true;
        }
        var next = 0;
        await _cases.AddImportedTimelineEntriesAsync(caseId, pending.Select(x => x.Item).ToList(), lastStep, ids =>
        {
            foreach (var id in ids)
            {
                pending[next].Row.AppliedId = id;
                pending[next].Row.Applied = true;
                next++;
            }
        }, ct);
        timeline = included.Count;

        // BUG-202: in batches (one load and one audited save each), not a whole-case reload and save per indicator. A
        // batch's items are marked applied once it's saved; matching makes a retry of an unsaved one harmless anyway.
        var includedEntities = p.Entities.Where(e => e.Include).ToList();
        // BUG-420: one directory allowance for the whole import, not one per batch.
        var capture = new Accounts.AccountDirectoryService.CaptureAllowance();
        foreach (var batch in includedEntities.Where(e => !e.Applied).Chunk(CaseService.EntitiesPerSave))
        {
            // BUG-152: the document's marking is kept, and only ever raises one the case already has.
            await _cases.AddOrMatchEntitiesAsync(caseId, batch.Select(e => new CaseService.EntityToAdd(e.Type, e.Value, e.Label,
                e.Disposition, e.Description, e.Source ?? origin, e.Tlp)).ToList(), "Set by import", capture, ct);   // WF-29
            foreach (var e in batch) e.Applied = true;
        }
        var entities = includedEntities.Count;

        // BUG-255: tasks in batches too.
        var tasks = p.ActionItems.Where(a => a.Include).ToList();
        var todo = tasks.Where(a => !a.Applied).ToList();
        var done = 0;
        await _cases.AddImportedActionItemsAsync(caseId, todo.Select(a => (a.Title, a.Owner, a.DueAtUtc)).ToList(), n =>
        {
            foreach (var a in todo.Skip(done).Take(n)) a.Applied = true;
            done += n;
        }, ct);
        var actionItems = tasks.Count;

        // CAP-35: the team, then the history, last, so a case that closes does so with its content in (and nothing reads as
        // added after closure).
        if (p.TargetKind == CaseImportTargetKind.NewCase) await ApplyHistoryAsync(p, caseId, ct);

        await EmitAppliedAsync(caseId, pendingImportId, p.CreatedCaseId is not null, ct);
        return new CaseImportResult(caseId, caseNumber, created, notes, timeline, entities, actionItems);
    }

    // CAP-06: the import's SIEM event (5515), naming the case as it now stands (scoped: the reviewer just wrote to it).
    private async Task EmitAppliedAsync(Guid caseId, Guid? pendingImportId, bool createdCase, CancellationToken ct)
    {
        if (_siem is null) return;
        using var db = _factory.CreateDbContext();
        var c = await db.Cases.AsNoTracking().ForUser(_user).Where(x => x.Id == caseId)
            .Select(x => new { x.CaseNumber, x.DetectionCaseId, x.IsExercise }).FirstOrDefaultAsync(ct);
        if (c is null) return;
        _siem.EmitSafely(() => SecurityEvents.ImportApplied(new CaseSubject(c.CaseNumber, c.DetectionCaseId, c.IsExercise),
            pendingImportId, createdCase, _user.UserId, _user.UserPrincipalName));
    }

    /// <summary>
    /// CAP-35: the team and the history of a new case, through the audited, permission-checked writes, as the confirmer.
    /// Each phase change goes through <see cref="CaseService.ChangePhaseAsync"/> at its effective time (decisions 0010,
    /// 0011), so the contained, resolved and closed milestones derive from it as for a change made in CaseBook. A close
    /// runs the close gate; when its checks can't be met, it's overridden with "imported record: &lt;origin&gt;", so the
    /// passage records that it was. Resume-safe: each written step is marked applied.
    /// </summary>
    private async Task ApplyHistoryAsync(CaseImportPreview p, Guid caseId, CancellationToken ct)
    {
        // CAP-35 review: the team is added quietly for a history that closes the case: a record of work finished elsewhere
        // isn't an assignment to act on, so nobody is emailed "you've been assigned" to a closed case. One that stays open is
        // work in hand, so its incident commander and team are told, as for any assignment.
        var notify = !p.ClosesCase;
        foreach (var who in (p.IncidentCommander is { } ic ? [ic] : Array.Empty<ImportAssignmentRow>()).Concat(p.Assignments))
        {
            if (who.Applied || who.UserId is not { } userId) continue;
            await _cases.AssignImportedAsync(caseId, userId, who.DisplayName ?? userId, who.Role, notify, ct);
            who.Applied = true;
        }

        foreach (var h in p.History)
        {
            if (h.Applied) continue;
            CaseService.CaseClosing? closing = null;
            if (h.Phase == CasePhase.Closed)
            {
                var summary = p.NewCase?.Summary ?? p.Summary ?? p.NewCase?.Title ?? "Imported record";
                closing = new CaseService.CaseClosing(p.Outcome ?? "", TextFit.Cap(summary, CaseBrief.MaxPartLength, ""), p.Conclusion ?? "");
            }
            // CAP-35 review: a close takes the step's own reason, or none, so ChangePhaseAsync records the conclusion as it
            // does for any close; that's what the gate's commentary minimum was checked against (CloseGateProblemAsync).
            var reason = closing is not null ? h.Reason : h.Reason ?? p.ImportedRecordReason;
            var containment = h.ContainedAtUtc is not null || h.ContainmentNotNeeded is not null
                ? new CaseService.ContainmentDecision(h.ContainedAtUtc, h.ContainmentNotNeeded) : null;
            try
            {
                await _cases.ChangePhaseAsync(caseId, h.Phase, reason, effectiveAtUtc: h.AtUtc, closing: closing,
                    containment: containment, resolvedAtUtc: h.ResolvedAtUtc, ct: ct);
            }
            catch (StageGates.GateNotSatisfiedException) when (closing is not null)
            {
                var justification = p.CloseOverrideReason(await CloseCommentaryMinAsync(ct));
                await _cases.ChangePhaseAsync(caseId, h.Phase, reason, overrideJustification: justification,
                    effectiveAtUtc: h.AtUtc, closing: closing, containment: containment, resolvedAtUtc: h.ResolvedAtUtc, ct: ct);
            }
            h.Applied = true;
        }
    }

    // CAP-35 review: the active close gate's commentary minimum (0 when none asks), read as the gate evaluation picks it.
    private async Task<int> CloseCommentaryMinAsync(CancellationToken ct)
    {
        using var db = _factory.CreateDbContext();
        return await StageGates.StageGateEvaluator.ActiveGate(db, StageGateTrigger.CloseCase)
            .Select(g => g.CommentaryMinLength).FirstOrDefaultAsync(ct);
    }

    /// <summary>
    /// CAP-35 review: why a history's close can't meet the close gate's commentary minimum, or null. The close's reason is
    /// the step's own, or the conclusion standing in for it (as <see cref="CaseService.ChangePhaseAsync"/> falls back), and
    /// an override's justification is built to be at least as long (<see cref="CaseImportPreview.CloseOverrideReason"/>),
    /// so this one check covers both. Checked in the preview and again before apply writes anything.
    /// </summary>
    private async Task<string?> CloseGateProblemAsync(CaseImportPreview p, CancellationToken ct)
    {
        if (p.TargetKind != CaseImportTargetKind.NewCase || !p.ClosesCase) return null;
        var min = await CloseCommentaryMinAsync(ct);
        var length = p.CloseReason.Length;
        if (min == 0 || length >= min) return null;
        return $"The close gate asks for a reason of at least {min:N0} characters, and the history's close gives {length:N0}. " +
               $"Give the closing step a \"reason\" of at least {min:N0} characters (without one, the \"conclusion\" stands in for it).";
    }

    /// <summary>CAP-35: the most queued submissions one batch confirm applies.</summary>
    public const int MaxBatchConfirm = 25;

    /// <summary>
    /// CAP-35: the oldest waiting submissions from <paramref name="submittedBy"/> the caller may review (the queue's
    /// need-to-know), at most <see cref="MaxBatchConfirm"/>, for the reviewer to see named before confirming them.
    /// </summary>
    public async Task<IReadOnlyList<PendingImportSummary>> ListBatchFromSubmitterAsync(string submittedBy, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await VisiblePending(db).AsNoTracking()
            .Where(p => p.Status == PendingImportStatus.Pending && p.SubmittedBy == submittedBy)
            .OrderBy(p => p.SubmittedAtUtc).ThenBy(p => p.Id)   // a tie (one producer's burst) in a fixed order
            .Take(MaxBatchConfirm)
            .Select(p => new PendingImportSummary(p.Id, p.SubmittedBy, p.SubmittedAtUtc, p.Origin, p.Summary, null, null))
            .ToListAsync(ct);
    }

    /// <summary>
    /// CAP-35: "Confirm all from this submitter". A person confirms (decision 0004): the reviewer saw these submissions named
    /// (<see cref="ListBatchFromSubmitterAsync"/>) and confirms them, at most <see cref="MaxBatchConfirm"/> at a time. Each is
    /// claimed, previewed as the reviewer sees it, and applied by the same audited writes as a single confirm, under the
    /// reviewer's name, one after another; one that needs a person's eye (a target to choose, a filing gate to tick, a
    /// history that breaks R4's checks, a decision without its why, CAP-35 review: a history that closes the case, whose close
    /// can override the close gate) or that fails, however it fails, is left in the queue with why. A
    /// submission not from <paramref name="submittedBy"/>, or no longer waiting, is reported and left alone.
    /// </summary>
    public async Task<IReadOnlyList<BatchConfirmItem>> ConfirmBatchAsync(string submittedBy, IReadOnlyList<Guid> pendingIds,
        CancellationToken ct = default)
    {
        RequireEdit();
        if (pendingIds.Count > MaxBatchConfirm)
            throw new ArgumentException($"Confirm up to {MaxBatchConfirm} imports at a time; this asks for {pendingIds.Count}.");
        var results = new List<BatchConfirmItem>(pendingIds.Count);
        foreach (var id in pendingIds.Distinct())
            results.Add(await ConfirmOneAsync(submittedBy, id, ct));
        return results;
    }

    private async Task<BatchConfirmItem> ConfirmOneAsync(string submittedBy, Guid id, CancellationToken ct)
    {
        string summary;
        using (var db = _factory.CreateDbContext())
        {
            var row = await VisiblePending(db).AsNoTracking().Where(p => p.Id == id)
                .Select(p => new { p.SubmittedBy, p.Status, p.Summary }).FirstOrDefaultAsync(ct);
            if (row is null || row.Status != PendingImportStatus.Pending)
                return new BatchConfirmItem(id, row?.Summary ?? "(no longer in the queue)", false, null, null,
                    "It's no longer waiting: someone else applied or rejected it, or it's being applied.");
            if (row.SubmittedBy != submittedBy)
                return new BatchConfirmItem(id, row.Summary, false, null, null, "It's from another submitter, so it wasn't confirmed.");
            summary = row.Summary;
        }
        CaseImportPreview? preview;
        try { preview = await BuildPreviewForPendingAsync(id, ct); }
        catch (Exception ex) when (ex is not OutOfMemoryException && !(ex is OperationCanceledException && ct.IsCancellationRequested))
        {
            // CAP-35 review: one that can't be previewed (unreadable resume state, say) is reported, and the batch goes on.
            // Nothing was claimed, so it's still waiting.
            _log?.LogError(ex, "A batch confirm couldn't preview import {PendingImportId}.", id);
            return new BatchConfirmItem(id, summary, false, null, null,
                "Not applied: it couldn't be previewed (the error is logged). It's still in the queue to review on its own.");
        }
        if (preview is null)
            return new BatchConfirmItem(id, summary, false, null, null, "It's no longer waiting, or can't be read.");
        if (NeedsReview(preview) is { } why) return new BatchConfirmItem(id, summary, false, null, null, why);
        if (preview is { TargetKind: CaseImportTargetKind.NewCase, NewCase: { } nc })
        {
            // As the review page files it (WF-16): the filing gate sees the indicators it brings. Nothing is ticked or
            // overridden for a person: a filing gate it doesn't meet leaves it for review.
            nc.PlannedEntityCount = preview.Entities.Count(e => e.Include && !e.Applied);
            nc.PlannedDispositions = preview.Entities.Where(e => e.Include && !e.Applied).Select(e => e.Disposition).ToList();
        }

        DateTimeOffset claim;
        // CAP-35 review: the claim's stamp is fixed here, so a claim whose call then threw can still be released (only that
        // claim: ReleaseClaimAsync matches it).
        var claimAt = _clock.UtcNow;
        try
        {
            if (await ClaimCoreAsync(id, preview, ct, claimAt) is not { } claimed)
                return new BatchConfirmItem(id, summary, false, null, null, "It's being applied (perhaps in another tab), or was just decided.");
            claim = claimed;
        }
        catch (StaleResumeException ex)
        {
            return new BatchConfirmItem(id, summary, false, null, null, ex.Message);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            await ReleaseQuietlyAsync(id, preview, claimAt);
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // CAP-35 review: a claim that fails otherwise is that one's failure, not the batch's; if it was taken, it's put back.
            await ReleaseQuietlyAsync(id, preview, claimAt);
            _log?.LogError(ex, "A batch confirm couldn't claim import {PendingImportId}.", id);
            return new BatchConfirmItem(id, summary, false, null, null,
                "Not applied: it couldn't be claimed (the error is logged). It's in the queue to review on its own.");
        }
        try
        {
            var result = await ApplyAsync(preview, id, ct);
            await MarkPendingAppliedAsync(id, result, claim, ct);
            return new BatchConfirmItem(id, summary, true, result.CaseNumber, result.CaseId, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // CAP-35 review: the reviewer left; this one goes back in the queue (with what was written marked) and the batch stops.
            await ReleaseQuietlyAsync(id, preview, claim);
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // BUG-116: back in the queue (with what was written marked), for a person to finish. CAP-35 review: whatever the
            // failure, so one unexpected exception neither strands its claim nor stops the rest of the batch.
            await ReleaseQuietlyAsync(id, preview, claim);
            var known = ex is ArgumentException or InvalidOperationException or ForbiddenException
                or StageGates.GateNotSatisfiedException or ConcurrentEditException or DbUpdateException;
            if (!known) _log?.LogError(ex, "A batch confirm couldn't apply import {PendingImportId}.", id);
            return new BatchConfirmItem(id, summary, false, null, null,
                $"Not applied: {(known ? ex.Message : "something went wrong applying it (the error is logged).")} It's back in the queue to review on its own.");
        }
    }

    private async Task ReleaseQuietlyAsync(Guid id, CaseImportPreview preview, DateTimeOffset claim)
    {
        try { await ReleaseClaimAsync(id, preview, claim, CancellationToken.None); }
        catch (Exception releaseEx) when (releaseEx is not OutOfMemoryException)
        {
            _log?.LogWarning(releaseEx, "Couldn't put import {PendingImportId} back in the queue after a batch confirm failed.", id);
        }
    }

    // CAP-35: what in a preview needs a person's eye rather than a batch confirm, or null.
    private static string? NeedsReview(CaseImportPreview p)
    {
        if (!p.HasAnything) return "It has nothing to import.";
        if (p.TargetKind == CaseImportTargetKind.ExistingCase && p.ExistingCaseId is null)
            return "It needs a target case chosen (more than one open case carries its detection case id).";
        if (p.TargetKind == CaseImportTargetKind.NewCase && p.HistoryProblem is { } problem) return problem;
        // CAP-35 review: a close may be forced past the close gate's unmet checks ("imported record"), which a person must see.
        if (p.TargetKind == CaseImportTargetKind.NewCase && p.ClosesCase)
            return "Its history closes the case, and a close can override the close gate's checks, so confirm it on its own to see that.";
        if (p.TargetKind == CaseImportTargetKind.NewCase && string.IsNullOrWhiteSpace(p.NewCase?.Title)) return "Its new case has no title.";
        if (p.Timeline.Any(t => t.Include && t.Type == TimelineEntryType.Decision && string.IsNullOrWhiteSpace(t.Rationale)))
            return "A decision on its timeline needs its why.";
        if (p.Warnings.Any(w => w.StartsWith("An earlier apply of this import", StringComparison.Ordinal)))
            return "An earlier apply of it stopped part-way; check the case before applying it.";
        return null;
    }

    /// <summary>BUG-152: a TLP marking as written in a document ("Red", "TLP:RED", "amber+strict"); null when absent.</summary>
    internal static TlpLevel? ParseTlp(string? raw, List<string> warnings)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var v = raw.Trim();
        if (v.StartsWith("TLP:", StringComparison.OrdinalIgnoreCase)) v = v[4..];
        v = v.Replace("+", "", StringComparison.Ordinal).Replace("_", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal);
        if (v.Equals("white", StringComparison.OrdinalIgnoreCase)) return TlpLevel.Clear;   // TLP 1.0
        // BUG-282: by name only. Enum.TryParse also took "2" (Amber) and "Green,Amber" (OR-ed to AmberStrict).
        if (ImportEnums.TryName<TlpLevel>(v, out var t)) return t;
        warnings.Add($"Unknown TLP marking '{raw}'. The indicator was given none, so the case's default applies.");
        return null;
    }

    // ── Pending imports queue (PROD-33) ──────────────────────────────────────────────────────────

    /// <summary>
    /// Stages a programmatically-submitted document as a <see cref="PendingImport"/> awaiting human review —
    /// the API never writes case state directly. The document is previewed for the response (so the caller
    /// gets the item count + any warnings), then persisted verbatim so a human confirms it later.
    /// </summary>
    /// <summary>BUG-217: how long an identical resubmission is taken for a retry of one still waiting for review.</summary>
    public static readonly TimeSpan RetryWindow = TimeSpan.FromHours(24);

    /// <summary>
    /// BUG-217: queues a submission from the API, unless the same submitter sent the identical document within
    /// <see cref="RetryWindow"/> and it's still waiting for review: a producer's retry after a timeout returns that one
    /// (<c>AlreadyQueued</c>) rather than queueing a second, which a reviewer could confirm into a second case.
    /// </summary>
    public async Task<(Guid Id, CaseImportPreview Preview, bool AlreadyQueued)> SubmitOnceAsync(string rawJson, CaseImportDocument doc,
        CancellationToken ct = default)
    {
        // BUG-236: the look and the insert run one submission at a time, so two identical POSTs a moment apart (two
        // playbook runs for one alert) can't both find nothing and both queue. API submissions are few; one server.
        (Guid Id, CaseImportPreview Preview, PendingImport? Queued) result;
        await SubmitGate.WaitAsync(ct);
        try { result = await SubmitOnceCoreAsync(rawJson, doc, ct); }
        finally { SubmitGate.Release(); }
        // CAP-01 review: the reviewers are told after the gate is released, so a stalled relay or webhook doesn't hold up
        // every other API submission.
        if (result.Queued is { } row) await NotifySubmittedAsync(row, result.Preview);
        return (result.Id, result.Preview, result.Queued is null);
    }

    private static readonly SemaphoreSlim SubmitGate = new(1, 1);

    private static string Sha256(string text) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    // The row queued, or null when an identical one already waited (BUG-217).
    private async Task<(Guid Id, CaseImportPreview Preview, PendingImport? Queued)> SubmitOnceCoreAsync(string rawJson, CaseImportDocument doc,
        CancellationToken ct)
    {
        using (var db = _factory.CreateDbContext())
        {
            var me = _user.UserId;
            var since = _clock.UtcNow - RetryWindow;
            // WF-23: matched by the text's hash, in the database: each POST no longer reads every waiting document (up to
            // 5 MiB each) of the submitter's last day. A hash names the exact text (REV-57: trailing spaces count). Rows
            // queued before the hash was recorded are compared by their text, as before, until they leave the window.
            var hash = Sha256(rawJson);
            var waiting = db.PendingImports.AsNoTracking()
                .Where(p => p.SubmittedBy == me && p.Status == PendingImportStatus.Pending && p.SubmittedAtUtc >= since);
            var same = await waiting.Where(p => p.RawJsonSha256 == hash)
                .OrderByDescending(p => p.SubmittedAtUtc).Select(p => (Guid?)p.Id).FirstOrDefaultAsync(ct);
            same ??= (await waiting.Where(p => p.RawJsonSha256 == null).Select(p => new { p.Id, p.SubmittedAtUtc, p.RawJson }).ToListAsync(ct))
                .Where(p => string.Equals(p.RawJson, rawJson, StringComparison.Ordinal))
                .OrderByDescending(p => p.SubmittedAtUtc).Select(p => (Guid?)p.Id).FirstOrDefault();
            if (same is { } id0)
                return (id0, await PreviewAsync(doc, null, resolveDetection: false, ct), null);   // CAP-14
        }
        var (row, preview) = await QueueAsync(rawJson, doc, ct);
        return (row.Id, preview, row);
    }

    public async Task<(Guid Id, CaseImportPreview Preview)> SubmitAsync(string rawJson, CaseImportDocument doc,
        CancellationToken ct = default)
    {
        var (row, preview) = await QueueAsync(rawJson, doc, ct);
        await NotifySubmittedAsync(row, preview);
        return (row.Id, preview);
    }

    private async Task<(PendingImport Row, CaseImportPreview Preview)> QueueAsync(string rawJson, CaseImportDocument doc,
        CancellationToken ct)
    {
        // CAP-14: a detection case id stays unresolved here, so the row has no target and every reviewer's own view decides.
        var preview = await PreviewAsync(doc, null, resolveDetection: false, ct);

        var row = new PendingImport
        {
            SubmittedBy = _user.UserId,
            SubmittedAtUtc = _clock.UtcNow,
            Origin = preview.Origin,
            Summary = SummariseForQueue(preview),
            RawJson = rawJson,
            RawJsonSha256 = Sha256(rawJson),   // WF-23
            // BUG-279: the target as the submitter's preview resolved it. A case they can't see was prepared as a new case, and
            // keeping its id hid the row from them and every reviewer outside that case, applied it into the restricted case
            // under a "New case" summary, and told the submitter the id was a real case.
            TargetCaseId = preview.ExistingCaseId,
            Status = PendingImportStatus.Pending
        };

        using (var db = _factory.CreateDbContext())
        {
            db.PendingImports.Add(row);
            await db.SaveChangesAsync(ct);
        }
        _signal?.Raise();
        return (row, preview);
    }

    /// <summary>CAP-01 review: the longest the reviewers' notice (chat post, then an email each) may take in the background.</summary>
    internal static readonly TimeSpan NotifyTimeLimit = TimeSpan.FromMinutes(5);

    /// <summary>
    /// CAP-01: tells the reviewers a submission is waiting (the email and chat toggles decide whether anything is sent).
    /// The reviewers are the people who can confirm it (EditCases), cut to those who may see a restricted target, as the
    /// queue is (<see cref="PendingImportQueue.Visible"/>). The submission is queued already, so nothing here fails it:
    /// the API answers as it always has, and the queue, the Desk and the badge show it whatever happens to the email.
    /// </summary>
    /// <remarks>
    /// CAP-01 review: only the target case is read here, with this request's scoped services (its database factory and the
    /// submitter, for <see cref="CaseQueryExtensions.ForUser"/>). Working out who is told, and telling them (a chat post
    /// tried three times, then an email each), runs in the background with singletons only, so it may outlive the request:
    /// the response doesn't wait for it, the caller's cancellation doesn't reach it, it stops after
    /// <see cref="NotifyTimeLimit"/>, and whatever goes wrong is logged, never thrown.
    /// </remarks>
    private async Task NotifySubmittedAsync(PendingImport row, CaseImportPreview preview)
    {
        if (_notifications is null) return;
        var restricted = false;   // a document can't file a new case restricted; only its target can be
        var exercise = preview.NewCase?.IsExercise == true;
        string? commander = null;
        IReadOnlyCollection<string> team = [];
        try
        {
            if (row.TargetCaseId is { } caseId)
            {
                // The target as the submitter's preview resolved it (BUG-279): one they can see. Not the caller's token:
                // the submission is saved, and telling people of it shouldn't stop because the producer stopped waiting.
                using var db = _factory.CreateDbContext();
                var target = await db.Cases.AsNoTracking().ForUser(_user).Where(c => c.Id == caseId)
                    .Select(c => new { c.IsRestricted, c.IsExercise, c.IncidentCommander, Team = c.Assignments.Select(a => a.UserId).ToList() })
                    .FirstOrDefaultAsync(CancellationToken.None);
                if (target is not null)
                    (restricted, exercise, commander, team) = (target.IsRestricted, target.IsExercise, target.IncidentCommander, target.Team);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Deliberately not thrown (CAP-01): the submission is queued, and the queue, the Desk and the badge show it.
            _log?.LogWarning(ex, "Couldn't tell the reviewers that import {PendingImportId} is waiting. It's in the review queue.", row.Id);
            return;
        }

        var draft = new ImportSubmission(row.Id, row.SubmittedBy, row.Origin, row.Summary, preview.IncludedItemCount,
            row.TargetCaseId, restricted, exercise, []);
        var (notifications, users, roles, audience, log) = (_notifications, _users, _roles, _audience, _log);
        // Not awaited, and without this request's execution context (its HttpContext, a caller's delivery watch).
        using (ExecutionContext.SuppressFlow())
            _ = Task.Run(() => TellReviewersAsync(draft, commander, team, notifications, users, roles, audience, log), CancellationToken.None);
    }

    // CAP-01 review: the background half. Static, so it uses only what it's handed: singletons (the notifier, the user and
    // role directories) and the audience, whose own dependencies are singletons. Never the request's scope.
    private static async Task TellReviewersAsync(ImportSubmission draft, string? commander, IReadOnlyCollection<string> team,
        ICaseNotifications notifications, IUserDirectory? users, IRoleDirectory? roles, Notifications.ReminderAudience? audience,
        ILogger? log)
    {
        using var limit = new CancellationTokenSource(NotifyTimeLimit);
        try
        {
            var reviewers = (users?.All() ?? [])
                .Where(u => roles is not null && roles.PermissionsForRoles(Domain.Common.RoleList.Split(u.RolesCsv, roles.IsRole))
                    .Contains(Permission.EditCases))
                .Select(u => u.UserId)
                .ToList();
            var recipients = await (audience ?? new Notifications.ReminderAudience(users, roles))
                .RecipientsAsync(reviewers, draft.IsRestricted, commander, team, limit.Token);
            await notifications.OnImportSubmittedAsync(draft with { ReviewerUserIds = recipients }, limit.Token);
        }
        catch (OperationCanceledException) when (limit.IsCancellationRequested)
        {
            log?.LogWarning("Gave up telling the reviewers that import {PendingImportId} is waiting after {Minutes} minutes. It's in the review queue.",
                draft.PendingImportId, NotifyTimeLimit.TotalMinutes);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Deliberately swallowed (CAP-01): the submission is queued, and the queue, the Desk and the badge show it.
            log?.LogWarning(ex, "Couldn't tell the reviewers that import {PendingImportId} is waiting. It's in the review queue.", draft.PendingImportId);
        }
    }

    /// <summary>
    /// The queued submissions the caller may see: need-to-know scoped on the target case, because the queue shows
    /// the submitter, origin and a summary naming the target's case number. A submission into an existing case the
    /// caller can't see (<see cref="CaseQueryExtensions.ForUser"/>) is left out; one with no target, or whose
    /// target no longer exists (it previews as a new case), is visible to every reviewer.
    /// </summary>
    private IQueryable<PendingImport> VisiblePending(IAppDbContext db) => PendingImportQueue.Visible(db, _user);   // CAP-01: shared

    /// <summary>The queue of imports awaiting review, newest first (need-to-know scoped, <see cref="VisiblePending"/>).</summary>
    public async Task<IReadOnlyList<PendingImportSummary>> ListPendingAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var pending = await VisiblePending(db).AsNoTracking()
            .Where(p => p.Status == PendingImportStatus.Pending)
            .OrderByDescending(p => p.SubmittedAtUtc)
            .Select(p => new PendingImportSummary(p.Id, p.SubmittedBy, p.SubmittedAtUtc, p.Origin, p.Summary, null, null))
            .ToListAsync(ct);
        // WF-18: an apply that stopped without an exception (a recycle, a crash) left its row claimed with no case, out of
        // the queue for good. Listed again once the claim is stale, so a reviewer can reopen it.
        var staleBefore = _clock.UtcNow - StaleClaim;
        var stuck = (await VisiblePending(db).AsNoTracking()
                .Where(p => p.Status == PendingImportStatus.Applied && p.ResolvedCaseId == null && p.DecidedAtUtc != null)
                .Select(p => new { p.Id, p.SubmittedBy, p.SubmittedAtUtc, p.Origin, p.Summary, p.DecidedBy, p.DecidedAtUtc })
                .ToListAsync(ct))
            .Where(p => p.DecidedAtUtc < staleBefore)
            .Select(p => new PendingImportSummary(p.Id, p.SubmittedBy, p.SubmittedAtUtc, p.Origin, p.Summary, p.DecidedBy ?? "", p.DecidedAtUtc));
        return pending.Concat(stuck).OrderByDescending(p => p.SubmittedAtUtc).ToList();
    }

    /// <summary>
    /// WF-18: puts a stuck import (see <see cref="ListPendingAsync"/>) back in the queue, for any reviewer (owner's
    /// decision). Conditional, so a claim that moved on meanwhile isn't undone; audited, naming whose claim it was.
    /// The stopped apply may have created a case before it stopped: the preview says so, to check before applying.
    /// </summary>
    public async Task<bool> ReopenStuckAsync(Guid pendingId, CancellationToken ct = default)
    {
        RequireEdit();
        using var db = _factory.CreateDbContext();
        var row = await VisiblePending(db).AsNoTracking().Where(p => p.Id == pendingId)
            .Select(p => new { p.Status, p.ResolvedCaseId, p.DecidedBy, p.DecidedAtUtc, p.Summary }).FirstOrDefaultAsync(ct);
        if (row is not { Status: PendingImportStatus.Applied, ResolvedCaseId: null, DecidedAtUtc: { } at }
            || _clock.UtcNow - at < StaleClaim) return false;
        var reopened = await VisiblePending(db)
            .Where(p => p.Id == pendingId && p.Status == PendingImportStatus.Applied && p.ResolvedCaseId == null && p.DecidedAtUtc == at)
            .ExecuteUpdateAsync(s => s
                .SetProperty(p => p.Status, PendingImportStatus.Pending)
                // WF-94: kept on the row, so whoever previews it next (not only this reviewer's tab) is warned.
                // BUG-531: saved text, so the invariant calendar, not the server culture's.
                .SetProperty(p => p.DecisionNote, $"{ReopenedMarker} {row.DecidedBy} at {Utc(at)}")
                .SetProperty(p => p.DecidedBy, (string?)null)
                .SetProperty(p => p.DecidedAtUtc, (DateTimeOffset?)null), ct);
        if (reopened != 1) return false;
        _signal?.Raise();   // CAP-01
        if (_audit is not null)
            await _audit.RecordAsync(AuditAction.Update, "PendingImport", pendingId.ToString(), null,
                $"Reopened a stuck import \"{row.Summary}\" (claimed by {row.DecidedBy} at {Utc(at)}, no case recorded)", ct);
        return true;
    }

    /// <summary>
    /// CAP-13: what became of a submission, for the API caller asking: one it sent itself, or any it could review (EditCases,
    /// within the queue's need-to-know, <see cref="VisiblePending"/>). Null for an id it may not see, as for one that doesn't
    /// exist, so the answer never says a submission is there. Pending until a reviewer has finished applying it (one claimed
    /// is still being applied); applied, with the case's number and id as they are now when the caller can see that case
    /// (<see cref="CaseQueryExtensions.ForUser"/>) and without them when it can't; or rejected.
    /// </summary>
    public async Task<ImportSubmissionStatus?> GetSubmissionStatusAsync(Guid pendingId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;
        var row = await db.PendingImports.AsNoTracking().Where(p => p.Id == pendingId && p.SubmittedBy == me)
            .Select(p => new { p.Status, p.DecidedAtUtc, p.ResolvedCaseId }).FirstOrDefaultAsync(ct);
        if (row is null && _user.Has(Permission.EditCases))
            row = await VisiblePending(db).AsNoTracking().Where(p => p.Id == pendingId)
                .Select(p => new { p.Status, p.DecidedAtUtc, p.ResolvedCaseId }).FirstOrDefaultAsync(ct);
        if (row is null) return null;

        if (row.Status == PendingImportStatus.Rejected) return new ImportSubmissionStatus("rejected", row.DecidedAtUtc, null, null);
        if (row.Status != PendingImportStatus.Applied || row.ResolvedCaseId is not { } caseId)
            return new ImportSubmissionStatus("pending", null, null, null);
        var number = await db.Cases.AsNoTracking().ForUser(_user).Where(c => c.Id == caseId)
            .Select(c => c.CaseNumber).FirstOrDefaultAsync(ct);
        return number is null
            ? new ImportSubmissionStatus("applied", row.DecidedAtUtc, null, null)
            : new ImportSubmissionStatus("applied", row.DecidedAtUtc, number, caseId);
    }

    /// <summary>How many imports are awaiting review — for a queue badge.</summary>
    public async Task<int> CountPendingAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await VisiblePending(db).CountAsync(p => p.Status == PendingImportStatus.Pending, ct);
    }

    /// <summary>Re-parses and previews a queued submission for the reviewer; null if it is gone or not pending.</summary>
    public async Task<CaseImportPreview?> BuildPreviewForPendingAsync(Guid pendingId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var row = await VisiblePending(db).AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == pendingId && p.Status == PendingImportStatus.Pending, ct);
        if (row is null) return null;

        var reopenedBy = row.DecisionNote is { } note && note.StartsWith(ReopenedMarker, StringComparison.Ordinal)
            ? note[ReopenedMarker.Length..].Trim() : null;

        // BUG-146: an apply that failed part-way left the reviewed preview, marked with what it wrote.
        if (row.ResumeJson is { } resume && JsonSerializer.Deserialize<CaseImportPreview>(resume, ResumeJsonOptions) is { } resumed)
        {
            // BUG-556: the saved Warnings are the reviewed preview's, from its own load (an earlier resume's "won't be written
            // again", a target since replaced by the created case), so they're rebuilt here rather than shown again.
            resumed.Warnings.Clear();
            // BUG-541: a later apply that stopped without releasing (WF-94) recorded nothing, so what it wrote isn't marked.
            resumed.Warnings.Add(reopenedBy is null
                ? "An earlier apply of this import stopped part-way. The items already written are marked and " +
                  "won't be written again; applying carries on into the same case."
                : $"An earlier apply of this import (by {reopenedBy}) stopped without finishing and may have written more than " +
                  "the items marked here: its summary note, timeline entries and tasks. Check the case before applying: applying " +
                  "carries on into the same case and writes again anything not marked (entities aren't duplicated).");
            return resumed;
        }

        var parsed = Parse(row.RawJson);
        if (!parsed.Ok) return null; // validated at submit, so this is defensive
        // BUG-334: the row's recorded target is the only one. Null means the submitter's preview prepared a new case (BUG-279:
        // they couldn't see the document's), so the document's case id mustn't resolve again under the reviewer.
        // CAP-14: a detection case id resolves now, under the reviewer, unless it came with a case id: that pair named one case
        // (CheckTargetAsync), so when the submitter couldn't see it, neither half resolves again.
        if (parsed.Document!.Target is { } target)
        {
            if (target.CaseId is not null) target.DetectionCaseId = null;
            target.CaseId = null;
        }
        var preview = await BuildPreviewAsync(parsed.Document!, intoCaseId: row.TargetCaseId, ct: ct);
        // WF-18/WF-94: an apply that stopped without recording anything may have written before it stopped.
        if (reopenedBy is { } who)
        {
            preview.Warnings.Add(row.TargetCaseId is null
                ? $"An earlier apply of this import (by {who}) stopped without finishing and may have created a case before it " +
                  "did. Check the case list for it before applying, and pick it as the target if it's there, or the case is filed twice."
                : $"An earlier apply of this import (by {who}) stopped without finishing and may already have written its summary " +
                  "note, timeline entries and tasks into the target case. Check the case before applying: applying again writes " +
                  "them again (entities aren't duplicated).");
        }
        return preview;
    }

    // WF-94: DecisionNote on a stuck import put back in the queue, followed by whose claim it was and when.
    private const string ReopenedMarker = "Reopened after a stopped apply by";

    // The preview's lists are get-only, so they're filled in place.
    private static readonly JsonSerializerOptions ResumeJsonOptions = new()
    {
        PreferredObjectCreationHandling = System.Text.Json.Serialization.JsonObjectCreationHandling.Populate,
    };

    /// <summary>Whether an apply of <paramref name="p"/> has written anything (a case, the summary note or any row).</summary>
    public static bool HasApplied(CaseImportPreview p) =>
        p.CreatedCaseId is not null || p.SummaryApplied || p.Timeline.Any(t => t.Applied)
        || p.Entities.Any(e => e.Applied) || p.ActionItems.Any(a => a.Applied)
        || p.History.Any(h => h.Applied) || p.IncidentCommander?.Applied == true || p.Assignments.Any(a => a.Applied);   // CAP-35

    /// <summary>BUG-198: how old a claim of one's own with no case must be before it can be taken again. Younger, it's an
    /// apply still running (in another tab, say).</summary>
    public static readonly TimeSpan StaleClaim = TimeSpan.FromMinutes(30);

    /// <summary>
    /// BUG-13: claims a queued submission for this reviewer before anything is applied, in one conditional update, so
    /// two reviewers (or two tabs) can't both apply it. Returns the claim, which recording the result or releasing it
    /// must present; null when it's taken (applied, rejected, or being applied, even by this reviewer in another tab:
    /// BUG-198). A failed apply puts it back in the queue (BUG-116); a claim of this reviewer's left behind anyway (the
    /// release failed too) can be taken again once it's <see cref="StaleClaim"/> old.
    /// </summary>
    public Task<DateTimeOffset?> ClaimPendingAsync(Guid pendingId, CancellationToken ct = default) =>
        ClaimCoreAsync(pendingId, null, ct);

    /// <summary>
    /// <see cref="ClaimPendingAsync(Guid, CancellationToken)"/> for applying <paramref name="preview"/>. CAP-35 review: the
    /// claim honours the row's resume state (BUG-146): when an apply since this preview was built stopped part-way and was
    /// put back (another reviewer's, or another tab's), applying this preview would write again what that one wrote (a
    /// second case), so it's refused with <see cref="StaleResumeException"/>, and reopening the import resumes it. The
    /// check and the claim are one conditional update, so a release landing between them can't slip past.
    /// </summary>
    public Task<DateTimeOffset?> ClaimPendingAsync(Guid pendingId, CaseImportPreview preview, CancellationToken ct = default) =>
        ClaimCoreAsync(pendingId, preview, ct);

    // The claim is stamped claimAt (now, unless the caller fixed it first so it can release a claim whose call then threw).
    private async Task<DateTimeOffset?> ClaimCoreAsync(Guid pendingId, CaseImportPreview? preview, CancellationToken ct,
        DateTimeOffset? claimAt = null)
    {
        RequireEdit();
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;
        var now = claimAt ?? _clock.UtcNow;
        var resume = await VisiblePending(db).AsNoTracking().Where(p => p.Id == pendingId).Select(p => p.ResumeJson).FirstOrDefaultAsync(ct);
        var checkResume = preview is not null;
        if (checkResume && !ResumesFrom(preview!, resume))
            throw new StaleResumeException();
        var claimed = await VisiblePending(db)
            .Where(p => p.Id == pendingId && p.Status == PendingImportStatus.Pending && (!checkResume || p.ResumeJson == resume))
            .ExecuteUpdateAsync(s => s
                .SetProperty(p => p.Status, PendingImportStatus.Applied)
                .SetProperty(p => p.DecidedBy, me)
                .SetProperty(p => p.DecidedAtUtc, now), ct);
        if (claimed == 1) { _signal?.Raise(); return now; }   // CAP-01: out of the queue

        var left = await VisiblePending(db).AsNoTracking().Where(p => p.Id == pendingId)
            .Select(p => new { p.Status, p.DecidedBy, p.ResolvedCaseId, p.DecidedAtUtc }).FirstOrDefaultAsync(ct);
        if (left is not { Status: PendingImportStatus.Applied, ResolvedCaseId: null } || left.DecidedBy != me
            || left.DecidedAtUtc is not { } at || now - at < StaleClaim) return null;
        claimed = await VisiblePending(db)
            .Where(p => p.Id == pendingId && p.Status == PendingImportStatus.Applied && p.DecidedBy == me
                        && p.ResolvedCaseId == null && p.DecidedAtUtc == at && (!checkResume || p.ResumeJson == resume))
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.DecidedAtUtc, now), ct);
        return claimed == 1 ? now : null;
    }

    /// <summary>
    /// CAP-35 review: whether <paramref name="preview"/> carries the progress the queued row records (<paramref name="resumeJson"/>,
    /// BUG-146), so applying it carries on rather than writing again. With none recorded, any preview does. Otherwise it must be
    /// that resume state or the very preview that saved it (<see cref="CaseImportPreview.ResumeStamp"/>); one saved before the
    /// stamp existed is matched by the case it created, and by having written something itself.
    /// </summary>
    private static bool ResumesFrom(CaseImportPreview preview, string? resumeJson)
    {
        if (resumeJson is null) return true;
        CaseImportPreview? saved;
        try { saved = JsonSerializer.Deserialize<CaseImportPreview>(resumeJson, ResumeJsonOptions); }
        catch (JsonException) { return false; }
        if (saved is null) return true;
        if (saved.ResumeStamp is { } stamp) return preview.ResumeStamp == stamp;
        return preview.CreatedCaseId == saved.CreatedCaseId && HasApplied(preview);
    }

    /// <summary>Records the case a claimed submission went into (<see cref="ClaimPendingAsync"/> claims it first, and
    /// <paramref name="claim"/> is what it returned; null for a submission applied without a claim).</summary>
    public async Task MarkPendingAppliedAsync(Guid pendingId, CaseImportResult result, DateTimeOffset? claim = null,
        CancellationToken ct = default)
    {
        RequireEdit();
        using var db = _factory.CreateDbContext();
        var row = await VisiblePending(db).FirstOrDefaultAsync(p => p.Id == pendingId, ct);
        if (row is null || row.ResolvedCaseId is not null) return;
        if (row.Status != PendingImportStatus.Pending && !(row.Status == PendingImportStatus.Applied && row.DecidedBy == _user.UserId)) return;
        if (claim is { } mine && row.Status == PendingImportStatus.Applied && row.DecidedAtUtc != mine) return;   // BUG-198: not this claim
        row.Status = PendingImportStatus.Applied;
        row.DecidedBy = _user.UserId;
        row.DecidedAtUtc = _clock.UtcNow;
        row.ResolvedCaseId = result.CaseId;
        row.ResolvedCaseNumber = result.CaseNumber;
        row.ResumeJson = null;
        await db.SaveChangesAsync(ct);
        _signal?.Raise();   // CAP-01
    }

    /// <summary>
    /// BUG-116: puts a claimed submission back in the queue when its apply failed, so it isn't left marked applied with
    /// no case. If the apply had already created the case, the submission now targets it, so a retry (by anyone)
    /// carries on into that case rather than creating another. BUG-146: and if it wrote anything, the reviewed preview is
    /// kept with what it wrote, so reopening the submission doesn't write those items again.
    /// </summary>
    public async Task ReleaseClaimAsync(Guid pendingId, CaseImportPreview preview, DateTimeOffset? claim = null,
        CancellationToken ct = default)
    {
        RequireEdit();
        using var db = _factory.CreateDbContext();
        var row = await VisiblePending(db).FirstOrDefaultAsync(p => p.Id == pendingId, ct);
        if (row is not { Status: PendingImportStatus.Applied, ResolvedCaseId: null } || row.DecidedBy != _user.UserId) return;
        if (claim is { } mine && row.DecidedAtUtc != mine) return;   // BUG-198: another tab's claim, still applying
        row.Status = PendingImportStatus.Pending;
        row.DecidedBy = null;
        row.DecidedAtUtc = null;
        if (preview.CreatedCaseId is { } created) row.TargetCaseId = created;
        else if (preview is { TargetKind: CaseImportTargetKind.ExistingCase, ExistingCaseId: { } into } && HasApplied(preview))
            row.TargetCaseId = into;
        Guid? stamp = null;
        if (HasApplied(preview))
        {
            // CAP-35 review: a fresh stamp each time, kept on this preview too, so only it (or a reload of this state)
            // claims the import next (ResumesFrom). R2: kept only once the row has it; a failed save left the preview
            // with a stamp the row never got, and its own retry was refused for good.
            stamp = Guid.NewGuid();
            var prior = preview.ResumeStamp;
            preview.ResumeStamp = stamp;
            try { row.ResumeJson = JsonSerializer.Serialize(preview, ResumeJsonOptions); }
            finally { preview.ResumeStamp = prior; }
        }
        await db.SaveChangesAsync(ct);
        if (stamp is not null) preview.ResumeStamp = stamp;
        _signal?.Raise();   // CAP-01: back in the queue
    }

    /// <summary>Discards a queued submission with an optional reason (nothing is written to any case). False when it
    /// was no longer waiting (BUG-92: someone else applied or rejected it first).</summary>
    public async Task<bool> RejectPendingAsync(Guid pendingId, string? note, CancellationToken ct = default)
    {
        RequireEdit();
        using var db = _factory.CreateDbContext();
        // BUG-236: only while it's still pending, in one statement, as a claim is (ClaimPendingAsync): a read-then-save
        // reject landing between another reviewer's claim and apply wrote Rejected over Applied for a case being created.
        var me = _user.UserId;
        var now = _clock.UtcNow;
        var why = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        // C12: the update is one statement, so a reason over the column failed it on SQL Server with a raw exception.
        if (why?.Length > MaxDecisionNoteLength)
            throw new ArgumentException(string.Create(CultureInfo.InvariantCulture,
                $"Keep the reason to {MaxDecisionNoteLength:N0} characters (this one has {why.Length:N0}). The import is still waiting."));
        var rejected = await VisiblePending(db)
            .Where(p => p.Id == pendingId && p.Status == PendingImportStatus.Pending)
            .ExecuteUpdateAsync(s => s
                .SetProperty(p => p.Status, PendingImportStatus.Rejected)
                .SetProperty(p => p.DecidedBy, me)
                .SetProperty(p => p.DecidedAtUtc, now)
                .SetProperty(p => p.DecisionNote, why), ct);
        if (rejected == 1) _signal?.Raise();   // CAP-01
        return rejected == 1;
    }

    /// <summary>S-09: deciding a queued import is a case edit (the page is EditCases-gated; this is the backstop).</summary>
    private void RequireEdit([System.Runtime.CompilerServices.CallerMemberName] string action = "")
    {
        if (!_user.Has(Permission.EditCases)) throw new ForbiddenException(Permission.EditCases, action);
    }

    private static string SummariseForQueue(CaseImportPreview p)
    {
        string target;
        if (p.TargetKind == CaseImportTargetKind.ExistingCase) target = $"Into {p.ExistingCaseNumber ?? "an existing case"}";
        // CAP-14: no case is named; the reviewer's view decides which it is.
        else if (p.DetectionCaseId is { } detection) target = $"Into the open case with detection case id {detection}";
        else target = $"New case: {(string.IsNullOrWhiteSpace(p.NewCase?.Title) ? "(untitled)" : p.NewCase!.Title)}";
        var s = $"{target} ({Plural.Of(p.IncludedItemCount, "item")})";
        return TextFit.Cap(s, MaxQueueSummaryLength, "");
    }

    // ── Pure preview construction (no I/O) ───────────────────────────────────────────────────────

    /// <summary>
    /// Validates and normalizes a document into an editable preview, defaulting to a <b>new-case</b> target.
    /// Untrusted-input handling: strings are trimmed and clamped, unknown enum values fall back to a safe
    /// default (flagged in <see cref="CaseImportPreview.Warnings"/>), indicator values are refanged/auto-typed,
    /// entities are de-duplicated, future-dated timeline entries are flagged and excluded, and empty rows are
    /// dropped. Pure — used directly by unit tests.
    /// </summary>
    public static CaseImportPreview BuildPreviewCore(CaseImportDocument doc, DateTimeOffset nowUtc)
    {
        var p = new CaseImportPreview { TargetKind = CaseImportTargetKind.NewCase };
        p.Origin = Clamp(doc.Origin, MaxSource, "Origin", p.Warnings);
        p.NewCase = BuildNewCase(doc.Target?.NewCase, nowUtc, p.Warnings);

        var summary = Clamp(doc.Summary, MaxSummary, "Summary", p.Warnings);
        if (!string.IsNullOrWhiteSpace(summary))
        {
            p.Summary = summary;
            p.IncludeSummary = true;
        }

        // Timeline
        var droppedTimeline = 0;
        foreach (var t in doc.Timeline ?? [])
        {
            if (t is null) { droppedTimeline++; continue; }   // BUG-473: a null element ([null]) is an empty row
            var desc = Clamp(t.Description, MaxDescription, "Timeline description", p.Warnings);
            if (string.IsNullOrWhiteSpace(desc)) { droppedTimeline++; continue; }

            var row = new ImportTimelineRow
            {
                Kind = ParseEnum(t.Kind, TimelineKind.Investigation, "timeline kind", p.Warnings),
                Type = ImportableTimelineType(ParseEnum(t.Type, TimelineEntryType.Communication, "timeline type", p.Warnings), p.Warnings),
                Description = desc!,
                Source = Clamp(t.Source, MaxSource, "Timeline source", p.Warnings) ?? p.Origin
            };
            // INV-18: a decision comes in with its why; without one it's imported as Communication, with a note.
            if (row.Type == TimelineEntryType.Decision)
            {
                row.Rationale = Blank(Clamp(t.Rationale, 4000, "Decision rationale", p.Warnings));
                row.OptionsConsidered = Blank(Clamp(t.OptionsConsidered, 2000, "Options considered", p.Warnings));
                row.DecidedBy = Blank(Clamp(t.DecidedBy, 300, "Decided by", p.Warnings));
                if (row.Rationale is null)
                {
                    row.Type = TimelineEntryType.Communication;
                    row.Warning = "A decision needs its why. Imported as Communication; add the why and set the type back to Decision to keep it as a decision.";
                }
            }
            // ST-03: an event step can carry its time as stated. A date-based precision needs the date; a window its end.
            if (row.Kind == TimelineKind.Event && !string.IsNullOrWhiteSpace(t.TimePrecision))
            {
                row.Precision = ParseEnum(t.TimePrecision, TimePrecision.Exact, "time precision", p.Warnings);
                if (row.Precision is TimePrecision.Day or TimePrecision.Window or TimePrecision.OnOrBefore && t.OccurredAtUtc is null)
                {
                    row.Precision = TimePrecision.NotStated;
                    row.Warning = "No date was given, so it's imported as time not stated.";
                }
                else if (row.Precision == TimePrecision.Window)
                {
                    if (t.OccurredUntilUtc is { } until && StepTiming.DateAnchor(until) > StepTiming.DateAnchor(t.OccurredAtUtc!.Value))
                        row.OccurredUntilUtc = until;
                    else
                    {
                        row.Precision = TimePrecision.Day;
                        row.Warning = "The window had no later last date, so it's imported as its first date only.";
                    }
                }
            }
            if (row.Precision == TimePrecision.NotStated)
            {
                row.OccurredAtUtc = t.OccurredAtUtc ?? nowUtc;   // only a fallback sort key; placed by order
            }
            else if (t.OccurredAtUtc is { } occ)
            {
                row.OccurredAtUtc = occ;
                if (occ > nowUtc)
                {
                    row.Include = false;
                    row.Warning = "This time is in the future, so the entry is excluded. Correct the time to include it.";
                }
            }
            else
            {
                row.OccurredAtUtc = nowUtc;
                row.Warning = "No timestamp, so it defaulted to now.";
            }
            p.Timeline.Add(row);
        }
        if (droppedTimeline > 0) p.Warnings.Add(droppedTimeline == 1 ? "1 timeline entry had no description and was skipped." : $"{droppedTimeline} timeline entries had no description and were skipped.");

        // Entities (refang/auto-type + dedupe by type+value)
        var seen = new Dictionary<string, ImportEntityRow>(StringComparer.OrdinalIgnoreCase);
        var droppedEntities = 0;
        foreach (var e in doc.Entities ?? [])
        {
            var rawValue = e?.Value?.Trim();   // BUG-473: a null element is a row with no value
            if (e is null || string.IsNullOrWhiteSpace(rawValue)) { droppedEntities++; continue; }

            EntityType type;
            if (string.IsNullOrWhiteSpace(e.Type))
                type = IocObservable.DetectType(rawValue);
            else if (ImportEnums.TryName<EntityType>(e.Type, out var parsed))
                type = parsed;
            else
            {
                type = IocObservable.DetectType(rawValue);
                p.Warnings.Add($"Unknown entity type '{e.Type}'. Detected as {type} from the value.");
            }

            var value = IocObservable.Normalize(type, rawValue);
            if (value.Length == 0) { droppedEntities++; continue; }
            // BUG-175: a cut-short indicator is a different one (a truncated URL still marked Malicious, fed to blocking),
            // so one longer than the column is left out, after refanging, and named.
            if (value.Length > MaxValue)
            {
                p.Warnings.Add($"An entity value of {value.Length:N0} characters (starting \"{TextFit.Cap(value, 60)}\") is longer than " +
                               $"{MaxValue:N0}, the most an indicator holds, so it wasn't imported (a shortened one would be a different indicator).");
                continue;
            }

            var row = new ImportEntityRow
            {
                Type = type,
                Value = value,
                Label = Clamp(e.Label, MaxLabel, "Entity label", p.Warnings),
                Disposition = ParseEnum(e.Disposition, EntityDisposition.Unknown, "entity disposition", p.Warnings),
                Description = Clamp(e.Description, MaxEntityDescription, "Entity description", p.Warnings),
                Source = Clamp(e.Source, MaxSource, "Entity source", p.Warnings) ?? p.Origin,
                Tlp = ParseTlp(e.Tlp, p.Warnings),
            };
            // Dedupe. BUG-170: a value listed twice (a STIX observable and an indicator for it) is one row with what both
            // say: a verdict over Unknown, a name or description where the first had none, the stricter marking.
            if (seen.TryGetValue($"{(int)type}|{value.ToLowerInvariant()}", out var first))
            {
                if (first.Disposition == EntityDisposition.Unknown) first.Disposition = row.Disposition;
                first.Label ??= row.Label;
                first.Description ??= row.Description;
                if (row.Tlp is { } t && (first.Tlp is null || t > first.Tlp)) first.Tlp = t;
                continue;
            }
            seen[$"{(int)type}|{value.ToLowerInvariant()}"] = row;
            p.Entities.Add(row);
        }
        if (droppedEntities > 0) p.Warnings.Add(droppedEntities == 1 ? "1 entity had no value and was skipped." : $"{droppedEntities} entities had no value and were skipped.");

        // Action items
        var droppedTasks = 0;
        foreach (var a in doc.ActionItems ?? [])
        {
            if (a is null) { droppedTasks++; continue; }   // BUG-473
            var title = Clamp(a.Title, MaxTitle, "Task title", p.Warnings);
            if (string.IsNullOrWhiteSpace(title)) { droppedTasks++; continue; }
            p.ActionItems.Add(new ImportActionItemRow
            {
                Title = title!,
                Owner = Clamp(a.Owner, MaxOwner, "Task owner", p.Warnings),
                DueAtUtc = a.DueAtUtc
            });
        }
        if (droppedTasks > 0) p.Warnings.Add(droppedTasks == 1 ? "1 task had no title and was skipped." : $"{droppedTasks} tasks had no title and were skipped.");

        BuildHistory(doc, p, nowUtc);   // CAP-35
        return p;
    }

    /// <summary>CAP-35: the most phase transitions one imported history carries, and team members besides the IC.</summary>
    public const int MaxHistory = 50, MaxAssignments = 50;

    /// <summary>
    /// CAP-35: a v2 document's history (phase transitions with when each happened and why), outcome, conclusion, incident
    /// commander and team, for a new case. The history is held to R4's checks before anything is written: every step has
    /// a time, none is in the future or before the case was detected, they're in order, a step past Containment or
    /// Recovery without it says what the domain asks (BUG-165, BUG-208), and a history closes only at its end, with an
    /// outcome and a conclusion. What fails sets <see cref="CaseImportPreview.HistoryProblem"/>, which Apply refuses on.
    /// People are matched to the directory later (<see cref="ResolveTeam"/>).
    /// </summary>
    private static void BuildHistory(CaseImportDocument doc, CaseImportPreview p, DateTimeOffset nowUtc)
    {
        if (doc.Target?.NewCase is not { } nc) return;
        var carries = nc.History is { Count: > 0 } || nc.Assignments is { Count: > 0 } || !string.IsNullOrWhiteSpace(nc.Outcome)
                      || !string.IsNullOrWhiteSpace(nc.Conclusion) || !string.IsNullOrWhiteSpace(nc.IncidentCommander);
        if (!carries) return;
        if ((doc.SchemaVersion ?? 1) < CaseImportJson.HistorySchemaVersion)
        {
            p.Warnings.Add("The new case's history, outcome, conclusion and team need \"schemaVersion\": 2. This document is v1, so they were ignored.");
            return;
        }
        if (nc.History?.Count > MaxHistory) { p.HistoryProblem = $"The history has {nc.History.Count} steps; an import takes up to {MaxHistory}."; return; }
        if (nc.Assignments?.Count > MaxAssignments) { p.HistoryProblem = $"The team has {nc.Assignments.Count} people; an import takes up to {MaxAssignments}."; return; }

        p.Outcome = Clamp(nc.Outcome, 64, "Outcome", p.Warnings);
        p.Conclusion = Clamp(nc.Conclusion, CaseBrief.MaxPartLength, "Conclusion", p.Warnings);
        if (Clamp(nc.IncidentCommander, MaxOwner, "Incident commander", p.Warnings) is { } ic)
            p.IncidentCommander = new ImportAssignmentRow { Named = ic, Role = CaseAssignmentRole.IncidentCommander };
        foreach (var a in nc.Assignments ?? [])
        {
            if (Clamp(a?.User, MaxOwner, "Team member", p.Warnings) is not { } who) continue;
            var role = ParseEnum(a!.Role, CaseAssignmentRole.Analyst, "team role", p.Warnings);
            if (role == CaseAssignmentRole.IncidentCommander)
            {
                p.Warnings.Add($"{who} is named incident commander in the team; the incident commander goes in \"incidentCommander\", so they're added as an analyst.");
                role = CaseAssignmentRole.Analyst;
            }
            if (p.Assignments.Any(x => string.Equals(x.Named, who, StringComparison.OrdinalIgnoreCase))) continue;
            p.Assignments.Add(new ImportAssignmentRow { Named = who, Role = role });
        }

        var steps = nc.History ?? [];
        var detected = p.NewCase?.DetectedAtUtc;
        var phase = CasePhase.New;
        DateTimeOffset? previous = null;
        for (var i = 0; i < steps.Count; i++)
        {
            var n = i + 1;
            string Problem(string why) => p.HistoryProblem ??= $"History step {n}: {why}";
            if (steps[i] is not { } s) { Problem("it's empty."); return; }
            if (!ImportEnums.TryName<CasePhase>(s.Phase, out var to)) { Problem($"\"{s.Phase}\" isn't a phase ({string.Join(", ", Enum.GetNames<CasePhase>())})."); return; }
            if (s.At is not { } at) { Problem("say when it happened (\"at\")."); return; }
            if (detected is null) { Problem("a case with a history needs newCase.detectedAt, so its steps can be checked against it."); return; }
            if (previous is { } prev && Case.ToMinute(at) < Case.ToMinute(prev)) { Problem($"{Utc(at)} is before the step before it ({Utc(prev)}): give the history in order."); return; }
            if (to == phase) { Problem($"the case is already in {to}."); return; }
            if (phase == CasePhase.Closed) { Problem("a history closes only at its end."); return; }
            if (to == CasePhase.Closed && n != steps.Count) { Problem("a history closes only at its end."); return; }
            p.History.Add(new ImportHistoryRow
            {
                Phase = to, AtUtc = at, Reason = Clamp(s.Reason, 2000, "Transition reason", p.Warnings),
                ContainedAtUtc = s.ContainedAt, ResolvedAtUtc = s.ResolvedAt,
                ContainmentNotNeeded = Blank(Clamp(s.ContainmentNotNeeded, Case.MaxContainmentReason, "Why containment wasn't needed", p.Warnings)),
            });
            (phase, previous) = (to, at);
        }
        // CAP-35 review: everything else (future, before detection, the containment and resolution times a skip states, the
        // REV-11 resolution a later Containment clears) is the domain's own check, replayed (C2), so preview and apply agree.
        if (detected is { } detectedAt && ReplayHistory(p.History, detectedAt, nowUtc) is { } refused)
        {
            p.HistoryProblem ??= refused;
            return;
        }
        if (phase == CasePhase.Closed)
        {
            if (p.Outcome is null) p.HistoryProblem ??= "The history closes the case: give its \"outcome\" (an outcome key from Administration › Case outcomes).";
            else if (p.Conclusion is null) p.HistoryProblem ??= "The history closes the case: give its \"conclusion\" (what the team concluded).";
        }
        else if (p.Outcome is not null || p.Conclusion is not null)
        {
            p.Warnings.Add("The outcome and conclusion are recorded only when the history closes the case, so they were ignored.");
            (p.Outcome, p.Conclusion) = (null, null);
        }
    }

    /// <summary>
    /// CAP-35 review: why <paramref name="history"/> can't be applied to a case detected at <paramref name="detectedAtUtc"/>,
    /// or null. Each step is replayed through <see cref="Case.ChangePhase"/> itself, on a scratch case held in memory, so
    /// the preview refuses exactly what the apply would (C2): a time in the future or before detection, a contained or
    /// resolved time after the move or before detection, resolved before contained, and the REV-11 case (a Containment after
    /// "not needed" clears the resolution, so a later step to PostIncident must say when it was resolved again). Only the
    /// wording is the import's: a skip names the document's field.
    /// </summary>
    internal static string? ReplayHistory(IReadOnlyList<ImportHistoryRow> history, DateTimeOffset detectedAtUtc, DateTimeOffset nowUtc)
    {
        var scratch = Case.Open(nowUtc.Year, 0, "imported history", "imported history", null, Severity.Medium,
            CaseOrigin.InternalDetection, "import", nowUtc);
        scratch.DetectedAtUtc = detectedAtUtc;
        var resolutionTakenBack = false;
        for (var i = 0; i < history.Count; i++)
        {
            var h = history[i];
            var where = $"History step {i + 1}";
            var skipsContainment = scratch.SkipsContainment(h.Phase);
            if (skipsContainment && h.ContainedAtUtc is null && h.ContainmentNotNeeded is null)
                return $"{where}: moving to {h.Phase} skips Containment: give \"containedAt\" or \"containmentNotNeeded\".";
            if (!skipsContainment && (h.ContainedAtUtc is not null || h.ContainmentNotNeeded is not null))
                return $"{where}: \"containedAt\" and \"containmentNotNeeded\" belong only on a step that skips Containment.";
            var skipsRecovery = scratch.SkipsRecovery(h.Phase);
            if (skipsRecovery != (h.ResolvedAtUtc is not null))
                return skipsRecovery
                    ? $"{where}: moving to PostIncident skips Recovery: give \"resolvedAt\"" + (resolutionTakenBack
                        ? " (coming into Containment after \"containmentNotNeeded\" took back the resolution recorded before it)." : ".")
                    : $"{where}: \"resolvedAt\" belongs only on a step to PostIncident that skips Recovery.";
            var resolvedBefore = scratch.ResolvedAtUtc;
            try
            {
                scratch.ChangePhase(h.Phase, "imported", "import", nowUtc, h.AtUtc,
                    h.Phase == CasePhase.Closed ? "imported" : null, h.ContainedAtUtc, h.ContainmentNotNeeded, h.ResolvedAtUtc);
            }
            catch (ArgumentException ex)
            {
                return $"{where} ({h.Phase} at {Utc(h.AtUtc)}): {ex.Message}";
            }
            resolutionTakenBack |= resolvedBefore is not null && scratch.ResolvedAtUtc is null;
        }
        return null;
    }

    /// <summary>
    /// CAP-35: matches the incident commander and team to the user directory, by user id or UPN, as the reviewer reviews it.
    /// Someone it doesn't know is a warning, and isn't added: never dropped without a word. CAP-35 review: nor is someone
    /// two directory rows answer to (a UPN shared by two accounts): which one was meant is for a person to say.
    /// </summary>
    private void ResolveTeam(CaseImportPreview p)
    {
        var people = (p.IncidentCommander is { } ic ? [ic] : Array.Empty<ImportAssignmentRow>()).Concat(p.Assignments).ToList();
        if (people.Count == 0) return;
        var all = _users?.All() ?? [];
        foreach (var row in people)
        {
            var who = row.Role == CaseAssignmentRole.IncidentCommander ? "The incident commander" : "Team member";
            // CAP-35 review: a user id, then a UPN; more than one row answering either is ambiguous, not the first found.
            var byId = all.Where(x => string.Equals(x.UserId, row.Named, StringComparison.OrdinalIgnoreCase)).Take(2).ToList();
            var matches = byId.Count > 0 ? byId
                : all.Where(x => string.Equals(x.UserPrincipalName, row.Named, StringComparison.OrdinalIgnoreCase)).Take(2).ToList();
            var u = matches.Count == 1 ? matches[0] : null;
            (row.UserId, row.DisplayName) = (u?.UserId, u?.DisplayName);
            if (matches.Count > 1)
                p.Warnings.Add($"{who} \"{row.Named}\" matches more than one CaseBook user ({string.Join(", ", matches.Select(m => m.UserId))}), " +
                               "so they won't be added. Add the right one on the case.");
            else if (u is null)
                p.Warnings.Add($"{who} \"{row.Named}\" " +
                               "isn't a user CaseBook knows (by user id or UPN), so they won't be added. Add them on the case once they've signed in.");
        }
        // The team doesn't repeat the incident commander.
        if (p.IncidentCommander?.UserId is { } icId) p.Assignments.RemoveAll(a => a.UserId == icId);
    }

    // CAP-35: an outcome a history closes with must be one the close accepts (an active outcome). CAP-35 review: and its
    // reason must meet the close gate's commentary minimum, or every closing history would fail at its last step.
    private async Task CheckOutcomeAsync(CaseImportPreview p, CancellationToken ct)
    {
        if (p.HistoryProblem is not null) return;
        if (p.Outcome is { } key)
        {
            using var db = _factory.CreateDbContext();
            if (!await db.CaseOutcomes.AsNoTracking().AnyAsync(o => o.Key == key && o.IsActive, ct))
            {
                p.HistoryProblem = $"The outcome \"{key}\" isn't an active outcome (Administration › Case outcomes).";
                return;
            }
        }
        p.HistoryProblem = await CloseGateProblemAsync(p, ct);
    }

    private static CreateCaseRequest BuildNewCase(CaseImportNewCase? nc, DateTimeOffset nowUtc, List<string> warnings)
    {
        // BUG-528: CreateAsync refuses a detected time in the future, activity after detection, or a dwell over
        // Case.MaxDwellYears, and the preview can't edit either time, so a bad one is left out (with a warning) and
        // CreateAsync defaults it, rather than failing every Apply. Occurred is checked against the detected time
        // CreateAsync will use: the document's, or filing time.
        var detected = nc?.DetectedAtUtc;
        if (detected > nowUtc)
        {
            warnings.Add($"The detected time ({Utc(detected.Value)}) is in the future, so it was left out. The case counts from when it's filed.");
            detected = null;
        }
        var occurred = nc?.OccurredAtUtc;
        var against = detected ?? nowUtc;
        if (occurred > against)
        {
            warnings.Add($"The time activity began ({Utc(occurred.Value)}) is {(occurred > nowUtc ? "in the future" : "after it was detected")}, so it was left out.");
            occurred = null;
        }
        // (A detected time in the first years of the calendar can't take AddYears at all, so its occurred time goes too.)
        else if (occurred is not null && (against.Year <= Case.MaxDwellYears || occurred < against.AddYears(-Case.MaxDwellYears)))
        {
            warnings.Add($"The time activity began ({Utc(occurred.Value)}) is more than {Case.MaxDwellYears} years before it was detected, so it was left out. Check the year.");
            occurred = null;
        }

        var title = Clamp(nc?.Title, MaxTitle, "Title", warnings) ?? string.Empty;
        var descriptive = Clamp(nc?.DescriptiveName, MaxDescriptiveName, "Descriptive name", warnings);
        if (string.IsNullOrWhiteSpace(descriptive))
            descriptive = SlugSource(title); // derive when omitted, like the New Case form

        // Classification: omitted / "complexevent" / "none" ⇒ Complex Event (null), as the published schema
        // documents — an elevated event lands as intake and a person classifies it; otherwise parse with fallback.
        Classification? classification = null;
        if (nc?.Classification is { } rawCls && !string.IsNullOrWhiteSpace(rawCls))
        {
            var trimmed = rawCls.Trim();
            if (trimmed.Equals("ComplexEvent", StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("None", StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("null", StringComparison.OrdinalIgnoreCase))
                classification = null;
            else if (ImportEnums.TryName<Classification>(trimmed, out var c))
                classification = c;
            else
                warnings.Add($"Unknown classification '{rawCls}'. Filing it as a Complex Event, to be classified by a person.");
        }

        return new CreateCaseRequest
        {
            Title = title,
            DescriptiveName = descriptive,
            Classification = classification,
            Severity = ParseEnum(nc?.Severity, Severity.Medium, "severity", warnings),
            Origin = ParseEnum(nc?.Origin, CaseOrigin.InternalDetection, "origin", warnings),
            Summary = Clamp(nc?.Summary, MaxSummary, "Case summary", warnings),
            DetectedAtUtc = detected,
            OccurredAtUtc = occurred,
            DataTypesInvolved = Clamp(nc?.DataTypesInvolved, 4000, "Data context", warnings),   // BUG-247: the column, not a label's 300
            ImpactedAssets = Clamp(nc?.ImpactedAssets, 4000, "Impacted assets", warnings),   // BUG-105: the column
            DetectionCaseId = Clamp(nc?.DetectionCaseId, 100, "Detection case ID", warnings),
            VendorName = Clamp(nc?.VendorName, 300, "Vendor name", warnings),   // BUG-117: a third-party case needs one
            IsExercise = nc?.Exercise == true   // BUG-635: a tabletop case, as the New case form's switch
        };
    }

    private static string Utc(DateTimeOffset at) => at.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static string? Clamp(string? value, int max, string field, List<string> warnings)
    {
        var v = value?.Trim();
        if (string.IsNullOrEmpty(v)) return null;
        if (v.Length <= max) return v;
        warnings.Add($"{field} was longer than {max} characters and was truncated.");
        return TextFit.Cap(v, max, "");   // C12: never half a surrogate pair
    }

    private static TEnum ParseEnum<TEnum>(string? raw, TEnum fallback, string field, List<string> warnings)
        where TEnum : struct, Enum
    {
        if (string.IsNullOrWhiteSpace(raw)) return fallback;
        if (ImportEnums.TryName<TEnum>(raw, out var v)) return v;
        warnings.Add($"Unknown {field} '{raw}'. Using {fallback} instead.");
        return fallback;
    }

    // INV-06: a Decision needs a rationale, which the import schema doesn't carry yet.
    private static TimelineEntryType ImportableTimelineType(TimelineEntryType t, List<string> warnings)
    {
        if (t != TimelineEntryType.Handoff) return t;
        warnings.Add("Timeline type 'Handoff' can't be imported (use Hand off in CaseBook). Using Communication instead.");
        return TimelineEntryType.Communication;
    }

    /// <summary>The case-number slug source for a title (the first six words, at most 42 characters), as the New case
    /// form derives it. BUG-637: also used by the import preview when the title is edited.</summary>
    public static string SlugSource(string? title)
    {
        var t = (title ?? "").Trim();
        if (t.Length == 0) return "Imported case";
        var s = string.Join(' ', t.Split(' ', StringSplitOptions.RemoveEmptyEntries).Take(6));
        return TextFit.Cap(s, 42, "").TrimEnd();
    }
}
