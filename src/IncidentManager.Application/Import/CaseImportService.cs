using System.Globalization;
using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using Microsoft.EntityFrameworkCore;
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

    public CaseImportService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, CaseService cases,
        IAuditWriter? audit = null)
    {
        _audit = audit;
        _factory = factory;
        _user = user;
        _clock = clock;
        _cases = cases;
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
    public async Task<CaseImportPreview> BuildPreviewAsync(CaseImportDocument doc, Guid? intoCaseId = null,
        CancellationToken ct = default)
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

        return preview;
    }

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
    public async Task<CaseImportResult> ApplyAsync(CaseImportPreview p, CancellationToken ct = default)
    {
        // INV-18: checked before anything is written, so a missing why can't leave a half-applied import.
        if (p.Timeline.Any(t => t.Include && t.Type == TimelineEntryType.Decision && string.IsNullOrWhiteSpace(t.Rationale)))
            throw new ArgumentException("A decision on the timeline needs its why. Add it, or change the entry's type.");

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

        return new CaseImportResult(caseId, caseNumber, created, notes, timeline, entities, actionItems);
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
        await SubmitGate.WaitAsync(ct);
        try { return await SubmitOnceCoreAsync(rawJson, doc, ct); }
        finally { SubmitGate.Release(); }
    }

    private static readonly SemaphoreSlim SubmitGate = new(1, 1);

    private static string Sha256(string text) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    private async Task<(Guid Id, CaseImportPreview Preview, bool AlreadyQueued)> SubmitOnceCoreAsync(string rawJson, CaseImportDocument doc,
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
                return (id0, await BuildPreviewAsync(doc, ct: ct), true);
        }
        var (id, preview) = await SubmitAsync(rawJson, doc, ct);
        return (id, preview, false);
    }

    public async Task<(Guid Id, CaseImportPreview Preview)> SubmitAsync(string rawJson, CaseImportDocument doc,
        CancellationToken ct = default)
    {
        var preview = await BuildPreviewAsync(doc, ct: ct);

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

        using var db = _factory.CreateDbContext();
        db.PendingImports.Add(row);
        await db.SaveChangesAsync(ct);
        return (row.Id, preview);
    }

    /// <summary>
    /// The queued submissions the caller may see: need-to-know scoped on the target case, because the queue shows
    /// the submitter, origin and a summary naming the target's case number. A submission into an existing case the
    /// caller can't see (<see cref="CaseQueryExtensions.ForUser"/>) is left out; one with no target, or whose
    /// target no longer exists (it previews as a new case), is visible to every reviewer.
    /// </summary>
    private IQueryable<PendingImport> VisiblePending(IAppDbContext db)
    {
        var visible = db.Cases.ForUser(_user).Select(c => c.Id);
        return db.PendingImports.Where(p => p.TargetCaseId == null
            || visible.Contains(p.TargetCaseId.Value)
            || !db.Cases.Any(c => c.Id == p.TargetCaseId));
    }

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
        if (_audit is not null)
            await _audit.RecordAsync(AuditAction.Update, "PendingImport", pendingId.ToString(), null,
                $"Reopened a stuck import \"{row.Summary}\" (claimed by {row.DecidedBy} at {Utc(at)}, no case recorded)", ct);
        return true;
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
        if (parsed.Document!.Target is { } target) target.CaseId = null;
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
        || p.Entities.Any(e => e.Applied) || p.ActionItems.Any(a => a.Applied);

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
    public async Task<DateTimeOffset?> ClaimPendingAsync(Guid pendingId, CancellationToken ct = default)
    {
        RequireEdit();
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;
        var now = _clock.UtcNow;
        var claimed = await VisiblePending(db)
            .Where(p => p.Id == pendingId && p.Status == PendingImportStatus.Pending)
            .ExecuteUpdateAsync(s => s
                .SetProperty(p => p.Status, PendingImportStatus.Applied)
                .SetProperty(p => p.DecidedBy, me)
                .SetProperty(p => p.DecidedAtUtc, now), ct);
        if (claimed == 1) return now;

        var left = await VisiblePending(db).AsNoTracking().Where(p => p.Id == pendingId)
            .Select(p => new { p.Status, p.DecidedBy, p.ResolvedCaseId, p.DecidedAtUtc }).FirstOrDefaultAsync(ct);
        if (left is not { Status: PendingImportStatus.Applied, ResolvedCaseId: null } || left.DecidedBy != me
            || left.DecidedAtUtc is not { } at || now - at < StaleClaim) return null;
        claimed = await VisiblePending(db)
            .Where(p => p.Id == pendingId && p.Status == PendingImportStatus.Applied && p.DecidedBy == me
                        && p.ResolvedCaseId == null && p.DecidedAtUtc == at)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.DecidedAtUtc, now), ct);
        return claimed == 1 ? now : null;
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
        if (HasApplied(preview)) row.ResumeJson = JsonSerializer.Serialize(preview, ResumeJsonOptions);
        await db.SaveChangesAsync(ct);
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
        return rejected == 1;
    }

    /// <summary>S-09: deciding a queued import is a case edit (the page is EditCases-gated; this is the backstop).</summary>
    private void RequireEdit([System.Runtime.CompilerServices.CallerMemberName] string action = "")
    {
        if (!_user.Has(Permission.EditCases)) throw new ForbiddenException(Permission.EditCases, action);
    }

    private static string SummariseForQueue(CaseImportPreview p)
    {
        var target = p.TargetKind == CaseImportTargetKind.ExistingCase
            ? $"Into {p.ExistingCaseNumber ?? "an existing case"}"
            : $"New case: {(string.IsNullOrWhiteSpace(p.NewCase?.Title) ? "(untitled)" : p.NewCase!.Title)}";
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

        return p;
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
