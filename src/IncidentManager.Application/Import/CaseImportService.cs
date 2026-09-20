using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using Microsoft.EntityFrameworkCore;

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

    public CaseImportService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, CaseService cases)
    {
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
    private const int MaxValue = 1024;
    private const int MaxLabel = 300;
    private const int MaxOwner = 200;

    /// <summary>Parses import JSON, guarding format and schema version. Never throws on bad input — returns a
    /// friendly <see cref="CaseImportParse.Error"/> instead, so the UI/API can show it.</summary>
    public static CaseImportParse Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return CaseImportParse.Fail("Paste or upload a case-import document first.");

        CaseImportDocument? doc;
        try
        {
            doc = JsonSerializer.Deserialize<CaseImportDocument>(json, CaseImportJson.Options);
        }
        catch (JsonException)
        {
            return CaseImportParse.Fail("This isn't valid JSON. Check the document and try again.");
        }

        if (doc is null)
            return CaseImportParse.Fail("This isn't a case-import document.");
        if (!string.Equals(doc.Format, CaseImportJson.FormatTag, StringComparison.Ordinal))
            return CaseImportParse.Fail(
                $"This isn't a CaseBook case-import document (expected \"format\": \"{CaseImportJson.FormatTag}\").");
        if (doc.SchemaVersion is { } v && v > CaseImportJson.CurrentSchemaVersion)
            return CaseImportParse.Fail(
                $"This document is schema v{v}, newer than this app supports (v{CaseImportJson.CurrentSchemaVersion}). Upgrade CaseBook first.");

        return CaseImportParse.Success(doc);
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
                preview.Warnings.Add("The target case wasn't found or isn't visible to you — prepared a new case instead.");
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
            await _cases.AddNoteAsync(caseId, p.Summary!, ct);
            p.SummaryApplied = true;
        }
        if (p.SummaryApplied) notes = 1;

        var timeline = 0;
        foreach (var t in p.Timeline.Where(t => t.Include))
        {
            if (!t.Applied)
            {
                await _cases.AddTimelineEntryAsync(caseId, t.Kind, t.Type, t.OccurredAtUtc,
                    t.Description, t.Source ?? origin, null, ct);
                t.Applied = true;
            }
            timeline++;
        }

        var entities = 0;
        foreach (var e in p.Entities.Where(e => e.Include))
        {
            if (!e.Applied)
            {
                await _cases.AddEntityAsync(caseId, e.Type, e.Value, e.Label, e.Disposition,
                    e.Description, e.Source ?? origin, ct);
                e.Applied = true;
            }
            entities++;
        }

        var actionItems = 0;
        foreach (var a in p.ActionItems.Where(a => a.Include))
        {
            if (!a.Applied)
            {
                await _cases.AddActionItemAsync(caseId, a.Title, a.Owner, a.DueAtUtc, ct);
                a.Applied = true;
            }
            actionItems++;
        }

        return new CaseImportResult(caseId, caseNumber, created, notes, timeline, entities, actionItems);
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
        var p = new CaseImportPreview
        {
            TargetKind = CaseImportTargetKind.NewCase,
            Origin = string.IsNullOrWhiteSpace(doc.Origin) ? null : doc.Origin.Trim()
        };
        p.NewCase = BuildNewCase(doc.Target?.NewCase, p.Warnings);

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
            var desc = Clamp(t.Description, MaxDescription, "Timeline description", p.Warnings);
            if (string.IsNullOrWhiteSpace(desc)) { droppedTimeline++; continue; }

            var row = new ImportTimelineRow
            {
                Kind = ParseEnum(t.Kind, TimelineKind.Investigation, "timeline kind", p.Warnings),
                Type = ParseEnum(t.Type, TimelineEntryType.Communication, "timeline type", p.Warnings),
                Description = desc!,
                Source = string.IsNullOrWhiteSpace(t.Source) ? p.Origin : t.Source.Trim()
            };
            if (t.OccurredAtUtc is { } occ)
            {
                row.OccurredAtUtc = occ;
                if (occ > nowUtc)
                {
                    row.Include = false;
                    row.Warning = "In the future — excluded. Correct the time to include it.";
                }
            }
            else
            {
                row.OccurredAtUtc = nowUtc;
                row.Warning = "No timestamp — defaulted to now.";
            }
            p.Timeline.Add(row);
        }
        if (droppedTimeline > 0) p.Warnings.Add($"{droppedTimeline} timeline entr(y/ies) had no description and were skipped.");

        // Entities (refang/auto-type + dedupe by type+value)
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var droppedEntities = 0;
        foreach (var e in doc.Entities ?? [])
        {
            var rawValue = Clamp(e.Value, MaxValue, "Entity value", p.Warnings);
            if (string.IsNullOrWhiteSpace(rawValue)) { droppedEntities++; continue; }

            EntityType type;
            if (string.IsNullOrWhiteSpace(e.Type))
                type = IocObservable.DetectType(rawValue);
            else if (Enum.TryParse<EntityType>(e.Type, ignoreCase: true, out var parsed))
                type = parsed;
            else
            {
                type = IocObservable.DetectType(rawValue);
                p.Warnings.Add($"Unknown entity type '{e.Type}' — auto-detected as {type}.");
            }

            var value = IocObservable.Normalize(type, rawValue);
            if (value.Length == 0) { droppedEntities++; continue; }
            if (!seen.Add($"{(int)type}|{value.ToLowerInvariant()}")) continue; // dedupe

            p.Entities.Add(new ImportEntityRow
            {
                Type = type,
                Value = value,
                Label = Clamp(e.Label, MaxLabel, "Entity label", p.Warnings),
                Disposition = ParseEnum(e.Disposition, EntityDisposition.Unknown, "entity disposition", p.Warnings),
                Description = Clamp(e.Description, MaxDescription, "Entity description", p.Warnings),
                Source = string.IsNullOrWhiteSpace(e.Source) ? p.Origin : e.Source.Trim()
            });
        }
        if (droppedEntities > 0) p.Warnings.Add($"{droppedEntities} entit(y/ies) had no value and were skipped.");

        // Action items
        var droppedTasks = 0;
        foreach (var a in doc.ActionItems ?? [])
        {
            var title = Clamp(a.Title, MaxTitle, "Action-item title", p.Warnings);
            if (string.IsNullOrWhiteSpace(title)) { droppedTasks++; continue; }
            p.ActionItems.Add(new ImportActionItemRow
            {
                Title = title!,
                Owner = Clamp(a.Owner, MaxOwner, "Action-item owner", p.Warnings),
                DueAtUtc = a.DueAtUtc
            });
        }
        if (droppedTasks > 0) p.Warnings.Add($"{droppedTasks} action item(s) had no title and were skipped.");

        return p;
    }

    private static CreateCaseRequest BuildNewCase(CaseImportNewCase? nc, List<string> warnings)
    {
        var title = Clamp(nc?.Title, MaxTitle, "Title", warnings) ?? string.Empty;
        var descriptive = Clamp(nc?.DescriptiveName, MaxDescriptiveName, "Descriptive name", warnings);
        if (string.IsNullOrWhiteSpace(descriptive))
            descriptive = SlugSource(title); // derive when omitted, like the New Case form

        // Classification: null / "complexevent" / "none" ⇒ Complex Event (null); otherwise parse with fallback.
        Classification? classification = Classification.AdverseEvent;
        if (nc?.Classification is { } rawCls && !string.IsNullOrWhiteSpace(rawCls))
        {
            var trimmed = rawCls.Trim();
            if (trimmed.Equals("ComplexEvent", StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("None", StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("null", StringComparison.OrdinalIgnoreCase))
                classification = null;
            else if (Enum.TryParse<Classification>(trimmed, ignoreCase: true, out var c))
                classification = c;
            else
                warnings.Add($"Unknown classification '{rawCls}' — defaulted to {Classification.AdverseEvent}.");
        }

        return new CreateCaseRequest
        {
            Title = title,
            DescriptiveName = descriptive,
            Classification = classification,
            Severity = ParseEnum(nc?.Severity, Severity.Medium, "severity", warnings),
            Origin = ParseEnum(nc?.Origin, CaseOrigin.InternalDetection, "origin", warnings),
            Summary = Clamp(nc?.Summary, MaxSummary, "Case summary", warnings),
            DetectedAtUtc = nc?.DetectedAtUtc,
            OccurredAtUtc = nc?.OccurredAtUtc,
            DataTypesInvolved = Clamp(nc?.DataTypesInvolved, MaxLabel, "Data types", warnings),
            ImpactedAssets = Clamp(nc?.ImpactedAssets, MaxSummary, "Impacted assets", warnings)
        };
    }

    private static string? Clamp(string? value, int max, string field, List<string> warnings)
    {
        var v = value?.Trim();
        if (string.IsNullOrEmpty(v)) return null;
        if (v.Length <= max) return v;
        warnings.Add($"{field} was longer than {max} characters and was truncated.");
        return v[..max];
    }

    private static TEnum ParseEnum<TEnum>(string? raw, TEnum fallback, string field, List<string> warnings)
        where TEnum : struct, Enum
    {
        if (string.IsNullOrWhiteSpace(raw)) return fallback;
        if (Enum.TryParse<TEnum>(raw.Trim(), ignoreCase: true, out var v) && Enum.IsDefined(v)) return v;
        warnings.Add($"Unknown {field} '{raw}' — defaulted to {fallback}.");
        return fallback;
    }

    private static string SlugSource(string? title)
    {
        var t = (title ?? "").Trim();
        if (t.Length == 0) return "Imported case";
        var s = string.Join(' ', t.Split(' ', StringSplitOptions.RemoveEmptyEntries).Take(6));
        return s.Length <= 42 ? s : s[..42].TrimEnd();
    }
}
