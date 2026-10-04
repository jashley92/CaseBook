using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentManager.Application.Reporting;

/// <summary>
/// Generates, stores, lists and verifies case reports. Each generated file is hashed; the hash
/// is persisted on the <see cref="Report"/> record so the artifact can be integrity-checked later.
/// </summary>
public sealed class ReportService
{
    private readonly IAppDbContextFactory _factory;
    private readonly IReportGenerator _generator;
    private readonly IReportStore _store;
    private readonly IHashChainService _hasher;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly Content.IMarkdownService _markdown;
    private readonly IOptionsMonitor<ReportingOptions> _reporting;
    private readonly IReportBrandingStore _branding;
    private readonly IUserDirectory _users;
    private readonly ISeverityLabels _severityLabels;
    private readonly ITaxonomyDisplay? _taxonomy;

    private readonly IReportDiagrams? _diagrams;   // PROD-46: report pictures (null = tables only)
    private readonly IReportTemplateEngine? _templates;      // PROD-47
    private readonly IReportTemplateStore? _templateStore;   // PROD-47

    public ReportService(IAppDbContextFactory factory, IReportGenerator generator, IReportStore store,
        IHashChainService hasher, ICurrentUser user, IClock clock, Content.IMarkdownService markdown,
        IOptionsMonitor<ReportingOptions> reporting, IReportBrandingStore branding, IUserDirectory users,
        ISeverityLabels severityLabels, ITaxonomyDisplay? taxonomy = null, IReportDiagrams? diagrams = null,
        IReportTemplateEngine? templates = null, IReportTemplateStore? templateStore = null)
    {
        _templates = templates;
        _templateStore = templateStore;
        _diagrams = diagrams;
        _factory = factory;
        _generator = generator;
        _store = store;
        _hasher = hasher;
        _user = user;
        _clock = clock;
        _markdown = markdown;
        _reporting = reporting;
        _branding = branding;
        _users = users;
        _severityLabels = severityLabels;
        _taxonomy = taxonomy;
    }

    // X-02: apply the org's taxonomy display labels to the report, consistent with the on-screen labels
    // and the severity labels already used here. Canonical member names when no provider/override is set.
    private string ClassificationLabel(Classification? c)
    {
        var member = c?.ToString() ?? "ComplexEvent";
        var def = c is null ? "Complex Event" : Admin.TaxonomyCatalog.DefaultLabel("Classification", member);
        return _taxonomy?.Label("Classification", member, def) ?? def;
    }

    // Same wording as the Tasks tab, so the report never prints "InProgress" or "Cancelled".
    private static string TaskStatusLabel(ActionItemStatus s) => s switch
    {
        ActionItemStatus.InProgress => "In progress",
        ActionItemStatus.Cancelled => "Canceled",
        _ => s.ToString()
    };

    /// <summary>
    /// The report's account of the response: the analyst's investigation entries and (INV-16, when enabled) the
    /// response milestones, interleaved by when they happened. An item entered more than an hour after it happened
    /// can carry a neutral "Recorded …" note (<see cref="ReportingOptions.MarkLateEntries"/>).
    /// </summary>
    private List<ReportTimelineItem> InvestigationTimeline(Case c, ReportDefanger d, ReportingOptions opts)
    {
        string Late(DateTimeOffset happened, DateTimeOffset recorded) =>
            opts.MarkLateEntries && recorded - happened > Cases.CaseService.BackdateReasonThreshold
                ? $" (Recorded {recorded.ToString("u", System.Globalization.CultureInfo.InvariantCulture)}.)"
                : "";

        var rows = c.TimelineEntries
            .Where(x => x.Kind == TimelineKind.Investigation && x.IsCurrent)
            // Investigation descriptions are Markdown; flatten to readable plain text for the report. An edited
            // entry was first recorded when its original version was.
            // INV-23: an imported entry was always recorded after it happened; the subtitle says so once.
            .Select(x => (At: x.OccurredAtUtc, Order: x.CreatedAtUtc, Item: new ReportTimelineItem(x.OccurredAtUtc,
                TaxLabel("TimelineEntryType", x.Type.ToString()),
                d.Text(EntryText(x)) + Cited(c, x) + (x.IsImported ? "" : Late(x.OccurredAtUtc, FirstRecorded(c, x))),
                x.Source, x.IsImported, _users.DisplayFor(x.CreatedBy))))
            .ToList();

        if (opts.IncludeMilestones)
        {
            var labels = new Cases.MilestoneLabels(ClassificationLabel, _severityLabels.For, PhaseLabel, MaterialityLabel);
            // A report listing its own earlier versions reads oddly, so final-report milestones stay out; so do
            // staffing changes (INV-31), which are the team's working record rather than findings.
            foreach (var m in Cases.CaseMilestones.Project(c, labels)
                         .Where(m => m.Kind is not (Cases.MilestoneKind.ReportFinal or Cases.MilestoneKind.Command)))
            {
                var text = m.Detail is { } detail ? $"{m.Title}. {detail}" : m.Title;
                if (m.RecordedAtUtc is { } rec) text += Late(m.AtUtc, rec);
                var by = m.Actor is { } who ? _users.DisplayFor(who) : null;
                rows.Add((m.AtUtc, m.AtUtc, new ReportTimelineItem(m.AtUtc, ReportTimelineItem.Milestone, d.Text(text),
                    by, By: by)));
            }
        }

        return rows.OrderBy(r => r.At).ThenBy(r => r.Order).Select(r => r.Item).ToList();
    }

    // An investigation entry as report text (Markdown flattened). INV-06: a decision prints as a sentence
    // followed by its rationale, the options considered and who decided.
    private static string EntryText(TimelineEntry e)
    {
        var text = Content.RichText.ToText(e.Description).Trim();
        if (e.Type != TimelineEntryType.Decision) return text;
        var sb = new System.Text.StringBuilder(text);
        if (text.Length > 0 && !".!?".Contains(text[^1])) sb.Append('.');
        if (e.Rationale is { } why) sb.Append(" Why: ").Append(why.TrimEnd('.')).Append('.');
        if (e.OptionsConsidered is { } options) sb.Append(" Options considered: ").Append(options.TrimEnd('.')).Append('.');
        if (e.DecidedBy is { } who) sb.Append(" Decided by: ").Append(who.TrimEnd('.')).Append('.');
        return sb.ToString();
    }

    // INV-19: a brief part as report text — Markdown flattened, indicators defanged.
    private string? BriefText(string? markdown, ReportDefanger d) =>
        string.IsNullOrWhiteSpace(markdown) ? null : d.Text(_markdown.ToPlainText(markdown).Trim());

    // INV-10: the evidence an entry cites, by file name.
    private static string Cited(Case c, TimelineEntry e)
    {
        var files = c.Citations.Where(x => x.TimelineEntryId == e.Id)
            .Select(x => c.Evidence.FirstOrDefault(ev => ev.Id == x.EvidenceId)?.OriginalFileName)
            .Where(n => n is not null).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        return files.Count == 0 ? "" : $" Evidence: {string.Join(", ", files)}.";
    }

    // When an investigation entry was first put on the record: its original version's creation time.
    private static DateTimeOffset FirstRecorded(Case c, TimelineEntry e)
    {
        var first = e;
        while (first.SupersedesEntryId is { } prior && c.TimelineEntries.FirstOrDefault(x => x.Id == prior) is { } p)
            first = p;
        return first.CreatedAtUtc;
    }

    private string PhaseLabel(CasePhase p) =>
        _taxonomy?.Label("CasePhase", p.ToString(), p.ToString()) ?? p.ToString();

    // Applies a taxonomy override (X-02) with the catalog's built-in default as the fallback, so entity and
    // timeline labels in the report match the on-screen labels whether or not an override is set.
    private string TaxLabel(string kind, string member)
    {
        var def = Admin.TaxonomyCatalog.DefaultLabel(kind, member);
        return _taxonomy?.Label(kind, member, def) ?? def;
    }

    /// <summary>A case's stored reports of one kind, newest first. The case report and the separate
    /// lessons-learned report are listed (and versioned) independently.</summary>
    public async Task<List<Report>> ListAsync(Guid caseId, ReportKind kind = ReportKind.Case, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.Reports.AsNoTracking().Where(r => r.CaseId == caseId && r.Kind == kind)
            .OrderByDescending(r => r.CreatedAtUtc).ToListAsync(ct);
    }

    /// <summary>
    /// Generates a report as a <b>working draft</b> (E-15). Finalization is a separate, permission-gated
    /// approval step (<see cref="ApproveAsync"/>) — generating no longer self-approves.
    /// </summary>
    /// <param name="template">PROD-47: which Word template to fill. Null = the case's profile default (the built-in
    /// layout when it has none); <see cref="Guid.Empty"/> = the built-in layout; otherwise that library template.</param>
    public async Task<Report> GenerateAsync(Guid caseId, TlpLevel? tlp = null, CancellationToken ct = default,
        Guid? template = null)
    {
        if (!_user.Has(Permission.EditCases)) throw new Security.ForbiddenException(Permission.EditCases);
        using var db = _factory.CreateDbContext();
        // Need-to-know on the parent case, same "not found" message as the preview so a restricted case's
        // existence isn't leaked by generating against its GUID.
        var canAccess = await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(x => x.Id == caseId, ct);
        if (!canAccess) throw new InvalidOperationException("Case not found.");
        var c = await LoadFullCaseAsync(db, caseId, ct)
            ?? throw new InvalidOperationException("Case not found.");

        var now = _clock.UtcNow;
        var logo = await _branding.GetLogoAsync(ct);
        var sections = await ResolveSectionsAsync(db, c.ReportProfileId, ct);
        var (elemSummary, triggers) = await ImpactElementsAsync(db, c, ct);
        var model = BuildModel(c, now, logo, sections, elemSummary, triggers, tlp, await TaskResultsAsync(db, c.Id, ct));

        // PROD-47: the report can be filled from a customer-designed template (the profile's default, or one picked
        // for this report). Reports are Word only: there's no way to turn a filled template into a matching PDF on
        // the server without Word or LibreOffice, so PDF output was dropped rather than offer one that doesn't match.
        byte[]? rendered = null;
        ResolvedTemplate? used = null;
        if (await ResolveTemplateAsync(db, await ProfileTemplateIdAsync(db, c.ReportProfileId, ct), template, ct) is { } t)
        {
            // A template may use any field, the review's included (the admin decides what it prints), so it's filled
            // from the case model with the review added. The built-in layout never prints the review.
            rendered = _templates!.Render(t.Bytes, await WithReviewAsync(db, c, model, ct));
            used = t;
        }

        return await StoreAsync(db, caseId, c.CaseNumber, ReportKind.Case, model, now, ct, rendered, used);
    }

    /// <summary>
    /// PROD-47: fills a library template with a case's data for an admin to check, without storing a report, adding
    /// a version or touching the case. The document opens with a "PREVIEW" line so it can't pass for a report.
    /// Admin-only, and need-to-know on the case applies like any report. The web endpoint records the download in
    /// the access log.
    /// </summary>
    public async Task<(string FileName, byte[] Bytes, string CaseNumber)> PreviewTemplateAsync(Guid templateId, Guid caseId,
        CancellationToken ct = default)
    {
        if (!_user.Has(Permission.Administer)) throw new Security.ForbiddenException(Permission.Administer);
        if (_templates is null || _templateStore is null) throw new InvalidOperationException("Word templates aren't available on this server.");
        using var db = _factory.CreateDbContext();
        var canAccess = await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(x => x.Id == caseId, ct);
        if (!canAccess) throw new InvalidOperationException("Case not found.");
        var tpl = await db.ReportTemplates.AsNoTracking().FirstOrDefaultAsync(t => t.Id == templateId, ct)
                  ?? throw new InvalidOperationException("That template no longer exists. Reload the page and try again.");
        var bytes = await _templateStore.GetAsync(templateId, ct)
                    ?? throw new InvalidOperationException("The template's file is missing from the template folder. Replace it to fix this.");
        var c = await LoadFullCaseAsync(db, caseId, ct) ?? throw new InvalidOperationException("Case not found.");

        var now = _clock.UtcNow;
        var logo = await _branding.GetLogoAsync(ct);
        var sections = await ResolveSectionsAsync(db, c.ReportProfileId, ct);
        var (elemSummary, triggers) = await ImpactElementsAsync(db, c, ct);
        var model = await WithReviewAsync(db, c, BuildModel(c, now, logo, sections, elemSummary, triggers, null), ct);
        var banner = $"PREVIEW of template “{tpl.Name}” with case {c.CaseNumber}, {now:yyyy-MM-dd HH:mm} UTC. " +
                     "Not a stored or approved report.";
        var rendered = _templates.Render(bytes, model, banner);
        var safeName = string.Concat(tpl.Name.Select(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_' ? ch : '-'));
        return ($"PREVIEW_{safeName}_{c.CaseNumber}.docx", rendered, c.CaseNumber);
    }

    /// <summary>
    /// Generates the separate lessons-learned report (E-26/PROD-41): the post-incident review and its
    /// improvement actions, and nothing else from the case. A <b>working draft</b> like the case report, stored,
    /// hashed and approvable through the same path, but listed and versioned on its own so it is never mixed
    /// into the examiner-facing case report. Prints the admin-set legend (if any) on every page.
    /// </summary>
    /// <param name="template">Which Word template to fill. Null = the library's lessons-learned default (the built-in
    /// layout when there is none); <see cref="Guid.Empty"/> = the built-in layout; otherwise that library template.</param>
    public async Task<Report> GenerateLessonsAsync(Guid caseId, TlpLevel? tlp = null, CancellationToken ct = default,
        Guid? template = null)
    {
        if (!_user.Has(Permission.EditCases)) throw new Security.ForbiddenException(Permission.EditCases);
        using var db = _factory.CreateDbContext();
        var c = await db.Cases.AsNoTracking().ForUser(_user).FirstOrDefaultAsync(x => x.Id == caseId, ct)
            ?? throw new InvalidOperationException("Case not found.");

        var now = _clock.UtcNow;
        var model = await BuildLessonsModelAsync(db, c, now, ct, tlp);

        // A Word template may use any field, case fields included (the admin decides what it prints), so it's filled
        // from the full case model carrying this report's identity: its kind, legend, review and content hash.
        byte[]? rendered = null;
        ResolvedTemplate? used = null;
        var lessonsDefault = await db.ReportTemplates.AsNoTracking().Where(t => t.IsLessonsDefault && t.IsActive)
            .Select(t => (Guid?)t.Id).FirstOrDefaultAsync(ct);
        if (await ResolveTemplateAsync(db, lessonsDefault, template, ct) is { } t)
        {
            var full = await LoadFullCaseAsync(db, caseId, ct) ?? throw new InvalidOperationException("Case not found.");
            var sections = await ResolveSectionsAsync(db, full.ReportProfileId, ct);
            var (elemSummary, triggers) = await ImpactElementsAsync(db, full, ct);
            var caseModel = BuildModel(full, now, await _branding.GetLogoAsync(ct), sections, elemSummary, triggers, tlp, await TaskResultsAsync(db, full.Id, ct));
            rendered = _templates!.Render(t.Bytes, caseModel with
            {
                Kind = ReportKind.LessonsLearned,
                Legend = model.Legend,
                Review = model.Review,
                ImprovementActions = model.ImprovementActions,
                ContentHash = model.ContentHash,
            });
            used = t;
        }
        return await StoreAsync(db, caseId, c.CaseNumber, ReportKind.LessonsLearned, model, now, ct, rendered, used);
    }

    /// <summary>The template id a report profile names as its default, if any.</summary>
    private static async Task<Guid?> ProfileTemplateIdAsync(IAppDbContext db, Guid? profileId, CancellationToken ct) =>
        profileId is { } pid
            ? await db.ReportProfiles.AsNoTracking().Where(p => p.Id == pid && p.IsActive).Select(p => p.TemplateId).FirstOrDefaultAsync(ct)
            : null;

    /// <summary>The case model with the post-incident review and improvement actions added, for a Word template.</summary>
    private async Task<CaseReportModel> WithReviewAsync(IAppDbContext db, Case c, CaseReportModel model, CancellationToken ct)
    {
        var (review, actions, _) = await ReviewPartsAsync(db, c.Id, ReportDefanger.For(c.Entities, model.IndicatorsDefanged), ct);
        return model with { Review = review, ImprovementActions = actions };
    }

    /// <summary>Renders, stores and records a report; versions number per case + kind + format.</summary>
    private sealed record ResolvedTemplate(string Name, string Sha256, byte[] Bytes);

    /// <summary>PROD-47: the Word template to fill (see <see cref="GenerateAsync"/>'s template argument), or null for
    /// the built-in layout. A picked template must be active; a default that's gone falls back to built-in.</summary>
    private async Task<ResolvedTemplate?> ResolveTemplateAsync(IAppDbContext db, Guid? defaultId, Guid? choice, CancellationToken ct)
    {
        if (_templates is null || _templateStore is null) return null;
        if (choice == Guid.Empty) return null;

        if ((choice ?? defaultId) is not { } tid) return null;

        var t = await db.ReportTemplates.AsNoTracking().FirstOrDefaultAsync(x => x.Id == tid && x.IsActive, ct);
        if (t is null)
        {
            if (choice is not null) throw new InvalidOperationException("That Word template is archived or no longer exists. Pick another.");
            return null;
        }
        var bytes = await _templateStore.GetAsync(tid, ct)
                    ?? throw new InvalidOperationException($"The file for template “{t.Name}” is missing. Ask an administrator to replace it.");
        return new ResolvedTemplate(t.Name, t.Sha256, bytes);
    }

    private async Task<Report> StoreAsync(IAppDbContext db, Guid caseId, string caseNumber, ReportKind kind,
        CaseReportModel model, DateTimeOffset now, CancellationToken ct, byte[]? rendered = null,
        ResolvedTemplate? template = null)
    {
        const ReportFormat format = ReportFormat.Word;   // PDF generation was removed; stored PDFs stay readable
        var bytes = rendered ?? _generator.GenerateWord(model);
        const string ext = "docx";
        var version = await db.Reports.CountAsync(r => r.CaseId == caseId && r.Kind == kind && r.Format == format, ct) + 1;
        var fileName = kind == ReportKind.LessonsLearned
            ? $"{caseNumber}_lessons-learned_v{version}.{ext}"
            : $"{caseNumber}_v{version}.{ext}";

        var stored = await _store.SaveAsync(caseId, fileName, bytes, ct);

        var report = new Report
        {
            Tlp = model.Tlp,   // PROD-45
            TemplateName = template?.Name,       // PROD-47: which template filled it, by value
            TemplateSha256 = template?.Sha256,
            CaseId = caseId,
            Kind = kind,
            Version = version,
            Format = format,
            FileName = fileName,
            StoragePath = stored.StoragePath,
            ContentSha256 = stored.Sha256,
            IsFinal = false,          // always a draft; finalization is the separate ApproveAsync step (E-15)
            ApprovedBy = null,
            ApprovedAtUtc = null,
            CreatedBy = _user.UserId,
            CreatedAtUtc = now
        };
        db.Reports.Add(report);
        await db.SaveChangesAsync(ct);
        return report;
    }

    /// <summary>
    /// Approves and finalizes a generated draft (E-15) — stamps the approver + timestamp and marks it
    /// the locked final. Enforces need-to-know on the parent case and, when configured, separation of
    /// duties (approver ≠ generator). Asserts <c>ApproveReports</c> here too, not only via the web-layer policy.
    /// </summary>
    public async Task<Report> ApproveAsync(Guid reportId, CancellationToken ct = default)
    {
        if (!_user.Has(Permission.ApproveReports)) throw new Security.ForbiddenException(Permission.ApproveReports);
        using var db = _factory.CreateDbContext();
        var report = await db.Reports.FirstOrDefaultAsync(r => r.Id == reportId, ct)
                     ?? throw new InvalidOperationException("Report not found.");

        // Same need-to-know guard (and same "not found" message) as OpenAsync.
        var canAccess = await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == report.CaseId, ct);
        if (!canAccess) throw new InvalidOperationException("Report not found.");

        if (_reporting.CurrentValue.RequireSeparateApprover
            && string.Equals(report.CreatedBy, _user.UserId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Two-person control is on. Someone other than the analyst who generated this report must approve it.");

        report.Approve(_user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        return report;
    }

    public async Task<(Report Report, Stream Content)> OpenAsync(Guid reportId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var report = await db.Reports.AsNoTracking().FirstOrDefaultAsync(r => r.Id == reportId, ct)
                     ?? throw new InvalidOperationException("Report not found.");

        // Enforce need-to-know on the parent case: a restricted case's report must not be reachable
        // by GUID alone. Same "not found" message so we don't leak its existence.
        var canAccess = await db.Cases.AsNoTracking().ForUser(_user)
            .AnyAsync(c => c.Id == report.CaseId, ct);
        if (!canAccess) throw new InvalidOperationException("Report not found.");

        var stream = await _store.OpenReadAsync(report.StoragePath, ct);
        return (report, stream);
    }

    /// <summary>
    /// Recomputes the stored file's hash and compares it to the recorded hash. Need-to-know scoped like
    /// <see cref="OpenAsync"/>: a report on a case the caller can't see is "not found", so the answer can't
    /// confirm that it exists.
    /// </summary>
    public async Task<bool> VerifyFileAsync(Guid reportId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var report = await db.Reports.AsNoTracking().FirstOrDefaultAsync(r => r.Id == reportId, ct)
                     ?? throw new InvalidOperationException("Report not found.");
        var canAccess = await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == report.CaseId, ct);
        if (!canAccess) throw new InvalidOperationException("Report not found.");
        await using var stream = await _store.OpenReadAsync(report.StoragePath, ct);
        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms, ct);
        var actual = HashBytes(ms.ToArray());
        return string.Equals(actual, report.ContentSha256, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Display string for an entity referenced by a relationship: "Label (value)" or just the value.</summary>
    private static string EntityDisplay(Case c, Guid entityId)
    {
        var e = c.Entities.FirstOrDefault(x => x.Id == entityId);
        if (e is null) return "(unknown)";
        return string.IsNullOrWhiteSpace(e.Label) ? e.Value : $"{e.Label} ({e.Value})";
    }

    /// <summary>Readable label for a materiality status (compound names get a space).</summary>
    private static string MaterialityLabel(Domain.Enums.MaterialityStatus s) => s switch
    {
        Domain.Enums.MaterialityStatus.UnderReview => "Under review",
        Domain.Enums.MaterialityStatus.NotMaterial => "Not material",
        _ => s.ToString()
    };

    /// <summary>Turns a PascalCase enum name into spaced words, e.g. "LoggedInTo" → "Logged In To".</summary>
    private static string Humanize(string pascal)
    {
        if (string.IsNullOrEmpty(pascal)) return pascal;
        var sb = new System.Text.StringBuilder(pascal.Length + 4);
        for (var i = 0; i < pascal.Length; i++)
        {
            if (i > 0 && char.IsUpper(pascal[i]) && !char.IsUpper(pascal[i - 1])) sb.Append(' ');
            sb.Append(pascal[i]);
        }
        return sb.ToString();
    }

    private static string HashBytes(byte[] bytes) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();

    /// <summary>PROD-46: the attack chain drawn across tactic lanes — first-party cases with at least one mapped tactic.</summary>
    private IReadOnlyList<byte[]> AttackChainImages(Case c, ReportDefanger d)
    {
        if (_diagrams is null || c.Origin == CaseOrigin.ThirdParty) return [];
        var steps = c.TimelineEntries
            .Where(x => x.Kind == TimelineKind.Event)
            .OrderBy(x => x.OccurredAtUtc).ThenBy(x => x.CreatedAtUtc)
            .Select((x, i) => new DiagramStep(i + 1, x.OccurredAtUtc, x.Tactics.Select(t => t.Tactic).ToList(), x.TechniqueId,
                d.Text(EntityName(c, x.ActorEntityId)), d.Text(EntityName(c, x.TargetEntityId))))
            .ToList();
        // Nothing mapped to ATT&CK means one "Unmapped" lane — the table already says that better.
        return steps.Any(s => s.Tactics.Any(t => t != MitreTactic.Unspecified)) ? _diagrams.AttackChain(steps) : [];
    }

    /// <summary>PROD-46: the relationship graph, laid out as the analyst arranged it on the IOCs tab when saved.</summary>
    private byte[]? EntityGraphImage(Case c, ReportDefanger d)
    {
        if (_diagrams is null || c.EntityRelationships.Count == 0) return null;
        var layout = c.EntityLayouts.ToDictionary(l => l.EntityId);
        var nodes = c.Entities.Select(e => new DiagramNode(e.Id,
                string.IsNullOrWhiteSpace(e.Label) ? d.Value(e.Type, e.Value) : d.Text(e.Label!), e.Type, e.Disposition,
                layout.TryGetValue(e.Id, out var p) ? p.X : null, layout.TryGetValue(e.Id, out var q) ? q.Y : null))
            .ToList();
        var edges = c.EntityRelationships
            .Select(r => new DiagramEdge(r.SourceEntityId, r.TargetEntityId, TaxLabel("EntityRelationshipType", r.Type.ToString())))
            .ToList();
        return _diagrams.EntityGraph(nodes, edges);
    }

    private static string EntityName(Case c, Guid? entityId)
    {
        if (entityId is not { } id) return "";
        var e = c.Entities.FirstOrDefault(x => x.Id == id);
        return e is null ? "" : (string.IsNullOrWhiteSpace(e.Label) ? e.Value : e.Label!);
    }

    /// <summary>
    /// Builds the presentation model for an in-app preview (U-37) without generating/storing a file, honouring
    /// the <paramref name="selectedProfileId"/> the analyst has chosen on the Report tab (null = global default
    /// layout). Lets the approver/analyst see exactly what a profile produces — same section order as the
    /// house template — before Generate/Approve. Enforces need-to-know on the parent case.
    /// </summary>
    public async Task<CaseReportModel> BuildPreviewModelAsync(
        Guid caseId, Guid? selectedProfileId, TlpLevel? tlp = null, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var canAccess = await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct);
        if (!canAccess) throw new InvalidOperationException("Case not found.");

        var c = await LoadFullCaseAsync(db, caseId, ct)
            ?? throw new InvalidOperationException("Case not found.");
        var logo = await _branding.GetLogoAsync(ct);
        var sections = await ResolveSectionsAsync(db, selectedProfileId, ct);
        var (elemSummary, triggers) = await ImpactElementsAsync(db, c, ct);
        return BuildModel(c, _clock.UtcNow, logo, sections, elemSummary, triggers, tlp, await TaskResultsAsync(db, c.Id, ct));
    }

    /// <summary>
    /// The Word template the next report would be filled from, filled with the case as Generate would fill it, for the
    /// Report tab to show in place of the built-in preview. Null when the report would use the built-in layout. Nothing
    /// is stored. <paramref name="template"/> is read as in <see cref="GenerateAsync"/>; the default is the template of
    /// <paramref name="selectedProfileId"/>, the profile on screen (Generate saves that choice first).
    /// </summary>
    public async Task<(string TemplateName, byte[] Bytes)?> FillTemplatePreviewAsync(
        Guid caseId, Guid? selectedProfileId, TlpLevel? tlp = null, Guid? template = null, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var canAccess = await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct);
        if (!canAccess) throw new InvalidOperationException("Case not found.");
        if (await ResolveTemplateAsync(db, await ProfileTemplateIdAsync(db, selectedProfileId, ct), template, ct) is not { } t)
            return null;

        var c = await LoadFullCaseAsync(db, caseId, ct)
            ?? throw new InvalidOperationException("Case not found.");
        var logo = await _branding.GetLogoAsync(ct);
        var sections = await ResolveSectionsAsync(db, selectedProfileId, ct);
        var (elemSummary, triggers) = await ImpactElementsAsync(db, c, ct);
        var model = BuildModel(c, _clock.UtcNow, logo, sections, elemSummary, triggers, tlp, await TaskResultsAsync(db, c.Id, ct));
        return (t.Name, _templates!.Render(t.Bytes, await WithReviewAsync(db, c, model, ct)));
    }

    // HR-02: the latest recorded result of each task, for the Response Tasks table.
    private static async Task<IReadOnlyDictionary<Guid, TaskResult>> TaskResultsAsync(IAppDbContext db, Guid caseId, CancellationToken ct) =>
        TaskResults.Latest(await db.ActionItemComments.AsNoTracking()
            .Where(x => x.CaseId == caseId && x.Body.StartsWith(TaskResults.Prefix)).ToListAsync(ct));

    private static Task<Case?> LoadFullCaseAsync(IAppDbContext db, Guid caseId, CancellationToken ct) =>
        // S8733: eager-loading many independent collections in one query is a Cartesian explosion (row count =
        // the product of every collection's size). Split into one correlated query per collection. Read-only
        // AsNoTracking snapshot for report generation, so the split-query consistency trade-off is moot.
        db.Cases.AsNoTracking()
            .AsSplitQuery()
            .Include(x => x.ClassificationChanges)
            .Include(x => x.SeverityChanges)
            .Include(x => x.StatusChanges)        // INV-16: milestones in the investigation timeline
            .Include(x => x.MaterialityChanges)
            .Include(x => x.GatePassages)
            .Include(x => x.Citations)            // INV-10: evidence an entry cites
            .Include(x => x.Briefs)               // INV-19: the case brief, for an opt-in section
            .Include(x => x.TimelineEntries).ThenInclude(t => t.Tactics)
            .Include(x => x.Evidence)
            .Include(x => x.Notes)
            .Include(x => x.ActionItems)
            .Include(x => x.Assignments)
            .Include(x => x.Entities)
            .Include(x => x.EntityRelationships)
            .Include(x => x.EntityLayouts)   // PROD-46: the analyst's graph arrangement for the report picture
            .Include(x => x.Techniques)
            .Include(x => x.DataElements)
            .FirstOrDefaultAsync(x => x.Id == caseId, ct);

    /// <summary>
    /// Resolves the case's involved data elements (X-03) into two report strings, in one query: a
    /// comma-separated label list in the reference set's display order, and a regulatory-notification grouping
    /// (jurisdiction → the involved elements that trigger it). Codes with no matching reference row (an element
    /// removed after the fact) fall back to their code and carry no jurisdiction.
    /// </summary>
    private static async Task<(string? Summary, string? NotificationTriggers)> ImpactElementsAsync(
        IAppDbContext db, Case c, CancellationToken ct)
    {
        if (c.DataElements.Count == 0) return (null, null);
        var keys = c.DataElements.Select(d => d.ElementKey).ToHashSet(StringComparer.Ordinal);
        var elements = await db.DataElements.AsNoTracking()
            .Where(e => keys.Contains(e.Key))
            .OrderBy(e => e.SortOrder).ThenBy(e => e.Label)
            .Select(e => new { e.Key, e.Label, e.NotificationJurisdictions })
            .ToListAsync(ct);

        var labels = elements.Select(e => e.Label).ToList();
        // Any key without a reference row (should not happen for the seeded set) trails, labelled by key.
        labels.AddRange(keys.Where(k => elements.All(e => e.Key != k)).OrderBy(x => x, StringComparer.Ordinal));
        var summary = labels.Count == 0 ? null : string.Join(", ", labels);

        // Group the involved elements by each jurisdiction they trigger notification in — the regulatory
        // "who must we notify, and because of what data" view, in element display order within each group.
        var byJurisdiction = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var e in elements.Where(e => !string.IsNullOrWhiteSpace(e.NotificationJurisdictions)))
            foreach (var j in e.NotificationJurisdictions!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                (byJurisdiction.TryGetValue(j, out var list) ? list : byJurisdiction[j] = new()).Add(e.Label);

        var triggers = byJurisdiction.Count == 0
            ? null
            : string.Join("; ", byJurisdiction.Select(kv => $"{kv.Key}: {string.Join(", ", kv.Value)}"));

        return (summary, triggers);
    }

    /// <summary>
    /// Resolves the effective body-section layout: the chosen active <see cref="ReportProfile"/>'s layout
    /// when one is selected and still exists, otherwise the global <c>Reporting:SectionLayout</c> default.
    /// A deleted/inactive profile transparently falls back to the global default.
    /// </summary>
    private async Task<IReadOnlyList<ReportSection>> ResolveSectionsAsync(
        IAppDbContext db, Guid? profileId, CancellationToken ct)
    {
        if (profileId is { } id)
        {
            var profile = await db.ReportProfiles.AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == id && p.IsActive, ct);
            if (profile is not null) return ReportLayout.Resolve(profile.SectionLayout);
        }
        return ReportLayout.Resolve(_reporting.CurrentValue.SectionLayout);
    }

    /// <summary>
    /// The lessons-learned report model: case identity + branding, the review, and the improvement actions.
    /// Its provenance hash covers the review and actions (their canonical content), not the case row.
    /// </summary>
    private async Task<CaseReportModel> BuildLessonsModelAsync(IAppDbContext db, Case c, DateTimeOffset now, CancellationToken ct,
        TlpLevel? tlp = null)
    {
        var logo = await _branding.GetLogoAsync(ct);
        var opts = _reporting.CurrentValue;
        var d = ReportDefanger.For(
            await db.CaseEntities.AsNoTracking().Where(e => e.CaseId == c.Id).ToListAsync(ct), opts.DefangIndicators);
        var (review, actions, canonical) = await ReviewPartsAsync(db, c.Id, d, ct);

        return new CaseReportModel
        {
            Kind = ReportKind.LessonsLearned,
            IndicatorsDefanged = d.Enabled,
            Tlp = tlp ?? opts.EffectiveDefaultTlp,
            Legend = string.IsNullOrWhiteSpace(opts.LessonsLegend) ? null : opts.LessonsLegend.Trim(),
            OrganizationName = string.IsNullOrWhiteSpace(opts.OrganizationName) ? null : opts.OrganizationName.Trim(),
            TeamName = string.IsNullOrWhiteSpace(opts.TeamName) ? null : opts.TeamName.Trim(),
            LogoBytes = logo?.Bytes,
            LogoContentType = logo?.ContentType,
            Sections = [],
            CaseNumber = c.CaseNumber,
            Title = c.Title,
            Classification = ClassificationLabel(c.Classification),
            Phase = PhaseLabel(c.Phase),
            Severity = _severityLabels.For(c.Severity),
            Origin = c.Origin == CaseOrigin.ThirdParty ? "Third-party / vendor" : "Internal detection",
            ClosedAtUtc = c.ClosedAtUtc,
            Review = review,
            ImprovementActions = actions,
            GeneratedBy = _users.DisplayFor(_user.UserId),
            GeneratedAtUtc = now,
            ContentHash = _hasher.Hash(canonical)
        };
    }

    /// <summary>The post-incident review and improvement actions as printed, plus their canonical content (what the
    /// lessons-learned report's provenance hash covers).</summary>
    private async Task<(ReportReview? Review, List<ReportImprovementActionRow> Actions, string Canonical)> ReviewPartsAsync(
        IAppDbContext db, Guid caseId, ReportDefanger d, CancellationToken ct)
    {
        var review = await db.PostIncidentReviews.AsNoTracking().FirstOrDefaultAsync(x => x.CaseId == caseId, ct);
        var actions = Lessons.LessonsService.Ordered(
            await db.ImprovementActions.AsNoTracking().Where(x => x.CaseId == caseId).ToListAsync(ct)).ToList();
        var canonical = string.Join('\n',
            new[] { review?.BuildCanonicalContent() ?? "" }.Concat(actions.Select(a => a.BuildCanonicalContent())));

        // The long fields are Markdown (edited like Notes/Summary): the review keeps its formatting as blocks;
        // action details/outcome sit in table cells, so they print as list-aware plain text.
        var printed = review is null ? null : new ReportReview(d.Blocks(Content.RichText.Parse(review.WhatHappened)),
            d.Blocks(Content.RichText.Parse(review.ContributingFactors)), d.Blocks(Content.RichText.Parse(review.WhatWorkedWell)),
            d.Blocks(Content.RichText.Parse(review.OpportunitiesToImprove)), review.NoActionsIdentified);
        var rows = actions.Select(a => new ReportImprovementActionRow(d.Text(a.Title), a.RelatedArea, d.NullableText(Plain(a.Details)),
            a.Owner is null ? "Unassigned" : _users.DisplayFor(a.Owner), a.TargetDateUtc,
            Lessons.LessonsService.StatusLabel(a.Status), d.NullableText(Plain(a.OutcomeNote)))).ToList();
        return (printed, rows, canonical);
    }

    // Table cells can't carry styling: keep list markers and line breaks, drop emphasis.
    private static string? Plain(string? markdown) => string.IsNullOrWhiteSpace(markdown) ? null : Content.RichText.ToText(markdown);

    private CaseReportModel BuildModel(Case c, DateTimeOffset now, ReportLogo? logo, IReadOnlyList<ReportSection> sections,
        string? dataElementsSummary, string? notificationTriggersSummary, TlpLevel? tlp = null,
        IReadOnlyDictionary<Guid, TaskResult>? taskResults = null)
    {
        taskResults ??= new Dictionary<Guid, TaskResult>();
        var contentHash = _hasher.Hash(c.BuildCanonicalContent());
        var opts = _reporting.CurrentValue;
        var d = ReportDefanger.For(c.Entities, opts.DefangIndicators);   // PROD-44
        return new CaseReportModel
        {
            IndicatorsDefanged = d.Enabled,
            Tlp = tlp ?? opts.EffectiveDefaultTlp,
            // PROD-45: the actionable list — anything judged malicious or suspicious, whatever its type (a rogue
            // account is an indicator too); compromised/benign/unknown entities stay in Systems Reviewed only.
            Iocs = c.Entities
                .Where(x => x.Disposition is EntityDisposition.Malicious or EntityDisposition.Suspicious)
                .OrderBy(x => x.Disposition == EntityDisposition.Malicious ? 0 : 1).ThenBy(x => x.Type).ThenBy(x => x.Value)
                .Select(x => new ReportIocRow(TaxLabel("EntityType", x.Type.ToString()), d.Value(x.Type, x.Value),
                    TaxLabel("EntityDisposition", x.Disposition.ToString()), x.Tlp is { } t ? Domain.Enums.Tlp.Label(t) : null,
                    x.CreatedAtUtc, x.Source, d.NullableText(x.Description)))
                .ToList(),
            OrganizationName = string.IsNullOrWhiteSpace(opts.OrganizationName) ? null : opts.OrganizationName.Trim(),
            TeamName = string.IsNullOrWhiteSpace(opts.TeamName) ? null : opts.TeamName.Trim(),
            LogoBytes = logo?.Bytes,
            LogoContentType = logo?.ContentType,
            Sections = sections,
            CaseNumber = c.CaseNumber,
            Title = c.Title,
            Classification = ClassificationLabel(c.Classification),
            Phase = PhaseLabel(c.Phase),
            Severity = _severityLabels.For(c.Severity),
            Origin = c.Origin == CaseOrigin.ThirdParty ? "Third-party / vendor" : "Internal detection",
            VendorName = c.ThirdParty?.VendorName,
            DetectionCaseId = c.DetectionCaseId,
            Summary = d.Text(_markdown.ToPlainText(c.Summary)),
            SummaryBlocks = d.Blocks(Content.RichText.Parse(c.Summary)),
            DataTypesInvolved = d.NullableText(c.DataTypesInvolved),
            ImpactedAssets = d.NullableText(c.ImpactedAssets),
            AffectedIndividualsCount = c.AffectedIndividualsCount,
            DataElementsSummary = dataElementsSummary,
            NotificationTriggersSummary = notificationTriggersSummary,
            AffectedStates = c.AffectedStates,
            LegalReferred = c.LegalReferral.IsReferred,
            LegalNote = c.LegalReferral.RegulatoryRelevanceNote,
            LegalHold = c.LegalHold,
            MaterialityStatus = c.Materiality.Status == Domain.Enums.MaterialityStatus.Undetermined
                ? null : MaterialityLabel(c.Materiality.Status),
            MaterialityDetermined = c.Materiality.IsDetermined,
            MaterialityDecisionMaker = c.Materiality.DecisionMaker,
            MaterialityDecidedOnUtc = c.Materiality.DecidedOnUtc,
            MaterialityRationale = c.Materiality.Rationale,
            DetectedAtUtc = c.DetectedAtUtc,
            ReportedAtUtc = c.ReportedAtUtc,
            ContainedAtUtc = c.ContainedAtUtc,
            ResolvedAtUtc = c.ResolvedAtUtc,
            ClosedAtUtc = c.ClosedAtUtc,
            // INV-05: history reads in the order things happened, dated when they happened.
            ClassificationHistory = c.ClassificationChanges
                .OrderBy(x => x.EffectiveAt)
                .Select(x => new ReportClassificationItem(x.EffectiveAt, x.From is { } fc ? ClassificationLabel(fc) : "—", ClassificationLabel(x.To), x.Reason, _users.DisplayFor(x.ChangedBy)))
                .ToList(),
            SeverityHistory = c.SeverityChanges
                .OrderBy(x => x.EffectiveAt)
                .Select(x => new ReportClassificationItem(x.EffectiveAt, x.From is { } f ? _severityLabels.For(f) : "—", _severityLabels.For(x.To), x.Reason ?? "", _users.DisplayFor(x.ChangedBy)))
                .ToList(),
            EventTimeline = c.TimelineEntries
                .Where(x => x.Kind == TimelineKind.Event)
                .OrderBy(x => x.OccurredAtUtc).ThenBy(x => x.CreatedAtUtc)
                .Select(x => new ReportTimelineItem(x.OccurredAtUtc, TaxLabel("TimelineEntryType", x.Type.ToString()), d.Text(x.Description), x.Source))
                .ToList(),
            // The attack chain (ATT&CK tactics + actor→target in our estate) only applies to a first-party
            // case. A third-party/vendor case (E-32) has no adversary kill-chain here — its event steps are
            // vendor-disclosure milestones, carried by the Event timeline above — so the chain is empty.
            AttackChain = c.Origin == CaseOrigin.ThirdParty ? new List<ReportAttackStep>() : c.TimelineEntries
                .Where(x => x.Kind == TimelineKind.Event)
                .OrderBy(x => x.OccurredAtUtc).ThenBy(x => x.CreatedAtUtc)
                .Select((x, i) => new ReportAttackStep(
                    i + 1,
                    x.OccurredAtUtc,
                    string.Join(", ", x.Tactics.Select(t => Humanize(t.Tactic.ToString())).OrderBy(s => s)),
                    d.Text(EntityName(c, x.ActorEntityId)),
                    d.Text(EntityName(c, x.TargetEntityId)),
                    x.TechniqueId,
                    d.Text(x.Description)))
                .ToList(),
            InvestigationTimeline = InvestigationTimeline(c, d, opts),
            Brief = c.Briefs.FirstOrDefault(b => b.IsCurrent) is { } brief
                ? new ReportBrief(brief.Version, brief.CreatedAtUtc, _users.DisplayFor(brief.CreatedBy),
                    BriefText(brief.WorkingAssessment, d), BriefText(brief.Known, d),
                    BriefText(brief.OpenQuestions, d), BriefText(brief.NextSteps, d))
                : null,
            Evidence = c.Evidence
                .OrderBy(x => x.CreatedAtUtc)
                .Select(x => new ReportEvidenceItem(x.OriginalFileName, x.SizeBytes, x.Sha256, x.CreatedAtUtc, _users.DisplayFor(x.CreatedBy)))
                .ToList(),
            Notes = c.Notes.Where(x => x.IsCurrent)
                .OrderBy(x => x.CreatedAtUtc)
                // Notes are Markdown (U-35); flatten to readable plain text for the report.
                .Select(x => new ReportNoteItem(x.CreatedAtUtc, _users.DisplayFor(x.CreatedBy), d.Text(_markdown.ToPlainText(x.Body)), d.Blocks(Content.RichText.Parse(x.Body))))
                .ToList(),
            ActionItems = c.ActionItems
                .OrderBy(x => x.Status)
                .ThenBy(x => x.DueAtUtc ?? DateTimeOffset.MaxValue)   // INV-45: soonest due first within a status
                // Owner may be a user id (playbook tasks default to the case owner) or free text; resolve
                // ids to display names, pass free text through, so the examiner report never shows a raw id.
                // HR-02: a done task prints what it found or did, when, and who did it.
                .Select(x => new ReportActionItemRow(x.Title, _users.DisplayFor(x.Owner), x.DueAtUtc, TaskStatusLabel(x.Status),
                    x.Status == ActionItemStatus.Done && taskResults.TryGetValue(x.Id, out var r) ? d.Text(r.Text) : null,
                    x.Status == ActionItemStatus.Done ? x.CompletedAtUtc : null,
                    x.Status == ActionItemStatus.Done && x.CompletedBy is { } by ? _users.DisplayFor(by) : null))
                .ToList(),
            Assignments = c.Assignments
                .OrderBy(x => x.Role)
                .Select(x => new ReportAssignmentRow(
                    string.IsNullOrWhiteSpace(x.UserDisplayName) ? _users.DisplayFor(x.UserId) : x.UserDisplayName,
                    x.Role == CaseAssignmentRole.IncidentCommander ? "Incident Commander" : x.Role.ToString()))
                .ToList(),
            Entities = c.Entities
                .OrderBy(x => x.Type).ThenBy(x => x.Value)
                .Select(x => new ReportEntityRow(TaxLabel("EntityType", x.Type.ToString()), d.Value(x.Type, x.Value), d.NullableText(x.Label),
                    TaxLabel("EntityDisposition", x.Disposition.ToString()), d.NullableText(x.Description), x.Source))
                .ToList(),
            Relationships = c.EntityRelationships
                .OrderBy(x => x.CreatedAtUtc)
                .Select(x => new ReportRelationshipRow(
                    d.Text(EntityDisplay(c, x.SourceEntityId)), TaxLabel("EntityRelationshipType", x.Type.ToString()),
                    d.Text(EntityDisplay(c, x.TargetEntityId)), d.NullableText(x.Description)))
                .ToList(),
            Techniques = c.Techniques
                .OrderBy(x => x.Tactic).ThenBy(x => x.TechniqueId)
                .Select(x => new ReportTechniqueRow(x.TechniqueId, x.Name, Humanize(x.Tactic.ToString())))
                .ToList(),
            AttackChainImages = sections.Contains(ReportSection.EventTimeline) ? AttackChainImages(c, d) : [],
            EntityGraphImage = sections.Contains(ReportSection.SystemsReviewed) ? EntityGraphImage(c, d) : null,
            GeneratedBy = _users.DisplayFor(_user.UserId),
            GeneratedAtUtc = now,
            ContentHash = contentHash
        };
    }
}
