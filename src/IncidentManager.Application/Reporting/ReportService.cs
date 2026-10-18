using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
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
    private readonly IOrganizationTimeZone? _zone;   // WF-36
    private readonly ISecurityEventSink? _siem;   // CAP-06
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
    private readonly Compliance.NotificationDeadlineService? _deadlines;   // CAP-38: each outstanding regulator's deadline

    private readonly IReportDiagrams? _diagrams;   // PROD-46: report pictures (null = tables only)
    private readonly IReportTemplateEngine? _templates;      // PROD-47
    private readonly IReportTemplateStore? _templateStore;   // PROD-47

    public ReportService(IAppDbContextFactory factory, IReportGenerator generator, IReportStore store,
        IHashChainService hasher, ICurrentUser user, IClock clock, Content.IMarkdownService markdown,
        IOptionsMonitor<ReportingOptions> reporting, IReportBrandingStore branding, IUserDirectory users,
        ISeverityLabels severityLabels, ITaxonomyDisplay? taxonomy = null, IReportDiagrams? diagrams = null,
        IReportTemplateEngine? templates = null, IReportTemplateStore? templateStore = null, IOrganizationTimeZone? zone = null,
        Security.ISecurityEventSink? siem = null, Compliance.NotificationDeadlineService? deadlines = null)
    {
        _deadlines = deadlines;
        _siem = siem;
        _zone = zone;
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
    private List<ReportTimelineItem> InvestigationTimeline(Case c, ReportDefanger d, ReportingOptions opts,
        ReportExtras? extras = null, bool withBrief = false)
    {
        var outcomeLabels = extras?.OutcomeLabels;
        var taskResults = extras?.TaskResults ?? new Dictionary<Guid, Cases.TaskResult>();
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
                d.Text(EntryText(x) + ActionsTaken(c, x, taskResults)) + Cited(c, x) + (x.IsImported ? "" : Late(x.OccurredAtUtc, FirstRecorded(c, x)))
                    + AfterClosureNote(c, FirstRecorded(c, x), x.CreatedAtUtc),
                d.NullableText(x.Source), x.IsImported, _users.DisplayFor(x.CreatedBy))))
            .ToList();

        if (opts.IncludeMilestones)
        {
            var labels = new Cases.MilestoneLabels(ClassificationLabel, _severityLabels.For, PhaseLabel, MaterialityLabel,
                k => outcomeLabels?.GetValueOrDefault(k) ?? Admin.CaseOutcomeCatalog.Label(k),
                d => TaxLabel("EntityDisposition", d.ToString()), Standing: extras?.Standing);   // CAP-38 review
            // A report listing its own earlier versions reads oddly, so final-report milestones stay out; so do
            // staffing changes (INV-31), which are the team's working record rather than findings.
            foreach (var m in Cases.CaseMilestones.Project(c, labels)
                         // CAP-21: a withdrawn file leaves the report, as a retracted entry does (BUG-413).
                         .Where(m => m.Kind is not (Cases.MilestoneKind.ReportFinal or Cases.MilestoneKind.Command or Cases.MilestoneKind.EvidenceWithdrawn))
                         // WF-34: each brief version's working assessment is the working brief (decision 0012): in the report
                         // only when the profile prints the Case Brief.
                         .Where(m => withBrief || m.Kind != Cases.MilestoneKind.Assessment))
            {
                var title = m.Note is { } note ? $"{m.Title} ({note})" : m.Title;   // HR-07: the gate it passed
                var text = m.Detail is { } detail ? $"{title}. {detail}" : title;
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

    // HR-08: what was done about a decision: the tasks started from it, with when, by whom and the result.
    private string ActionsTaken(Case c, TimelineEntry e, IReadOnlyDictionary<Guid, Cases.TaskResult> results)
    {
        if (e.Type != TimelineEntryType.Decision) return "";
        var first = e;
        while (first.SupersedesEntryId is { } prior && c.TimelineEntries.FirstOrDefault(x => x.Id == prior) is { } p) first = p;
        var about = $"{ActionItem.AboutEntry}:{first.Id}";
        var tasks = c.ActionItems.Where(t => t.AboutRef == about).OrderBy(t => t.CompletedAtUtc ?? DateTimeOffset.MaxValue).ToList();
        if (tasks.Count == 0) return "";
        var parts = tasks.Select(t =>
        {
            if (t.Status != ActionItemStatus.Done)
                return $"{t.Title} ({TaskStatusLabel(t.Status).ToLowerInvariant()})";
            var done = t.CompletedAtUtc is { } at ? string.Create(System.Globalization.CultureInfo.InvariantCulture, $"done {at.UtcDateTime:yyyy-MM-dd HH:mm} UTC") : "done";
            if (t.CompletedBy is { } by) done += $" by {_users.DisplayFor(by)}";
            return results.TryGetValue(t.Id, out var r) ? $"{t.Title} ({done}): {Cases.TaskResults.Excerpt(r.Text, 300)}" : $"{t.Title} ({done})";
        });
        return " Actions taken: " + string.Join("; ", parts.Select(x => x.TrimEnd('.'))) + ".";
    }

    // INV-19: a brief part as report text — Markdown flattened, indicators defanged.
    private string? BriefText(string? markdown, ReportDefanger d) =>
        string.IsNullOrWhiteSpace(markdown) ? null : d.Text(_markdown.ToPlainText(markdown).Trim());

    // INV-10: the evidence an entry cites, by file name. CAP-21: a withdrawn file is left out, as from the evidence list.
    private static string Cited(Case c, TimelineEntry e)
    {
        var files = c.Citations.Where(x => x.TimelineEntryId == e.Id)
            .Select(x => c.Evidence.FirstOrDefault(ev => ev.Id == x.EvidenceId && !ev.IsWithdrawn)?.OriginalFileName)
            .Where(n => n is not null).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        return files.Count == 0 ? "" : $" Evidence: {string.Join(", ", files)}.";
    }

    // When an investigation entry was first put on the record: its original version's creation time.
    // HR-15: an entry added or edited after the case closed says so, as the timeline does.
    private static string AfterClosureNote(Case c, DateTimeOffset added, DateTimeOffset lastChanged) =>
        c.ClosureRecordedAtUtc is { } closed && lastChanged > closed
            ? $" ({(added > closed ? "Added" : "Edited")} after closure, {lastChanged.ToString("u", System.Globalization.CultureInfo.InvariantCulture)}.)"
            : "";

    private static DateTimeOffset FirstRecorded(Case c, TimelineEntry e)
    {
        var first = e;
        while (first.SupersedesEntryId is { } prior && c.TimelineEntries.FirstOrDefault(x => x.Id == prior) is { } p)
            first = p;
        return first.CreatedAtUtc;
    }

    // HR-16: the catalog's label ("Post-Incident"), not the enum name, when no override is set.
    private string PhaseLabel(CasePhase p) => TaxLabel("CasePhase", p.ToString());

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
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct)) return [];   // BUG-46
        return await db.Reports.AsNoTracking().Where(r => r.CaseId == caseId && r.Kind == kind)
            .OrderByDescending(r => r.CreatedAtUtc).ToListAsync(ct);
    }

    /// <summary>
    /// Generates a report as a <b>working draft</b> (E-15). Finalization is a separate, permission-gated
    /// approval step (<see cref="ApproveAsync"/>) — generating no longer self-approves.
    /// </summary>
    /// <param name="template">PROD-47: which Word template to fill. Null = the case's profile default (the built-in
    /// layout when it has none); <see cref="Guid.Empty"/> = the built-in layout; otherwise that library template.</param>
    /// <param name="progress">RD-23: told each stage as it starts (<see cref="ReportStages"/>), for a background run's progress.</param>
    public async Task<Report> GenerateAsync(Guid caseId, TlpLevel? tlp = null,
        Guid? template = null, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        if (!_user.Has(Permission.EditCases)) throw new Security.ForbiddenException(Permission.EditCases);
        progress?.Report(ReportStages.Reading);
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
        progress?.Report(ReportStages.Writing);
        var model = BuildModel(c, now, logo, sections, elemSummary, triggers, tlp, await ExtrasAsync(db, c.Id, ct));

        // PROD-47: the report can be filled from a customer-designed template (the profile's default, or one picked
        // for this report). Reports are Word only: there's no way to turn a filled template into a matching PDF on
        // the server without Word or LibreOffice, so PDF output was dropped rather than offer one that doesn't match.
        byte[]? rendered = null;
        ResolvedTemplate? used = null;
        if (await ResolveTemplateAsync(db, await ProfileTemplateIdAsync(db, c.ReportProfileId, ct), template, ct) is { } t)
        {
            // A template may use any field, the review's included (the admin decides what it prints), so it's filled
            // from the case model with the review added. The built-in layout never prints the review.
            rendered = _templates!.Render(t.Bytes, ForTemplate(c, await WithReviewAsync(db, c, model, ct)));
            used = t;
        }

        progress?.Report(ReportStages.Storing);
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
        // WF-81: built as a real template report is (task results, outcome labels, the image fields), so the preview shows
        // what a generated report will.
        var model = ForTemplate(c, await WithReviewAsync(db, c,
            BuildModel(c, now, logo, sections, elemSummary, triggers, null, await ExtrasAsync(db, c.Id, ct)), ct));
        var banner = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"PREVIEW of template “{tpl.Name}” with case {c.CaseNumber}, {now.UtcDateTime:yyyy-MM-dd HH:mm} UTC. ") +
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
    public async Task<Report> GenerateLessonsAsync(Guid caseId, TlpLevel? tlp = null,
        Guid? template = null, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        if (!_user.Has(Permission.EditCases)) throw new Security.ForbiddenException(Permission.EditCases);
        progress?.Report(ReportStages.Reading);
        using var db = _factory.CreateDbContext();
        var c = await db.Cases.AsNoTracking().ForUser(_user).FirstOrDefaultAsync(x => x.Id == caseId, ct)
            ?? throw new InvalidOperationException("Case not found.");

        var now = _clock.UtcNow;
        progress?.Report(ReportStages.Writing);
        var model = await BuildLessonsModelAsync(db, c, now, ct, tlp);

        // A Word template may use any field, case fields included (the admin decides what it prints), so it's filled
        // from the full case model carrying this report's identity: its kind, legend, review and content hash.
        byte[]? rendered = null;
        ResolvedTemplate? used = null;
        // BUG-487: two defaults left by an earlier race give the same pick every time (by name), until one is set again.
        var lessonsDefault = await db.ReportTemplates.AsNoTracking().Where(t => t.IsLessonsDefault && t.IsActive)
            .OrderBy(t => t.Name).ThenBy(t => t.Id).Select(t => (Guid?)t.Id).FirstOrDefaultAsync(ct);
        if (await ResolveTemplateAsync(db, lessonsDefault, template, ct) is { } t)
        {
            // WF-32: the legend is the report's discovery protection (decision 0012), so a template that can't print it is
            // refused, as one without {{report.tlp}} is, rather than filled without it.
            if (!string.IsNullOrWhiteSpace(model.Legend)
                && _templates!.Check(t.Bytes) is var check
                && !(check.Fillable ?? check.Placeholders).Contains(ReportTemplateFields.LegendField, StringComparer.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Template “{t.Name}” has no {{{{{ReportTemplateFields.LegendField}}}}} field, so the " +
                    "lessons-learned report would print without its confidentiality legend. Ask an administrator to add it (the page " +
                    "header is a good place) and replace the file, or pick another template.");
            var full = await LoadFullCaseAsync(db, caseId, ct) ?? throw new InvalidOperationException("Case not found.");
            var sections = await ResolveSectionsAsync(db, full.ReportProfileId, ct);
            var (elemSummary, triggers) = await ImpactElementsAsync(db, full, ct);
            var caseModel = ForTemplate(full, BuildModel(full, now, await _branding.GetLogoAsync(ct), sections, elemSummary, triggers, tlp, await ExtrasAsync(db, full.Id, ct)));
            rendered = _templates!.Render(t.Bytes, caseModel with
            {
                Kind = ReportKind.LessonsLearned,
                Legend = model.Legend,
                Review = model.Review,
                ImprovementActions = model.ImprovementActions,
                ContentHash = model.ContentHash,
            });
            model = model with { Tlp = caseModel.Tlp };   // BUG-141: a template can print the case's entities, so its marking too
            used = t;
        }
        progress?.Report(ReportStages.Storing);
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
        // BUG-199: the report records which template filled it, so that's the file recorded for it. One that differs was
        // changed outside CaseBook, or is being replaced right now. (A template moved from a profile without a recorded
        // hash has none to check, and the report records the file's.)
        var actual = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        if (t.Sha256.Length > 0 && !string.Equals(actual, t.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"The file for template “{t.Name}” doesn't match the one recorded for it: it was " +
                "changed outside CaseBook, or is being replaced. Try again in a moment; if it persists, ask an administrator to " +
                "replace the template.");
        // BUG-75: a template stored before the upload check required the marking is refused here, not filled unmarked.
        // BUG-166: one it can fill: a field only in a tracked deletion or split across a link prints nothing or as typed.
        var check = _templates.Check(bytes);
        // WF-39 follow-up: a template stored before the upload check refused fields that load or run something (DDEAUTO,
        // INCLUDEPICTURE…) is refused here too, not copied into every report sent outside the SOC.
        if (!check.Safe)
            throw new InvalidOperationException($"Template “{t.Name}” can't be used: " +
                string.Join(" ", check.Problems.Where(p => check.FillProblems?.Contains(p) != true)) +
                " Ask an administrator to fix the file and replace it, or pick another template.");
        if (!(check.Fillable ?? check.Placeholders).Contains(ReportTemplateFields.MarkingField, StringComparer.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Template “{t.Name}” has no {{{{report.tlp}}}} field it can fill, so the report would print " +
                                                "without its TLP marking. Ask an administrator to add it (typed in one go, outside any tracked " +
                                                "change) and replace the file, or pick another template.");
        return new ResolvedTemplate(t.Name, actual, bytes);
    }

    private async Task<Report> StoreAsync(IAppDbContext db, Guid caseId, string caseNumber, ReportKind kind,
        CaseReportModel model, DateTimeOffset now, CancellationToken ct, byte[]? rendered = null,
        ResolvedTemplate? template = null)
    {
        const ReportFormat format = ReportFormat.Word;   // PDF generation was removed; stored PDFs stay readable
        var bytes = rendered ?? _generator.GenerateWord(model);
        const string ext = "docx";
        // BUG-16: numbering and storing one at a time, so two generations at once don't share a version (and the
        // store never overwrites a file, so neither can replace the other's bytes).
        await VersionGate.WaitAsync(ct);
        try
        {
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
        finally { VersionGate.Release(); }
    }

    private static readonly SemaphoreSlim VersionGate = new(1, 1);

    /// <summary>
    /// Approves and finalizes a generated draft (E-15) — stamps the approver + timestamp and marks it
    /// the locked final. Enforces need-to-know on the parent case and, when configured, separation of
    /// duties (approver ≠ generator). Asserts <c>ApproveReports</c> here too, not only via the web-layer policy.
    /// </summary>
    public async Task<Report> ApproveAsync(Guid reportId, CancellationToken ct = default)
    {
        if (!_user.Has(Permission.ApproveReports)) throw new Security.ForbiddenException(Permission.ApproveReports);
        // WF-40: one approval at a time, read and written under the gate, so two approvers clicking together can't both
        // pass the "already final" check and leave the second's name over the first's (the app runs as one instance).
        await ApproveGate.WaitAsync(ct);
        try { return await ApproveCoreAsync(reportId, ct); }
        finally { ApproveGate.Release(); }
    }

    private static readonly SemaphoreSlim ApproveGate = new(1, 1);

    private async Task<Report> ApproveCoreAsync(Guid reportId, CancellationToken ct)
    {
        using var db = _factory.CreateDbContext();
        var report = await db.Reports.FirstOrDefaultAsync(r => r.Id == reportId, ct)
                     ?? throw new InvalidOperationException("Report not found.");

        // Same need-to-know guard (and same "not found" message) as OpenAsync. CAP-06: it also names the case for the SIEM.
        var subject = await db.Cases.AsNoTracking().ForUser(_user).Where(c => c.Id == report.CaseId)
            .Select(c => new { c.CaseNumber, c.DetectionCaseId, c.IsExercise }).FirstOrDefaultAsync(ct)
            ?? throw new InvalidOperationException("Report not found.");

        if (_reporting.CurrentValue.RequireSeparateApprover
            && string.Equals(report.CreatedBy, _user.UserId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Two-person control is on. Someone other than the analyst who generated this report must approve it.");
        if (!await FileMatchesAsync(db, report, ct))
            throw new ReportFileAlteredException(AlteredMessage + " It can't be approved; generate it again.");

        report.Approve(_user.UserId, _clock.UtcNow);
        await db.SaveChangesAsync(ct);
        _siem.EmitSafely(() => Security.SecurityEvents.ReportApproved(   // CAP-06
            new Security.CaseSubject(subject.CaseNumber, subject.DetectionCaseId, subject.IsExercise), report.Id,
            _user.UserId, _user.UserPrincipalName));
        return report;
    }

    public async Task<(Report Report, Stream Content)> OpenAsync(Guid reportId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var report = await db.Reports.AsNoTracking().FirstOrDefaultAsync(r => r.Id == reportId, ct)
                     ?? throw new Common.NotFoundException("Report not found.");

        // Enforce need-to-know on the parent case: a restricted case's report must not be reachable
        // by GUID alone. Same "not found" message so we don't leak its existence.
        var canAccess = await db.Cases.AsNoTracking().ForUser(_user)
            .AnyAsync(c => c.Id == report.CaseId, ct);
        if (!canAccess) throw new Common.NotFoundException("Report not found.");
        // BUG-657: the bytes handed over are the ones that were checked (one read), not a second open of the file.
        var (matches, content) = await CheckFileAsync(db, report, keep: true, ct);
        if (!matches) throw new ReportFileAlteredException(AlteredMessage);
        return (report, content!);
    }

    /// <summary>BUG-69: the stored file doesn't match the hash recorded when it was generated.</summary>
    public sealed class ReportFileAlteredException(string message) : InvalidOperationException(message);

    private const string AlteredMessage =
        "This report's file no longer matches the one generated: it was changed or replaced outside CaseBook.";

    /// <summary>
    /// BUG-69: the stored file against the hash recorded when it was generated. That hash is taken from the audit chain
    /// (the report's creation entry), which is linked and sealed, rather than only from the report's own row, which an
    /// edit in the database could change along with the file. A report from before its creation was audited is
    /// checked against its row.
    /// </summary>
    private async Task<bool> FileMatchesAsync(IAppDbContext db, Report report, CancellationToken ct) =>
        (await CheckFileAsync(db, report, keep: false, ct)).Matches;

    // With keep, the file's bytes as read and hashed, rewound, when they match.
    private async Task<(bool Matches, MemoryStream? Content)> CheckFileAsync(IAppDbContext db, Report report, bool keep, CancellationToken ct)
    {
        var id = report.Id.ToString();
        var created = await db.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == nameof(Report) && a.EntityId == id && a.Action == Domain.Enums.AuditAction.Create)
            .Select(a => a.AfterJson).FirstOrDefaultAsync(ct);
        var recorded = report.ContentSha256;
        if (created is not null)
        {
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(created);
                if (doc.RootElement.TryGetProperty(nameof(Report.ContentSha256), out var h) && h.GetString() is { } chained)
                {
                    if (!string.Equals(chained, recorded, StringComparison.OrdinalIgnoreCase)) return (false, null);
                    recorded = chained;
                }
            }
            catch (System.Text.Json.JsonException) { /* not a snapshot this reads; the row's hash stands */ }
        }
        MemoryStream? content = null;
        try
        {
            await using var stream = await _store.OpenReadAsync(report.StoragePath, ct);
            Stream hashed = stream;
            if (keep)
            {
                content = new MemoryStream();
                await stream.CopyToAsync(content, ct);
                content.Position = 0;
                hashed = content;
            }
            using var sha = System.Security.Cryptography.SHA256.Create();
            var actual = Convert.ToHexString(await sha.ComputeHashAsync(hashed, ct)).ToLowerInvariant();
            if (!string.Equals(actual, recorded, StringComparison.OrdinalIgnoreCase)) { content?.Dispose(); return (false, null); }
            content?.Seek(0, SeekOrigin.Begin);
            return (true, content);
        }
        // BUG-657: a path edited to lead outside the store is an altered report, not an access error.
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException or ReportPathOutsideStoreException)
        {
            return (false, null);
        }
        catch
        {
            content?.Dispose();
            throw;
        }
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
        return await FileMatchesAsync(db, report, ct);
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

    /// <summary>
    /// WF-41: a template decides what it prints, so its {{image.*}} fields get their pictures whatever the profile's
    /// sections are (the built-in layout draws them only with Event Timeline / Systems Reviewed); left out, they went
    /// silently blank beside the tables they illustrate.
    /// </summary>
    private CaseReportModel ForTemplate(Case c, CaseReportModel m)
    {
        if (m.AttackChainImages.Count > 0 && m.EntityGraphImage is not null) return m;
        var d = ReportDefanger.For(c.Entities, _reporting.CurrentValue.DefangIndicators);
        return m with
        {
            AttackChainImages = m.AttackChainImages.Count > 0 ? m.AttackChainImages : AttackChainImages(c, d),
            EntityGraphImage = m.EntityGraphImage ?? EntityGraphImage(c, d),
        };
    }

    /// <summary>PROD-46: the attack chain drawn across tactic lanes — first-party cases with at least one mapped tactic.</summary>
    private IReadOnlyList<byte[]> AttackChainImages(Case c, ReportDefanger d)
    {
        if (_diagrams is null) return [];
        var steps = c.TimelineEntries
            .Where(x => EventSteps.IsAttack(c, x))
            .InTimelineOrder()
            .Select((x, i) => new DiagramStep(i + 1, x.OccurredAtUtc, x.Tactics.Select(t => t.Tactic).ToList(), x.TechniqueId,
                d.Text(EntityName(c, x.ActorEntityId)), d.Text(EntityName(c, x.TargetEntityId)),
                c.Origin == CaseOrigin.ThirdParty ? EventSteps.Where(c, x) == StepEnvironment.Ours : null)
                { Stated = StepTime.Short(x) })
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
        return BuildModel(c, _clock.UtcNow, logo, sections, elemSummary, triggers, tlp, await ExtrasAsync(db, c.Id, ct));
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
        var model = BuildModel(c, _clock.UtcNow, logo, sections, elemSummary, triggers, tlp, await ExtrasAsync(db, c.Id, ct));
        return (t.Name, _templates!.Render(t.Bytes, ForTemplate(c, await WithReviewAsync(db, c, model, ct))));
    }

    // Records the report reads beside the case aggregate: each task's latest result (HR-02) and outcome labels (HR-01).
    // HR-15: and what changed after closure.
    // CAP-38: and where the case stands with its regulators (fully or partly reported), in the shared wording. CAP-38 review:
    // and the standing itself, which the report's "Reported" (the outcome stamp, case.reported, the reported milestone) is
    // read from, so it can't say reported beside a line that says partly reported.
    private sealed record ReportExtras(IReadOnlyDictionary<Guid, TaskResult> TaskResults, IReadOnlyDictionary<string, string> OutcomeLabels,
        AfterClosureChanges? AfterClosure = null, string? NotificationStanding = null, NoticeStanding? Standing = null);

    private async Task<ReportExtras> ExtrasAsync(IAppDbContext db, Guid caseId, CancellationToken ct)
    {
        var taskResults = TaskResults.Latest(await db.ActionItemComments.AsNoTracking()
            .Where(x => x.CaseId == caseId && x.Body.StartsWith(TaskResults.Prefix)).ToListAsync(ct));
        var outcomes = await db.CaseOutcomes.AsNoTracking().ToDictionaryAsync(o => o.Key, o => o.Label, StringComparer.Ordinal, ct);
        var afterClosure = await AfterClosure.QueryAsync(db, caseId, ct);
        var (line, standing) = await NotificationStandingAsync(db, caseId, ct);
        return new(taskResults, outcomes, afterClosure, line, standing);
    }

    /// <summary>
    /// CAP-38: "Partly reported: NY notified …, CA due …" (or fully reported), by the reading the case page, Briefing, close
    /// gate and reminders use (<see cref="Compliance.NotificationDeadlineService.Standing"/>), so the report can't say every
    /// regulator was told while one's clock runs. Deadlines come from the clocks when they're tracked; otherwise an
    /// outstanding regulator reads "not yet notified".
    /// </summary>
    private async Task<(string? Line, NoticeStanding Standing)> NotificationStandingAsync(IAppDbContext db, Guid caseId, CancellationToken ct)
    {
        var clocks = _deadlines is null ? null : await _deadlines.EvaluateAsync(caseId, ct);
        var standing = clocks is { Enabled: true } ? clocks.Standing : await Compliance.NotificationDeadlineService.StandingAsync(db, caseId, ct);
        var dues = (clocks?.Statuses ?? []).Where(x => x.DueAtUtc is not null)
            .GroupBy(x => x.JurisdictionCode, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().DueAtUtc, StringComparer.OrdinalIgnoreCase);
        return (Compliance.NoticeDetailText.Standing(standing, code => dues.GetValueOrDefault(code),
            t => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture) + " UTC"), standing);
    }

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
            .Include(x => x.JurisdictionNotices)  // WF-35: each regulator's notice is its own milestone (BUG-09)
            .Include(x => x.Parties)              // CAP-34: outside parties, with the legal lines
            .Include(x => x.VerdictChanges)      // HR-05: verdict milestones in the investigation timeline
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
        // WF-67: a reported case lists the jurisdictions in play when it was reported, not ones an admin added since.
        // BUG-284: by the same rule as the deadlines, also while the case waits on a regulator an element added since brought in.
        var liveMap = elements.Where(e => !string.IsNullOrWhiteSpace(e.NotificationJurisdictions))
            .GroupBy(e => e.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().NotificationJurisdictions!, StringComparer.OrdinalIgnoreCase);
        var frozen = c.ReportedJurisdictions is null ? null
            : Case.KeptInPlay(c.ReportedJurisdictions, keys.ToList(), Compliance.NotificationDeadlineService.Live(liveMap))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var byJurisdiction = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var e in elements.Where(e => !string.IsNullOrWhiteSpace(e.NotificationJurisdictions)))
            foreach (var j in Compliance.NotificationDeadlineService.SplitCodes(e.NotificationJurisdictions)   // BUG-404: ',' or ';'
                         .Where(j => frozen is null || frozen.Contains(j)))
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
            Title = d.Text(c.Title),   // BUG-74: a title like "Phishing from hxxp://…" is defanged too
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
        // C18: each part in the current canonical format (text escaped), as row hashes are.
        var canonical = Domain.Common.Canonical.InFormat(Domain.Common.Canonical.CurrentFormat, () => string.Join('\n',
            new[] { review?.BuildCanonicalContent() ?? "" }.Concat(actions.Select(a => a.BuildCanonicalContent()))));

        // The long fields are Markdown (edited like Notes/Summary): the review keeps its formatting as blocks;
        // action details/outcome sit in table cells, so they print as list-aware plain text.
        var printed = review is null ? null : new ReportReview(d.Blocks(Content.RichText.Parse(review.WhatHappened)),
            d.Blocks(Content.RichText.Parse(review.ContributingFactors)), d.Blocks(Content.RichText.Parse(review.WhatWorkedWell)),
            d.Blocks(Content.RichText.Parse(review.OpportunitiesToImprove)), review.NoActionsIdentified);
        var rows = actions.Select(a => new ReportImprovementActionRow(d.Text(a.Title), a.RelatedArea, d.NullableText(Plain(a.Details)),
            a.Owner is null ? "Unassigned" : _users.DisplayFor(a.Owner), OrgDay(a.TargetDateUtc),
            Lessons.LessonsService.StatusLabel(a.Status), d.NullableText(Plain(a.OutcomeNote)))).ToList();
        return (printed, rows, canonical);
    }

    // Table cells can't carry styling: keep list markers and line breaks, drop emphasis.
    private static string? Plain(string? markdown) => string.IsNullOrWhiteSpace(markdown) ? null : Content.RichText.ToText(markdown);

    /// <summary>
    /// WF-36: a value that stands for a day (a task's due date, an improvement target, the day a materiality call was
    /// made) carried in the organization's zone, so the report prints the day that was picked. A bare date is stored as
    /// 23:59 where it was picked, so as a UTC date it read a day late for anyone west of UTC. Times keep printing in UTC.
    /// </summary>
    private DateTimeOffset? OrgDay(DateTimeOffset? t) =>
        t is { } v && _zone?.Current is { } z ? TimeZoneInfo.ConvertTime(v, z) : t;

    private CaseReportModel BuildModel(Case c, DateTimeOffset now, ReportLogo? logo, IReadOnlyList<ReportSection> sections,
        string? dataElementsSummary, string? notificationTriggersSummary, TlpLevel? tlp = null,
        ReportExtras? extras = null)
    {
        var taskResults = extras?.TaskResults ?? new Dictionary<Guid, TaskResult>();
        // C18: the case's row hash as CaseBook computes it (current format, prefixed), not a hash of the canonical built
        // outside any format (which matched no stored hash, and left text unescaped).
        var contentHash = _hasher.ComputeRowHash(c);
        var opts = _reporting.CurrentValue;
        var d = ReportDefanger.For(c.Entities, opts.DefangIndicators);   // PROD-44
        return new CaseReportModel
        {
            IndicatorsDefanged = d.Enabled,
            Tlp = ReportMarking.Effective(tlp ?? opts.EffectiveDefaultTlp, ReportMarking.MostRestrictive(c)),   // BUG-141
            // PROD-45: the actionable list — anything judged malicious or suspicious, whatever its type (a rogue
            // account is an indicator too); compromised/benign/unknown entities stay in Systems Reviewed only.
            Iocs = c.Entities
                .Where(x => x.Disposition is EntityDisposition.Malicious or EntityDisposition.Suspicious)
                .OrderBy(x => x.Disposition == EntityDisposition.Malicious ? 0 : 1).ThenBy(x => x.Type).ThenBy(x => x.Value)
                .Select(x => new ReportIocRow(TaxLabel("EntityType", x.Type.ToString()), d.Value(x.Type, x.Value),
                    TaxLabel("EntityDisposition", x.Disposition.ToString()), x.Tlp is { } t ? Domain.Enums.Tlp.Label(t) : null,
                    x.CreatedAtUtc, d.NullableText(x.Source), d.NullableText(x.Description)))
                .ToList(),
            OrganizationName = string.IsNullOrWhiteSpace(opts.OrganizationName) ? null : opts.OrganizationName.Trim(),
            TeamName = string.IsNullOrWhiteSpace(opts.TeamName) ? null : opts.TeamName.Trim(),
            LogoBytes = logo?.Bytes,
            LogoContentType = logo?.ContentType,
            Sections = sections,
            CaseNumber = c.CaseNumber,
            Title = d.Text(c.Title),   // BUG-74: a title like "Phishing from hxxp://…" is defanged too
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
            LegalNote = d.NullableText(c.LegalReferral.RegulatoryRelevanceNote),
            LegalHold = c.LegalHold,
            MaterialityStatus = c.Materiality.Status == Domain.Enums.MaterialityStatus.Undetermined
                ? null : MaterialityLabel(c.Materiality.Status),
            MaterialityDetermined = c.Materiality.IsDetermined,
            MaterialityDecisionMaker = c.Materiality.DecisionMaker,
            MaterialityDecidedOnUtc = OrgDay(c.Materiality.DecidedOnUtc),
            MaterialityRationale = d.NullableText(c.Materiality.Rationale),
            DetectedAtUtc = c.DetectedAtUtc,
            // CAP-38 review: reported once every regulator in play has its notice (the standing), not the stored time, which can
            // be set over a clock still running (an older build, a restore, a hand edit).
            ReportedAtUtc = extras?.Standing is { } standing ? standing.ReportedAtUtc : c.ReportedAtUtc,
            NotificationStanding = extras?.NotificationStanding,   // CAP-38
            // CAP-07: each regulator's notice and how it was given (typed text defanged like the rest).
            Notices = c.JurisdictionNotices.OrderBy(n => n.NotifiedAtUtc).ThenBy(n => n.Jurisdiction, StringComparer.Ordinal)
                .Select(n =>
                {
                    var (reference, by, file) = (d.NullableText(n.Reference), d.NullableText(n.NotifiedBy), Compliance.NoticeDetailText.FileName(n, c.Evidence));
                    return new ReportNoticeRow(n.Jurisdiction, n.NotifiedAtUtc, n.DueAtUtc,
                        n.Method is { } m ? Compliance.NoticeDetailText.Label(m) : null, reference, by, file,
                        Compliance.NoticeDetailText.Summary(n.Method, reference, by, file));
                })
                .ToList(),
            // CAP-34: the outside parties, in the order engaged (typed text defanged like the rest).
            Parties = c.Parties.OrderBy(p => p.EngagedAtUtc ?? p.CreatedAtUtc).ThenBy(p => p.CreatedAtUtc)
                .Select(p =>
                {
                    var (name, contact, reference) = (d.Text(p.Name), d.NullableText(p.Contact), d.NullableText(p.Reference));
                    return new ReportPartyRow(Cases.PartyText.Label(p.Role), name, contact, reference, p.EngagedAtUtc,
                        d.NullableText(p.Notes), Cases.PartyText.Line(p.Role, name, contact, reference, p.EngagedAtUtc));
                })
                .ToList(),
            ContainedAtUtc = c.ContainmentNotNeededReason is null ? c.ContainedAtUtc : null,
            ContainmentNotNeeded = d.NullableText(c.ContainmentNotNeededReason),
            ContainmentDecidedAtUtc = c.ContainmentNotNeededReason is null ? null : c.ContainedAtUtc,
            ResolvedAtUtc = c.ResolvedAtUtc,
            ActivityBeganAtUtc = c.OccurredAtUtc,
            ActivityBeganApproximate = c.OccurredAtUtc is null ? null : StepTime.ActivityBeganCaveat(c),
            ClosedAtUtc = c.ClosedAtUtc,
            // HR-01: the outcome and the closing brief's conclusion (BUG-310: the version written when it closed, not a revision since).
            Outcome = c.OutcomeKey is { } ok ? extras?.OutcomeLabels.GetValueOrDefault(ok) ?? Admin.CaseOutcomeCatalog.Label(ok) : null,
            ChangedAfterClosure = extras?.AfterClosure is { Count: > 0 } after
                ? $"{after.Count} {(after.Count == 1 ? "change was" : "changes were")} recorded after the case closed on "
                  + $"{after.ClosedRecordedAtUtc.ToString("u", System.Globalization.CultureInfo.InvariantCulture)}, by "
                  + string.Join(", ", after.People.Select(_users.DisplayFor)) + ". Each is in the case's audit trail."
                : null,
            Conclusion = c.OutcomeKey is null ? null
                : c.ClosingBrief?.WorkingAssessment is { Length: > 0 } wa ? d.Text(_markdown.ToPlainText(wa)) : null,
            // INV-05: history reads in the order things happened, dated when they happened.
            ClassificationHistory = c.ClassificationChanges
                .OrderBy(x => x.EffectiveAt)
                .Select(x => new ReportClassificationItem(x.EffectiveAt, x.From is { } fc ? ClassificationLabel(fc) : "—", ClassificationLabel(x.To), d.Text(x.Reason), _users.DisplayFor(x.ChangedBy)))
                .ToList(),
            SeverityHistory = c.SeverityChanges
                .OrderBy(x => x.EffectiveAt)
                .Select(x => new ReportClassificationItem(x.EffectiveAt, x.From is { } f ? _severityLabels.For(f) : "—", _severityLabels.For(x.To), d.Text(x.Reason ?? ""), _users.DisplayFor(x.ChangedBy)))
                .ToList(),
            // A third-party case's disclosure milestones: when the vendor told us what, and what we confirmed.
            DisclosureMilestones = c.TimelineEntries
                .Where(x => EventSteps.IsDisclosure(c, x))
                .InTimelineOrder()
                .Select(x => new ReportTimelineItem(x.OccurredAtUtc, TaxLabel("TimelineEntryType", x.Type.ToString()),
                    d.Text(Content.MarkdownService.PlainLine(x.Description)), d.NullableText(x.Source), Stated: StepTime.Stated(x)))
                .ToList(),
            // The attack chain: the adversary's steps, in our estate or, on a third-party case, in the vendor's.
            AttackChain = c.TimelineEntries
                .Where(x => EventSteps.IsAttack(c, x))
                .InTimelineOrder()
                .Select((x, i) => new ReportAttackStep(
                    i + 1,
                    x.OccurredAtUtc,
                    // BUG-500: in matrix order with the app's labels, as on the timeline and the diagrams.
                    string.Join(", ", x.Tactics.Select(t => t.Tactic).Distinct().OrderBy(DiagramPalette.TacticRank).Select(DiagramPalette.TacticLabel)),
                    d.Text(EntityName(c, x.ActorEntityId)),
                    d.Text(EntityName(c, x.TargetEntityId)),
                    x.TechniqueId,
                    d.Text(Content.MarkdownService.PlainLine(x.Description)),
                    EventSteps.Where(c, x) is { } env && c.Origin == CaseOrigin.ThirdParty
                        ? (env == StepEnvironment.Ours ? "Our environment" : "Vendor") : null,
                    StepTime.Stated(x)))
                .ToList(),
            InvestigationTimeline = InvestigationTimeline(c, d, opts, extras, sections.Contains(ReportSection.CaseBrief)),
            Brief = c.Briefs.FirstOrDefault(b => b.IsCurrent) is { } brief
                ? new ReportBrief(brief.Version, brief.CreatedAtUtc, _users.DisplayFor(brief.CreatedBy),
                    BriefText(brief.WorkingAssessment, d), BriefText(brief.Known, d),
                    BriefText(brief.OpenQuestions, d), BriefText(brief.NextSteps, d))
                : null,
            Evidence = c.Evidence
                .Where(x => !x.IsWithdrawn)   // CAP-21: a withdrawn file isn't the case's evidence
                .OrderBy(x => x.CreatedAtUtc)
                .Select(x => new ReportEvidenceItem(x.OriginalFileName, x.SizeBytes, x.Sha256, x.CreatedAtUtc, _users.DisplayFor(x.CreatedBy),
                    x.CollectedAtUtc, d.NullableText(x.CollectedFrom), d.NullableText(x.CollectedBy)))   // CAP-08
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
                .Select(x => new ReportActionItemRow(d.Text(x.Title), _users.DisplayFor(x.Owner), OrgDay(x.DueAtUtc), TaskStatusLabel(x.Status),
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
                    TaxLabel("EntityDisposition", x.Disposition.ToString()), d.NullableText(x.Description), d.NullableText(x.Source),
                    x.Tlp is { } tlpMark ? Domain.Enums.Tlp.Label(tlpMark) : null))
                .ToList(),
            Relationships = c.EntityRelationships
                .OrderBy(x => x.CreatedAtUtc)
                .Select(x => new ReportRelationshipRow(
                    d.Text(EntityDisplay(c, x.SourceEntityId)), TaxLabel("EntityRelationshipType", x.Type.ToString()),
                    d.Text(EntityDisplay(c, x.TargetEntityId)), d.NullableText(x.Description)))
                .ToList(),
            // HR-13: the tags plus the techniques recorded on the attack chain.
            Techniques = Mitre.CaseTechniques.For(c)
                .Select(x => new ReportTechniqueRow(x.TechniqueId, x.Name, DiagramPalette.TacticLabel(x.Tactic),   // BUG-500
                    string.Join("; ", new[]
                    {
                        x.IsTagged ? "Tagged" : null,
                        x.FromChain ? $"Attack chain ({x.ChainSteps} {(x.ChainSteps == 1 ? "step" : "steps")})" : null
                    }.Where(s => s is not null))))
                .ToList(),
            AttackChainImages = sections.Contains(ReportSection.EventTimeline) ? AttackChainImages(c, d) : [],
            EntityGraphImage = sections.Contains(ReportSection.SystemsReviewed) ? EntityGraphImage(c, d) : null,
            GeneratedBy = _users.DisplayFor(_user.UserId),
            GeneratedAtUtc = now,
            ContentHash = contentHash
        };
    }
}
