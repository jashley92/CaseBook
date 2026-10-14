using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Compliance;

/// <summary>A case's evaluated regulatory-notification position (PROD-07): the per-jurisdiction deadlines and
/// the single headline, plus the context needed to render them.</summary>
public sealed record CaseNotificationDeadlines(
    bool Enabled,
    NotificationStartBasis StartBasis,
    DateTimeOffset? StartInstant,
    DateTimeOffset? ReportedAtUtc,
    IReadOnlyList<NotificationDeadlineStatus> Statuses,
    NotificationDeadlineStatus? Headline)
{
    public static readonly CaseNotificationDeadlines Disabled = new(
        false, NotificationStartBasis.Determination, null, null,
        Array.Empty<NotificationDeadlineStatus>(), null);

    /// <summary>
    /// WF-12: the clock follows the latest Material call (owner's decision), so a call that went back to Under review and
    /// was made again restarts it. When the running clock started later than the first Material call, that first call's
    /// decision time, so it's shown beside the clock; when the case is back under review after a Material call, the one
    /// that clock ran from. Null otherwise, and under the Detection basis.
    /// </summary>
    public DateTimeOffset? EarlierMaterialUtc { get; init; }

    /// <summary>BUG-09: the jurisdictions with a recorded notice (empty for a case reported before notices were per jurisdiction).</summary>
    public IReadOnlySet<string> NoticeCodes { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>There is a live countdown to show (feature on, clock started, at least one jurisdiction).</summary>
    public bool HasClock => Enabled && StartInstant is not null && Statuses.Count > 0;
    /// <summary>Feature is on and the obligation is triggered, but no jurisdiction is in play yet.</summary>
    public bool StartedButNoJurisdictions => Enabled && StartInstant is not null && Statuses.Count == 0;
    /// <summary>Feature is on but the obligation hasn't been triggered (no material determination / not a breach).</summary>
    public bool AwaitingTrigger => Enabled && StartInstant is null;
}

/// <summary>
/// Evaluates a case against the administered notification-deadline rules (PROD-07). Reads the live settings
/// (feature toggle + start basis + default window + at-risk threshold), resolves the clock-start instant
/// from the case per the configured basis, gathers the jurisdictions the case's data elements trigger, and
/// runs the pure <see cref="NotificationDeadlinePolicy"/>. No case state is mutated — reminders/escalation
/// are the only automation, and a human records the reported milestone.
/// </summary>
public sealed class NotificationDeadlineService
{
    private readonly IAppDbContextFactory _factory;
    private readonly INotificationDeadlineSettingsProvider _settings;
    private readonly NotificationRuleService _rules;
    private readonly IClock _clock;

    public NotificationDeadlineService(IAppDbContextFactory factory,
        INotificationDeadlineSettingsProvider settings, NotificationRuleService rules, IClock clock)
    {
        _factory = factory;
        _settings = settings;
        _rules = rules;
        _clock = clock;
    }

    public async Task<CaseNotificationDeadlines> EvaluateAsync(Guid caseId, CancellationToken ct = default)
    {
        var settings = _settings.Current;
        if (!settings.Enabled) return CaseNotificationDeadlines.Disabled;

        using var db = _factory.CreateDbContext();
        var c = await db.Cases.AsNoTracking()
            .Where(x => x.Id == caseId)
            .Select(x => new
            {
                x.Classification,
                x.DetectedAtUtc,
                x.ReportedAtUtc,
                x.ReportedJurisdictions,
                MatStatus = x.Materiality.Status,
                MatDecidedOn = x.Materiality.DecidedOnUtc,
                MatRecordedAt = x.Materiality.RecordedAtUtc,
                Keys = x.DataElements.Select(d => d.ElementKey).ToList(),
                Notices = x.JurisdictionNotices.Select(n => new { n.Jurisdiction, n.NotifiedAtUtc, n.DueAtUtc }).ToList(),
                MaterialCalls = x.MaterialityChanges.Where(m => m.To == MaterialityStatus.Material)
                    .Select(m => new { m.From, m.DecidedOnUtc, m.ChangedAtUtc }).ToList()
            })
            .FirstOrDefaultAsync(ct);

        if (c is null) return CaseNotificationDeadlines.Disabled with { Enabled = true };

        var start = ResolveStart(settings.StartBasis, c.Classification, c.DetectedAtUtc,
            c.MatStatus, c.MatDecidedOn, c.MatRecordedAt);

        // WF-12: the first Material call, when the clock now runs from a later one (or not at all, back under review).
        // WF-66: a Material call revised while still Material (a corrected decision date) is the same call, so each call's
        // date is its latest revision before it was taken back; only a call taken back and made again is a restart.
        DateTimeOffset? earlier = null;
        var calls = new List<DateTimeOffset>();
        foreach (var m in c.MaterialCalls.OrderBy(m => m.ChangedAtUtc))
        {
            var on = m.DecidedOnUtc ?? m.ChangedAtUtc;
            if (m.From == MaterialityStatus.Material && calls.Count > 0) calls[^1] = on;
            else calls.Add(on);
        }
        if (settings.StartBasis == NotificationStartBasis.Determination && calls.Count > 0
            && (start is null ? c.MatStatus != MaterialityStatus.NotMaterial : calls.Count > 1 && calls[0] < start))
            earlier = calls[0];

        var empty = new CaseNotificationDeadlines(true, settings.StartBasis, start, c.ReportedAtUtc,
            Array.Empty<NotificationDeadlineStatus>(), null) { EarlierMaterialUtc = earlier };
        if (start is null) return empty;

        // WF-11 / BUG-284: what was in play when it was reported, and what elements added since bring in.
        var jurisdictions = Case.KeptInPlay(c.ReportedJurisdictions, c.Keys, Live(await ElementJurisdictionsAsync(db, ct)));
        if (jurisdictions.Count == 0) return empty;

        var ruleSet = await _rules.LoadRuleSetAsync(settings.DefaultWindowHours, ct);
        // BUG-428: a legacy notice coded "NY;CA" counts for each code it names.
        var notices = Case.ByNoticeCode(c.Notices.Select(n => (n.Jurisdiction, n.NotifiedAtUtc)));
        var kept = Case.ByNoticeCode(c.Notices.Where(n => n.DueAtUtc is not null).Select(n => (n.Jurisdiction, n.DueAtUtc!.Value)));
        var statuses = NotificationDeadlinePolicy.EvaluateByJurisdiction(start, NotifiedAt(notices, c.ReportedAtUtc), jurisdictions, ruleSet,
            settings.AtRiskThresholdPercent, _clock.UtcNow, KeptDue(kept));

        return new CaseNotificationDeadlines(true, settings.StartBasis, start, c.ReportedAtUtc,
            statuses, NotificationDeadlinePolicy.Headline(statuses))
        // BUG-428: only the codes with a notice of their own, which can be removed one by one; a combined legacy notice is
        // cleared with the rest.
        { NoticeCodes = c.Notices.Select(n => n.Jurisdiction).ToHashSet(StringComparer.OrdinalIgnoreCase), EarlierMaterialUtc = earlier };
    }

    /// <summary>
    /// BUG-11: the headline for each case in <paramref name="cases"/> in one pass, with the live settings and rules (the
    /// same answer <see cref="EvaluateAsync"/> gives per case). Unreported cases only unless
    /// <paramref name="includeReported"/>, which adds reported cases' met / missed outcome. Empty when the feature is off.
    /// </summary>
    public async Task<Dictionary<Guid, NotificationDeadlineStatus>> HeadlinesNowAsync(IAppDbContext db, IQueryable<Case> cases,
        bool includeReported = false, CancellationToken ct = default)
    {
        var settings = _settings.Current;
        if (!settings.Enabled) return [];
        var ruleSet = await _rules.LoadRuleSetAsync(settings.DefaultWindowHours, ct);
        var now = _clock.UtcNow;
        var heads = await HeadlinesAsync(db, cases, settings, ruleSet, now, reported: false, ct);
        if (includeReported)
            foreach (var (id, head) in await HeadlinesAsync(db, cases, settings, ruleSet, now, reported: true, ct))
                heads[id] = head;
        return heads;
    }

    /// <summary>
    /// BUG-191: every jurisdiction's clock for each unreported case in <paramref name="cases"/> (not just the headline),
    /// with the live settings and rules, for the reminders: a breached jurisdiction stays the headline until it's
    /// notified, and would hide another's at-risk and breach. Empty when the feature is off.
    /// </summary>
    public async Task<Dictionary<Guid, IReadOnlyList<NotificationDeadlineStatus>>> AllNowAsync(IAppDbContext db, IQueryable<Case> cases,
        CancellationToken ct = default)
    {
        var settings = _settings.Current;
        if (!settings.Enabled) return [];
        var ruleSet = await _rules.LoadRuleSetAsync(settings.DefaultWindowHours, ct);
        return await StatusesAsync(db, cases, settings, ruleSet, _clock.UtcNow, reported: false, ct);
    }

    /// <summary>
    /// WF-77: records each new notice's deadline as it stands now (see <see cref="JurisdictionNotice.DueAtUtc"/>), for one
    /// case or, with null, every case with a notice lacking one (start-up). Written straight to the column, not audited:
    /// it's derived from the rules. A no-op while the deadline clock is off. Returns how many notices it filled.
    /// </summary>
    public async Task<int> FreezeNoticeDuesAsync(Guid? caseId = null, CancellationToken ct = default)
    {
        var settings = _settings.Current;
        if (!settings.Enabled) return 0;
        using var db = _factory.CreateDbContext();
        var cases = db.Cases.AsNoTracking().Where(c => c.JurisdictionNotices.Any(n => n.DueAtUtc == null));
        if (caseId is { } one) cases = cases.Where(c => c.Id == one);
        var ruleSet = await _rules.LoadRuleSetAsync(settings.DefaultWindowHours, ct);
        var now = _clock.UtcNow;
        var dues = new Dictionary<Guid, Dictionary<string, DateTimeOffset>>();
        foreach (var reported in new[] { true, false })   // a notice can be on a case not yet reported to every regulator
            foreach (var (id, statuses) in await StatusesAsync(db, cases, settings, ruleSet, now, reported, ct))
                dues[id] = statuses.Where(s => s.DueAtUtc is not null)
                    .GroupBy(s => s.JurisdictionCode, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(g => g.Key, g => g.Min(s => s.DueAtUtc!.Value), StringComparer.OrdinalIgnoreCase);
        if (dues.Count == 0) return 0;

        var open = await cases.SelectMany(c => c.JurisdictionNotices).Where(n => n.DueAtUtc == null)
            .Select(n => new { n.Id, n.CaseId, n.Jurisdiction })
            .ToListAsync(ct);
        var filled = 0;
        foreach (var n in open)
        {
            // BUG-456: a legacy notice coded "NY;CA" covers each code (BUG-428), and one kept deadline is read for every code
            // it names. So it's frozen only when its codes all have that same deadline; otherwise it stays on today's clock,
            // which judges each code against its own.
            if (!dues.TryGetValue(n.CaseId, out var byCode)) continue;
            var codes = SplitCodes(n.Jurisdiction).ToList();
            if (codes.Count == 0 || !codes.All(byCode.ContainsKey)) continue;
            var codeDues = codes.Select(code => byCode[code]).Distinct().ToList();
            if (codeDues.Count != 1) continue;
            DateTimeOffset? due = codeDues[0];
            var noticeId = n.Id;
            filled += await db.JurisdictionNotices
                .Where(x => x.Id == noticeId && x.DueAtUtc == null)
                .ExecuteUpdateAsync(u => u.SetProperty(x => x.DueAtUtc, due), ct);
        }
        return filled;
    }

    /// <summary>Each data element's notification jurisdictions as administered now (key → "NY,NJ").</summary>
    public static async Task<IReadOnlyDictionary<string, string>> ElementJurisdictionsAsync(IAppDbContext db, CancellationToken ct = default) =>
        (await db.DataElements.AsNoTracking()
            .Where(e => e.NotificationJurisdictions != null && e.NotificationJurisdictions != "")
            .Select(e => new { e.Key, e.NotificationJurisdictions })
            .ToListAsync(ct))
        .GroupBy(e => e.Key, StringComparer.OrdinalIgnoreCase)
        .ToDictionary(g => g.Key, g => g.First().NotificationJurisdictions!, StringComparer.OrdinalIgnoreCase);

    /// <summary>The jurisdictions <paramref name="elementJur"/> gives a set of data elements.</summary>
    public static Func<IEnumerable<string>, IReadOnlyList<string>> Live(IReadOnlyDictionary<string, string> elementJur) =>
        keys => keys.Where(elementJur.ContainsKey)
            .SelectMany(k => SplitCodes(elementJur[k]))
            .Select(j => j.ToUpperInvariant()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>
    /// BUG-404: a data element's jurisdiction codes. A ";" separates codes too: it separates the kept jurisdictions from
    /// the elements in <see cref="Case.ReportedJurisdictions"/>, so a code holding one (stored before the page split on
    /// it) put a phantom jurisdiction there.
    /// </summary>
    public static string[] SplitCodes(string? jurisdictions) =>
        (jurisdictions ?? "").Split(JurisdictionSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static readonly char[] JurisdictionSeparators = [',', ';'];

    /// <summary>
    /// WF-11: after a data element's jurisdictions change, the cases not yet reported that carry it are judged again: one
    /// whose remaining jurisdictions are all notified becomes reported (a case reported already keeps what was in play).
    /// BUG-390: judged on <paramref name="elements"/> (the elements as the caller is about to save them) and left for the
    /// caller's own save, so the element change and the recheck are saved together or not at all.
    /// </summary>
    public static async Task RecheckUnreportedAsync(IAppDbContext db, IReadOnlyCollection<string> elementKeys,
        IEnumerable<DataElement> elements, string actor, DateTimeOffset now, CancellationToken ct = default)
    {
        if (elementKeys.Count == 0) return;
        var cases = await db.Cases.AsSplitQuery()   // S8733: two collections, one query each
            .Include(c => c.DataElements).Include(c => c.JurisdictionNotices)
            .Where(c => c.ReportedAtUtc == null && !c.IsArchived && c.JurisdictionNotices.Any()
                        && c.DataElements.Any(d => elementKeys.Contains(d.ElementKey)))
            .ToListAsync(ct);
        // BUG-284: a case once reported keeps what was in play then; only the elements added since follow the change.
        var live = Live(elements.Where(e => !string.IsNullOrEmpty(e.NotificationJurisdictions))
            .GroupBy(e => e.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().NotificationJurisdictions!, StringComparer.OrdinalIgnoreCase));
        foreach (var c in cases)
            c.ReportedFromNotices(Case.KeptInPlay(c.ReportedJurisdictions, c.DataElements.Select(d => d.ElementKey).ToList(), live), actor, now);
    }

    /// <summary>Jurisdictions in play = the union of the notification jurisdictions across the case's data elements.</summary>
    public static async Task<IReadOnlyList<string>> JurisdictionsInPlayAsync(IAppDbContext db, IEnumerable<string> elementKeys,
        CancellationToken ct = default)
    {
        var keys = elementKeys.ToList();
        if (keys.Count == 0) return [];
        var raw = await db.DataElements.AsNoTracking()
            .Where(e => keys.Contains(e.Key) && e.NotificationJurisdictions != null && e.NotificationJurisdictions != "")
            .Select(e => e.NotificationJurisdictions!)
            .ToListAsync(ct);
        return raw
            .SelectMany(SplitCodes)   // BUG-404
            .Select(j => j.ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// BUG-09: when a jurisdiction was notified: its own notice; for a case reported before notices were recorded per
    /// jurisdiction (none recorded), the case's reported time, which meant every regulator.
    /// </summary>
    private static Func<string, DateTimeOffset?> NotifiedAt(IReadOnlyDictionary<string, DateTimeOffset> notices, DateTimeOffset? reportedAtUtc) =>
        code => notices.TryGetValue(code, out var at) ? at : notices.Count == 0 ? reportedAtUtc : null;

    // BUG-286: each notice's kept deadline (WF-77), so every reader judges a notice as the program report does.
    private static Func<string, DateTimeOffset?> KeptDue(IReadOnlyDictionary<string, DateTimeOffset> kept) =>
        code => kept.TryGetValue(code, out var due) ? due : null;

    /// <summary>
    /// The headline deadline for each unreported case in <paramref name="cases"/> whose obligation is triggered
    /// and whose data elements put at least one jurisdiction in play. Shared by the dashboard counts and the case
    /// list's notification-deadline filter so the two always agree. The caller scopes <paramref name="cases"/>
    /// (not archived, visible to the user; closed cases included — INV-43) and checks that the feature is enabled.
    /// </summary>
    public static Task<Dictionary<Guid, NotificationDeadlineStatus>> OpenHeadlinesAsync(
        IAppDbContext db, IQueryable<Case> cases, NotificationDeadlineSettings settings,
        NotificationRuleSet ruleSet, DateTimeOffset now, CancellationToken ct = default)
        => HeadlinesAsync(db, cases, settings, ruleSet, now, reported: false, ct);

    /// <summary>
    /// The headline for each case in <paramref name="cases"/> with a triggered obligation and a jurisdiction in play:
    /// for unreported cases (<paramref name="reported"/> false) the running clock, for reported ones the outcome
    /// (met or missed). The caller scopes <paramref name="cases"/>.
    /// </summary>
    public static async Task<Dictionary<Guid, NotificationDeadlineStatus>> HeadlinesAsync(
        IAppDbContext db, IQueryable<Case> cases, NotificationDeadlineSettings settings,
        NotificationRuleSet ruleSet, DateTimeOffset now, bool reported, CancellationToken ct = default)
    {
        var result = new Dictionary<Guid, NotificationDeadlineStatus>();
        foreach (var (id, statuses) in await StatusesAsync(db, cases, settings, ruleSet, now, reported, ct))
            if (NotificationDeadlinePolicy.Headline(statuses) is { } head) result[id] = head;
        return result;
    }

    /// <summary>
    /// BUG-287: every notice given on the cases in <paramref name="cases"/>, reported or not yet (a case still waiting on
    /// another regulator has given this one's notice), each with when it was given and whether that was inside its
    /// window (its kept deadline, WF-77). So a quarter counts the notices given in it, and a jurisdiction that comes into
    /// play later doesn't move them. BUG-375: a notice with a kept deadline is judged on its own, so one given in a past
    /// quarter stays counted when the trigger is later withdrawn (materiality taken back, the Breach reclassified) or its
    /// jurisdiction leaves play; only a notice from before deadlines were kept is judged through today's clock.
    /// </summary>
    public static async Task<List<(Guid CaseId, DateTimeOffset NotifiedAtUtc, SlaState State)>> NoticeOutcomesAsync(
        IAppDbContext db, IQueryable<Case> cases, NotificationDeadlineSettings settings, NotificationRuleSet ruleSet,
        DateTimeOffset now, CancellationToken ct = default)
    {
        var result = new List<(Guid, DateTimeOffset, SlaState)>();
        // Compared in memory: DateTimeOffset comparison stays off SQLite (F-08).
        var kept = await cases.SelectMany(c => c.JurisdictionNotices).Where(n => n.DueAtUtc != null)
            .Select(n => new { n.CaseId, n.Jurisdiction, n.NotifiedAtUtc, n.DueAtUtc }).ToListAsync(ct);
        // BUG-456: a legacy "NY;CA" notice now keeps a deadline too; it counts once for each code it names, as it did through
        // today's clock before it had one, and a code's own notice wins over it (BUG-428).
        var judged = new HashSet<(Guid, string)>();
        foreach (var g in kept.GroupBy(n => n.CaseId))
            foreach (var (code, (at, due)) in Case.ByNoticeCode(g.Select(n => (n.Jurisdiction, (n.NotifiedAtUtc, n.DueAtUtc!.Value)))))
            {
                result.Add((g.Key, at, at <= due ? SlaState.Met : SlaState.Missed));
                judged.Add((g.Key, code.ToUpperInvariant()));
            }

        foreach (var reported in new[] { true, false })
            foreach (var (id, statuses) in await StatusesAsync(db, cases, settings, ruleSet, now, reported, ct))
                foreach (var s in statuses)
                    if (s.State is SlaState.Met or SlaState.Missed && s.NotifiedAtUtc is { } at
                        && !judged.Contains((id, s.JurisdictionCode.ToUpperInvariant())))
                        result.Add((id, at, s.State));
        return result;
    }

    // Each case's per-jurisdiction statuses, for cases with a triggered obligation and a jurisdiction in play.
    private static async Task<Dictionary<Guid, IReadOnlyList<NotificationDeadlineStatus>>> StatusesAsync(
        IAppDbContext db, IQueryable<Case> cases, NotificationDeadlineSettings settings,
        NotificationRuleSet ruleSet, DateTimeOffset now, bool reported, CancellationToken ct)
    {
        var live = Live(await ElementJurisdictionsAsync(db, ct));

        var rows = await cases
            .Where(c => reported ? c.ReportedAtUtc != null : c.ReportedAtUtc == null) // a recorded report stops the clock
            .Select(c => new
            {
                c.Id, c.Classification, c.DetectedAtUtc, c.ReportedAtUtc, c.ReportedJurisdictions,
                MatStatus = c.Materiality.Status, MatDecided = c.Materiality.DecidedOnUtc, MatRecorded = c.Materiality.RecordedAtUtc,
                Keys = c.DataElements.Select(d => d.ElementKey).ToList(),
                Notices = c.JurisdictionNotices.Select(n => new { n.Jurisdiction, n.NotifiedAtUtc, n.DueAtUtc }).ToList()
            })
            .ToListAsync(ct);

        var result = new Dictionary<Guid, IReadOnlyList<NotificationDeadlineStatus>>();
        foreach (var c in rows)
        {
            var start = ResolveStart(settings.StartBasis, c.Classification, c.DetectedAtUtc, c.MatStatus, c.MatDecided, c.MatRecorded);
            if (start is null) continue; // obligation not triggered yet

            var jurisdictions = Case.KeptInPlay(c.ReportedJurisdictions, c.Keys, live);   // WF-11, BUG-284
            if (jurisdictions.Count == 0) continue;

            result[c.Id] = NotificationDeadlinePolicy.EvaluateByJurisdiction(start,
                NotifiedAt(Case.ByNoticeCode(c.Notices.Select(n => (n.Jurisdiction, n.NotifiedAtUtc))), c.ReportedAtUtc),   // BUG-428
                jurisdictions, ruleSet, settings.AtRiskThresholdPercent, now,
                KeptDue(Case.ByNoticeCode(c.Notices.Where(n => n.DueAtUtc is not null).Select(n => (n.Jurisdiction, n.DueAtUtc!.Value)))));
        }
        return result;
    }

    /// <summary>The clock-start instant for a case under a given basis, or null when the obligation is not yet
    /// triggered (not determined material / not a breach). Pure, so it is unit-testable.</summary>
    public static DateTimeOffset? ResolveStart(NotificationStartBasis basis, Classification? classification,
        DateTimeOffset? detectedAtUtc, MaterialityStatus materiality,
        DateTimeOffset? materialityDecidedOn, DateTimeOffset? materialityRecordedAt) => basis switch
    {
        // The materiality "Material" call is the trigger; its decision date is the start (falls back to when
        // it was recorded if a date is somehow absent). Not material / undetermined ⇒ no clock.
        NotificationStartBasis.Determination => materiality == MaterialityStatus.Material
            ? (materialityDecidedOn ?? materialityRecordedAt)
            : null,
        // Detection basis: a Breach classification triggers the clock from the detection stamp.
        NotificationStartBasis.Detection => classification == Classification.Breach ? detectedAtUtc : null,
        _ => null
    };
}
