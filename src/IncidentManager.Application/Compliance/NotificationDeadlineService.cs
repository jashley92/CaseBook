using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
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
                Notices = x.JurisdictionNotices.Select(n => new { n.Jurisdiction, n.NotifiedAtUtc }).ToList()
            })
            .FirstOrDefaultAsync(ct);

        if (c is null) return CaseNotificationDeadlines.Disabled with { Enabled = true };

        var start = ResolveStart(settings.StartBasis, c.Classification, c.DetectedAtUtc,
            c.MatStatus, c.MatDecidedOn, c.MatRecordedAt);

        var empty = new CaseNotificationDeadlines(true, settings.StartBasis, start, c.ReportedAtUtc,
            Array.Empty<NotificationDeadlineStatus>(), null);
        if (start is null) return empty;

        // WF-11: a reported case is judged on what was in play when it was reported.
        var jurisdictions = c.ReportedAtUtc is not null && Frozen(c.ReportedJurisdictions) is { } frozen ? frozen
            : await JurisdictionsInPlayAsync(db, c.Keys, ct);
        if (jurisdictions.Count == 0) return empty;

        var ruleSet = await _rules.LoadRuleSetAsync(settings.DefaultWindowHours, ct);
        var notices = c.Notices.ToDictionary(n => n.Jurisdiction, n => n.NotifiedAtUtc, StringComparer.OrdinalIgnoreCase);
        var statuses = NotificationDeadlinePolicy.EvaluateByJurisdiction(start, NotifiedAt(notices, c.ReportedAtUtc), jurisdictions, ruleSet,
            settings.AtRiskThresholdPercent, _clock.UtcNow);

        return new CaseNotificationDeadlines(true, settings.StartBasis, start, c.ReportedAtUtc,
            statuses, NotificationDeadlinePolicy.Headline(statuses))
        { NoticeCodes = notices.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase) };
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

    private static IReadOnlyList<string>? Frozen(string? csv) =>
        csv?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// WF-11: after a data element's jurisdictions change, the cases not yet reported that carry it are judged again: one
    /// whose remaining jurisdictions are all notified becomes reported (a case reported already keeps what was in play).
    /// </summary>
    public static async Task RecheckUnreportedAsync(IAppDbContext db, IReadOnlyCollection<string> elementKeys, string actor,
        DateTimeOffset now, CancellationToken ct = default)
    {
        if (elementKeys.Count == 0) return;
        var cases = await db.Cases
            .Include(c => c.DataElements).Include(c => c.JurisdictionNotices)
            .Where(c => c.ReportedAtUtc == null && !c.IsArchived && c.JurisdictionNotices.Any()
                        && c.DataElements.Any(d => elementKeys.Contains(d.ElementKey)))
            .ToListAsync(ct);
        foreach (var c in cases)
            c.ReportedFromNotices(await JurisdictionsInPlayAsync(db, c.DataElements.Select(d => d.ElementKey), ct), actor, now);
        if (cases.Count > 0) await db.SaveChangesAsync(ct);
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
            .SelectMany(s => s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
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

    // Each case's per-jurisdiction statuses, for cases with a triggered obligation and a jurisdiction in play.
    private static async Task<Dictionary<Guid, IReadOnlyList<NotificationDeadlineStatus>>> StatusesAsync(
        IAppDbContext db, IQueryable<Case> cases, NotificationDeadlineSettings settings,
        NotificationRuleSet ruleSet, DateTimeOffset now, bool reported, CancellationToken ct)
    {
        var elementJur = await db.DataElements.AsNoTracking()
            .Where(e => e.NotificationJurisdictions != null && e.NotificationJurisdictions != "")
            .Select(e => new { e.Key, e.NotificationJurisdictions })
            .ToDictionaryAsync(e => e.Key, e => e.NotificationJurisdictions!, ct);

        var rows = await cases
            .Where(c => reported ? c.ReportedAtUtc != null : c.ReportedAtUtc == null) // a recorded report stops the clock
            .Select(c => new
            {
                c.Id, c.Classification, c.DetectedAtUtc, c.ReportedAtUtc, c.ReportedJurisdictions,
                MatStatus = c.Materiality.Status, MatDecided = c.Materiality.DecidedOnUtc, MatRecorded = c.Materiality.RecordedAtUtc,
                Keys = c.DataElements.Select(d => d.ElementKey).ToList(),
                Notices = c.JurisdictionNotices.Select(n => new { n.Jurisdiction, n.NotifiedAtUtc }).ToList()
            })
            .ToListAsync(ct);

        var result = new Dictionary<Guid, IReadOnlyList<NotificationDeadlineStatus>>();
        foreach (var c in rows)
        {
            var start = ResolveStart(settings.StartBasis, c.Classification, c.DetectedAtUtc, c.MatStatus, c.MatDecided, c.MatRecorded);
            if (start is null) continue; // obligation not triggered yet

            var jurisdictions = c.ReportedAtUtc is not null && Frozen(c.ReportedJurisdictions) is { } frozen ? frozen.ToList()   // WF-11
                : c.Keys.Where(elementJur.ContainsKey)
                    .SelectMany(k => elementJur[k].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    .Select(j => j.ToUpperInvariant()).Distinct().ToList();
            if (jurisdictions.Count == 0) continue;

            result[c.Id] = NotificationDeadlinePolicy.EvaluateByJurisdiction(start,
                NotifiedAt(c.Notices.ToDictionary(n => n.Jurisdiction, n => n.NotifiedAtUtc, StringComparer.OrdinalIgnoreCase), c.ReportedAtUtc),
                jurisdictions, ruleSet, settings.AtRiskThresholdPercent, now);
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
