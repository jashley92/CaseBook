using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
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
                MatStatus = x.Materiality.Status,
                MatDecidedOn = x.Materiality.DecidedOnUtc,
                MatRecordedAt = x.Materiality.RecordedAtUtc,
                Keys = x.DataElements.Select(d => d.ElementKey).ToList()
            })
            .FirstOrDefaultAsync(ct);

        if (c is null) return CaseNotificationDeadlines.Disabled with { Enabled = true };

        var start = ResolveStart(settings.StartBasis, c.Classification, c.DetectedAtUtc,
            c.MatStatus, c.MatDecidedOn, c.MatRecordedAt);

        var empty = new CaseNotificationDeadlines(true, settings.StartBasis, start, c.ReportedAtUtc,
            Array.Empty<NotificationDeadlineStatus>(), null);
        if (start is null) return empty;

        // Jurisdictions in play = the union of the notification jurisdictions across the case's data elements.
        var raw = await db.DataElements.AsNoTracking()
            .Where(e => c.Keys.Contains(e.Key)
                        && e.NotificationJurisdictions != null && e.NotificationJurisdictions != "")
            .Select(e => e.NotificationJurisdictions!)
            .ToListAsync(ct);
        var jurisdictions = raw
            .SelectMany(s => s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(j => j.ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (jurisdictions.Count == 0) return empty;

        var ruleSet = await _rules.LoadRuleSetAsync(settings.DefaultWindowHours, ct);
        var statuses = NotificationDeadlinePolicy.Evaluate(start, c.ReportedAtUtc, jurisdictions, ruleSet,
            settings.AtRiskThresholdPercent, _clock.UtcNow);

        return new CaseNotificationDeadlines(true, settings.StartBasis, start, c.ReportedAtUtc,
            statuses, NotificationDeadlinePolicy.Headline(statuses));
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
