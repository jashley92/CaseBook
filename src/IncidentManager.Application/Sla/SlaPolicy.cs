using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Sla;

/// <summary>Which response-time milestone an SLA clock measures, timed from detection (E-16).</summary>
public enum SlaClock
{
    /// <summary>Detected → Contained.</summary>
    Containment,
    /// <summary>Detected → Resolved (recovery reached).</summary>
    Resolution
}

/// <summary>A case's standing against a response-time target.</summary>
public enum SlaState
{
    /// <summary>No target applies (Informational severity, no target configured, or nothing left to chase).</summary>
    NoTarget,
    /// <summary>Active clock, comfortably inside target.</summary>
    OnTrack,
    /// <summary>Active clock, past the at-risk threshold but not yet breached.</summary>
    AtRisk,
    /// <summary>Active clock, target passed without the milestone being reached.</summary>
    Breached,
    /// <summary>Milestone reached within target (historical).</summary>
    Met,
    /// <summary>Milestone reached only after target had passed (historical).</summary>
    Missed
}

/// <summary>
/// A case's evaluated position against one response-time target. <see cref="Clock"/> names the milestone
/// the status is about; <see cref="DueAtUtc"/> is when an active clock breaches; <see cref="Remaining"/>
/// is time left on an active clock (negative once breached) and is null for historical outcomes.
/// </summary>
public sealed record SlaStatus(
    SlaState State,
    SlaClock? Clock,
    int? TargetHours,
    DateTimeOffset? DueAtUtc,
    TimeSpan? Remaining,
    double? ElapsedHours)
{
    /// <summary>No SLA applies to this case.</summary>
    public static readonly SlaStatus None = new(SlaState.NoTarget, null, null, null, null, null);

    /// <summary>The clock is still running (not yet met/missed).</summary>
    public bool IsActive => State is SlaState.OnTrack or SlaState.AtRisk or SlaState.Breached;

    /// <summary>The case should be surfaced to an analyst/leadership now (approaching or past target).</summary>
    public bool NeedsAttention => State is SlaState.AtRisk or SlaState.Breached;
}

/// <summary>
/// Per-severity response-time targets (hours) and the at-risk threshold, as administered under the
/// <c>Sla:*</c> settings. A missing or non-positive hour value means that severity/clock has no target.
/// </summary>
public sealed record SlaTargets(
    IReadOnlyDictionary<(SlaClock Clock, Severity Severity), int> Hours,
    int AtRiskThresholdPercent)
{
    public static readonly SlaTargets Empty =
        new(new Dictionary<(SlaClock, Severity), int>(), SlaPolicy.DefaultAtRiskThresholdPercent);

    /// <summary>The configured target for a clock/severity, or null when none applies.</summary>
    public int? HoursFor(SlaClock clock, Severity severity)
        => Hours.TryGetValue((clock, severity), out var h) && h > 0 ? h : null;
}

/// <summary>
/// Turns the administered SLA targets and a case's lifecycle timestamps into a forward-looking
/// <see cref="SlaStatus"/>. Pure and side-effect free, so the timing rules are unit-tested independently
/// of the query/UI plumbing (mirrors <see cref="Security.IdleTimeoutPolicy"/>). Reuses the same
/// <c>DetectedAtUtc → ContainedAtUtc/ResolvedAtUtc</c> stamps that drive MTTD/MTTR — no new data.
/// </summary>
public static class SlaPolicy
{
    /// <summary>Fraction of the target elapsed at which an active clock flips to <see cref="SlaState.AtRisk"/>.</summary>
    public const int DefaultAtRiskThresholdPercent = 80;

    /// <summary>
    /// The single headline status for a case: the earliest still-running clock (containment before
    /// resolution) if any, otherwise the most-advanced historical outcome. Informational severity and
    /// cases with no detection stamp have no SLA.
    /// </summary>
    public static SlaStatus Evaluate(
        Severity severity, CasePhase phase,
        DateTimeOffset? detectedAtUtc, DateTimeOffset? containedAtUtc, DateTimeOffset? resolvedAtUtc,
        SlaTargets targets, DateTimeOffset nowUtc)
    {
        var (containment, resolution) =
            Breakdown(severity, phase, detectedAtUtc, containedAtUtc, resolvedAtUtc, targets, nowUtc);

        // An open clock takes precedence — containment is chased before resolution.
        if (containment.IsActive) return containment;
        if (resolution.IsActive) return resolution;
        // Otherwise report the furthest milestone that actually has an outcome.
        if (resolution.State is SlaState.Met or SlaState.Missed) return resolution;
        if (containment.State is SlaState.Met or SlaState.Missed) return containment;
        return SlaStatus.None;
    }

    /// <summary>
    /// Both clocks evaluated independently, for a workspace view that shows containment and resolution
    /// side by side. Each is <see cref="SlaStatus.None"/> when that clock has no configured target.
    /// </summary>
    public static (SlaStatus Containment, SlaStatus Resolution) Breakdown(
        Severity severity, CasePhase phase,
        DateTimeOffset? detectedAtUtc, DateTimeOffset? containedAtUtc, DateTimeOffset? resolvedAtUtc,
        SlaTargets targets, DateTimeOffset nowUtc)
    {
        // Informational carries no SLA, and every clock is measured from detection.
        if (severity == Severity.Informational || detectedAtUtc is not { } start)
            return (SlaStatus.None, SlaStatus.None);

        // A closed case that never reached a milestone has nothing left to chase (its clock is abandoned).
        var abandoned = phase == CasePhase.Closed;

        var containment = EvaluateClock(SlaClock.Containment, start, containedAtUtc, abandoned,
            targets.HoursFor(SlaClock.Containment, severity), targets.AtRiskThresholdPercent, nowUtc);
        var resolution = EvaluateClock(SlaClock.Resolution, start, resolvedAtUtc, abandoned,
            targets.HoursFor(SlaClock.Resolution, severity), targets.AtRiskThresholdPercent, nowUtc);
        return (containment, resolution);
    }

    private static SlaStatus EvaluateClock(SlaClock clock, DateTimeOffset start, DateTimeOffset? milestoneUtc,
        bool abandoned, int? targetHours, int atRiskPercent, DateTimeOffset now)
    {
        if (targetHours is not { } hours)
            return SlaStatus.None with { Clock = clock };

        var due = start.AddHours(hours);

        if (milestoneUtc is { } reached)
        {
            // Historical: did we make it before the target?
            var elapsed = Math.Round((reached - start).TotalHours, 1);
            var outcome = reached <= due ? SlaState.Met : SlaState.Missed;
            return new SlaStatus(outcome, clock, hours, due, null, elapsed);
        }

        if (abandoned)
            return SlaStatus.None with { Clock = clock };

        // Active clock.
        var elapsedNow = Math.Round((now - start).TotalHours, 1);
        var atRiskAt = start.AddHours(hours * (atRiskPercent / 100.0));
        var state = now >= due ? SlaState.Breached
                  : now >= atRiskAt ? SlaState.AtRisk
                  : SlaState.OnTrack;
        return new SlaStatus(state, clock, hours, due, due - now, elapsedNow);
    }
}
