using System.Linq.Expressions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Sla;

/// <summary>
/// F-08: the rules in <see cref="SlaPolicy"/> restated as database filters, so the dashboard can count met, missed,
/// at-risk and breached cases without loading every case. Targets vary by severity (and by the breach override),
/// so each filter is an OR across the severity groups that have a target, each with its own target as a constant.
/// <see cref="SlaPolicy"/> stays the source of truth; DashboardSlaParityTests holds these filters to it.
/// </summary>
public static class SlaQueries
{
    private static readonly Severity[] Graded = Enum.GetValues<Severity>().Where(s => s != Severity.Informational).ToArray();

    /// <summary>Cases that reached <paramref name="clock"/>'s milestone within target (<paramref name="met"/>) or after it.</summary>
    public static Expression<Func<Case, bool>> Reached(SlaClock clock, bool met, SlaTargets targets)
    {
        var any = False;
        foreach (var severity in Graded)
        {
            if (clock == SlaClock.Detection)
            {
                // The detection target has no breach override (SlaPolicy.EvaluateDetection).
                if (targets.HoursFor(clock, severity) is { } hours)
                    any = Or(any, And(IsSeverity(severity), ReachedWithin(clock, met, hours * TimeSpan.TicksPerHour)));
                continue;
            }
            foreach (var breach in new[] { false, true })
            {
                if (targets.HoursFor(clock, severity, breach ? Classification.Breach : null) is { } hours)
                    any = Or(any, And(InGroup(severity, breach), ReachedWithin(clock, met, hours * TimeSpan.TicksPerHour)));
            }
        }
        return any;
    }

    /// <summary>
    /// Open cases whose headline status (<see cref="SlaPolicy.Evaluate"/>) is <see cref="SlaState.Breached"/>, or
    /// <see cref="SlaState.AtRisk"/> when <paramref name="breached"/> is false. The headline follows the containment
    /// clock while it runs, then resolution. Apply to cases already narrowed to open (not closed or archived).
    /// </summary>
    public static Expression<Func<Case, bool>> Headline(bool breached, SlaTargets targets, DateTimeOffset now)
    {
        var any = False;
        foreach (var severity in Graded)
        foreach (var breach in new[] { false, true })
        {
            var classification = breach ? Classification.Breach : (Classification?)null;
            var contHours = targets.HoursFor(SlaClock.Containment, severity, classification);
            var resHours = targets.HoursFor(SlaClock.Resolution, severity, classification);
            if (contHours is null && resHours is null) continue;

            // A clock counts as running once detected and until its milestone is reached.
            Expression<Func<Case, bool>> containmentRunning = c => c.DetectedAtUtc != null && c.ContainedAtUtc == null;
            Expression<Func<Case, bool>> resolutionRunning = c => c.DetectedAtUtc != null && c.ResolvedAtUtc == null;

            var state = False;
            if (contHours is { } ch)
                state = And(containmentRunning, InState(ch, breached, targets.AtRiskThresholdPercent, now));
            if (resHours is { } rh)
            {
                var resolution = And(resolutionRunning, InState(rh, breached, targets.AtRiskThresholdPercent, now));
                state = Or(state, contHours is null ? resolution : And(Not(containmentRunning), resolution));
            }
            any = Or(any, And(InGroup(severity, breach), state));
        }
        return any;
    }

    /// <summary>Open cases whose headline status is at risk or breached (<see cref="SlaStatus.NeedsAttention"/>).</summary>
    public static Expression<Func<Case, bool>> NeedsAttention(SlaTargets targets, DateTimeOffset now)
        => Or(Headline(breached: true, targets, now), Headline(breached: false, targets, now));

    // Detected long enough ago to be past the target (breached), or past the at-risk point but not the target.
    // Mirrors SlaPolicy.EvaluateClock: due = detected + hours; at risk from detected + hours × threshold%.
    private static Expression<Func<Case, bool>> InState(int hours, bool breached, int atRiskPercent, DateTimeOffset now)
    {
        var dueCutoff = now.AddHours(-hours);
        if (breached) return c => c.DetectedAtUtc <= dueCutoff;
        var riskCutoff = now.AddHours(-(hours * (atRiskPercent / 100.0)));
        return c => c.DetectedAtUtc <= riskCutoff && c.DetectedAtUtc > dueCutoff;
    }

    // Each clock's start and milestone; met means the milestone came no later than start + target.
    private static Expression<Func<Case, bool>> ReachedWithin(SlaClock clock, bool met, long limit)
        => And(c => c.DetectedAtUtc != null, Milestone(clock, met, limit));

    private static Expression<Func<Case, bool>> Milestone(SlaClock clock, bool met, long limit) => (clock, met) switch
    {
        (SlaClock.Containment, true) => c => c.ContainedAtUtc != null && DbTime.TicksBetween(c.DetectedAtUtc, c.ContainedAtUtc) <= limit,
        (SlaClock.Containment, false) => c => c.ContainedAtUtc != null && DbTime.TicksBetween(c.DetectedAtUtc, c.ContainedAtUtc) > limit,
        (SlaClock.Resolution, true) => c => c.ResolvedAtUtc != null && DbTime.TicksBetween(c.DetectedAtUtc, c.ResolvedAtUtc) <= limit,
        (SlaClock.Resolution, false) => c => c.ResolvedAtUtc != null && DbTime.TicksBetween(c.DetectedAtUtc, c.ResolvedAtUtc) > limit,
        (SlaClock.Detection, true) => c => c.OccurredAtUtc != null && DbTime.TicksBetween(c.OccurredAtUtc, c.DetectedAtUtc) <= limit,
        (SlaClock.Detection, false) => c => c.OccurredAtUtc != null && DbTime.TicksBetween(c.OccurredAtUtc, c.DetectedAtUtc) > limit,
        _ => throw new ArgumentOutOfRangeException(nameof(clock))
    };

    private static Expression<Func<Case, bool>> IsSeverity(Severity severity) => c => c.Severity == severity;

    // The breach override applies only to cases classified Breach; everything else (including unclassified
    // Complex Events) uses the base target.
    private static Expression<Func<Case, bool>> InGroup(Severity severity, bool breach) => breach
        ? c => c.Severity == severity && c.Classification == Classification.Breach
        : c => c.Severity == severity && c.Classification != Classification.Breach;

    // --- Composition: one parameter throughout, so EF sees a single plain predicate. ---

    private static readonly Expression<Func<Case, bool>> False = c => false;

    private static Expression<Func<Case, bool>> And(Expression<Func<Case, bool>> a, Expression<Func<Case, bool>> b)
        => Combine(a, b, Expression.AndAlso);

    private static Expression<Func<Case, bool>> Or(Expression<Func<Case, bool>> a, Expression<Func<Case, bool>> b)
        => ReferenceEquals(a, False) ? b : Combine(a, b, Expression.OrElse);

    private static Expression<Func<Case, bool>> Not(Expression<Func<Case, bool>> a)
        => Expression.Lambda<Func<Case, bool>>(Expression.Not(a.Body), a.Parameters);

    private static Expression<Func<Case, bool>> Combine(Expression<Func<Case, bool>> a, Expression<Func<Case, bool>> b,
        Func<Expression, Expression, BinaryExpression> op)
        => Expression.Lambda<Func<Case, bool>>(op(a.Body, new Rebind(b.Parameters[0], a.Parameters[0]).Visit(b.Body)), a.Parameters);

    private sealed class Rebind(ParameterExpression from, ParameterExpression to) : ExpressionVisitor
    {
        protected override Expression VisitParameter(ParameterExpression node) => node == from ? to : node;
    }
}
