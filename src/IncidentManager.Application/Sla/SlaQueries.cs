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

    /// <summary>
    /// Cases that reached <paramref name="clock"/>'s milestone within target (<paramref name="met"/>) or after it.
    /// The elapsed time is computed once and compared with the case's own target, looked up by severity (and the breach
    /// override) in a single CASE, rather than recomputed for every severity group: far cheaper per row at scale.
    /// </summary>
    public static Expression<Func<Case, bool>> Reached(SlaClock clock, bool met, SlaTargets targets)
    {
        var groups = new List<(Expression<Func<Case, bool>> InGroup, long Ticks)>();
        foreach (var severity in Graded)
        {
            if (clock == SlaClock.Detection)
            {
                // The detection target has no breach override (SlaPolicy.EvaluateDetection).
                if (targets.HoursFor(clock, severity) is { } hours)
                    groups.Add((IsSeverity(severity), hours * TimeSpan.TicksPerHour));
                continue;
            }
            foreach (var breach in new[] { false, true })
            {
                if (targets.HoursFor(clock, severity, breach ? Classification.Breach : null) is { } hours)
                    groups.Add((InGroup(severity, breach), hours * TimeSpan.TicksPerHour));
            }
        }
        if (groups.Count == 0) return False;

        // The case's target in ticks: CASE WHEN <group> THEN <ticks> … ELSE NULL END. No target, no match.
        var elapsed = Elapsed(clock);
        var c = elapsed.Parameters[0];
        Expression target = Expression.Constant(null, typeof(long?));
        foreach (var (inGroup, ticks) in Enumerable.Reverse(groups))
            target = Expression.Condition(new Rebind(inGroup.Parameters[0], c).Visit(inGroup.Body),
                Expression.Constant(ticks, typeof(long?)), target);

        // Met: reached no later than start + target (SlaPolicy: reached <= due). A null elapsed (not reached) never counts.
        var compare = met ? Expression.LessThanOrEqual(elapsed.Body, target) : Expression.GreaterThan(elapsed.Body, target);
        return Expression.Lambda<Func<Case, bool>>(compare, c);
    }

    /// <summary>
    /// Cases that reached <paramref name="clock"/>'s milestone and have a target for it: met + missed. Needs no elapsed
    /// time, so a count of missed is this minus <see cref="Reached"/> with met, one date calculation fewer per row.
    /// </summary>
    public static Expression<Func<Case, bool>> Judged(SlaClock clock, SlaTargets targets)
    {
        var any = False;
        foreach (var severity in Graded)
        {
            if (clock == SlaClock.Detection)
            {
                if (targets.HoursFor(clock, severity) is not null) any = Or(any, IsSeverity(severity));
                continue;
            }
            foreach (var breach in new[] { false, true })
                if (targets.HoursFor(clock, severity, breach ? Classification.Breach : null) is not null)
                    any = Or(any, InGroup(severity, breach));
        }
        Expression<Func<Case, bool>> reached = clock switch
        {
            SlaClock.Containment => c => c.DetectedAtUtc != null && c.ContainedAtUtc != null,
            SlaClock.Resolution => c => c.DetectedAtUtc != null && c.ResolvedAtUtc != null,
            SlaClock.Detection => c => c.OccurredAtUtc != null && c.DetectedAtUtc != null,
            _ => throw new ArgumentOutOfRangeException(nameof(clock))
        };
        return And(reached, any);
    }

    // Each clock's start and milestone, as an elapsed time in ticks (null until both are recorded).
    private static Expression<Func<Case, long?>> Elapsed(SlaClock clock) => clock switch
    {
        SlaClock.Containment => c => DbTime.TicksBetween(c.DetectedAtUtc, c.ContainedAtUtc),
        SlaClock.Resolution => c => DbTime.TicksBetween(c.DetectedAtUtc, c.ResolvedAtUtc),
        SlaClock.Detection => c => DbTime.TicksBetween(c.OccurredAtUtc, c.DetectedAtUtc),
        _ => throw new ArgumentOutOfRangeException(nameof(clock))
    };

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

    private static Expression<Func<Case, bool>> IsSeverity(Severity severity) => c => c.Severity == severity;

    // The breach override applies only to cases classified Breach; everything else (including unclassified
    // Complex Events) uses the base target.
    private static Expression<Func<Case, bool>> InGroup(Severity severity, bool breach) => breach
        ? c => c.Severity == severity && c.Classification == Classification.Breach
        : c => c.Severity == severity && c.Classification != Classification.Breach;

    // --- Composition: one parameter throughout, so EF sees a single plain predicate. ---

    private static readonly Expression<Func<Case, bool>> False = c => false;

    internal static Expression<Func<Case, bool>> And(Expression<Func<Case, bool>> a, Expression<Func<Case, bool>> b)
        => ReferenceEquals(a, False) || ReferenceEquals(b, False) ? False : Combine(a, b, Expression.AndAlso);

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
