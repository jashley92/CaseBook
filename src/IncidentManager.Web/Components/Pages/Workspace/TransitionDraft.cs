using IncidentManager.Application.Cases;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Components.Pages.Workspace;

/// <summary>
/// RD-27: what a transition being prepared holds before it's saved: the stage gate it runs (with the statements the
/// analyst ticked and an override justification for anything unmet) and when it happened (INV-05: left at its default
/// it means now). The phase and reclassify dialogs and the close-out view each hold one.
/// </summary>
public sealed class TransitionDraft
{
    public GateEvaluation? Gate { get; set; }
    public HashSet<Guid> Attested { get; } = new();
    public string? Override { get; set; }

    /// <summary>When it happened, as a wall time in the display zone.</summary>
    public DateTime? When { get; set; }
    /// <summary>The time the draft started at; left there, the transition is stored as happening now.</summary>
    public DateTime? WhenDefault { get; set; }

    /// <summary>Starts over at "now": no ticks, no override, a fresh time.</summary>
    public void Reset(DateTime nowWall)
    {
        When = WhenDefault = nowWall;
        Attested.Clear();
        Override = null;
    }

    /// <summary>A different gate applies (the target changed): its ticks and override start over.</summary>
    public void UseGate(GateEvaluation? gate)
    {
        Attested.Clear();
        Override = null;
        Gate = gate;
    }

    public IReadOnlyList<GateRequirementResult> UnmetBlocking => Gate?.UnmetBlocking(Attested) ?? Array.Empty<GateRequirementResult>();

    public bool NeedsOverride => UnmetBlocking.Count > 0;

    /// <summary>
    /// A gate may require a minimum-length rationale: enforced on the transition reason, and on the override
    /// justification when the move is being forced through. An error message, or null.
    /// </summary>
    public string? RationaleError(string? reason)
    {
        if (Gate is not { RequiresCommentary: true } g) return null;
        var min = g.CommentaryMinLength;
        if ((reason?.Trim().Length ?? 0) < min)
            return $"Record a reason of at least {min} characters to pass this gate.";
        if (NeedsOverride && (Override?.Trim().Length ?? 0) < min)
            return $"The override justification needs at least {min} characters.";
        return null;
    }

    /// <summary>The chosen time as UTC, or null when it was left at the default (it happened now).</summary>
    public DateTimeOffset? EffectiveUtc(TimeZoneInfo zone) =>
        When is { } w && w != WhenDefault ? WallClock.ToUtc(w, zone) : null;

    /// <summary>More than the backdating threshold ago, so the transition needs a reason.</summary>
    public bool Backdated(TimeZoneInfo zone, DateTimeOffset nowUtc) => CaseService.IsBackdated(EffectiveUtc(zone), nowUtc);
}

/// <summary>RD-27: wall times in the display zone (what a datetime-local input holds) to and from UTC.</summary>
public static class WallClock
{
    public static DateTimeOffset ToUtc(DateTime wall, TimeZoneInfo zone)
    {
        var unspecified = DateTime.SpecifyKind(wall, DateTimeKind.Unspecified);
        try { return new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(unspecified, zone), TimeSpan.Zero); }
        catch { return new DateTimeOffset(DateTime.SpecifyKind(unspecified, DateTimeKind.Utc), TimeSpan.Zero); } // DST-invalid wall time: treat as UTC
    }

    public static DateTime ToWall(DateTimeOffset utc, TimeZoneInfo zone) =>
        DateTime.SpecifyKind(TimeZoneInfo.ConvertTime(utc, zone).DateTime, DateTimeKind.Unspecified);
}

/// <summary>RD-27: which stage gate a transition runs.</summary>
public static class CaseFlowGates
{
    /// <summary>The gate a case is heading toward next, given its current classification and phase.</summary>
    public static StageGateTrigger? Next(Case? c)
    {
        if (c is null || c.Phase == CasePhase.Closed) return null;
        return c.Classification switch
        {
            null => StageGateTrigger.PromoteToAdverseEvent,
            Classification.AdverseEvent => StageGateTrigger.EscalateToIncident,
            Classification.Incident => StageGateTrigger.EscalateToBreach,
            Classification.Breach => StageGateTrigger.CloseCase,
            _ => null
        };
    }

    /// <summary>The gate governing a reclassification to <paramref name="to"/> (escalations only).</summary>
    public static StageGateTrigger? Reclassify(Case? c, Classification to) =>
        c is not null && (c.Classification is null || to > c.Classification) ? StageGateTriggers.ForClassification(to) : null;

    /// <summary>The close gate, when the phase being moved to is Closed.</summary>
    public static StageGateTrigger? Phase(Case? c, CasePhase to) =>
        c is { Phase: not CasePhase.Closed } && to == CasePhase.Closed ? StageGateTrigger.CloseCase : null;
}
