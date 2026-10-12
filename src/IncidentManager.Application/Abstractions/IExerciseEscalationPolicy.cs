namespace IncidentManager.Application.Abstractions;

/// <summary>BUG-100: what an exercise case escalated to Breach sends outside CaseBook.</summary>
public enum ExerciseEscalation
{
    /// <summary>Send the Legal email, chat alert and SIEM event as for a real case, each marked EXERCISE.</summary>
    Tag,
    /// <summary>Send none of them. The escalation is still recorded on the case.</summary>
    Skip
}

/// <summary>
/// BUG-100: the administered choice for exercise escalations (<c>Notifications:ExerciseEscalation</c>). A tabletop
/// that escalates to Breach either tests the real alert paths with every message marked EXERCISE, or stays inside
/// CaseBook.
/// </summary>
public interface IExerciseEscalationPolicy
{
    ExerciseEscalation Mode { get; }
}

public static class ExerciseMarking
{
    /// <summary>Put in front of the subject, title and SIEM detail of anything an exercise sends.</summary>
    public const string Prefix = "EXERCISE: ";

    /// <summary>The SIEM event's detail for an exercise escalation.</summary>
    public const string SiemDetail = "EXERCISE: a tabletop case, not a real breach";
}
