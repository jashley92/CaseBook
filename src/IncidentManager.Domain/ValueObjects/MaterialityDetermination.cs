using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.ValueObjects;

/// <summary>
/// Records the <b>materiality determination</b> for a case — whether the incident/breach is a material,
/// disclosure-triggering matter. Like <see cref="LegalReferral"/>, this stands in for a decision the SOC
/// does <em>not</em> make: Legal/Privacy or a disclosure committee owns the call. The tool captures the
/// outcome, who made it (the external authority), when they decided, and why, plus which SOC user entered
/// it and when. Folded into the case's tamper-evident canonical so a recorded determination is hashed.
/// </summary>
public class MaterialityDetermination
{
    public MaterialityStatus Status { get; set; } = MaterialityStatus.Undetermined;

    /// <summary>The external authority that made the call (e.g. "Disclosure Committee", "General Counsel") —
    /// deliberately distinct from the SOC user who recorded it here.</summary>
    public string? DecisionMaker { get; set; }

    /// <summary>The date the off-app determination was actually made (distinct from when it was recorded here).</summary>
    public DateTimeOffset? DecidedOnUtc { get; set; }

    /// <summary>The rationale for the determination, as reported by the decision-maker.</summary>
    public string? Rationale { get; set; }

    /// <summary>The SOC user who recorded the determination in the tool.</summary>
    public string? RecordedBy { get; set; }
    public DateTimeOffset? RecordedAtUtc { get; set; }

    /// <summary>True once a final call (material / not material) has been recorded.</summary>
    public bool IsDetermined => Status is MaterialityStatus.Material or MaterialityStatus.NotMaterial;

    public string ToCanonical() =>
        $"{(int)Status}|{DecisionMaker}|{DecidedOnUtc:o}|{Rationale}|{RecordedBy}|{RecordedAtUtc:o}";
}
