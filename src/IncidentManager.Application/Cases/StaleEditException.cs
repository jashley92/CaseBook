namespace IncidentManager.Application.Cases;

/// <summary>
/// Thrown when a single-field edit (case details or the impact assessment) is saved after another author
/// changed those same fields — optimistic-concurrency, expected-value check (FR-06). Rather than silently
/// clobbering the other author's work (last-write-wins), the save is refused so the caller can warn and let
/// the user re-decide. <see cref="CurrentStamp"/> is the now-current signature, so a caller that wants to
/// proceed can re-baseline against it and save again as a deliberate overwrite.
/// </summary>
public sealed class StaleEditException : Exception
{
    public StaleEditException(string currentStamp, string message)
        : base(message) => CurrentStamp = currentStamp;

    /// <summary>The current persisted signature of the edited fields, for an intentional re-save.</summary>
    public string CurrentStamp { get; }
}
