namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// BUG-603 (C8): a handler that changes server state ignores a second invocation while the first runs (a double-click,
/// Enter and a click, two shortcuts), so it neither saves twice nor shows a false refusal from the second attempt:
/// <code>
/// private readonly InFlight _saving = new();
/// private Task Save() => _saving.Run(SaveCore);
/// // markup: disabled="@_saving.Busy"
/// </code>
/// One per handler, or per group of handlers that mustn't overlap. It runs on the circuit's dispatcher, so the check and
/// the set can't interleave.
/// </summary>
public sealed class InFlight
{
    /// <summary>Whether a run is under way.</summary>
    public bool Busy { get; private set; }

    /// <summary>Runs <paramref name="action"/> unless a run is under way; true when it ran.</summary>
    public async Task<bool> Run(Func<Task> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (Busy) return false;
        Busy = true;
        try
        {
            await action();
            return true;
        }
        finally { Busy = false; }
    }
}
