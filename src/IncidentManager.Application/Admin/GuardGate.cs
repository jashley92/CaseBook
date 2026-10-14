namespace IncidentManager.Application.Admin;

/// <summary>
/// BUG-268: the lock-out guards ("the last administrator access", "the last active outcome") check, then save, in two
/// steps. Two administrators each removing one of the last two admin mappings at once both passed the check, and nobody
/// was left with Administer. Changes those guards protect run one at a time in this process, check and save together
/// (CaseBook runs as one instance; see known issues).
/// </summary>
public static class GuardGate
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    /// <summary>Waits for the gate; dispose the result to release it.</summary>
    public static async Task<IDisposable> EnterAsync(CancellationToken ct = default)
    {
        await Gate.WaitAsync(ct).ConfigureAwait(false);
        return new Releaser();
    }

    private sealed class Releaser : IDisposable
    {
        private int _released;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0) Gate.Release();
        }
    }
}
