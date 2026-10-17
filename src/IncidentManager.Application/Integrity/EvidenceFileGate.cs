namespace IncidentManager.Application.Integrity;

/// <summary>
/// PROD-57: one evidence-file sweep at a time: the evidence re-check and the conversion of plain files to encrypted ones
/// never run together, so the re-check never reads a file the conversion is swapping (a spurious missing or unreadable),
/// and the conversion's swap isn't refused by the re-check holding the file open. Singleton.
/// </summary>
public sealed class EvidenceFileGate : IDisposable
{
    public void Dispose() => _gate.Dispose();

    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<IDisposable> EnterAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        return new Release(_gate);
    }

    private sealed class Release(SemaphoreSlim gate) : IDisposable
    {
        private int _done;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) == 0) gate.Release();
        }
    }
}
