using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// C21: plays a slow reload. Once armed, the first query whose text contains <c>match</c> is held after its rows have been
/// read (as its reader is disposed, so the database holds no lock for it) until <see cref="Release"/>: the reload has its
/// old snapshot in hand while the test changes the data and runs a newer reload. Once only.
/// </summary>
public sealed class HeldReadInterceptor(string match) : DbCommandInterceptor, IDisposable
{
    private readonly ManualResetEventSlim _held = new();
    private readonly ManualResetEventSlim _release = new();
    private volatile bool _armed;
    private int _taken;

    /// <summary>From now on, the next matching read is held.</summary>
    public void Arm() => _armed = true;

    /// <summary>Waits until a read is being held; false if none was within the time.</summary>
    public bool WaitHeld(TimeSpan within) => _held.Wait(within);

    /// <summary>Lets the held read go on (to store what it read).</summary>
    public void Release() => _release.Set();

    private void Hold(DbCommand command)
    {
        if (!_armed || !command.CommandText.Contains(match, StringComparison.Ordinal)) return;
        if (Interlocked.Exchange(ref _taken, 1) != 0) return;
        _held.Set();
        _release.Wait(TimeSpan.FromSeconds(30));
    }

    public override InterceptionResult DataReaderDisposing(DbCommand command, DataReaderDisposingEventData eventData, InterceptionResult result)
    {
        Hold(command);
        return base.DataReaderDisposing(command, eventData, result);
    }

    public void Dispose()
    {
        _release.Set();
        _held.Dispose();
        _release.Dispose();
    }
}
