using System.Runtime.InteropServices;

namespace IncidentManager.Infrastructure.Storage;

/// <summary>
/// PROD-55: questions about a store's folder that can hang when it's on a network share (a UNC path whose server is down
/// blocks the calling thread for a long time): free space, and whether the folder can be written and read. Each runs with
/// a time limit (C10), so a check never holds a request or a background run for longer than that; a call that times out
/// answers "unknown" or "unreachable".
/// </summary>
public static class StoreVolume
{
    public static readonly TimeSpan TimeLimit = TimeSpan.FromSeconds(15);

    /// <summary>The free bytes available to this account on the volume holding <paramref name="folder"/>, or null when it
    /// can't be told in time.</summary>
    public static async Task<long?> FreeBytesAsync(string folder, CancellationToken ct = default) =>
        (await SpaceAsync(folder, ct))?.Free;

    /// <summary>The bytes free to this account and the volume's (or share's) size, or null when it can't be told in time.</summary>
    public static async Task<(long Free, long Total)?> SpaceAsync(string folder, CancellationToken ct = default)
    {
        try { return await Task.Run(() => Space(folder), ct).WaitAsync(TimeLimit, ct); }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    private static (long Free, long Total)? Space(string folder)
    {
        if (OperatingSystem.IsWindows())   // works on UNC paths
            return GetDiskFreeSpaceEx(folder, out var available, out var total, out _) ? ((long)available, (long)total) : null;
        var root = Path.GetPathRoot(Path.GetFullPath(folder));
        if (string.IsNullOrEmpty(root)) return null;
        var drive = new DriveInfo(root);
        return (drive.AvailableFreeSpace, drive.TotalSize);
    }

    // Classic interop: LibraryImport would need unsafe code switched on for the whole project, for one call.
#pragma warning disable SYSLIB1054
    [DllImport("kernel32.dll", EntryPoint = "GetDiskFreeSpaceExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceEx(string directoryName, out ulong freeBytesAvailable, out ulong totalBytes,
        out ulong totalFreeBytes);
#pragma warning restore SYSLIB1054

    /// <summary>
    /// Whether the folder can be written, read back and cleaned up, as the app's account: null when it can, else why not.
    /// Creates the folder if it's missing only when <paramref name="mayCreate"/> (a fresh store); a store that holds
    /// evidence and has vanished is reported, not recreated empty.
    /// </summary>
    public static async Task<string?> ProbeAsync(string folder, bool mayCreate = true, CancellationToken ct = default)
    {
        try { return await Task.Run(() => Probe(folder, mayCreate), ct).WaitAsync(TimeLimit, ct); }
        catch (TimeoutException) { return $"no answer within {TimeLimit.TotalSeconds:0} seconds"; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException
                                       or System.Security.SecurityException)
        {
            return ex.Message;
        }
    }

    private static string? Probe(string folder, bool mayCreate)
    {
        if (!Directory.Exists(folder))
        {
            if (!mayCreate) return "the folder isn't there (it held evidence, so it isn't recreated empty)";
            Directory.CreateDirectory(folder);
        }
        var probe = Path.Combine(folder, $".probe-{Guid.NewGuid():N}");
        var bytes = Guid.NewGuid().ToByteArray();
        try
        {
            File.WriteAllBytes(probe, bytes);
            return File.ReadAllBytes(probe).AsSpan().SequenceEqual(bytes) ? null : "a file written there read back differently";
        }
        finally
        {
            try { File.Delete(probe); } catch (IOException) { /* best effort; a later probe uses a new name */ }
        }
    }
}
