using Microsoft.AspNetCore.Components.Forms;

namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// BUG-341 (B2 review): the one way a component reads the files of a pick, paste or drop.
/// <see cref="InputFileChangeEventArgs.GetMultipleFiles"/> throws past its limit, and the throw lands outside a handler's
/// per-file catch, so a drop of more files than that took the circuit down. A guard test keeps every call here.
/// </summary>
public static class DroppedFiles
{
    /// <summary>The files, or null when there are more than <paramref name="max"/> (the caller says how many it takes).</summary>
    public static IReadOnlyList<IBrowserFile>? UpTo(InputFileChangeEventArgs e, int max)
    {
        ArgumentNullException.ThrowIfNull(e);
        if (e.FileCount > max) return null;
        try { return e.GetMultipleFiles(maximumFileCount: max); }
        catch (InvalidOperationException) { return null; }
    }

    /// <summary>The first file, and how many came (zero, with no file, for none), however many were dropped.</summary>
    public static (IBrowserFile? First, int Count) First(InputFileChangeEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);
        if (e.FileCount == 0) return (null, 0);
        try { return (e.GetMultipleFiles(maximumFileCount: e.FileCount)[0], e.FileCount); }
        catch (InvalidOperationException) { return (null, 0); }
    }
}
