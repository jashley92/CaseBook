namespace IncidentManager.Application.Cases;

/// <summary>
/// BUG-113: two people saved the same case at the same moment, and the other save landed first. Rather than record both
/// (two closes, two current briefs), the second is refused. An <see cref="InvalidOperationException"/>, so every form
/// that shows a refused save's message shows this one.
/// </summary>
public sealed class ConcurrentEditException(Exception inner)
    : InvalidOperationException("Someone else just changed this case. Reload to see their change, then try again.", inner);
