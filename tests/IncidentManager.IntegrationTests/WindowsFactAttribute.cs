using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// A test of Windows-only behaviour (security identifiers, Windows auth). It runs on Windows, where CaseBook is
/// deployed, and is skipped elsewhere (the Linux CI runner), where that code deliberately does nothing.
/// </summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows only: security identifiers aren't read on other platforms.";
    }
}
