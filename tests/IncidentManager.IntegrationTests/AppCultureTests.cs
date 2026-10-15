using System.Globalization;
using FluentAssertions;
using IncidentManager.Web.Services;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-547: the culture pinned at startup holds on every thread, whatever culture the process started under.</summary>
public class AppCultureTests
{
    private static readonly DateTimeOffset Instant = new(2026, 8, 17, 0, 33, 0, TimeSpan.Zero);

    // What a culture-blind site prints: a month label, a plain date, a decimal and a grouped figure.
    private static string Sample() => string.Format(CultureInfo.CurrentCulture, "{0:MMM yyyy}|{0:yyyy-MM-dd}|{1}|{2:N1}",
        Instant, 1.5, 1234.5);

    private const string Invariant = "Aug 2026|2026-08-17|1.5|1,234.5";

    [Fact]
    public async Task Dates_and_numbers_are_invariant_on_every_thread_after_a_th_TH_start()
    {
        var (was, wasUi) = (CultureInfo.CurrentCulture, CultureInfo.CurrentUICulture);
        var (wasDefault, wasDefaultUi) = (CultureInfo.DefaultThreadCurrentCulture, CultureInfo.DefaultThreadCurrentUICulture);
        try
        {
            // The startup thread under a Buddhist-era calendar (2026 is 2569), as on a Thai IIS account.
            CultureInfo.CurrentCulture = CultureInfo.CurrentUICulture = new CultureInfo("th-TH");
            Sample().Should().NotBe(Invariant, "the test starts from a culture that would leak");

            AppCulture.Pin();

            Sample().Should().Be(Invariant, "the startup thread");
            CultureInfo.CurrentUICulture.Should().Be(CultureInfo.InvariantCulture);
            (await Task.Run(Sample)).Should().Be(Invariant, "thread-pool work (hosted services, circuits)");
            await Task.Yield();
            Sample().Should().Be(Invariant, "an async continuation");

            string? onThread = null;
            var t = new Thread(() => onThread = Sample());
            t.Start();
            t.Join();
            onThread.Should().Be(Invariant, "a new thread takes the default");
        }
        finally
        {
            CultureInfo.DefaultThreadCurrentCulture = wasDefault;
            CultureInfo.DefaultThreadCurrentUICulture = wasDefaultUi;
            CultureInfo.CurrentCulture = was;
            CultureInfo.CurrentUICulture = wasUi;
        }
    }
}
