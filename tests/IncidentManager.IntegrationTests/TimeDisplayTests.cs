using FluentAssertions;
using IncidentManager.Web.Services;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// U-29: the on-screen time-zone display service. Pure formatting logic (no I/O) — lives here because
/// the type is in the Web project, which only this test project references. DST-free <c>Etc/GMT±N</c>
/// zones are used so the expected offsets are deterministic across platforms/ICU data.
/// </summary>
public class TimeDisplayTests
{
    // POSIX sign is inverted: Etc/GMT+5 is five hours *behind* UTC (UTC-05:00).
    private static readonly DateTimeOffset Instant = new(2026, 8, 17, 0, 33, 0, TimeSpan.Zero);

    [Fact]
    public void Default_is_utc_and_leaves_the_instant_unconverted()
    {
        var t = new TimeDisplay();

        t.Mode.Should().Be(TimeDisplayMode.Utc);
        t.Label.Should().Be("UTC");
        t.Long(Instant).Should().Be("2026-08-17 00:33:00 UTC");
    }

    [Fact]
    public void Local_mode_converts_and_labels_with_the_offset()
    {
        var t = new TimeDisplay();
        t.Configure("Etc/GMT+5", TimeDisplayMode.Local); // UTC-05:00

        t.Long(Instant).Should().Be("2026-08-16 19:33:00 UTC-05:00");
        t.Short(Instant).Should().Be("Aug 16, 19:33 UTC-05:00");
        t.TimeOnly(Instant).Should().Be("19:33 UTC-05:00");
        t.DateOnly(Instant).Should().Be("2026-08-16");
    }

    [Fact]
    public void Positive_offset_zone_labels_with_a_plus_sign()
    {
        var t = new TimeDisplay();
        t.Configure("Etc/GMT-5", TimeDisplayMode.Local); // UTC+05:00

        t.Long(Instant).Should().Be("2026-08-17 05:33:00 UTC+05:00");
    }

    [Fact]
    public void Configured_local_but_still_utc_zone_labels_as_utc()
    {
        var t = new TimeDisplay();
        t.Configure("Etc/UTC", TimeDisplayMode.Local);

        t.Label.Should().Be("UTC");
        t.Long(Instant).Should().Be("2026-08-17 00:33:00 UTC");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Not/AZone")]
    public void Unknown_or_missing_zone_falls_back_to_utc(string? zoneId)
    {
        var t = new TimeDisplay();
        t.Configure(zoneId, TimeDisplayMode.Local);

        t.Long(Instant).Should().Be("2026-08-17 00:33:00 UTC");
    }

    [Fact]
    public void SetMode_flips_between_utc_and_the_detected_zone()
    {
        var t = new TimeDisplay();
        t.Configure("Etc/GMT+5", TimeDisplayMode.Utc);

        t.Long(Instant).Should().EndWith("UTC"); // still UTC while mode is Utc

        t.SetMode(TimeDisplayMode.Local);
        t.Long(Instant).Should().Be("2026-08-16 19:33:00 UTC-05:00");

        t.SetMode(TimeDisplayMode.Utc);
        t.Long(Instant).Should().Be("2026-08-17 00:33:00 UTC");
    }

    [Fact]
    public void Nullable_overloads_render_a_dash_when_absent()
    {
        var t = new TimeDisplay();

        t.Long((DateTimeOffset?)null).Should().Be("—");
        t.DateOnly((DateTimeOffset?)null).Should().Be("—");
        t.Long((DateTimeOffset?)Instant).Should().Be("2026-08-17 00:33:00 UTC");
    }

    [Fact]
    public void Configure_marks_the_circuit_initialized_and_records_the_browser_zone()
    {
        var t = new TimeDisplay();
        t.Initialized.Should().BeFalse();

        t.Configure("Etc/GMT+5", TimeDisplayMode.Local);

        t.Initialized.Should().BeTrue();
        t.BrowserZoneId.Should().Be("Etc/GMT+5");
    }
}
