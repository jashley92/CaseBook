using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Secrets;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// F-19: the secret-reference grammar and the default (passthrough) provider. A literal value is used
/// as-is; a <c>@cyberark:</c> reference names a CCP location; the passthrough provider — which ships
/// enabled unless CyberArk is configured — fails a reference closed rather than leaking its text.
/// </summary>
public class SecretResolutionTests
{
    [Theory]
    [InlineData("hunter2", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("@cyberark:Safe=SIEM;Object=Tok", true)]
    [InlineData("@CyberArk:Safe=SIEM;Object=Tok", true)] // scheme is case-insensitive
    public void IsReference_distinguishes_references_from_literals(string? value, bool expected) =>
        SecretReference.IsReference(value).Should().Be(expected);

    [Fact]
    public void TryParse_reads_query_pairs_in_order()
    {
        SecretReference.TryParse("@cyberark:Safe=SIEM;Folder=Root;Object=CaseBook-Webhook", out var r)
            .Should().BeTrue();

        r!.Query.Should().Equal(
            new KeyValuePair<string, string>("Safe", "SIEM"),
            new KeyValuePair<string, string>("Folder", "Root"),
            new KeyValuePair<string, string>("Object", "CaseBook-Webhook"));
    }

    [Theory]
    [InlineData("plain-literal")]                 // not a reference
    [InlineData("@cyberark:")]                     // empty body
    [InlineData("@cyberark:Safe")]                 // no '='
    [InlineData("@cyberark:=SIEM")]                // no key
    [InlineData("@cyberark:Safe=")]                // empty value
    public void TryParse_rejects_non_references_and_malformed_references(string value) =>
        SecretReference.TryParse(value, out _).Should().BeFalse();

    [Fact]
    public void Reference_ToString_names_the_location_without_a_secret()
    {
        SecretReference.TryParse("@cyberark:Safe=SIEM;Object=Tok", out var r).Should().BeTrue();
        r!.ToString().Should().Be("@cyberark:Safe=SIEM;Object=Tok");
    }

    // --- Passthrough (default) provider ----------------------------------------

    private static PassthroughSecretProvider Passthrough() => new(NullLogger<PassthroughSecretProvider>.Instance);

    [Fact]
    public async Task Passthrough_returns_a_literal_unchanged()
    {
        (await Passthrough().ResolveAsync("hunter2")).Should().Be("hunter2");
    }

    [Fact]
    public async Task Passthrough_returns_null_for_null()
    {
        (await Passthrough().ResolveAsync(null)).Should().BeNull();
    }

    [Fact]
    public async Task Passthrough_fails_a_reference_closed_rather_than_returning_its_text()
    {
        // No provider can satisfy a reference here → null, never the "@cyberark:..." string.
        (await Passthrough().ResolveAsync("@cyberark:Safe=SIEM;Object=Tok")).Should().BeNull();
    }

    // --- Health monitor --------------------------------------------------------

    private sealed class StubClock(DateTimeOffset now) : IClock { public DateTimeOffset UtcNow { get; set; } = now; }

    [Fact]
    public void Health_starts_empty()
    {
        var h = new SecretResolutionHealth(new StubClock(DateTimeOffset.UnixEpoch));
        h.Current.AnyActivity.Should().BeFalse();
        h.Current.LastAttemptFailed.Should().BeFalse();
    }

    [Fact]
    public void Health_tracks_the_latest_outcome_by_time()
    {
        var clock = new StubClock(new DateTimeOffset(2026, 9, 10, 10, 0, 0, TimeSpan.Zero));
        var h = new SecretResolutionHealth(clock);

        h.RecordSuccess("@cyberark:Safe=A;Object=B");
        clock.UtcNow = clock.UtcNow.AddMinutes(5);
        h.RecordFailure("@cyberark:Safe=A;Object=B", "CCP returned HTTP 500");

        var s = h.Current;
        s.SuccessCount.Should().Be(1);
        s.FailureCount.Should().Be(1);
        s.LastAttemptFailed.Should().BeTrue();            // failure is newer than the success
        s.LastFailureReason.Should().Be("CCP returned HTTP 500");

        clock.UtcNow = clock.UtcNow.AddMinutes(5);
        h.RecordSuccess("@cyberark:Safe=A;Object=B");
        h.Current.LastAttemptFailed.Should().BeFalse();   // recovered
    }
}
