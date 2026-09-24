using FluentAssertions;
using IncidentManager.Infrastructure.Agenda;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// E-39 / S-12: the HMAC feed token round-trips its user and issue time, resists tampering with either, and is off
/// until keyed. (Whether the issue time is still the user's current one is AgendaFeedService's check.)
/// </summary>
public class AgendaFeedTokenServiceTests
{
    private static readonly DateTimeOffset Issued = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

    private static AgendaFeedTokenService With(string? key)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Agenda:FeedKey"] = key })
            .Build();
        return new AgendaFeedTokenService(config);
    }

    [Fact]
    public void Issued_token_validates_back_to_the_same_user_and_issue_time()
    {
        var svc = With("a-long-random-secret");
        var token = svc.Issue("SID-123", Issued);

        token.Should().NotBeNullOrWhiteSpace();
        svc.TryValidate(token!, out var uid, out var at).Should().BeTrue();
        uid.Should().Be("SID-123");
        at.Should().Be(Issued);
    }

    [Fact]
    public void Disabled_when_no_key_is_configured()
    {
        var svc = With(null);

        svc.Enabled.Should().BeFalse();
        svc.Issue("SID-123", Issued).Should().BeNull();
        svc.TryValidate("anything.1.here", out _, out _).Should().BeFalse();
    }

    [Fact]
    public void A_token_from_a_different_key_is_rejected()
    {
        var token = With("secret-one").Issue("SID-123", Issued)!;

        With("secret-two").TryValidate(token, out _, out _).Should().BeFalse();
    }

    [Fact]
    public void A_tampered_user_is_rejected()
    {
        var svc = With("a-long-random-secret");
        var token = svc.Issue("SID-123", Issued)!;

        // Swap the user-id part for another user while keeping the original time and signature.
        var forged = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("SID-999"))
                         .TrimEnd('=').Replace('+', '-').Replace('/', '_')
                     + token[token.IndexOf('.')..];

        svc.TryValidate(forged, out _, out _).Should().BeFalse();
    }

    [Fact]
    public void A_tampered_issue_time_is_rejected()
    {
        // S-12: the issue time is signed, so an old link can't be edited to look current.
        var svc = With("a-long-random-secret");
        var parts = svc.Issue("SID-123", Issued)!.Split('.');
        var forged = $"{parts[0]}.{Issued.AddDays(300).ToUnixTimeSeconds()}.{parts[2]}";

        svc.TryValidate(forged, out _, out _).Should().BeFalse();
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-dot")]
    [InlineData(".")]
    [InlineData("abc.")]
    [InlineData("abc.def")]            // the old two-part format
    [InlineData("abc.notanumber.def")]
    public void Malformed_tokens_are_rejected(string token)
    {
        With("a-long-random-secret").TryValidate(token, out _, out _).Should().BeFalse();
    }
}
