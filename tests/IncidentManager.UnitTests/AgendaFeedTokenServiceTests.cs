using FluentAssertions;
using IncidentManager.Infrastructure.Agenda;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>E-39: the stateless HMAC feed token round-trips, resists tampering, and is off until keyed.</summary>
public class AgendaFeedTokenServiceTests
{
    private static AgendaFeedTokenService With(string? key)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Agenda:FeedKey"] = key })
            .Build();
        return new AgendaFeedTokenService(config);
    }

    [Fact]
    public void Issued_token_validates_back_to_the_same_user()
    {
        var svc = With("a-long-random-secret");
        var token = svc.Issue("SID-123");

        token.Should().NotBeNullOrWhiteSpace();
        svc.TryValidate(token!, out var uid).Should().BeTrue();
        uid.Should().Be("SID-123");
    }

    [Fact]
    public void Disabled_when_no_key_is_configured()
    {
        var svc = With(null);

        svc.Enabled.Should().BeFalse();
        svc.Issue("SID-123").Should().BeNull();
        svc.TryValidate("anything.here", out _).Should().BeFalse();
    }

    [Fact]
    public void A_token_from_a_different_key_is_rejected()
    {
        var token = With("secret-one").Issue("SID-123")!;

        With("secret-two").TryValidate(token, out _).Should().BeFalse();
    }

    [Fact]
    public void A_tampered_payload_is_rejected()
    {
        var svc = With("a-long-random-secret");
        var token = svc.Issue("SID-123")!;

        // Swap the user-id half for another user while keeping the original signature.
        var forged = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("SID-999"))
                         .TrimEnd('=').Replace('+', '-').Replace('/', '_')
                     + token[token.IndexOf('.')..];

        svc.TryValidate(forged, out _).Should().BeFalse();
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-dot")]
    [InlineData(".")]
    [InlineData("abc.")]
    public void Malformed_tokens_are_rejected(string token)
    {
        With("a-long-random-secret").TryValidate(token, out _).Should().BeFalse();
    }
}
