using FluentAssertions;
using IncidentManager.Infrastructure.Siem;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// The SIEM webhook must not send the bearer token / event stream over an insecure or arbitrary
/// endpoint (S-06): https anywhere, plain http only to loopback, nothing else.
/// </summary>
public class SiemWebhookUrlTests
{
    [Theory]
    [InlineData("https://collector.example/ingest")]
    [InlineData("https://siem.internal:8443/http/log")]
    [InlineData("http://localhost:9099")]     // local dev/test receiver
    [InlineData("http://127.0.0.1:9099/x")]
    [InlineData("http://[::1]:9099")]
    public void Accepts_https_anywhere_and_http_to_loopback(string url)
        => SiemWebhookUrl.IsAcceptable(url, out _).Should().BeTrue();

    [Theory]
    [InlineData("http://collector.example/ingest")]   // cleartext token off-box
    [InlineData("ftp://host/x")]
    [InlineData("file:///etc/passwd")]
    [InlineData("not-a-url")]
    [InlineData("")]
    [InlineData(null)]
    public void Rejects_cleartext_remote_and_non_http_schemes(string? url)
    {
        SiemWebhookUrl.IsAcceptable(url, out var reason).Should().BeFalse();
        reason.Should().NotBeEmpty();
    }
}
