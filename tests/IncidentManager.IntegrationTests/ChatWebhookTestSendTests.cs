using System.Net;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Web.Notifications;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>The admin chat test reports why a post failed, while notification posts stay best-effort.</summary>
public sealed class ChatWebhookTestSendTests
{
    private static readonly ChatNotification Msg = new("Test", "Hello");

    private static ChatWebhookNotifier Notifier(HttpStatusCode status, string url = "https://hooks.example.com/abc") =>
        new(new StubFactory(status),
            new TestOptionsMonitor<ChatOptions>(new ChatOptions { Enabled = true, WebhookUrl = url, MaxAttempts = 1 }),
            new LiteralSecrets(), NullLogger<ChatWebhookNotifier>.Instance);

    [Fact]
    public async Task A_rejected_post_returns_the_status_as_the_reason()
    {
        var error = await Notifier(HttpStatusCode.Forbidden).SendTestAsync(Msg);
        error.Should().Contain("403");
    }

    [Fact]
    public async Task A_successful_post_returns_no_error()
    {
        (await Notifier(HttpStatusCode.OK).SendTestAsync(Msg)).Should().BeNull();
    }

    [Fact]
    public async Task A_plain_http_url_is_refused_with_a_reason()
    {
        var error = await Notifier(HttpStatusCode.OK, "http://hooks.example.com/abc").SendTestAsync(Msg);
        error.Should().Contain("https");
    }

    [Fact]
    public async Task Notification_posts_still_never_throw()
    {
        var act = () => Notifier(HttpStatusCode.InternalServerError).SendAsync(Msg);
        await act.Should().NotThrowAsync();
    }

    private sealed class LiteralSecrets : ISecretProvider
    {
        public ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default) => new(configuredValue);
    }

    private sealed class StubFactory(HttpStatusCode status) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new StubHandler(status));
    }

    private sealed class StubHandler(HttpStatusCode status) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(status));
    }
}
