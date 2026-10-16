using System.Net;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Web.Notifications;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-576: a chat webhook that isn't answering is backed off, so the posts made inline in assign, reclassify, mention
/// and handoff fail fast (and count as undelivered) instead of each waiting out its timeout and retries.
/// </summary>
public sealed class ChatWebhookCircuitTests
{
    private static readonly ChatNotification Msg = new("Case assigned", "2026-01");

    private sealed class LiteralSecrets : ISecretProvider
    {
        public ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default) => new(configuredValue);
    }

    private sealed class Hook(Func<HttpResponseMessage> answer) : HttpMessageHandler, IHttpClientFactory
    {
        public int Posts;
        public HttpClient CreateClient(string name) => new(this, disposeHandler: false);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Posts);
            return Task.FromResult(answer());
        }
    }

    private static ChatWebhookNotifier Notifier(Hook hook) =>
        new(hook, new TestOptionsMonitor<ChatOptions>(new ChatOptions { Enabled = true, WebhookUrl = "https://hooks.example.com/abc", MaxAttempts = 2 }),
            new LiteralSecrets(), NullLogger<ChatWebhookNotifier>.Instance, new OutboundCircuit());

    [Fact]
    public async Task After_the_webhook_stops_answering_posts_fail_fast_and_count_as_undelivered()
    {
        using var hook = new Hook(() => throw new HttpRequestException("connection refused"));
        var chat = Notifier(hook);

        using (var first = DeliveryWatch.Begin())
        {
            await chat.SendAsync(Msg);
            first.Failed.Should().BeTrue();
        }
        hook.Posts.Should().Be(2, "the first send makes its attempts");

        using (var second = DeliveryWatch.Begin())
        {
            await chat.SendAsync(Msg);
            second.Failed.Should().BeTrue("a scan's broadcast is tried again later");
        }
        hook.Posts.Should().Be(2, "nothing is posted while the webhook is backed off");

        (await chat.SendTestAsync(Msg)).Should().NotBeNull();
        hook.Posts.Should().BeGreaterThan(2, "the admin's test post always tries");
    }

    [Fact]
    public async Task A_webhook_that_answers_with_a_refusal_isnt_backed_off()
    {
        using var hook = new Hook(() => new HttpResponseMessage(HttpStatusCode.Forbidden));
        var chat = Notifier(hook);

        await chat.SendAsync(Msg);
        await chat.SendAsync(Msg);

        hook.Posts.Should().Be(4, "it answered, so it isn't hung: each post is still made");
    }

    [Fact]
    public async Task A_server_error_backs_the_webhook_off_and_a_good_test_post_ends_it()
    {
        var status = HttpStatusCode.ServiceUnavailable;
        using var hook = new Hook(() => new HttpResponseMessage(status));
        var chat = Notifier(hook);

        await chat.SendAsync(Msg);
        await chat.SendAsync(Msg);
        hook.Posts.Should().Be(2);

        status = HttpStatusCode.OK;
        (await chat.SendTestAsync(Msg)).Should().BeNull();
        using var watch = DeliveryWatch.Begin();
        await chat.SendAsync(Msg);
        watch.Failed.Should().BeFalse("the test post that went through ended the back-off");
    }
}
