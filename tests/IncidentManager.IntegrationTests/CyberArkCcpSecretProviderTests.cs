using System.Net;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Secrets;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// F-19: the CyberArk CCP provider fetches <c>@cyberark:</c> references over its HTTP transport (stubbed
/// here), passes literals through untouched, caches within the TTL, and fails closed on a CCP error or an
/// unsafe/misconfigured endpoint — never surfacing an exception or a reference string as if it were a secret.
/// </summary>
public sealed class CyberArkCcpSecretProviderTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public Uri? LastUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            LastUri = request.RequestUri;
            return Task.FromResult(responder(request));
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string json) =>
        new(code) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static CyberArkCcpSecretProvider Provider(StubHandler handler, Action<CyberArkOptions>? cfg = null,
        ISecretResolutionHealth? health = null)
    {
        var o = new CyberArkOptions
        {
            Enabled = true,
            BaseUrl = "https://ccp.example/AIMWebService",
            AppId = "App1",
            CacheTtlSeconds = 300
        };
        cfg?.Invoke(o);
        return new CyberArkCcpSecretProvider(handler, Options.Create(o),
            NullLogger<CyberArkCcpSecretProvider>.Instance,
            health ?? new SecretResolutionHealth(new FixedClock(DateTimeOffset.UtcNow)));
    }

    [Fact]
    public async Task Fetches_a_reference_and_builds_the_ccp_query()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "{\"Content\":\"s3cr3t\"}"));

        var value = await Provider(handler).ResolveAsync("@cyberark:Safe=SIEM;Object=CaseBook-Webhook");

        value.Should().Be("s3cr3t");
        handler.LastUri!.AbsolutePath.Should().EndWith("/api/Accounts");
        handler.LastUri.Query.Should()
            .Contain("AppID=App1").And
            .Contain("Safe=SIEM").And
            .Contain("Object=CaseBook-Webhook");
    }

    [Fact]
    public async Task Passes_a_literal_through_without_calling_ccp()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "{}"));

        (await Provider(handler).ResolveAsync("plain-token")).Should().Be("plain-token");
        handler.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Caches_within_the_ttl_so_ccp_is_hit_once()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "{\"Content\":\"s\"}"));
        var provider = Provider(handler);

        await provider.ResolveAsync("@cyberark:Safe=A;Object=B");
        await provider.ResolveAsync("@cyberark:Safe=A;Object=B");

        handler.Calls.Should().Be(1);
    }

    [Fact]
    public async Task Fails_closed_on_a_ccp_error()
    {
        var handler = new StubHandler(_ =>
            Json(HttpStatusCode.Forbidden, "{\"ErrorCode\":\"APPAP004E\",\"ErrorMsg\":\"denied\"}"));

        (await Provider(handler).ResolveAsync("@cyberark:Safe=A;Object=B")).Should().BeNull();
    }

    [Fact]
    public async Task Refuses_a_non_https_endpoint_without_calling_ccp()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "{\"Content\":\"s\"}"));

        var provider = Provider(handler, o => o.BaseUrl = "http://ccp.example/AIMWebService");

        (await provider.ResolveAsync("@cyberark:Safe=A;Object=B")).Should().BeNull();
        handler.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Records_the_last_success_in_health()
    {
        var health = new SecretResolutionHealth(new FixedClock(new DateTimeOffset(2026, 9, 10, 8, 0, 0, TimeSpan.Zero)));
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "{\"Content\":\"s3cr3t\"}"));

        await Provider(handler, health: health).ResolveAsync("@cyberark:Safe=SIEM;Object=Tok");

        var status = health.Current;
        status.SuccessCount.Should().Be(1);
        status.FailureCount.Should().Be(0);
        status.LastSuccessReference.Should().Be("@cyberark:Safe=SIEM;Object=Tok");
        status.LastSuccessUtc.Should().Be(new DateTimeOffset(2026, 9, 10, 8, 0, 0, TimeSpan.Zero));
        status.LastAttemptFailed.Should().BeFalse();
    }

    [Fact]
    public async Task Records_the_last_error_in_health_with_a_safe_reason()
    {
        var health = new SecretResolutionHealth(new FixedClock(new DateTimeOffset(2026, 9, 10, 9, 0, 0, TimeSpan.Zero)));
        var handler = new StubHandler(_ =>
            Json(HttpStatusCode.Forbidden, "{\"ErrorCode\":\"APPAP004E\",\"ErrorMsg\":\"denied\"}"));

        await Provider(handler, health: health).ResolveAsync("@cyberark:Safe=A;Object=B");

        var status = health.Current;
        status.FailureCount.Should().Be(1);
        status.LastAttemptFailed.Should().BeTrue();
        status.LastFailureReference.Should().Be("@cyberark:Safe=A;Object=B");
        status.LastFailureReason.Should().Contain("403").And.Contain("APPAP004E");
        status.LastFailureReason.Should().NotContain("s3cr3t"); // never the secret
    }

    [Fact]
    public async Task Serves_last_known_good_when_not_fail_closed_and_ccp_later_errors()
    {
        var ok = true;
        var handler = new StubHandler(_ => ok
            ? Json(HttpStatusCode.OK, "{\"Content\":\"good\"}")
            : Json(HttpStatusCode.InternalServerError, "{\"ErrorMsg\":\"down\"}"));
        // TTL 0 → clamped to 1s minimum, but we want an immediate re-fetch: use a fresh provider per call
        // isn't possible (cache is per-instance), so drive expiry by a tiny TTL and a short wait.
        var provider = Provider(handler, o => { o.FailClosed = false; o.CacheTtlSeconds = 1; });

        (await provider.ResolveAsync("@cyberark:Safe=A;Object=B")).Should().Be("good"); // caches good
        ok = false;
        await Task.Delay(1100);                                                          // expire the TTL

        // CCP now errors; FailClosed=false → serve the stale-but-real cached value, not null.
        (await provider.ResolveAsync("@cyberark:Safe=A;Object=B")).Should().Be("good");
    }
}
