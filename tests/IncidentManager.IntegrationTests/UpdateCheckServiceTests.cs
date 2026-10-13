using System.Net;
using System.Text;
using FluentAssertions;
using IncidentManager.Web.Updates;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>PROD-49: the update check asks GitHub only when it's on, and turns every failure into "couldn't check".</summary>
public sealed class UpdateCheckServiceTests
{
    private const string TwoNewer = """
        [{"tag_name":"v1.6.1","draft":false,"prerelease":false,"body":"Fixes","html_url":"https://github.com/jashley92/CaseBook/releases/tag/v1.6.1","assets":[]},
         {"tag_name":"v1.6.0","draft":false,"prerelease":false,"body":"New","html_url":"https://github.com/jashley92/CaseBook/releases/tag/v1.6.0","assets":[]},
         {"tag_name":"v1.5.9","draft":false,"prerelease":false,"body":"Old","assets":[]}]
        """;

    private static (UpdateCheckService Service, StubHandler Handler) Make(
        bool enabled = true, Version? running = null, HttpStatusCode status = HttpStatusCode.OK, string body = TwoNewer,
        Exception? throws = null, string repository = "jashley92/CaseBook")
    {
        var handler = new StubHandler(status, body, throws);
        var service = new UpdateCheckService(new StubFactory(handler),
            new TestOptionsMonitor<UpdateCheckOptions>(new UpdateCheckOptions { CheckEnabled = enabled, Repository = repository }),
            NullLogger<UpdateCheckService>.Instance, running: running ?? new Version(1, 5, 9));
        return (service, handler);
    }

    [Fact]
    public async Task Newer_releases_are_available_newest_first()
    {
        var (svc, handler) = Make();

        var s = await svc.CheckAsync();

        s.State.Should().Be(UpdateState.Available);
        s.Releases.Select(r => r.Tag).Should().Equal("v1.6.1", "v1.6.0");
        svc.UpdateAvailable.Should().BeTrue();
        handler.Requests.Should().ContainSingle();
        handler.Requests[0].RequestUri!.ToString().Should().StartWith("https://api.github.com/repos/jashley92/CaseBook/releases");
        handler.Requests[0].Headers.UserAgent.ToString().Should().Contain("CaseBook");
        handler.Requests[0].Headers.Authorization.Should().BeNull("the check is anonymous");
    }

    [Fact]
    public async Task The_latest_release_is_up_to_date()
    {
        var (svc, _) = Make(running: new Version(1, 6, 1));
        (await svc.CheckAsync()).State.Should().Be(UpdateState.UpToDate);
    }

    [Fact]
    public async Task Turned_off_it_makes_no_request()
    {
        var (svc, handler) = Make(enabled: false);

        (await svc.CheckAsync()).State.Should().Be(UpdateState.Disabled);
        handler.Requests.Should().BeEmpty();
    }

    [Fact]
    public async Task A_development_build_makes_no_request()
    {
        // A local build reads 1.0.0 (no version stamped): nothing meaningful to compare.
        var handler = new StubHandler(HttpStatusCode.OK, TwoNewer, null);
        var svc = new UpdateCheckService(new StubFactory(handler),
            new TestOptionsMonitor<UpdateCheckOptions>(new UpdateCheckOptions { CheckEnabled = true }),
            NullLogger<UpdateCheckService>.Instance);

        (await svc.CheckAsync()).State.Should().Be(UpdateState.DevBuild);
        handler.Requests.Should().BeEmpty();
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, "rate-limiting")]
    [InlineData(HttpStatusCode.NotFound, "404")]
    public async Task A_refusal_is_couldnt_check(HttpStatusCode status, string reason)
    {
        var (svc, _) = Make(status: status);

        var s = await svc.CheckAsync();

        s.State.Should().Be(UpdateState.Failed);
        s.Problem.Should().Contain(reason);
        svc.UpdateAvailable.Should().BeFalse();
    }

    [Fact]
    public async Task An_unreachable_github_is_couldnt_check()
    {
        var (svc, _) = Make(throws: new HttpRequestException("no route"));
        (await svc.CheckAsync()).State.Should().Be(UpdateState.Failed);
    }

    [Fact]
    public async Task An_answer_that_isnt_releases_is_couldnt_check()
    {
        var (svc, _) = Make(body: """{"message":"Moved"}""");
        (await svc.CheckAsync()).Problem.Should().Contain("list of releases");
    }

    [Fact]
    public async Task A_bad_repository_setting_makes_no_request()
    {
        var (svc, handler) = Make(repository: "https://evil.example/x");

        (await svc.CheckAsync()).State.Should().Be(UpdateState.Failed);
        handler.Requests.Should().BeEmpty();
    }

    [Fact]
    public async Task A_failure_keeps_the_releases_an_earlier_check_found()
    {
        var handler = new StubHandler(HttpStatusCode.OK, TwoNewer, null);
        var svc = new UpdateCheckService(new StubFactory(handler),
            new TestOptionsMonitor<UpdateCheckOptions>(new UpdateCheckOptions { CheckEnabled = true }),
            NullLogger<UpdateCheckService>.Instance, running: new Version(1, 5, 9));
        await svc.CheckAsync();

        handler.Status = HttpStatusCode.InternalServerError;
        var s = await svc.CheckAsync();

        s.State.Should().Be(UpdateState.Failed);
        s.Releases.Should().HaveCount(2);
    }

    [Fact]
    public async Task Check_now_twice_in_a_minute_asks_once()
    {
        var (svc, handler) = Make();

        await svc.CheckAsync(manual: true);
        await svc.CheckAsync(manual: true);

        handler.Requests.Should().ContainSingle();
    }

    private sealed class StubFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class StubHandler(HttpStatusCode status, string body, Exception? throws) : HttpMessageHandler
    {
        public HttpStatusCode Status { get; set; } = status;
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            if (throws is not null) throw throws;
            return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }
}
