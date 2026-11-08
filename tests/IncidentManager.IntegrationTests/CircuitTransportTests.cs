using System.Security.Claims;
using AwesomeAssertions;
using IncidentManager.Web.Realtime;
using IncidentManager.Web.Services;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Http.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.SignalR;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Diagnostics' Browser connection: the transport the hub filter reads from SignalR's IHttpTransportFeature reaches the
/// circuit's tracker, the check is to see to when it isn't WebSockets (with the fix), and the counts since start-up.
/// </summary>
public class CircuitTransportTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 5, 9, 0, 0, TimeSpan.Zero);

    private sealed class FakeTransportFeature(HttpTransportType type) : IHttpTransportFeature
    {
        public HttpTransportType TransportType => type;
    }

    private sealed class FakeCallerContext(IFeatureCollection features) : HubCallerContext
    {
        public override string ConnectionId => "conn-1";
        public override string? UserIdentifier => "admin1";
        public override ClaimsPrincipal? User => null;
        public override IDictionary<object, object?> Items { get; } = new Dictionary<object, object?>();
        public override IFeatureCollection Features => features;
        public override CancellationToken ConnectionAborted => CancellationToken.None;
        public override void Abort() { }
    }

    private sealed class FakeHub : Hub
    {
        public static void StartCircuit() { }
    }

    private static HubInvocationContext Invocation(HttpTransportType? transport)
    {
        var features = new FeatureCollection();
        if (transport is { } t) features.Set<IHttpTransportFeature>(new FakeTransportFeature(t));
        return new HubInvocationContext(new FakeCallerContext(features), new NoServices(),
            new FakeHub(), typeof(FakeHub).GetMethod(nameof(FakeHub.StartCircuit))!, []);
    }

    private sealed class NoServices : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }

    // As Blazor's StartCircuit does: the circuit's handlers run in work the hub call starts and doesn't wait for.
    private static async Task ConnectAsync(CircuitTransportTracker tracker, HttpTransportType? transport)
    {
        Task? handlers = null;
        await new CircuitTransportHubFilter().InvokeMethodAsync(Invocation(transport), _ =>
        {
            handlers = Task.Run(() => tracker.OnConnectionUpAsync(null!, CancellationToken.None));
            return ValueTask.FromResult<object?>(null);
        });
        await handlers!;
    }

    [Theory]
    [InlineData(HttpTransportType.WebSockets)]
    [InlineData(HttpTransportType.ServerSentEvents)]
    [InlineData(HttpTransportType.LongPolling)]
    public async Task The_circuit_reports_the_transport_its_connection_uses(HttpTransportType transport)
    {
        var counts = new CircuitTransportCounts(new FixedClock(Now));
        var tracker = new CircuitTransportTracker(counts);

        await ConnectAsync(tracker, transport);

        tracker.Transport.Should().Be(transport);
        CircuitTransportHubFilter.Current.Should().BeNull("the transport is current only inside the hub call");
        var tally = counts.Snapshot();
        tally.Total.Should().Be(1);
        CircuitTransportDisplay.Rows(tally).Single(r => r.Count == 1).Label.Should().Be(CircuitTransportDisplay.Label(transport));
    }

    [Fact]
    public async Task A_reconnect_over_another_transport_is_shown_but_the_circuit_is_counted_once()
    {
        var counts = new CircuitTransportCounts(new FixedClock(Now));
        var tracker = new CircuitTransportTracker(counts);

        await ConnectAsync(tracker, HttpTransportType.WebSockets);
        await ConnectAsync(tracker, HttpTransportType.LongPolling);

        tracker.Transport.Should().Be(HttpTransportType.LongPolling);
        counts.Snapshot().Should().Be(new CircuitTransportTally(1, 0, 0, 0, Now));
    }

    [Fact]
    public async Task A_connection_without_a_transport_feature_is_counted_as_not_known()
    {
        var counts = new CircuitTransportCounts(new FixedClock(Now));
        var tracker = new CircuitTransportTracker(counts);

        await ConnectAsync(tracker, null);

        tracker.Transport.Should().BeNull();
        counts.Snapshot().Unknown.Should().Be(1);
        AdminHealth.TransportCheck(tracker.Transport).Ok.Should().BeTrue("a page that hasn't connected yet isn't flagged");
    }

    [Fact]
    public void Many_circuits_at_once_are_each_counted_under_their_transport()
    {
        var counts = new CircuitTransportCounts(new FixedClock(Now));
        Parallel.For(0, 3000, i => new CircuitTransportTracker(counts).Observe(
            (i % 3) switch { 0 => HttpTransportType.WebSockets, 1 => HttpTransportType.LongPolling, _ => HttpTransportType.ServerSentEvents }));

        var tally = counts.Snapshot();
        tally.Should().Be(new CircuitTransportTally(1000, 1000, 1000, 0, Now));
        tally.Fallback.Should().Be(2000);
    }

    [Fact]
    public void WebSockets_is_OK_and_nothing_else_is()
    {
        var ok = AdminHealth.TransportCheck(HttpTransportType.WebSockets);
        ok.Ok.Should().BeTrue();
        ok.Detail.Should().Be("WebSockets");
        ok.FixHref.Should().Be(AdminHealth.ConnectionAnchor);

        foreach (var (transport, label) in new[] { (HttpTransportType.LongPolling, "Long polling"), (HttpTransportType.ServerSentEvents, "Server-Sent Events") })
        {
            var check = AdminHealth.TransportCheck(transport);
            check.Ok.Should().BeFalse();
            check.Level.Should().Be(AttentionLevel.Warning, "Needs attention lists it as something to see to");
            check.Label.Should().Be("Browser connection");
            check.Detail.Should().StartWith(label + ", not WebSockets")
                .And.Contain("Install-WindowsFeature Web-WebSockets")
                .And.Contain("reverse proxy or load balancer passes the Upgrade and Connection headers");
            check.FixHref.Should().Be(AdminHealth.ConnectionAnchor);
        }
    }

    [Fact]
    public void The_counts_read_as_one_line_and_a_fallback_is_said()
    {
        var allWebSockets = new CircuitTransportTally(12, 0, 0, 0, Now);
        CircuitTransportDisplay.Summary(allWebSockets).Should().Be("WebSockets: 12");
        CircuitTransportDisplay.FallbackNote(allWebSockets).Should().BeNull();

        var none = new CircuitTransportTally(0, 0, 0, 0, Now);
        CircuitTransportDisplay.Summary(none).Should().Be("WebSockets: 0");

        var mixed = new CircuitTransportTally(1200, 0, 3, 1, Now);
        CircuitTransportDisplay.Summary(mixed).Should().Be("WebSockets: 1,200 · Long polling: 3 · Not known: 1");
        CircuitTransportDisplay.FallbackNote(mixed).Should().StartWith("3 circuits fell back from WebSockets.");
        CircuitTransportDisplay.FallbackNote(new CircuitTransportTally(0, 1, 0, 0, Now)).Should().StartWith("1 circuit fell back");
    }

    [Fact]
    public void Every_circuit_gets_a_tracker_as_its_circuit_handler_and_every_hub_the_filter()
    {
        // The registration, read from Program.cs as the deploy-script tests read the scripts.
        var program = File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "Program.cs"));
        program.Should().Contain("AddFilter<IncidentManager.Web.Realtime.CircuitTransportHubFilter>");
        program.Should().Contain("sp => sp.GetRequiredService<IncidentManager.Web.Realtime.CircuitTransportTracker>()");
        program.Should().Contain("AddSingleton<IncidentManager.Web.Realtime.CircuitTransportCounts>");
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }
}
