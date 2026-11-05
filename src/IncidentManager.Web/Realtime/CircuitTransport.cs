using IncidentManager.Application.Abstractions;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Http.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.SignalR;

namespace IncidentManager.Web.Realtime;

// Which SignalR transport carries each circuit. WebSockets is the one Blazor Server is built for. Server-Sent Events and
// long polling are what the browser falls back to when the WebSocket handshake fails: under IIS, the WebSocket Protocol
// feature isn't installed, system.webServer/webSocket is off, or a reverse proxy or load balancer drops the Upgrade
// header. Long polling then sends a request for every keystroke (many xhr "_blazor?id=" rows in the browser's Network
// tab). The transport is read from SignalR's own IHttpTransportFeature on the _blazor connection, never guessed from
// the browser.

/// <summary>
/// A hub filter on every hub, Blazor's own included. SignalR keeps the transport on the connection's features, which a
/// <see cref="CircuitHandler"/> can't reach, so each hub call (StartCircuit and ConnectCircuit among them) makes the
/// connection's transport current for the work it starts; <see cref="CircuitTransportTracker"/> reads it there.
/// </summary>
public sealed class CircuitTransportHubFilter : IHubFilter
{
    private static readonly AsyncLocal<HttpTransportType?> Flow = new();

    /// <summary>The transport of the hub call this code runs under, or null outside one.</summary>
    public static HttpTransportType? Current => Flow.Value;

    public async ValueTask<object?> InvokeMethodAsync(HubInvocationContext invocationContext,
        Func<HubInvocationContext, ValueTask<object?>> next)
    {
        // Set inside this async method, so it flows into the call (and what the call starts) and is gone after it.
        Flow.Value = Read(invocationContext.Context.Features);
        return await next(invocationContext);
    }

    /// <summary>The transport a connection's features name, or null when they don't (no transport chosen yet).</summary>
    public static HttpTransportType? Read(IFeatureCollection features) =>
        features.Get<IHttpTransportFeature>()?.TransportType is { } t && t != HttpTransportType.None ? t : null;
}

/// <summary>
/// One per circuit (scoped, and the circuit's <see cref="CircuitHandler"/>): the transport the circuit's connection uses
/// now, and a count of the circuit in <see cref="CircuitTransportCounts"/> the first time it connects.
/// </summary>
public sealed class CircuitTransportTracker(CircuitTransportCounts counts) : CircuitHandler
{
    private bool _counted;

    /// <summary>The transport of this circuit's connection, or null when it isn't known (before it connects).</summary>
    public HttpTransportType? Transport { get; private set; }

    public override Task OnConnectionUpAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        Observe(CircuitTransportHubFilter.Current);
        return Task.CompletedTask;
    }

    /// <summary>Takes the connection's transport; a reconnect can change it. The circuit is counted once.</summary>
    public void Observe(HttpTransportType? transport)
    {
        if (transport is not null) Transport = transport;
        if (_counted) return;
        _counted = true;
        counts.Record(transport);
    }
}

/// <summary>Circuits opened since start-up, by the transport each first connected over.</summary>
public sealed record CircuitTransportTally(long WebSockets, long ServerSentEvents, long LongPolling, long Unknown, DateTimeOffset SinceUtc)
{
    public long Total => WebSockets + ServerSentEvents + LongPolling + Unknown;

    /// <summary>Circuits that fell back from WebSockets.</summary>
    public long Fallback => ServerSentEvents + LongPolling;
}

/// <summary>The counts behind <see cref="CircuitTransportTally"/>, held in memory (a singleton) since start-up.</summary>
public sealed class CircuitTransportCounts(IClock clock)
{
    private readonly DateTimeOffset _since = clock.UtcNow;
    private long _webSockets;
    private long _serverSentEvents;
    private long _longPolling;
    private long _unknown;

    public void Record(HttpTransportType? transport)
    {
        switch (transport)
        {
            case HttpTransportType.WebSockets: Interlocked.Increment(ref _webSockets); break;
            case HttpTransportType.ServerSentEvents: Interlocked.Increment(ref _serverSentEvents); break;
            case HttpTransportType.LongPolling: Interlocked.Increment(ref _longPolling); break;
            default: Interlocked.Increment(ref _unknown); break;
        }
    }

    public CircuitTransportTally Snapshot() => new(
        Interlocked.Read(ref _webSockets), Interlocked.Read(ref _serverSentEvents),
        Interlocked.Read(ref _longPolling), Interlocked.Read(ref _unknown), _since);
}

/// <summary>How Diagnostics words a transport, and the fix when it isn't WebSockets.</summary>
public static class CircuitTransportDisplay
{
    public const string Fix =
        "Install the IIS WebSocket Protocol feature (Install-WindowsFeature Web-WebSockets), check that " +
        "system.webServer/webSocket isn't turned off for the site, and check any reverse proxy or load balancer passes " +
        "the Upgrade and Connection headers. deploy\\Verify-Install.ps1 -Url checks all three.";

    public static string Label(HttpTransportType? transport) => transport switch
    {
        HttpTransportType.WebSockets => "WebSockets",
        HttpTransportType.ServerSentEvents => "Server-Sent Events",
        HttpTransportType.LongPolling => "Long polling",
        _ => "Not known",
    };

    /// <summary>The since-start-up rows, in a fixed order: label and count.</summary>
    public static IReadOnlyList<(string Label, long Count)> Rows(CircuitTransportTally tally) =>
    [
        (Label(HttpTransportType.WebSockets), tally.WebSockets),
        (Label(HttpTransportType.ServerSentEvents), tally.ServerSentEvents),
        (Label(HttpTransportType.LongPolling), tally.LongPolling),
        (Label(null), tally.Unknown),
    ];

    /// <summary>"WebSockets: 12 · Long polling: 3": WebSockets always, the others when there were any.</summary>
    public static string Summary(CircuitTransportTally tally) =>
        string.Join(" · ", Rows(tally).Where((r, i) => i == 0 || r.Count > 0)
            .Select(r => r.Label + ": " + r.Count.ToString("N0", System.Globalization.CultureInfo.InvariantCulture)));

    /// <summary>What a fallback count says, or null when every circuit used WebSockets.</summary>
    public static string? FallbackNote(CircuitTransportTally tally) => tally.Fallback switch
    {
        0 => null,
        1 => "1 circuit fell back from WebSockets. When it's every browser, look at the server; when it's some, at what's between them and it (a proxy).",
        var n => $"{n:N0} circuits fell back from WebSockets. When it's every browser, look at the server; when it's some, at what's between them and it (a proxy).",
    };
}
