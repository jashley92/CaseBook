using System.Net;
using System.Net.Sockets;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Secrets;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Siem;
using IncidentManager.Web.BackgroundJobs;
using IncidentManager.Web.Siem;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>A fake transport that records the events it is asked to send.</summary>
internal sealed class FakeTransport : ISecurityEventTransport
{
    public string Name { get; init; } = "fake";
    public bool Enabled { get; set; } = true;
    public List<SecurityEvent> Sent { get; } = new();
    public Func<SecurityEvent, Task>? OnSend { get; init; }
    private readonly TaskCompletionSource _seen = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task Seen => _seen.Task;

    public Task SendAsync(SecurityEvent e, CancellationToken ct)
    {
        Sent.Add(e);
        _seen.TrySetResult();
        return OnSend?.Invoke(e) ?? Task.CompletedTask;
    }
}

public class SecurityEventQueueTests
{
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 24, 12, 0, 0, TimeSpan.Zero));

    private static SecurityEvent Sample() => new()
    {
        EventId = SecurityEventIds.CaseOpened, Category = "DataAccess", Action = "CaseOpen", Actor = "analyst1"
    };

    private SecurityEventQueue Queue(int capacity, params ISecurityEventTransport[] transports) =>
        new(transports, _clock, NullLogger<SecurityEventQueue>.Instance, capacity);

    [Fact]
    public void With_no_transport_enabled_emit_is_a_no_op()
    {
        var q = Queue(64, new FakeTransport { Enabled = false });
        q.Emit(Sample());
        q.Reader.TryRead(out _).Should().BeFalse();
    }

    [Fact]
    public void With_a_transport_enabled_it_stamps_time_and_host_and_queues()
    {
        var q = Queue(64, new FakeTransport { Enabled = true });
        q.Emit(Sample());

        q.Reader.TryRead(out var e).Should().BeTrue();
        e!.AtUtc.Should().Be(_clock.UtcNow);
        e.Host.Should().NotBeNullOrEmpty();
        e.App.Should().Be("CaseBook");
    }

    [Fact]
    public void A_full_queue_drops_without_blocking_or_throwing()
    {
        var q = Queue(16, new FakeTransport { Enabled = true }); // min capacity is 16
        for (var i = 0; i < 100; i++) q.Emit(Sample()); // beyond capacity, no draining

        var drained = 0;
        while (q.Reader.TryRead(out _)) drained++;
        drained.Should().Be(16); // bounded; excess dropped
    }
}

public class SyslogTransportTests
{
    [Fact]
    public async Task Sends_a_cef_datagram_over_udp()
    {
        using var listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)listener.Client.LocalEndPoint!).Port;

        var opts = new SiemSyslogOptions { Enabled = true, Host = "127.0.0.1", Port = port, Protocol = "Udp" };
        var transport = new SyslogTransport(new TestOptionsMonitor<SiemSyslogOptions>(opts),
            NullLogger<SyslogTransport>.Instance);
        transport.Enabled.Should().BeTrue();

        var receive = listener.ReceiveAsync();
        await transport.SendAsync(new SecurityEvent
        {
            EventId = SecurityEventIds.EvidenceDownloaded, Category = "DataAccess", Action = "EvidenceDownload",
            Actor = "analyst1", Host = "H", AtUtc = DateTimeOffset.UtcNow
        }, CancellationToken.None);

        var result = await receive.WaitAsync(TimeSpan.FromSeconds(5));
        var text = Encoding.UTF8.GetString(result.Buffer);
        text.Should().Contain("CEF:0|CaseBook|CaseBook|");
        text.Should().Contain("|5302|EvidenceDownload|");
        text.Should().StartWith("<"); // syslog priority prefix
    }

    [Fact]
    public void Disabled_or_host_less_transport_reports_not_enabled()
    {
        new SyslogTransport(new TestOptionsMonitor<SiemSyslogOptions>(new SiemSyslogOptions { Enabled = false }),
            NullLogger<SyslogTransport>.Instance).Enabled.Should().BeFalse();
        new SyslogTransport(new TestOptionsMonitor<SiemSyslogOptions>(new SiemSyslogOptions { Enabled = true, Host = "" }),
            NullLogger<SyslogTransport>.Instance).Enabled.Should().BeFalse();
    }
}

public class WebhookTransportTests
{
    private sealed class CapturingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Request = request;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public StubHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
    }

    [Fact]
    public async Task Posts_the_event_as_json_with_the_auth_header()
    {
        var opts = new SiemWebhookOptions
        {
            Enabled = true, Url = "https://siem.example/collector", Token = "secret-token",
            AuthHeader = "Authorization", AuthScheme = "Bearer"
        };
        var handler = new CapturingHandler();
        var transport = new WebhookTransport(new StubHttpClientFactory(handler),
            new TestOptionsMonitor<SiemWebhookOptions>(opts), Secrets(), NullLogger<WebhookTransport>.Instance);

        transport.Enabled.Should().BeTrue();
        await transport.SendAsync(new SecurityEvent
        {
            EventId = SecurityEventIds.EvidenceDownloaded, Category = "DataAccess", Action = "EvidenceDownload", Actor = "analyst1"
        }, CancellationToken.None);

        handler.Request!.Method.Should().Be(HttpMethod.Post);
        handler.Request.RequestUri!.ToString().Should().Be("https://siem.example/collector");
        handler.Request.Headers.Authorization!.Scheme.Should().Be("Bearer");
        handler.Request.Headers.Authorization.Parameter.Should().Be("secret-token");
        handler.Body.Should().Contain("\"eventId\":5302");
        handler.Body.Should().Contain("\"action\":\"EvidenceDownload\"");
    }

    [Fact]
    public void Disabled_or_url_less_transport_reports_not_enabled()
    {
        new WebhookTransport(new StubHttpClientFactory(new CapturingHandler()),
                new TestOptionsMonitor<SiemWebhookOptions>(new SiemWebhookOptions { Enabled = false }),
                Secrets(), NullLogger<WebhookTransport>.Instance)
            .Enabled.Should().BeFalse();

        new WebhookTransport(new StubHttpClientFactory(new CapturingHandler()),
                new TestOptionsMonitor<SiemWebhookOptions>(new SiemWebhookOptions { Enabled = true, Url = "" }),
                Secrets(), NullLogger<WebhookTransport>.Instance)
            .Enabled.Should().BeFalse();
    }

    // F-19: the transport now resolves its token through ISecretProvider; a passthrough returns literals
    // unchanged, so the existing literal-token assertions are unaffected.
    private static ISecretProvider Secrets() => new PassthroughSecretProvider(NullLogger<PassthroughSecretProvider>.Instance);
}

public class SecurityEventDispatcherTests
{
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 24, 12, 0, 0, TimeSpan.Zero));

    private SecurityEventQueue Queue(params ISecurityEventTransport[] transports) =>
        new(transports, _clock, NullLogger<SecurityEventQueue>.Instance, 256);

    [Fact]
    public async Task Fans_each_event_out_to_every_enabled_transport()
    {
        var a = new FakeTransport { Name = "a", Enabled = true };
        var b = new FakeTransport { Name = "b", Enabled = true };
        var off = new FakeTransport { Name = "off", Enabled = false };
        var queue = Queue(a, b, off);
        var dispatcher = new SecurityEventDispatcher(queue, new ISecurityEventTransport[] { a, b, off },
            NullLogger<SecurityEventDispatcher>.Instance);

        queue.Emit(new SecurityEvent { EventId = SecurityEventIds.CaseOpened, Category = "DataAccess", Action = "CaseOpen", Actor = "x" });

        await dispatcher.StartAsync(CancellationToken.None);
        await Task.WhenAll(a.Seen, b.Seen).WaitAsync(TimeSpan.FromSeconds(5));
        await dispatcher.StopAsync(CancellationToken.None);

        a.Sent.Should().ContainSingle().Which.EventId.Should().Be(SecurityEventIds.CaseOpened);
        b.Sent.Should().ContainSingle();
        off.Sent.Should().BeEmpty(); // disabled transport is skipped
    }

    [Fact]
    public async Task One_throwing_transport_does_not_stop_the_others()
    {
        var bad = new FakeTransport { Name = "bad", Enabled = true, OnSend = _ => throw new InvalidOperationException("boom") };
        var good = new FakeTransport { Name = "good", Enabled = true };
        var queue = Queue(bad, good);
        var dispatcher = new SecurityEventDispatcher(queue, new ISecurityEventTransport[] { bad, good },
            NullLogger<SecurityEventDispatcher>.Instance);

        queue.Emit(new SecurityEvent { EventId = SecurityEventIds.CaseOpened, Category = "DataAccess", Action = "CaseOpen", Actor = "x" });

        await dispatcher.StartAsync(CancellationToken.None);
        await good.Seen.WaitAsync(TimeSpan.FromSeconds(5)); // the good transport still delivered
        var stop = async () => await dispatcher.StopAsync(CancellationToken.None);
        await stop.Should().NotThrowAsync();

        good.Sent.Should().ContainSingle();
    }
}

public sealed class SecurityEventEmitSiteTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 24, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly CapturingSecurityEventSink _siem = new();

    public SecurityEventEmitSiteTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin];
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private sealed class NoOpNotifications : ICaseNotifications
    {
        public System.Threading.Tasks.Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string assigneeUserId, string assigneeDisplayName, IncidentManager.Domain.Enums.CaseAssignmentRole role, string assignedByUserId, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsOverdueAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.OverdueActionItem> items, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsDueSoonAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.DueSoonActionItem> items, int leadHours, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
    }

    private CaseService NewCaseService(AppDbContext db) =>
        new(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
                .UseSqlite(_connection)
                .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
                .Options),
            _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpNotifications(),
            new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(), _siem);

    [Fact]
    public async Task Placing_and_releasing_a_legal_hold_emit_5501_then_5502()
    {
        Guid id;
        using (var db = NewContext())
        {
            var c = Case.Open(2026, 1, "Alpha", "Alpha", Classification.Incident, Severity.Medium,
                CaseOrigin.InternalDetection, "sys", _clock.UtcNow);
            db.Cases.Add(c);
            await db.SaveChangesAsync();
            id = c.Id;
        }

        using (var db = NewContext())
        {
            var svc = NewCaseService(db);
            await svc.SetLegalHoldAsync(id, held: true);
            await svc.SetLegalHoldAsync(id, held: false);
        }

        _siem.Events.Should().ContainSingle(e => e.EventId == SecurityEventIds.LegalHoldPlaced);
        _siem.Events.Should().ContainSingle(e => e.EventId == SecurityEventIds.LegalHoldReleased);
    }

    public void Dispose() => _connection.Dispose();
}
