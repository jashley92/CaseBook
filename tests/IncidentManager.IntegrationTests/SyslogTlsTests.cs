using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure.Siem;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-33: syslog over TLS against an in-process TLS listener with a self-signed certificate. A collector this server
/// doesn't trust is refused (and the delivery card says why); one it trusts gets the event octet-counted (RFC 5425); a
/// pinned thumbprint refuses any other certificate, even a trusted one; a client certificate is presented when named;
/// a misconfiguration stops the transport with a reason; and the protocol is read by name, never by number.
/// </summary>
public sealed class SyslogTlsTests : IDisposable
{
    private readonly X509Certificate2 _server = SelfSigned("CN=localhost", serverAuth: true);
    private readonly X509Certificate2 _other = SelfSigned("CN=localhost", serverAuth: true);
    private readonly X509Certificate2 _client = SelfSigned("CN=casebook-client", serverAuth: false);
    private readonly DeliveryHealth _health = new(new FixedClock(DateTimeOffset.UtcNow));

    public void Dispose()
    {
        _server.Dispose();
        _other.Dispose();
        _client.Dispose();
    }

    // A self-signed certificate with its key persisted (SChannel can't use an ephemeral key), named localhost and 127.0.0.1.
    private static X509Certificate2 SelfSigned(string subject, bool serverAuth)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [serverAuth ? new Oid("1.3.6.1.5.5.7.3.1") : new Oid("1.3.6.1.5.5.7.3.2")], false));
        if (serverAuth)
        {
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("localhost");
            san.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(san.Build());
        }
        using var made = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return X509CertificateLoader.LoadPkcs12(made.Export(X509ContentType.Pfx), null);
    }

    /// <summary>One TLS connection's worth of collector: what it read, and the client certificate it was shown.</summary>
    private sealed class Collector : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        public int Port { get; }
        public Task<(byte[] Bytes, string? ClientThumbprint)> Received { get; }

        public Collector(X509Certificate2 certificate, bool askForClientCertificate = false)
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            Received = AcceptAsync(certificate, askForClientCertificate);
        }

        private async Task<(byte[], string?)> AcceptAsync(X509Certificate2 certificate, bool ask)
        {
            using var tcp = await _listener.AcceptTcpClientAsync();
            await using var ssl = new SslStream(tcp.GetStream(), false);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                ClientCertificateRequired = ask,
                RemoteCertificateValidationCallback = (_, cert, _, _) => cert is not null || !ask,   // the test reads what it was shown
            });
            var client = ssl.RemoteCertificate is { } c ? X509CertificateLoader.LoadCertificate(c.GetRawCertData()).Thumbprint : null;
            using var all = new MemoryStream();
            var buffer = new byte[4096];
            int n;
            try
            {
                while ((n = await ssl.ReadAsync(buffer)) > 0) all.Write(buffer, 0, n);
            }
            catch (IOException) { /* the client closed without close_notify: what arrived is what was sent */ }
            return (all.ToArray(), client);
        }

        public void Dispose() => _listener.Stop();
    }

    private static SecurityEvent Event() => new()
    {
        EventId = SecurityEventIds.EvidenceDownloaded, Category = "DataAccess", Action = "EvidenceDownload",
        Actor = "analyst1", Host = "H", AtUtc = DateTimeOffset.UtcNow,
    };

    private SyslogTransport Transport(SiemSyslogOptions o, bool trustTestRoot = true, Func<string, X509Certificate2>? findClient = null) =>
        new(new TestOptionsMonitor<SiemSyslogOptions>(o), NullLogger<SyslogTransport>.Instance, _health, findClient)
        {
            ExtraTrustedRoots = trustTestRoot ? [_server] : null,
        };

    private static SiemSyslogOptions Tls(int port) =>
        new() { Enabled = true, Host = "127.0.0.1", Port = port, Protocol = "Tls", TimeoutSeconds = 10 };   // the name its SAN carries

    private DeliveryChannelStatus Syslog => _health.Snapshot()[DeliveryHealth.Siem("syslog")];

    [Fact]
    public async Task A_trusted_collector_gets_the_event_octet_counted()
    {
        using var collector = new Collector(_server);
        var transport = Transport(Tls(collector.Port));
        transport.Enabled.Should().BeTrue();

        await transport.SendAsync(Event(), CancellationToken.None);

        var (bytes, _) = await collector.Received.WaitAsync(TimeSpan.FromSeconds(15));
        var text = Encoding.UTF8.GetString(bytes);
        var space = text.IndexOf(' ', StringComparison.Ordinal);
        var length = int.Parse(text[..space], System.Globalization.CultureInfo.InvariantCulture);
        length.Should().Be(bytes.Length - space - 1, "RFC 5425: MSG-LEN counts the octets of the message after the space");
        text[(space + 1)..].Should().StartWith("<").And.Contain("|5302|EvidenceDownload|").And.NotEndWith("\n");
        (Syslog.SuccessCount, Syslog.FailureCount).Should().Be((1, 0), "CAP-04: the delivery card counts it");
    }

    [Fact]
    public async Task A_collector_this_server_doesnt_trust_is_refused_and_the_card_says_why()
    {
        using var collector = new Collector(_server);
        var o = Tls(collector.Port);
        o.TimeoutSeconds = 2;   // the second send finds no collector listening for it, so it times out
        var transport = Transport(o, trustTestRoot: false);

        var error = await transport.SendTestAsync(Event(), CancellationToken.None);

        error.Should().Contain("isn't trusted by this server");
        Syslog.LastAttemptFailed.Should().BeTrue();
        Syslog.LastFailure.Should().Contain("isn't trusted", "the reason is safe to show: no certificate contents");
        await transport.SendAsync(Event(), CancellationToken.None);   // never throws
        Syslog.FailureCount.Should().Be(2);
    }

    [Fact]
    public async Task A_pinned_thumbprint_admits_only_that_certificate()
    {
        // SHA-1, pasted with spaces: accepted.
        using (var collector = new Collector(_server))
        {
            var pinned = Tls(collector.Port);
            pinned.ServerCertificateThumbprint = string.Join(' ', _server.Thumbprint.Chunk(2).Select(c => new string(c)));
            (await Transport(pinned).SendTestAsync(Event(), CancellationToken.None)).Should().BeNull();
            (await collector.Received.WaitAsync(TimeSpan.FromSeconds(15))).Bytes.Should().NotBeEmpty();
        }

        // SHA-256 of the right certificate: accepted.
        using (var collector = new Collector(_server))
        {
            var pinned = Tls(collector.Port);
            pinned.ServerCertificateThumbprint = _server.GetCertHashString(HashAlgorithmName.SHA256);
            (await Transport(pinned).SendTestAsync(Event(), CancellationToken.None)).Should().BeNull();
        }

        // Another certificate, trusted and correctly named, but not the pinned one: refused.
        using (var collector = new Collector(_other))
        {
            var pinned = Tls(collector.Port);
            pinned.ServerCertificateThumbprint = _server.Thumbprint;
            var transport = new SyslogTransport(new TestOptionsMonitor<SiemSyslogOptions>(pinned), NullLogger<SyslogTransport>.Instance,
                _health, null) { ExtraTrustedRoots = [_server, _other] };
            (await transport.SendTestAsync(Event(), CancellationToken.None)).Should().Contain("isn't the one pinned");
        }
    }

    [Fact]
    public async Task A_named_client_certificate_is_presented()
    {
        using var collector = new Collector(_server, askForClientCertificate: true);
        var o = Tls(collector.Port);
        o.ClientCertificateThumbprint = _client.Thumbprint.ToLowerInvariant();
        string? looked = null;
        var transport = Transport(o, findClient: t => { looked = t; return _client; });

        (await transport.SendTestAsync(Event(), CancellationToken.None)).Should().BeNull();

        looked.Should().Be(_client.Thumbprint, "looked up by its normalized thumbprint");
        (await collector.Received.WaitAsync(TimeSpan.FromSeconds(15))).ClientThumbprint.Should().Be(_client.Thumbprint);
    }

    // CAP-33 review: the certificate a re-read replaces was never disposed. It is now, but only once no send holds it.
    [Fact]
    public void A_client_certificate_replaced_on_the_re_read_is_disposed_once_no_send_holds_it()
    {
        var o = Tls(6514);
        o.ClientCertificateThumbprint = _client.Thumbprint;
        var read = new List<X509Certificate2>();
        var now = DateTimeOffset.UtcNow;
        var transport = new SyslogTransport(new TestOptionsMonitor<SiemSyslogOptions>(o), NullLogger<SyslogTransport>.Instance,
            _health, _ => { var c = SelfSigned("CN=casebook-client", serverAuth: false); read.Add(c); return c; })
        {
            Now = () => now,
        };

        var inFlight = transport.LeaseClientCertificate(o);   // a send under way presents the first one read
        inFlight.Certificate.Should().BeSameAs(read[0]);
        now += SyslogTransport.ClientCertificateRecheck + TimeSpan.FromSeconds(1);
        using (var next = transport.LeaseClientCertificate(o))
        {
            next.Certificate.Should().BeSameAs(read[1], "the store is read again after the recheck");
        }
        read[0].Handle.Should().NotBe(IntPtr.Zero, "the send under way still holds it");

        inFlight.Dispose();
        read[0].Handle.Should().Be(IntPtr.Zero, "the replaced certificate is disposed when its last send is done");
        inFlight.Dispose();   // once only
        read[1].Handle.Should().NotBe(IntPtr.Zero, "the current one stays, held by the cache");
        transport.Enabled.Should().BeTrue();
        read.Should().HaveCount(2);
        read[1].Dispose();
    }

    [Fact]
    public void A_misconfiguration_stops_the_transport_with_a_reason()
    {
        var missing = Tls(6514);
        missing.ClientCertificateThumbprint = new string('A', 40);
        var transport = Transport(missing, findClient: _ => throw new InvalidOperationException("No certificate with thumbprint AAAA in LocalMachine\\My."));
        transport.Enabled.Should().BeFalse();
        transport.Configured.Should().BeTrue("it's on, so the delivery card shows it");
        transport.StoppedReason.Should().StartWith("not sending: No certificate with thumbprint");

        var badPin = Tls(6514);
        badPin.ServerCertificateThumbprint = "not-a-thumbprint";
        Transport(badPin).StoppedReason.Should().Contain("ServerCertificateThumbprint isn't a SHA-1 or SHA-256 thumbprint");

        Transport(Tls(6514)).StoppedReason.Should().BeNull();
    }

    [Theory]
    [InlineData("Tls", true)]
    [InlineData("tls", true)]
    [InlineData(" Tcp ", true)]
    [InlineData("udp", true)]
    [InlineData("2", false)]
    [InlineData("-1", false)]
    [InlineData("Tcp,Tls", false)]
    [InlineData("Ssl", false)]
    public void The_protocol_is_read_by_name_only(string text, bool known)
    {
        SyslogTransport.TryParseProtocol(text, out _).Should().Be(known, "C16: a number or a list isn't a protocol");
        var o = new SiemSyslogOptions { Enabled = true, Host = "collector", Protocol = text };
        var transport = Transport(o);
        transport.Enabled.Should().Be(known);
        if (!known) transport.StoppedReason.Should().Contain("isn't Udp, Tcp or Tls");
    }

    [Fact]
    public async Task A_collector_that_never_answers_the_handshake_is_given_up_in_time()
    {
        // C10: a listener that accepts the connection and then says nothing holds the handshake; the one limit ends it.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var o = Tls(((IPEndPoint)listener.LocalEndpoint).Port);
            o.TimeoutSeconds = 1;
            var started = DateTimeOffset.UtcNow;
            var error = await Transport(o).SendTestAsync(Event(), CancellationToken.None);
            (DateTimeOffset.UtcNow - started).Should().BeLessThan(TimeSpan.FromSeconds(10));
            error.Should().Contain("in time");
            Syslog.LastFailure.Should().Be("timed out");
        }
        finally { listener.Stop(); }
    }
}
