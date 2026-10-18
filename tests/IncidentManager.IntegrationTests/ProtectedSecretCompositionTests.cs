using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Secrets;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-05 (ADR 0018): <c>@protected:</c> opens in front of whichever provider the site runs, CyberArk on or off, so every
/// secret that goes through <see cref="ISecretProvider"/> (the chat webhook URL, the SIEM webhook token, the SMTP password)
/// can be one; a <c>@cyberark:</c> reference still goes to CyberArk, and fails closed without it. Also: the bounded count
/// of held mail the Diagnostics card reads (CAP-04, C10).
/// </summary>
public sealed class ProtectedSecretCompositionTests : IDisposable
{
    private readonly X509Certificate2 _cert;
    private readonly byte[] _pfx;   // the lookup hands out a fresh copy each time (the caller disposes it)

    public ProtectedSecretCompositionTests()
    {
        using var rsa = RSA.Create(2048);
        using var made = new CertificateRequest("CN=CaseBook composition test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        _pfx = made.Export(X509ContentType.Pfx, "");
        _cert = X509CertificateLoader.LoadPkcs12(_pfx, "", X509KeyStorageFlags.EphemeralKeySet);
    }

    public void Dispose() => _cert.Dispose();

    private static string NewSecret() => "s-" + Guid.NewGuid().ToString("N");   // S2068

    private X509Certificate2 Copy(string thumbprint) =>
        string.Equals(thumbprint, CertificateLookup.Normalize(_cert.Thumbprint), StringComparison.Ordinal)
            ? X509CertificateLoader.LoadPkcs12(_pfx, "", X509KeyStorageFlags.EphemeralKeySet)
            : throw new InvalidOperationException("not here");

    private sealed class Ccp(string content) : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{{\"Content\":\"{content}\"}}", Encoding.UTF8, "application/json"),
            });
        }
    }

    [Fact]
    public async Task With_cyberark_on_both_kinds_resolve_and_a_protected_value_never_reaches_ccp()
    {
        var fromVault = NewSecret();
        var ccp = new Ccp(fromVault);
        using var cyberArk = new CyberArkCcpSecretProvider(ccp, Options.Create(new CyberArkOptions
        {
            Enabled = true, BaseUrl = "https://ccp.example/AIMWebService", AppId = "CaseBook",
        }), NullLogger<CyberArkCcpSecretProvider>.Instance, new SecretResolutionHealth(new FixedClock(DateTimeOffset.UtcNow)));
        var provider = new ProtectedSecretProvider(cyberArk, NullLogger<ProtectedSecretProvider>.Instance, Copy);
        var local = NewSecret();

        (await provider.ResolveAsync(ProtectedSecret.Protect(local, _cert))).Should().Be(local);
        ccp.Calls.Should().Be(0, "a protected value is opened here, with the certificate; CCP never sees it");
        (await provider.ResolveAsync("@cyberark:Safe=Mail;Object=Relay")).Should().Be(fromVault);
        ccp.Calls.Should().Be(1);
        (await provider.ResolveAsync("literal")).Should().Be("literal");
    }

    [Fact]
    public async Task With_cyberark_off_a_protected_value_resolves_and_a_reference_fails_closed()
    {
        var provider = new ProtectedSecretProvider(new PassthroughSecretProvider(NullLogger<PassthroughSecretProvider>.Instance),
            NullLogger<ProtectedSecretProvider>.Instance, Copy);
        var local = NewSecret();
        (await provider.ResolveAsync(ProtectedSecret.Protect(local, _cert))).Should().Be(local);
        (await provider.ResolveAsync("@cyberark:Safe=Mail;Object=Relay")).Should().BeNull();
    }

    [Fact]
    public void A_private_key_the_account_cant_read_fails_closed_rather_than_throwing()
    {
        // On Windows, reading a private key without the right to it throws ("Keyset does not exist") instead of
        // returning null; CAP-05 review S2.
        var value = ProtectedSecret.Protect(NewSecret(), _cert);
        ProtectedSecret.TryOpen(value, Copy, _ => throw new CryptographicException("Keyset does not exist"),
                out var secret, out var reason)
            .Should().BeFalse();
        secret.Should().BeNull();
        reason.Should().Contain("no RSA private key this account can read");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Every_caller_gets_the_composed_provider_either_way(bool cyberArk)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Secrets:CyberArk:Enabled"] = cyberArk ? "true" : "false",
            ["Secrets:CyberArk:BaseUrl"] = "https://ccp.example/AIMWebService",
        }).Build();
        var services = new ServiceCollection().AddLogging();
        services.AddInfrastructure(config);
        using var sp = services.BuildServiceProvider();
        sp.GetRequiredService<ISecretProvider>().Should().BeOfType<ProtectedSecretProvider>(
            "the chat webhook, the SIEM token and the SMTP password all resolve through it");
        sp.GetRequiredService<IDeliveryHealth>().Should().NotBeNull("CAP-04: always registered");
    }

    [Fact]
    public async Task The_held_mail_count_is_bounded_and_says_so_when_the_database_doesnt_answer()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"casebook-held-{Guid.NewGuid():N}.db");
        var services = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite($"Data Source={dbPath};Pooling=False")).BuildServiceProvider();
        try
        {
            var factory = services.GetRequiredService<IDbContextFactory<AppDbContext>>();
            await using (var db = await factory.CreateDbContextAsync())
            {
                await db.Database.EnsureCreatedAsync();
                var t0 = new DateTimeOffset(2026, 10, 18, 8, 0, 0, TimeSpan.Zero);
                for (var i = 0; i < 3; i++)
                    db.HeldEmails.Add(new IncidentManager.Domain.Entities.HeldEmail { Recipients = $"u{i}@example.test", Subject = "s", TextBody = "b", HeldAtUtc = t0.AddMinutes(i) });
                await db.SaveChangesAsync();
            }

            var summary = await HeldEmailSummary.ReadAsync(factory, HeldEmailSummary.DefaultLimit);
            summary.Should().Be(new HeldEmailSummary(3, false, new DateTimeOffset(2026, 10, 18, 8, 0, 0, TimeSpan.Zero), null));

            var late = await HeldEmailSummary.ReadAsync(factory, TimeSpan.Zero);
            late.Problem.Should().Contain("didn't answer", "a database that doesn't answer in time is said, not waited on");
        }
        finally
        {
            await services.DisposeAsync();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { File.Delete(dbPath); } catch (IOException) { /* best effort */ }
        }
    }
}
