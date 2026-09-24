using System.Net;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Boots the real web host (Program.cs: DI registrations, startup migrate/seed, middleware) and serves a request.
/// Every other test builds services by hand, so none of them noticed when a dependency-injection cycle deadlocked
/// startup — twice, via the role directory (it loads through a DbContext whose audit interceptor needs the current
/// user, whose auth-state provider needed the directory). Everything runs under a timeout so a deadlock fails the
/// test instead of hanging the run. All data lives in a temp folder; the dev database and stores are never touched.
/// </summary>
public sealed class HostStartupSmokeTests : IDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(90);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "casebook-host-smoke", Guid.NewGuid().ToString("N"));

    private WebApplicationFactory<Program> Factory() => new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
    {
        b.UseEnvironment("Development");   // dev sign-in + demo seed, into the temp database below
        // UseSetting (not ConfigureAppConfiguration) so Program.cs sees these while it is still building services:
        // it reads the connection string for the DB-backed settings source before Build().
        b.UseSetting("ConnectionStrings:Default", $"Data Source={Path.Combine(_dir, "casebook.db")}");
        b.UseSetting("Database:Provider", "Sqlite");
        b.UseSetting("EvidenceStore:RootPath", Path.Combine(_dir, "evidence"));
        b.UseSetting("ReportOutput:RootPath", Path.Combine(_dir, "reports"));
        b.UseSetting("ReportBranding:RootPath", Path.Combine(_dir, "branding"));
        b.UseSetting("Integrity:SigningKeyPath", Path.Combine(_dir, "keys", "seal-signing.pem"));
        b.UseSetting("Integrity:ExportPath", Path.Combine(_dir, "seals"));
        b.UseSetting("Integrity:AutoSeal:Enabled", "false");
    });

    public HostStartupSmokeTests() => Directory.CreateDirectory(_dir);

    [Fact]
    public async Task The_app_starts_resolves_its_security_services_and_serves_requests()
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();

            var live = await client.GetAsync("/health/live");
            live.StatusCode.Should().Be(HttpStatusCode.OK);

            // The services whose construction formed the startup cycles, resolved as a request/circuit would.
            using var scope = factory.Services.CreateScope();
            var sp = scope.ServiceProvider;
            sp.GetRequiredService<AuthenticationStateProvider>().Should().NotBeNull();
            sp.GetRequiredService<ICurrentUser>().Should().NotBeNull();
            sp.GetRequiredService<IRoleDirectory>().IsRole("Analyst").Should().BeTrue("system roles are seeded at startup");
            sp.GetRequiredService<CaseService>().Should().NotBeNull();

            // A real page through the whole pipeline: dev sign-in, role → permission claims, [Authorize] policy.
            var page = await client.GetAsync("/cases");
            page.StatusCode.Should().Be(HttpStatusCode.OK);
        });
    }

    private static async Task RunWithin(TimeSpan limit, Func<Task> body)
    {
        var work = Task.Run(body);
        var finished = await Task.WhenAny(work, Task.Delay(limit));
        finished.Should().BeSameAs(work, $"the host should start and answer within {limit.TotalSeconds:0}s — a hang here is usually a DI cycle");
        await work;   // surface any exception from the body
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { }                   // SQLite may still hold the file briefly; it's a temp folder
        catch (UnauthorizedAccessException) { }
    }
}
