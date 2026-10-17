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

    private WebApplicationFactory<Program> Factory(params (string Key, string Value)[] settings) => new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
    {
        foreach (var (k, v) in settings) b.UseSetting(k, v);
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

    [Fact]
    public async Task Downloads_refuse_a_passive_load_but_answer_a_request()
    {
        // BUG-186: an <img> or <script> pointing at a download is the browser's load, not the person's.
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();

            using var asImage = new HttpRequestMessage(HttpMethod.Get, "/export/iocs.csv");
            asImage.Headers.Add("Sec-Fetch-Dest", "image");
            (await client.SendAsync(asImage)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

            using var asDocument = new HttpRequestMessage(HttpMethod.Get, "/export/iocs.csv");
            asDocument.Headers.Add("Sec-Fetch-Dest", "document");
            (await client.SendAsync(asDocument)).StatusCode.Should().Be(HttpStatusCode.OK);

            // BUG-222: a frame, or a load another site starts, runs with the viewer's Windows sign-in too.
            using var asFrame = new HttpRequestMessage(HttpMethod.Get, "/export/iocs.csv");
            asFrame.Headers.Add("Sec-Fetch-Dest", "iframe");
            (await client.SendAsync(asFrame)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

            using var fromElsewhere = new HttpRequestMessage(HttpMethod.Get, "/export/iocs.csv");
            fromElsewhere.Headers.Add("Sec-Fetch-Dest", "document");
            fromElsewhere.Headers.Add("Sec-Fetch-Site", "cross-site");
            (await client.SendAsync(fromElsewhere)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

            using var typed = new HttpRequestMessage(HttpMethod.Get, "/export/iocs.csv");
            typed.Headers.Add("Sec-Fetch-Dest", "document");
            typed.Headers.Add("Sec-Fetch-Site", "none");
            (await client.SendAsync(typed)).StatusCode.Should().Be(HttpStatusCode.OK);

            (await client.GetAsync("/export/iocs.csv")).StatusCode.Should().Be(HttpStatusCode.OK);
        });
    }

    [Fact]
    public async Task Large_upload_parts_need_the_pages_token_and_refuse_passive_or_cross_site_loads(/* PROD-56 */)
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();
            const string begin = """{"caseId":"00000000-0000-0000-0000-000000000001","name":"a.bin","size":100}""";

            // Signed in, but no antiforgery token: another site's page can't start or feed an upload.
            using var noToken = new HttpRequestMessage(HttpMethod.Post, "/evidence/uploads/")
            {
                Content = new StringContent(begin, System.Text.Encoding.UTF8, "application/json"),
            };
            var refused = await client.SendAsync(noToken);
            refused.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            (await refused.Content.ReadAsStringAsync()).Should().Contain("security token");

            using var forged = new HttpRequestMessage(HttpMethod.Post, "/evidence/uploads/")
            {
                Content = new StringContent(begin, System.Text.Encoding.UTF8, "application/json"),
            };
            forged.Headers.Add("RequestVerificationToken", "not-a-token");
            (await client.SendAsync(forged)).StatusCode.Should().Be(HttpStatusCode.BadRequest);

            using var crossSite = new HttpRequestMessage(HttpMethod.Put, "/evidence/uploads/abc/0") { Content = new ByteArrayContent([1, 2, 3]) };
            crossSite.Headers.Add("Sec-Fetch-Site", "cross-site");
            (await client.SendAsync(crossSite)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        });
    }

    [Fact]
    public async Task The_safe_download_is_a_zip_that_opens_with_infected_and_holds_the_file_as_recorded(/* PROD-58 */)
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();
            (await client.GetAsync("/health/live")).EnsureSuccessStatusCode();   // starts the host (and its demo seed)
            IncidentManager.Domain.Entities.Evidence evidence;
            using (var scope = factory.Services.CreateScope())
            {
                await using var db = await scope.ServiceProvider
                    .GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<IncidentManager.Infrastructure.Persistence.AppDbContext>>()
                    .CreateDbContextAsync();
                evidence = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.FirstAsync(db.Evidence);
            }

            var zipped = await client.GetAsync($"/evidence/{evidence.Id}/safe");
            zipped.StatusCode.Should().Be(HttpStatusCode.OK);
            zipped.Content.Headers.ContentType!.MediaType.Should().Be("application/zip");
            zipped.Content.Headers.ContentDisposition!.FileNameStar.Should().Be(evidence.OriginalFileName + ".zip");
            zipped.Headers.GetValues("Content-Security-Policy").Single().Should().StartWith("sandbox");

            await using var body = new MemoryStream(await zipped.Content.ReadAsByteArrayAsync());
            using var zip = new ICSharpCode.SharpZipLib.Zip.ZipFile(body) { Password = "infected" };
            var entry = zip.Cast<ICSharpCode.SharpZipLib.Zip.ZipEntry>().Should().ContainSingle().Subject;
            entry.Name.Should().Be(evidence.OriginalFileName);
            entry.IsCrypted.Should().BeTrue();
            entry.AESKeySize.Should().Be(0, "classic zip encryption, which Windows Explorer opens");
            await using (var inside = zip.GetInputStream(entry))
            {
                var hash = Convert.ToHexString(await System.Security.Cryptography.SHA256.HashDataAsync(inside)).ToLowerInvariant();
                hash.Should().Be(evidence.Sha256, "the zip holds the file exactly as recorded");
            }
            using (var wrong = new ICSharpCode.SharpZipLib.Zip.ZipFile(new MemoryStream(body.ToArray())) { Password = "not-it" })
            {
                var open = () => wrong.GetInputStream(wrong[0]).ReadByte();
                open.Should().Throw<ICSharpCode.SharpZipLib.Zip.ZipException>("only the password opens it");
            }

            var plain = await client.GetAsync($"/evidence/{evidence.Id}");
            plain.Content.Headers.ContentType!.MediaType.Should().Be("application/octet-stream", "the uploader's claimed type is never sent back");
            plain.Headers.GetValues("Content-Security-Policy").Single().Should().StartWith("sandbox");

            using var check = factory.Services.CreateScope();
            await using var ctx = await check.ServiceProvider
                .GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<IncidentManager.Infrastructure.Persistence.AppDbContext>>()
                .CreateDbContextAsync();
            var custody = ctx.Set<IncidentManager.Domain.Entities.ChainOfCustodyEvent>().Where(c => c.EvidenceId == evidence.Id && c.Action == "Downloaded").ToList();
            custody.Should().Contain(c => c.Details == "in a zip with the password \"infected\"");
            custody.Should().Contain(c => c.Details == null, "the plain download is recorded as before");
        });
    }

    [Fact]
    public async Task Refused_passive_loads_dont_spend_the_download_budget(/* REV-61 */)
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory(("RateLimiting:Downloads:TokenLimit", "2"), ("RateLimiting:Downloads:TokensPerPeriod", "1"),
                ("RateLimiting:Downloads:PeriodSeconds", "3600"));
            using var client = factory.CreateClient();

            for (var i = 0; i < 5; i++)   // a page full of planted <img> tags
            {
                using var asImage = new HttpRequestMessage(HttpMethod.Get, "/export/iocs.csv");
                asImage.Headers.Add("Sec-Fetch-Dest", "image");
                (await client.SendAsync(asImage)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
            }

            (await client.GetAsync("/export/iocs.csv")).StatusCode.Should().Be(HttpStatusCode.OK, "the viewer's own download still has its budget");
            (await client.GetAsync("/export/iocs.csv")).StatusCode.Should().Be(HttpStatusCode.OK);
            (await client.GetAsync("/export/iocs.csv")).StatusCode.Should().Be(HttpStatusCode.TooManyRequests, "the budget itself still applies");
        });
    }

    [Fact]
    public async Task A_download_of_something_that_isnt_there_is_a_404(/* REV-64 */)
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            var id = Guid.NewGuid();

            (await client.GetAsync($"/evidence/{id}")).StatusCode.Should().Be(HttpStatusCode.NotFound);
            (await client.GetAsync($"/evidence/{id}/inline")).StatusCode.Should().Be(HttpStatusCode.NotFound, "an <img>, not the error page");
            (await client.GetAsync($"/reports/{id}")).StatusCode.Should().Be(HttpStatusCode.NotFound);
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
