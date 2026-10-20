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

    // Every page with no route parameter, as a first visit prerenders it. The New case page once failed to prerender
    // ("The renderer does not have a component with ID …") and every first visit got the error page.
    private static readonly string[] Pages =
    [
        "/", "/access-log", "/account/access", "/account/api-tokens", "/account/keyboard", "/account/notifications",
        "/admin", "/admin/api-tokens", "/admin/config-bundle", "/admin/data-elements", "/admin/email-templates",
        "/admin/gates", "/admin/outcomes", "/admin/roles", "/admin/teams", "/admin/templates",
        "/cases", "/cases/import", "/cases/mine", "/cases/new", "/desk", "/exports", "/find", "/integrity",
        "/intel/attack", "/intel/campaigns", "/intel/indicators", "/program", "/program/due", "/program/improvement-actions",
        "/program/legal", "/program/report", "/program/team",
    ];

    [Fact]
    public async Task Every_page_prerenders_on_a_first_visit()
    {
        await RunWithin(TimeSpan.FromMinutes(4), async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            var failed = new List<string>();
            foreach (var path in Pages)
            {
                var r = await client.GetAsync(path);
                if (r.StatusCode != HttpStatusCode.OK && !(path == "/" && r.StatusCode == HttpStatusCode.Redirect))
                    failed.Add($"{path}: {(int)r.StatusCode}");
            }
            failed.Should().BeEmpty("each page renders on a first visit");
        });
    }

    // Every Administration destination in the rail, and every settings section, renders on a first visit; the pages that
    // moved send old links on; every settings group has a page of its own (none left on "Other").
    [Fact]
    public async Task Every_administration_page_renders_and_old_links_land_on_the_new_ones()
    {
        await RunWithin(TimeSpan.FromMinutes(4), async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            var hrefs = IncidentManager.Web.Components.Layout.AdminLayout.AllGroups.SelectMany(g => g.Items).Select(i => i.Href)
                .Concat(IncidentManager.Web.Components.Pages.Admin.Sections.Select(s => s.Href))
                .Distinct().ToList();
            var failed = new List<string>();
            foreach (var href in hrefs)
            {
                var r = await client.GetAsync("/" + href);
                if (r.StatusCode != HttpStatusCode.OK) failed.Add($"{href}: {(int)r.StatusCode}");
            }
            failed.Should().BeEmpty("each Administration page renders on a first visit");

            foreach (var (old, lands) in new[] { ("/admin/retention", "admin/settings/retention"), ("/admin/taxonomy", "admin/settings/taxonomy") })
            {
                var r = await client.GetAsync(old);
                r.StatusCode.Should().Be(HttpStatusCode.Redirect, old);
                r.Headers.Location!.ToString().Should().EndWith(lands, old);
            }
            var governance = await (await client.GetAsync("/admin/settings/governance")).Content.ReadAsStringAsync();
            governance.Should().Contain("Evidence storage", "the old Governance & security link opens Evidence storage");
        });
        IncidentManager.Web.Components.Pages.Admin.UnplacedSettingsGroups.Should().BeEmpty("every settings group has a page of its own");
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

            // PROD-59: carrying on an upload is guarded the same way (and is there: a refusal, not a 404).
            using var resume = new HttpRequestMessage(HttpMethod.Post, "/evidence/uploads/abc/resume")
            {
                Content = new StringContent("""{"name":"a.bin","size":100}""", System.Text.Encoding.UTF8, "application/json"),
            };
            var resumeRefused = await client.SendAsync(resume);
            resumeRefused.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            (await resumeRefused.Content.ReadAsStringAsync()).Should().Contain("security token");

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
                // Classic zip encryption checks a password against one byte of its random header, so about one zip in 256
                // gets past it with a wrong password and reads as noise: either way, the file doesn't come out.
                string? read = null;
                try
                {
                    using var noise = wrong.GetInputStream(wrong[0]);
                    read = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(noise)).ToLowerInvariant();
                }
                catch (ICSharpCode.SharpZipLib.SharpZipBaseException) { /* refused (or, past the check, noise that won't inflate) */ }
                read.Should().NotBe(evidence.Sha256, "only the password opens it");
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
    public async Task An_evidence_package_downloads_once_as_a_zip_with_its_manifest_and_refuses_a_passive_load(/* CAP-12 */)
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            (await client.GetAsync("/health/live")).EnsureSuccessStatusCode();   // starts the host (and its demo seed)
            IncidentManager.Domain.Entities.Evidence evidence;
            using (var scope = factory.Services.CreateScope())
            {
                await using var db = await scope.ServiceProvider
                    .GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<IncidentManager.Infrastructure.Persistence.AppDbContext>>()
                    .CreateDbContextAsync();
                evidence = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.FirstAsync(db.Evidence);
            }
            // As the Evidence tab's "Prepare the package" leaves it, for the signed-in (development) user.
            var me = factory.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<IncidentManager.Web.Security.DevAuthOptions>>().Value.UserId;
            var ticket = factory.Services.GetRequiredService<IncidentManager.Application.Evidence.EvidencePackageTickets>().Stage(me, evidence.CaseId,
                [evidence.Id], new IncidentManager.Application.Evidence.EvidenceHandOver("Outside counsel", null, "Litigation hold"), DateTimeOffset.UtcNow);

            using (var asImage = new HttpRequestMessage(HttpMethod.Get, $"/evidence/package/{ticket}"))
            {
                asImage.Headers.Add("Sec-Fetch-Dest", "image");
                (await client.SendAsync(asImage)).StatusCode.Should().Be(HttpStatusCode.Forbidden, "and the ticket isn't spent");
            }
            var zipped = await client.GetAsync($"/evidence/package/{ticket}");
            zipped.StatusCode.Should().Be(HttpStatusCode.OK);
            zipped.Content.Headers.ContentType!.MediaType.Should().Be("application/zip");
            zipped.Headers.GetValues("Content-Security-Policy").Single().Should().StartWith("sandbox");
            await using var body = new MemoryStream(await zipped.Content.ReadAsByteArrayAsync());
            using (var zip = new ICSharpCode.SharpZipLib.Zip.ZipFile(body) { Password = "infected" })
            {
                zip.Cast<ICSharpCode.SharpZipLib.Zip.ZipEntry>().Select(e => e.Name).Should().Equal(
                    IncidentManager.Application.Evidence.EvidenceRisk.EntryName(evidence.OriginalFileName), "MANIFEST.txt");
                await using var inside = zip.GetInputStream(zip[0]);
                Convert.ToHexString(await System.Security.Cryptography.SHA256.HashDataAsync(inside)).ToLowerInvariant().Should().Be(evidence.Sha256);
            }
            (await client.GetAsync($"/evidence/package/{ticket}")).StatusCode.Should().Be(HttpStatusCode.NotFound, "a ticket downloads once");

            using var check = factory.Services.CreateScope();
            await using var ctx = await check.ServiceProvider
                .GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<IncidentManager.Infrastructure.Persistence.AppDbContext>>()
                .CreateDbContextAsync();
            ctx.Set<IncidentManager.Domain.Entities.ChainOfCustodyEvent>().Where(c => c.EvidenceId == evidence.Id && c.Action == "Transferred").ToList()
                .Should().ContainSingle().Which.Details.Should().Contain("To Outside counsel. Purpose: Litigation hold");
            // CAP-12 review: begun before the first byte, then sent in full.
            ctx.AuditLog.Where(a => a.EntityType == "EvidencePackage").OrderBy(a => a.Sequence).Select(a => a.Summary ?? "").ToList()
                .Should().SatisfyRespectively(b => b.Should().StartWith("Began sending"), s => s.Should().StartWith("Sent evidence package"));
            ctx.Set<IncidentManager.Domain.Entities.ChainOfCustodyEvent>().Count(c => c.EvidenceId == evidence.Id && c.Action == "Transfer begun")
                .Should().Be(1);
            ctx.CaseAccessEvents.Where(a => a.AccessType == IncidentManager.Domain.Enums.AccessType.EvidencePackage).ToList().Should().ContainSingle();
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

    [Fact]
    public async Task The_endpoints_iis_lets_through_anonymously_still_hold_their_own_line(/* CAP-37 */)
    {
        // The installer opens /health*, /branding/logo and /agenda/feed.ics to anonymous requests, so what each gives away
        // is the app's to decide: a status word, the logo or nothing, and a feed only for a valid signed token.
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory(("Agenda:FeedKey", Convert.ToBase64String(new byte[32])));
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

            foreach (var probe in new[] { "/health/live", "/health", "/health/ready" })
            {
                var answer = await client.GetAsync(probe);
                (await answer.Content.ReadAsStringAsync()).Should().BeOneOf(["Healthy", "Unhealthy", "Degraded"], $"{probe} gives the status word only");
            }

            (await client.GetAsync("/branding/logo")).StatusCode.Should().Be(HttpStatusCode.NotFound, "no logo is configured");

            (await client.GetAsync("/agenda/feed.ics")).StatusCode.Should().Be(HttpStatusCode.NotFound, "no token, no feed");
            (await client.GetAsync("/agenda/feed.ics?token=forged.token")).StatusCode.Should().Be(HttpStatusCode.NotFound);
        });
    }

    [Fact]
    public async Task The_retention_settings_reach_the_retention_job(/* batch-4 review B1 */)
    {
        // A lost line break once left this registration at the end of a comment: the job then ran on its defaults (3 years,
        // 90 days) whatever the administrator set, and deleted what they had asked to keep.
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory(("Retention:AccessLogYears", "0"), ("Retention:DecidedImportDays", "0"));
            using var client = factory.CreateClient();
            var retention = factory.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<IncidentManager.Web.BackgroundJobs.RetentionOptions>>().CurrentValue;
            (retention.AccessLogYears, retention.DecidedImportDays).Should().Be((0, 0));
        });
    }

    [Fact]
    public async Task A_flood_of_probes_never_429s_readiness_only_the_alarms_word(/* CAP-37 review */)
    {
        // Behind a proxy every probe shares one address: a limited readiness probe would let anyone take the node out of
        // rotation. Only /health/alarms is limited.
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory(("RateLimiting:Health:TokenLimit", "2"), ("RateLimiting:Health:TokensPerPeriod", "1"),
                ("RateLimiting:Health:PeriodSeconds", "3600"));
            using var client = factory.CreateClient();
            for (var i = 0; i < 10; i++)
                foreach (var probe in new[] { "/health", "/health/ready", "/health/live" })
                    (await client.GetAsync(probe)).StatusCode.Should().NotBe(HttpStatusCode.TooManyRequests, probe);
            var alarms = new List<HttpStatusCode>();
            for (var i = 0; i < 4; i++) alarms.Add((await client.GetAsync("/health/alarms")).StatusCode);
            alarms.Should().Contain(HttpStatusCode.TooManyRequests, "the alarms word is still limited per address");
        });
    }

    [Fact]
    public async Task Alarms_say_degraded_with_no_detail_and_never_take_the_node_out_of_rotation(/* CAP-18 */)
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();
            (await client.GetAsync("/health/live")).EnsureSuccessStatusCode();
            var ready = (await client.GetAsync("/health")).StatusCode;

            var calm = await client.GetAsync("/health/alarms");
            calm.StatusCode.Should().Be(HttpStatusCode.OK);
            (await calm.Content.ReadAsStringAsync()).Should().Be("Healthy");

            factory.Services.GetRequiredService<IncidentManager.Application.Integrity.SealCopyStatus>()
                .Record("export folder", DateTimeOffset.UtcNow, @"Access to the path 'D:\CaseBook\seals' is denied.");

            var alarmed = await client.GetAsync("/health/alarms");
            alarmed.StatusCode.Should().Be(HttpStatusCode.OK, "a monitor reads the word; nothing reads it as the node being down");
            (await alarmed.Content.ReadAsStringAsync()).Should().Be("Degraded", "the word only: no source, path or error");
            (await client.GetAsync("/health")).StatusCode.Should().Be(ready, "readiness doesn't count alarms");
            (await client.GetAsync("/health/ready")).StatusCode.Should().Be(ready);
        });
    }

    [Fact]
    public async Task The_backup_manifest_downloads_as_json_is_access_logged_and_refuses_a_passive_load(/* CAP-19 */)
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();

            using var asImage = new HttpRequestMessage(HttpMethod.Get, "/export/backup-manifest.json");
            asImage.Headers.Add("Sec-Fetch-Dest", "image");
            (await client.SendAsync(asImage)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

            var manifest = await client.GetAsync("/export/backup-manifest.json");
            manifest.StatusCode.Should().Be(HttpStatusCode.OK);
            manifest.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
            using var doc = System.Text.Json.JsonDocument.Parse(await manifest.Content.ReadAsStringAsync());
            doc.RootElement.GetProperty("paths").EnumerateArray().Select(p => p.TryGetProperty("path", out var path) ? path.GetString() : null)
                .Should().Contain(Path.Combine(_dir, "evidence")).And.Contain(Path.Combine(_dir, "seals")).And.Contain(Path.Combine(_dir, "keys"));

            using var scope = factory.Services.CreateScope();
            await using var db = await scope.ServiceProvider
                .GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<IncidentManager.Infrastructure.Persistence.AppDbContext>>()
                .CreateDbContextAsync();
            db.CaseAccessEvents.AsEnumerable().Should().Contain(e => e.TargetLabel != null && e.TargetLabel.StartsWith("backup-manifest-"));
        });
    }

    [Fact]
    public async Task The_case_list_exports_as_csv_with_its_filters_and_a_held_search_never_in_the_url(/* CAP-17 */)
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();

            using var asImage = new HttpRequestMessage(HttpMethod.Get, "/export/cases.csv");
            asImage.Headers.Add("Sec-Fetch-Dest", "image");
            (await client.SendAsync(asImage)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

            var all = await client.GetAsync("/export/cases.csv?scope=all");
            all.StatusCode.Should().Be(HttpStatusCode.OK);
            all.Content.Headers.ContentType!.MediaType.Should().Be("text/csv");
            var rows = (await all.Content.ReadAsStringAsync()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
            rows[1].Should().StartWith("case_number,title,");
            rows.Length.Should().BeGreaterThan(2, "the demo cases are listed");

            var refs = factory.Services.GetRequiredService<IncidentManager.Web.Services.ExportSearchRefs>();
            var nothing = refs.Hold("S-1-5-21-DEV-1001", "no case is called this " + Guid.NewGuid());
            var searched = await client.GetAsync($"/export/cases.csv?scope=all&qref={nothing}");
            searched.StatusCode.Should().Be(HttpStatusCode.OK);
            (await searched.Content.ReadAsStringAsync()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
                .Should().HaveCount(2, "the held search is applied: only the comment and the header");

            (await client.GetAsync("/export/cases.csv?qref=0123456789abcdef0123456789abcdef")).StatusCode.Should().Be(HttpStatusCode.Gone);

            using var scope = factory.Services.CreateScope();
            await using var db = await scope.ServiceProvider
                .GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<IncidentManager.Infrastructure.Persistence.AppDbContext>>()
                .CreateDbContextAsync();
            db.CaseAccessEvents.AsEnumerable().Should().Contain(e => e.TargetLabel != null && e.TargetLabel.StartsWith("cases-"));
        });
    }

    [Fact]
    public async Task The_indicators_export_as_csv_with_a_held_search_never_in_the_url(/* CAP-27 */)
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();

            using var asImage = new HttpRequestMessage(HttpMethod.Get, "/export/indicators.csv");
            asImage.Headers.Add("Sec-Fetch-Dest", "image");
            (await client.SendAsync(asImage)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

            var all = await client.GetAsync("/export/indicators.csv?type=all&exercises=true");
            all.StatusCode.Should().Be(HttpStatusCode.OK);
            all.Content.Headers.ContentType!.MediaType.Should().Be("text/csv");
            var fileName = all.Content.Headers.ContentDisposition!.FileName!.Trim('"');
            fileName.Should().MatchRegex(@"^indicators-\d{8}-\d{4}\.csv$");
            var rows = (await all.Content.ReadAsStringAsync()).TrimStart('﻿').Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
            rows[0].Should().StartWith("# CaseBook indicators");
            rows[1].Should().StartWith("type,indicator,worst_verdict,case_count,");
            rows.Length.Should().BeGreaterThan(2, "the demo cases' indicators are listed");

            var refs = factory.Services.GetRequiredService<IncidentManager.Web.Services.ExportSearchRefs>();
            var nothing = refs.Hold("S-1-5-21-DEV-1001", "no indicator is this " + Guid.NewGuid());
            var searched = await client.GetAsync($"/export/indicators.csv?type=all&qref={nothing}");
            searched.StatusCode.Should().Be(HttpStatusCode.OK);
            (await searched.Content.ReadAsStringAsync()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
                .Should().HaveCount(2, "the held search is applied: only the comment and the header");

            var someoneElses = refs.Hold("S-1-5-21-OTHER", "203.0.113.5");
            (await client.GetAsync($"/export/indicators.csv?qref={someoneElses}")).StatusCode.Should().Be(HttpStatusCode.Gone,
                "a reference is read back only for the person it was held for");

            using var scope = factory.Services.CreateScope();
            await using var db = await scope.ServiceProvider
                .GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<IncidentManager.Infrastructure.Persistence.AppDbContext>>()
                .CreateDbContextAsync();
            db.CaseAccessEvents.AsEnumerable().Should().Contain(e => e.TargetLabel != null && e.TargetLabel.StartsWith(fileName + " ("));
        });
    }

    [Fact]
    public async Task The_audit_and_access_log_csvs_stream_as_attachments_and_are_recorded(/* CAP-32 */)
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();
            foreach (var (url, prefix, header) in new[]
                     {
                         ("/export/audit.csv", "audit-trail-", "sequence,at_utc,"),
                         ("/export/access-log.csv", "access-log-", "actor,access_type,"),
                     })
            {
                using var asImage = new HttpRequestMessage(HttpMethod.Get, url);
                asImage.Headers.Add("Sec-Fetch-Dest", "image");
                (await client.SendAsync(asImage)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

                var response = await client.GetAsync(url);
                response.StatusCode.Should().Be(HttpStatusCode.OK);
                response.Content.Headers.ContentType!.MediaType.Should().Be("text/csv");
                var fileName = response.Content.Headers.ContentDisposition!.FileName!.Trim('"');
                fileName.Should().StartWith(prefix);
                var bytes = await response.Content.ReadAsByteArrayAsync();
                bytes[..3].Should().Equal(System.Text.Encoding.UTF8.GetPreamble(), "Excel reads it as UTF-8");
                System.Text.Encoding.UTF8.GetString(bytes).Split("\r\n")[1].Should().StartWith(header);

                using var scope = factory.Services.CreateScope();
                await using var db = await scope.ServiceProvider
                    .GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<IncidentManager.Infrastructure.Persistence.AppDbContext>>()
                    .CreateDbContextAsync();
                db.CaseAccessEvents.AsEnumerable().Should().Contain(e => e.TargetLabel != null && e.TargetLabel.StartsWith(fileName));
            }
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
