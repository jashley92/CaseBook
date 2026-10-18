using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.ApiTokens;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-09, CAP-13 and CAP-14 through the real host (Program.cs): the IOC feeds and an import's status under <c>/api</c>,
/// signed in with an API token only (no token, a token without the permission, a revoked one), need-to-know scoped for the
/// token's owner, the 304 and <c>?since=</c> of a scheduled pull, the access log and SIEM 5304, the per-token rate limit,
/// and an import whose case id and detection case id disagree. All data lives in a temp folder, as in
/// <see cref="HostStartupSmokeTests"/>.
/// </summary>
public sealed class ApiEndpointTests : IDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(90);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "casebook-api-tests", Guid.NewGuid().ToString("N"));
    private readonly Sink _siem = new();

    private const string OpenIoc = "198.51.100.201", SecretIoc = "198.51.100.202", DrillIoc = "198.51.100.203";

    /// <summary>A thread-safe stand-in for the SIEM queue (requests run concurrently with the test).</summary>
    private sealed class Sink : ISecurityEventSink
    {
        public ConcurrentQueue<SecurityEvent> Events { get; } = new();
        public void Emit(SecurityEvent e) => Events.Enqueue(e);
    }

    public ApiEndpointTests() => Directory.CreateDirectory(_dir);

    private WebApplicationFactory<Program> Factory(params (string Key, string Value)[] settings) => new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
    {
        foreach (var (k, v) in settings) b.UseSetting(k, v);
        b.UseEnvironment("Development");
        b.UseSetting("ConnectionStrings:Default", $"Data Source={Path.Combine(_dir, "casebook.db")}");
        b.UseSetting("Database:Provider", "Sqlite");
        b.UseSetting("EvidenceStore:RootPath", Path.Combine(_dir, "evidence"));
        b.UseSetting("ReportOutput:RootPath", Path.Combine(_dir, "reports"));
        b.UseSetting("ReportBranding:RootPath", Path.Combine(_dir, "branding"));
        b.UseSetting("Integrity:SigningKeyPath", Path.Combine(_dir, "keys", "seal-signing.pem"));
        b.UseSetting("Integrity:ExportPath", Path.Combine(_dir, "seals"));
        b.UseSetting("Integrity:AutoSeal:Enabled", "false");
        b.ConfigureTestServices(s => s.AddSingleton<ISecurityEventSink>(_siem));
    });

    private static async Task<AppDbContext> DbAsync(IServiceScope scope) =>
        await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync();

    // Two custom roles beside the built-in ones: a feed reader (ViewCases only) and one that can't view cases.
    private static async Task SeedAsync(WebApplicationFactory<Program> factory)
    {
        using var scope = factory.Services.CreateScope();
        await using (var db = await DbAsync(scope))
        {
            var now = DateTimeOffset.UtcNow;
            db.Roles.Add(new Role { Name = "Feed reader", PermissionsCsv = "ViewCases", UpdatedAtUtc = now, UpdatedBy = "test" });
            db.Roles.Add(new Role { Name = "Legal clerk", PermissionsCsv = "ManageLegal", UpdatedAtUtc = now, UpdatedBy = "test" });
            Case Open(int seq, string slug, string ioc, bool restricted = false, bool exercise = false)
            {
                var c = Case.Open(2026, seq, slug, slug, Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1",
                    now.AddDays(-2), isExercise: exercise);
                c.IsRestricted = restricted;
                c.IncidentCommander = "commander-cap09";
                c.DetectionCaseId = "XS-" + seq;
                c.Entities.Add(new CaseEntity { Id = Guid.NewGuid(), CaseId = c.Id, Type = EntityType.IpAddress, Value = ioc,
                    Disposition = EntityDisposition.Malicious, CreatedAtUtc = now.AddDays(-2), CreatedBy = "ic1",
                    Tlp = restricted ? TlpLevel.Red : null });
                db.Cases.Add(c);
                return c;
            }
            Open(9001, "cap09-open", OpenIoc);
            Open(9002, "cap09-secret", SecretIoc, restricted: true);
            Open(9003, "cap09-drill", DrillIoc, exercise: true);
            await db.SaveChangesAsync();
        }
        scope.ServiceProvider.GetRequiredService<IRoleDirectory>().Invalidate();
    }

    private static async Task<string> TokenAsync(WebApplicationFactory<Program> factory, string slug, string roles, bool revoked = false)
    {
        var (plaintext, prefix, hash) = ApiTokenService.NewToken();
        using var scope = factory.Services.CreateScope();
        await using var db = await DbAsync(scope);
        var now = DateTimeOffset.UtcNow;
        db.ApiTokens.Add(new ApiToken
        {
            Name = slug, Kind = ApiTokenKind.System, OwnerUserId = "apitoken:" + slug, OwnerDisplayName = slug, RolesCsv = roles,
            TokenHash = hash, Prefix = prefix, CreatedBy = "test", CreatedAtUtc = now, ExpiresAtUtc = now.AddDays(30),
            RevokedAtUtc = revoked ? now : null, RevokedBy = revoked ? "test" : null,
        });
        await db.SaveChangesAsync();
        return plaintext;
    }

    private static HttpRequestMessage Get(string url, string? token, string? ifNoneMatch = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (token is not null) request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        if (ifNoneMatch is not null) request.Headers.TryAddWithoutValidation("If-None-Match", ifNoneMatch);
        return request;
    }

    [Fact]
    public async Task The_feeds_sign_in_by_token_only_and_hold_what_the_tokens_owner_may_see()
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            await SeedAsync(factory);
            var reader = await TokenAsync(factory, "firewall", "Feed reader");
            var cleared = await TokenAsync(factory, "tip", "IncidentCommander");
            var clerk = await TokenAsync(factory, "clerk", "Legal clerk");
            var revoked = await TokenAsync(factory, "old", "Feed reader", revoked: true);

            foreach (var url in new[] { "/api/export/iocs.csv", "/api/export/iocs.stix.json" })
            {
                // The development sign-in (or Windows, on a server) doesn't count here: only a token.
                (await client.SendAsync(Get(url, null))).StatusCode.Should().Be(HttpStatusCode.Unauthorized, url);
                (await client.SendAsync(Get(url, "cbk_not-a-real-token"))).StatusCode.Should().Be(HttpStatusCode.Unauthorized, url);
                (await client.SendAsync(Get(url, revoked))).StatusCode.Should().Be(HttpStatusCode.Unauthorized, url);
                (await client.SendAsync(Get(url, clerk))).StatusCode.Should().Be(HttpStatusCode.Forbidden, $"{url}: an API caller gets its 403, not a redirect");
            }

            var csv = await client.SendAsync(Get("/api/export/iocs.csv", reader));
            csv.StatusCode.Should().Be(HttpStatusCode.OK);
            csv.Content.Headers.ContentType!.MediaType.Should().Be("text/csv");
            var text = await csv.Content.ReadAsStringAsync();
            text.Should().StartWith("# CaseBook malicious-IOC feed").And.Contain(OpenIoc).And.NotContain(SecretIoc).And.NotContain(DrillIoc);
            csv.Headers.Contains("X-CaseBook-Truncated").Should().BeFalse();

            var all = await (await client.SendAsync(Get("/api/export/iocs.csv", cleared))).Content.ReadAsStringAsync();
            all.Should().Contain(OpenIoc).And.Contain($"ip,{SecretIoc},malicious,").And.Contain("TLP:RED").And.NotContain(DrillIoc);

            var stix = await client.SendAsync(Get("/api/export/iocs.stix.json", reader));
            stix.StatusCode.Should().Be(HttpStatusCode.OK);
            using var bundle = JsonDocument.Parse(await stix.Content.ReadAsStringAsync());
            bundle.RootElement.GetProperty("type").GetString().Should().Be("bundle");
            var values = bundle.RootElement.GetProperty("objects").EnumerateArray()
                .Where(o => o.TryGetProperty("value", out _)).Select(o => o.GetProperty("value").GetString()).ToList();
            values.Should().Contain(OpenIoc).And.NotContain(SecretIoc).And.NotContain(DrillIoc);

            // The access log and SIEM 5304, in the token's name.
            using var scope = factory.Services.CreateScope();
            await using var db = await DbAsync(scope);
            (await db.CaseAccessEvents.CountAsync(e => e.ActorUserId == "apitoken:firewall" && e.AccessType == AccessType.Export))
                .Should().Be(2);
            _siem.Events.Should().Contain(e => e.EventId == SecurityEventIds.DataExported && e.Actor == "apitoken:firewall"
                && e.Detail == "IOC feed (STIX, API)");
        });
    }

    [Fact]
    public async Task A_pull_that_would_get_the_same_feed_is_a_304_and_since_gives_a_delta()
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();
            await SeedAsync(factory);
            var token = await TokenAsync(factory, "edr", "Feed reader");

            var first = await client.SendAsync(Get("/api/export/iocs.csv", token));
            var tag = first.Headers.ETag!.ToString();
            tag.Should().StartWith("W/\"csv-");
            first.Headers.CacheControl!.NoCache.Should().BeTrue();

            var same = await client.SendAsync(Get("/api/export/iocs.csv", token, tag));
            same.StatusCode.Should().Be(HttpStatusCode.NotModified);
            (await same.Content.ReadAsByteArrayAsync()).Should().BeEmpty();
            (await client.SendAsync(Get("/api/export/iocs.csv", token, "\"something-else\", " + tag))).StatusCode.Should().Be(HttpStatusCode.NotModified);
            var stixTag = (await client.SendAsync(Get("/api/export/iocs.stix.json", token))).Headers.ETag!.ToString();
            stixTag.Should().StartWith("W/\"stix-");
            (await client.SendAsync(Get("/api/export/iocs.csv", token, stixTag))).StatusCode.Should().Be(HttpStatusCode.OK, "one format's tag isn't the other's");

            using (var scope = factory.Services.CreateScope())
            await using (var db = await DbAsync(scope))
            {
                (await db.CaseAccessEvents.CountAsync(e => e.ActorUserId == "apitoken:edr")).Should().Be(3, "a 304 sends nothing, so records nothing");
                var open = await db.Cases.SingleAsync(c => c.Title == "cap09-open");
                db.CaseEntities.Add(new CaseEntity { Id = Guid.NewGuid(), CaseId = open.Id, Type = EntityType.Domain, Value = "cap09-new.example",
                    Disposition = EntityDisposition.Malicious, CreatedAtUtc = DateTimeOffset.UtcNow, CreatedBy = "ic1" });
                await db.SaveChangesAsync();
            }
            var changed = await client.SendAsync(Get("/api/export/iocs.csv", token, tag));
            changed.StatusCode.Should().Be(HttpStatusCode.OK, "a new indicator is a new feed");
            changed.Headers.ETag!.ToString().Should().NotBe(tag);

            var since = Uri.EscapeDataString(DateTimeOffset.UtcNow.AddHours(-1).ToString("o"));
            var delta = await (await client.SendAsync(Get($"/api/export/iocs.csv?since={since}", token))).Content.ReadAsStringAsync();
            delta.Should().Contain("cap09-new.example").And.NotContain(OpenIoc).And.Contain("# Only indicators added or changed since");
            var later = await client.SendAsync(Get("/api/export/iocs.stix.json?since=2099-01-01T00:00:00Z", token));
            using (var bundle = JsonDocument.Parse(await later.Content.ReadAsStringAsync()))
                bundle.RootElement.GetProperty("objects").EnumerateArray().Count(o => o.TryGetProperty("value", out _)).Should().Be(0);

            var bad = await client.SendAsync(Get("/api/export/iocs.csv?since=last-tuesday", token));
            bad.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            (await bad.Content.ReadAsStringAsync()).Should().Contain("ISO 8601");
        });
    }

    [Fact]
    public async Task The_feed_is_rate_limited_per_token()
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory(("RateLimiting:ApiFeeds:TokenLimit", "2"), ("RateLimiting:ApiFeeds:TokensPerPeriod", "1"),
                ("RateLimiting:ApiFeeds:PeriodSeconds", "3600"));
            using var client = factory.CreateClient();
            await SeedAsync(factory);
            var busy = await TokenAsync(factory, "busy", "Feed reader");
            var other = await TokenAsync(factory, "other", "Feed reader");

            (await client.SendAsync(Get("/api/export/iocs.csv", busy))).StatusCode.Should().Be(HttpStatusCode.OK);
            (await client.SendAsync(Get("/api/export/iocs.stix.json", busy))).StatusCode.Should().Be(HttpStatusCode.OK);
            var refused = await client.SendAsync(Get("/api/export/iocs.csv", busy));
            refused.StatusCode.Should().Be(HttpStatusCode.TooManyRequests, "both formats share the token's budget");
            refused.Headers.RetryAfter.Should().NotBeNull();
            _siem.Events.Should().Contain(e => e.EventId == SecurityEventIds.DownloadRateLimited && e.Actor == "apitoken:busy");

            (await client.SendAsync(Get("/api/export/iocs.csv", other))).StatusCode.Should().Be(HttpStatusCode.OK, "each token has its own budget");
        });
    }

    [Fact]
    public async Task An_imports_sender_can_ask_what_became_of_it_and_a_conflicting_target_is_refused()
    {
        await RunWithin(Limit, async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            await SeedAsync(factory);
            var producer = await TokenAsync(factory, "xsiam", "Analyst");
            var reader = await TokenAsync(factory, "reader", "Feed reader");
            var revoked = await TokenAsync(factory, "gone", "Analyst", revoked: true);

            const string doc = """
                { "format": "casebook-case-import", "schemaVersion": 1, "origin": "XSIAM incident 9001",
                  "target": { "detectionCaseId": "XS-9001", "newCase": { "title": "Impossible travel" } },
                  "entities": [ { "value": "203.0.113.9", "disposition": "Malicious" } ] }
                """;
            using var post = new HttpRequestMessage(HttpMethod.Post, "/api/import/cases") { Content = new StringContent(doc, System.Text.Encoding.UTF8, "application/json") };
            post.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", producer);
            var created = await client.SendAsync(post);
            created.StatusCode.Should().Be(HttpStatusCode.Created);
            var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("pendingImportId").GetGuid();

            var status = await client.SendAsync(Get($"/api/import/cases/{id}", producer));
            status.StatusCode.Should().Be(HttpStatusCode.OK);
            var body = await status.Content.ReadFromJsonAsync<JsonElement>();
            body.GetProperty("status").GetString().Should().Be("pending");
            body.GetProperty("decidedAtUtc").ValueKind.Should().Be(JsonValueKind.Null);
            body.GetProperty("resolvedCaseNumber").ValueKind.Should().Be(JsonValueKind.Null);
            body.GetProperty("resolvedCaseId").ValueKind.Should().Be(JsonValueKind.Null);

            (await client.SendAsync(Get($"/api/import/cases/{id}", reader))).StatusCode.Should().Be(HttpStatusCode.NotFound, "not its own, and it reviews nothing");
            (await client.SendAsync(Get($"/api/import/cases/{Guid.NewGuid()}", producer))).StatusCode.Should().Be(HttpStatusCode.NotFound);
            (await client.SendAsync(Get($"/api/import/cases/{id}", null))).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            (await client.SendAsync(Get($"/api/import/cases/{id}", revoked))).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            (await client.SendAsync(Get("/api/import/cases/schema", null))).StatusCode.Should().Be(HttpStatusCode.OK, "the schema keeps its own route");

            // CAP-14: a case id and a detection case id that name different cases.
            Guid openId;
            using (var scope = factory.Services.CreateScope())
            await using (var db = await DbAsync(scope))
                openId = (await db.Cases.SingleAsync(c => c.Title == "cap09-open")).Id;
            var conflicting = doc.Replace("\"detectionCaseId\": \"XS-9001\"", $"\"caseId\": \"{openId}\", \"detectionCaseId\": \"XS-1234\"", StringComparison.Ordinal);
            using var bad = new HttpRequestMessage(HttpMethod.Post, "/api/import/cases") { Content = new StringContent(conflicting, System.Text.Encoding.UTF8, "application/json") };
            bad.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", producer);
            var refused = await client.SendAsync(bad);
            refused.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            (await refused.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString().Should().Contain("name different cases");
        });
    }

    private static async Task RunWithin(TimeSpan limit, Func<Task> body)
    {
        var work = Task.Run(body);
        var finished = await Task.WhenAny(work, Task.Delay(limit));
        finished.Should().BeSameAs(work, $"the host should start and answer within {limit.TotalSeconds:0}s");
        await work;
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { }                   // SQLite may still hold the file briefly; it's a temp folder
        catch (UnauthorizedAccessException) { }
    }
}
