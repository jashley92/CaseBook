using System.Net;
using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Config;
using IncidentManager.Application.Import;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Secrets;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Web.Notifications;
using IncidentManager.Web.Secrets;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-36: where a team's cases are told about and how a team travels. A chat post about a team's case goes to the team's own
/// webhook URL when one is saved (encrypted as CAP-40's secrets are), and to the shared channel otherwise; one that won't
/// decrypt isn't posted anywhere. A v2 import names a new case's team. A configuration bundle carries the teams but never
/// their members or webhook URL. Runs on SQLite and, when a server is configured, on SQL Server.
/// </summary>
public sealed class TeamRoutingTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _admin = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly CapturingSecurityEventSink _siem = new();

    public static TheoryData<string> Providers => TestDatabase.Providers;

    // S2068: made at run time, never a literal.
    private static string NewHookUrl() => "https://hooks.example.com/services/" + Guid.NewGuid().ToString("N");

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _admin, _clock, new CaseChangeNotifier()));

    private TeamService Teams(TestDatabase db) => new(db.Factory(), _admin, _clock, _siem);

    // The store as the host builds it: a singleton reading through a scoped context factory.
    private static (StoredSecretStore Store, ServiceProvider Services) Store(TestDatabase db, IDataProtectionProvider keys)
    {
        var services = new ServiceCollection().AddSingleton<IDbContextFactory<AppDbContext>>(new OptionsFactory(db.Options)).BuildServiceProvider();
        return (new StoredSecretStore(services.GetRequiredService<IServiceScopeFactory>(), keys, NullLogger<StoredSecretStore>.Instance), services);
    }

    private sealed class OptionsFactory(DbContextOptions<AppDbContext> options) : IDbContextFactory<AppDbContext>
    {
        public AppDbContext CreateDbContext() => new(options);
    }

    private sealed class RecordingAudit : IAuditWriter
    {
        public readonly List<string> Summaries = [];
        public Task RecordAsync(AuditAction action, string entityType, string? entityId, string? caseNumber, string summary, CancellationToken ct = default)
        {
            Summaries.Add($"{action} {entityType} {entityId} {summary}");
            return Task.CompletedTask;
        }
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public readonly List<Uri> Posted = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Posted.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class StubFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private static ChatWebhookNotifier Notifier(CapturingHandler handler, ChatOptions options, StoredSecretStore store) =>
        new(new StubFactory(handler), new TestOptionsMonitor<ChatOptions>(options),
            new PassthroughSecretProvider(NullLogger<PassthroughSecretProvider>.Instance), NullLogger<ChatWebhookNotifier>.Instance, stored: store);

    // --- Chat routing ---

    [Theory, MemberData(nameof(Providers))]
    public async Task A_post_about_a_teams_case_goes_to_the_teams_webhook_and_the_rest_to_the_shared_one(string provider)
    {
        using var db = Open(provider);
        var soc = await Teams(db).CreateAsync(new TeamEdit("SOC", null, null, []));
        var fraud = await Teams(db).CreateAsync(new TeamEdit("Fraud", null, null, []));
        var keys = new EphemeralDataProtectionProvider();
        var (store, services) = Store(db, keys);
        using var _ = services;
        var audit = new RecordingAudit();
        var webhooks = new TeamWebhookAdminService(store, services.GetRequiredService<IDbContextFactory<AppDbContext>>(), _admin, audit, _clock, _siem);
        var (teamUrl, sharedUrl) = (NewHookUrl(), NewHookUrl());
        var handler = new CapturingHandler();
        var chat = Notifier(handler, new ChatOptions { Enabled = true, WebhookUrl = sharedUrl, MaxAttempts = 1 }, store);

        await webhooks.SaveAsync(soc, teamUrl, expectedStamp: "");
        chat.RoutesTeam(soc).Should().BeTrue();
        chat.RoutesTeam(fraud).Should().BeFalse("no webhook of its own: the shared channel");

        await chat.SendAsync(new ChatNotification("Case assigned: 2026-01", "x", TeamId: soc));
        await chat.SendAsync(new ChatNotification("Case assigned: 2026-02", "x", TeamId: fraud));
        await chat.SendAsync(new ChatNotification("Case assigned: 2026-03", "x"));
        handler.Posted.Select(u => u.ToString()).Should().Equal(teamUrl, sharedUrl, sharedUrl);

        audit.Summaries.Should().ContainSingle().Which.Should().Contain("for the team \"SOC\" set").And.NotContain(teamUrl);
        await using (var ctx = db.NewContext())
        {
            var row = await ctx.StoredSecrets.AsNoTracking().SingleAsync();
            row.Name.Should().Be(StoredSecretStore.TeamWebhookName(soc));
            row.ProtectedValue.Should().NotContain("hooks.example.com", "kept as ciphertext only");
            (await ctx.AuditLog.AsNoTracking().AnyAsync(a => a.AfterJson != null && a.AfterJson.Contains("hooks.example.com")))
                .Should().BeFalse("the URL is never in the audit trail");
        }

        await webhooks.ClearAsync(soc, (await webhooks.GetAsync(soc)).Stamp);
        chat.RoutesTeam(soc).Should().BeFalse();
        await chat.SendAsync(new ChatNotification("Case assigned: 2026-04", "x", TeamId: soc));
        handler.Posted[^1].ToString().Should().Be(sharedUrl, "cleared: its posts go to the shared channel again");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_teams_webhook_that_wont_decrypt_here_isnt_posted_to_and_its_post_isnt_sent_to_the_shared_channel(string provider)
    {
        using var db = Open(provider);
        var soc = await Teams(db).CreateAsync(new TeamEdit("SOC", null, null, []));
        var (saving, savingServices) = Store(db, new EphemeralDataProtectionProvider());
        using (savingServices)
            await new TeamWebhookAdminService(saving, savingServices.GetRequiredService<IDbContextFactory<AppDbContext>>(), _admin,
                new RecordingAudit(), _clock).SaveAsync(soc, NewHookUrl());
        // A database restored on another server: its Data Protection keys aren't these.
        var (elsewhere, services) = Store(db, new EphemeralDataProtectionProvider());
        using var _ = services;
        var handler = new CapturingHandler();
        var chat = Notifier(handler, new ChatOptions { Enabled = true, WebhookUrl = NewHookUrl(), MaxAttempts = 1 }, elsewhere);

        var error = await chat.SendTestAsync(new ChatNotification("test", "x", TeamId: soc));

        error.Should().Contain("can't be decrypted");
        handler.Posted.Should().BeEmpty("fail closed: the team's cases may be meant for its channel only");
        (await elsewhere.TeamWebhookStatusAsync(soc, fresh: true)).Unreadable.Should().BeTrue();
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_team_webhook_is_refused_when_not_https_and_by_a_non_administrator(string provider)
    {
        using var db = Open(provider);
        var soc = await Teams(db).CreateAsync(new TeamEdit("SOC", null, null, []));
        var (store, services) = Store(db, new EphemeralDataProtectionProvider());
        using var _ = services;
        var factory = services.GetRequiredService<IDbContextFactory<AppDbContext>>();

        await new TeamWebhookAdminService(store, factory, _admin, new RecordingAudit(), _clock)
            .Invoking(w => w.SaveAsync(soc, "http://hooks.example.com/x")).Should().ThrowAsync<InvalidOperationException>().WithMessage("*https*");
        var analyst = new TestCurrentUser { UserId = "analyst1", RoleSet = [AppRole.Analyst] };
        await new TeamWebhookAdminService(store, factory, analyst, new RecordingAudit(), _clock, _siem)
            .Invoking(w => w.SaveAsync(soc, NewHookUrl())).Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
    }

    // --- The import field ---

    private CaseImportService Import(TestDatabase db) =>
        new(db.Factory(), _admin, _clock, new CaseService(db.Factory(), _admin, _clock, new CaseNumberGenerator(db.Factory()),
            new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(),
            new TestSlaTargets()));

    private CaseImportDocument Doc(string? team, int schemaVersion = 2) => new()
    {
        Format = CaseImportJson.FormatTag,
        SchemaVersion = schemaVersion,
        Origin = "XSIAM",
        Target = new CaseImportTarget { NewCase = new CaseImportNewCase { Title = "Beacon from a laptop", Severity = "High", Team = team } },
        Timeline = [new CaseImportTimelineEntry { OccurredAt = _clock.UtcNow.AddHours(-2), Description = "EDR alert." }],
    };

    private static CaseImportDocument Parsed(CaseImportDocument doc) =>
        CaseImportService.Parse(JsonSerializer.Serialize(doc, CaseImportJson.Options)).Document!;

    [Theory, MemberData(nameof(Providers))]
    public async Task A_v2_import_names_the_new_cases_team_by_key_or_name(string provider)
    {
        using var db = Open(provider);
        var soc = await Teams(db).CreateAsync(new TeamEdit("SOC tier 1", null, null, []));
        var retired = await Teams(db).CreateAsync(new TeamEdit("Old desk", null, null, []));
        await Teams(db).SetActiveAsync(retired, false, null);
        var import = Import(db);

        var byKey = await import.BuildPreviewAsync(Parsed(Doc("soctier1")));
        byKey.NewCase!.TeamId.Should().Be(soc);
        (await import.BuildPreviewAsync(Parsed(Doc("SOC TIER 1")))).NewCase!.TeamId.Should().Be(soc, "or by its name");

        var result = await import.ApplyAsync(byKey);
        await using (var ctx = db.NewContext())
            (await ctx.Cases.AsNoTracking().SingleAsync(c => c.Id == result.CaseId)).TeamId.Should().Be(soc);

        var unknown = await import.BuildPreviewAsync(Parsed(Doc("Nobody")));
        unknown.NewCase!.TeamId.Should().BeNull();
        unknown.Warnings.Should().Contain(w => w.Contains("\"Nobody\" isn't one CaseBook has"));
        var old = await import.BuildPreviewAsync(Parsed(Doc("OldDesk")));
        old.NewCase!.TeamId.Should().BeNull();
        old.Warnings.Should().Contain(w => w.Contains("retired"));
        var v1 = await import.BuildPreviewAsync(Parsed(Doc("SocTier1", schemaVersion: 1)));
        v1.NewCase!.TeamId.Should().BeNull();
        v1.Warnings.Should().Contain(w => w.Contains("team needs \"schemaVersion\": 2"));
        CaseImportSchema.V2NewCaseFields().Should().Contain("team");
    }

    // --- The configuration bundle ---

    private ConfigBundleService Bundles(TestDatabase db, RsaSealSigner signer) =>
        new(db.Factory(), signer, new AuditWriter(db.Factory(), _hasher, _admin, _clock), _admin, _clock);

    private ConfigBundleEnvelope Signed(RsaSealSigner signer, ConfigBundle bundle) => new(
        ConfigBundleJson.FormatTag, ConfigBundleJson.CurrentSchemaVersion, "test", _clock.UtcNow, _admin.UserId, "test-host",
        signer.Algorithm, signer.KeyId, signer.PublicKeyPem, signer.Sign(ConfigBundleJson.Canonicalize(bundle)), bundle);

    [Theory, MemberData(nameof(Providers))]
    public async Task A_bundle_carries_the_teams_but_never_their_members_or_webhook(string provider)
    {
        var dir = Path.Combine(Path.GetTempPath(), "im-team-bundle", Guid.NewGuid().ToString("N"));
        var signer = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(dir, "k.pem"), AllowKeyGeneration = true }));
        try
        {
            using var source = Open(provider);
            var soc = await Teams(source).CreateAsync(new TeamEdit("SOC tier 1", "EDR", "https://edr.example/case/{0}", ["analyst1"]));
            var (store, services) = Store(source, new EphemeralDataProtectionProvider());
            var hook = NewHookUrl();
            using (services)
                await new TeamWebhookAdminService(store, services.GetRequiredService<IDbContextFactory<AppDbContext>>(), _admin,
                    new RecordingAudit(), _clock).SaveAsync(soc, hook);

            var bundle = await Bundles(source, signer).BuildBundleAsync();
            bundle.Teams.Should().ContainSingle().Which.Should().Be(new ConfigTeam("SocTier1", "SOC tier 1", true, "EDR", "https://edr.example/case/{0}"));
            var json = ConfigBundleJson.Canonicalize(bundle);
            json.Should().NotContain(hook).And.NotContain("hooks.example.com").And.NotContain("analyst1", "people and the secret stay on their server");

            using var target = Open(provider);
            var first = await Bundles(target, signer).ImportAsync(Signed(signer, bundle));
            first.Added.Should().BeGreaterThan(0);
            await using (var ctx = target.NewContext())
            {
                var team = await ctx.Teams.AsNoTracking().SingleAsync();
                (team.Key, team.Name, team.DetectionSourceLabel, team.DetectionLinkTemplate).Should()
                    .Be(("SocTier1", "SOC tier 1", "EDR", "https://edr.example/case/{0}"));
                (await ctx.TeamMembers.AnyAsync()).Should().BeFalse("members don't travel");
                (await ctx.StoredSecrets.AnyAsync()).Should().BeFalse("nor the webhook URL");
            }
            (await Bundles(target, signer).PreviewAsync(bundle)).Changes.Should().BeEmpty("the same bundle again changes nothing");
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
}
