using IncidentManager.Application;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Web.BackgroundJobs;
using IncidentManager.Web.Components;
using IncidentManager.Web.Security;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

var builder = WebApplication.CreateBuilder(args);

// Don't advertise the server implementation.
builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

// --- Blazor Server ---
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// --- Data Protection ---
// The keyring protects antiforgery tokens and Blazor Server circuit state. By default it is ephemeral
// under an IIS app pool (no user profile / registry) so every recycle invalidates sessions. Persist it
// to a stable, ACL-restricted folder and encrypt at rest so keys survive restarts. A fixed application
// name keeps the ring stable if the content-root path ever changes. Dev (no path configured) keeps the
// framework default.
var dp = builder.Services.AddDataProtection().SetApplicationName("CaseBook");
var dpKeyPath = builder.Configuration["DataProtection:KeyPath"];
if (!string.IsNullOrWhiteSpace(dpKeyPath))
{
    // KeyPath is operator-supplied deployment config (not request input). Require an absolute path so a
    // misconfigured relative value can't silently place the keyring under the working directory, and so
    // the directory we create and persist to is canonical.
    if (!Path.IsPathRooted(dpKeyPath))
        throw new InvalidOperationException($"DataProtection:KeyPath must be an absolute path; got '{dpKeyPath}'.");
    var keyDir = Path.GetFullPath(dpKeyPath);
    Directory.CreateDirectory(keyDir);
    dp.PersistKeysToFileSystem(new DirectoryInfo(keyDir));
    // Machine-scope DPAPI works for a gMSA/app-pool identity with no loaded user profile. For stronger
    // separation (or a scaled-out farm) swap for ProtectKeysWithCertificate.
    if (OperatingSystem.IsWindows())
        dp.ProtectKeysWithDpapi(protectToLocalMachine: true);
}

// --- DB-backed operational settings layered over file/env config (A-08) ---
// Added last so administered overrides win over appsettings.json for the operational subset only.
// It reads its own connection from the already-loaded file config; on first run (pre-migration) it
// loads empty and is refreshed by a Reload() after the database is initialized below.
((Microsoft.Extensions.Configuration.IConfigurationBuilder)builder.Configuration).Add(
    new IncidentManager.Infrastructure.Configuration.DbSettingsConfigurationSource(
        builder.Configuration["Database:Provider"] ?? "Sqlite",
        builder.Configuration.GetConnectionString("Default") ?? "Data Source=App_Data/incidentmanager.db"));

// --- Application + Infrastructure ---
builder.Services.AddInfrastructure(builder.Configuration);
builder.Services.AddApplication();

// --- Scheduled audit-chain verify/seal job ---
builder.Services.Configure<AutoSealOptions>(builder.Configuration.GetSection("Integrity:AutoSeal"));
builder.Services.AddHostedService<IntegritySealHostedService>();

// --- F-17: periodic evidence-at-rest re-verification (re-hash stored bytes, alarm on drift) ---
builder.Services.Configure<EvidenceVerifyOptions>(builder.Configuration.GetSection("Integrity:EvidenceVerify"));
builder.Services.AddHostedService<EvidenceIntegrityHostedService>();

// --- E-03b: periodic overdue after-action scan (emails item owners a reminder, once per item) ---
builder.Services.Configure<OverdueScanOptions>(builder.Configuration.GetSection("Notifications:OverdueScan"));
builder.Services.AddHostedService<OverdueActionItemHostedService>();

// --- E-03d: periodic due-soon after-action scan (reminds owners ahead of the deadline, once per item) ---
builder.Services.Configure<DueSoonScanOptions>(builder.Configuration.GetSection("Notifications:DueSoonScan"));
builder.Services.AddHostedService<DueSoonActionItemHostedService>();

// --- PROD-37: periodic regulatory notification-deadline scan (reminds IC + assignees as a case's deadline
// approaches/passes, once per band). Also requires the deadline clock on; read-only, never mutates state. ---
builder.Services.Configure<DeadlineReminderScanOptions>(builder.Configuration.GetSection("Notifications:DeadlineScan"));
builder.Services.AddHostedService<NotificationDeadlineHostedService>();

// --- PROD-38: periodic stale-case nudge (open cases quiet past their severity threshold). Read-only, never
// mutates state; per-severity thresholds, off by default. ---
builder.Services.Configure<StaleCaseScanOptions>(builder.Configuration.GetSection("Notifications:StaleScan"));
builder.Services.AddHostedService<StaleCaseHostedService>();

// --- PROD-39: periodic consolidated work digest (one grouped email per opted-in user, on their cadence).
// Read-only, never mutates state; master switch off by default, per-user opt-in via the account menu. ---
builder.Services.Configure<DigestScanOptions>(builder.Configuration.GetSection("Notifications:DigestScan"));
builder.Services.AddHostedService<DigestHostedService>();

// --- F-18: outbound security-event stream. Transports fan out from a background dispatcher. ---
builder.Services.AddHttpClient("siem");
builder.Services.AddSingleton<IncidentManager.Infrastructure.Siem.ISecurityEventTransport, IncidentManager.Web.Siem.WebhookTransport>();
builder.Services.Configure<IncidentManager.Web.Siem.SiemEventLogOptions>(builder.Configuration.GetSection("Siem:EventLog"));
builder.Services.AddSingleton<IncidentManager.Infrastructure.Siem.ISecurityEventTransport, IncidentManager.Web.Siem.EventLogTransport>();
builder.Services.AddHostedService<IncidentManager.Web.BackgroundJobs.SecurityEventDispatcher>();

// --- PROD-02: team-chat (Slack/Teams) notification channel. Overrides the no-op default from Infrastructure. ---
builder.Services.AddHttpClient("chat");
builder.Services.AddSingleton<IncidentManager.Application.Abstractions.IChatNotifier, IncidentManager.Web.Notifications.ChatWebhookNotifier>();

// --- F-13: per-user rate limit on the download/export endpoints, so a compromised account can't bulk-
// scrape evidence/reports/exports. A token bucket keyed on the caller's id — bursts are fine, sustained
// volume is capped — with an immediate 429 (no queueing) past the budget. Limits are server-side config
// (RateLimiting:Downloads); a rejection is streamed to the SIEM (EventId 5306) and logged. ---
var downloadLimits = builder.Configuration.GetSection("RateLimiting:Downloads").Get<DownloadRateLimitOptions>()
    ?? new DownloadRateLimitOptions();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy("downloads", httpContext =>
    {
        var key = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)
                  ?? httpContext.User.FindFirstValue(ClaimTypes.Upn)
                  ?? httpContext.User.Identity?.Name
                  ?? "anonymous";
        return RateLimitPartition.GetTokenBucketLimiter(key, _ => new TokenBucketRateLimiterOptions
        {
            TokenLimit = downloadLimits.TokenLimit,
            TokensPerPeriod = downloadLimits.TokensPerPeriod,
            ReplenishmentPeriod = TimeSpan.FromSeconds(Math.Max(1, downloadLimits.PeriodSeconds)),
            QueueLimit = 0,                          // reject over-budget requests immediately (429), don't delay
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            AutoReplenishment = true
        });
    });

    options.OnRejected = (context, _) =>
    {
        var http = context.HttpContext;
        // F-18: stream the throttle as a security event (best-effort, non-blocking) and log it.
        http.RequestServices.GetService<ISecurityEventSink>()?.Emit(SecurityEvents.DownloadRateLimited(
            http.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? http.User.Identity?.Name ?? "anonymous",
            http.User.FindFirstValue(ClaimTypes.Upn),
            http.Request.Path.Value ?? ""));
        http.RequestServices.GetService<ILoggerFactory>()?.CreateLogger("Security.RateLimit")
            .LogWarning("Download rate limit reached for {Actor} on {Path}",
                http.User.Identity?.Name ?? "anonymous", http.Request.Path.Value);
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            http.Response.Headers.RetryAfter =
                ((int)retryAfter.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
        return ValueTask.CompletedTask;
    };
});

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUser, CurrentUser>();
builder.Services.AddScoped<IncidentManager.Web.Services.ToastService>();
// U-29: per-circuit on-screen time-zone display preference (UTC / local). Display-only; stored data
// and forensic artifacts stay UTC.
builder.Services.AddScoped<IncidentManager.Web.Services.TimeDisplay>();
// Lets the top-bar search pill open the hosted command palette (see CommandPaletteController).
builder.Services.AddScoped<IncidentManager.Web.Services.CommandPaletteController>();
// PROD-19: lets the open CaseWorkspace publish its action verbs to the hosted command palette.
builder.Services.AddScoped<IncidentManager.Web.Services.CaseCommandRegistry>();

// Live case-presence (U-01b): one tracker per circuit, also wired as the circuit handler so a
// closed/crashed tab's presence is cleaned up even if the component never disposes gracefully.
builder.Services.AddScoped<IncidentManager.Web.Realtime.PresenceCircuitTracker>();
builder.Services.AddScoped<Microsoft.AspNetCore.Components.Server.Circuits.CircuitHandler>(
    sp => sp.GetRequiredService<IncidentManager.Web.Realtime.PresenceCircuitTracker>());
builder.Services.AddScoped<IncidentManager.Web.Ops.BackupHealthReader>();
builder.Services.Configure<DevAuthOptions>(builder.Configuration.GetSection("DevAuth"));

// Idle-session timeout (F-15). Bound to the "Security" section; the value is administered in-app and
// layered over appsettings, so IOptionsSnapshot gives each new circuit the current effective duration.
builder.Services.Configure<IncidentManager.Web.Security.IdleTimeoutOptions>(
    builder.Configuration.GetSection("Security"));
builder.Services.Configure<IncidentManager.Application.Reporting.ReportingOptions>(
    builder.Configuration.GetSection("Reporting"));

// --- Authentication: Windows integrated in production, dev fallback locally ---
var authMode = builder.Configuration["Auth:Mode"] ?? "Dev";
var useWindows = string.Equals(authMode, "Windows", StringComparison.OrdinalIgnoreCase);

// Fail safe: never let the passwordless dev handler run in Production. A missing or mistyped
// Auth:Mode must stop startup, not silently authenticate everyone as an admin.
if (builder.Environment.IsProduction() && !useWindows)
{
    throw new InvalidOperationException(
        $"Auth:Mode is '{authMode}' in Production. Production requires Auth:Mode=Windows; " +
        "the development authentication handler must never be used outside Development.");
}

if (useWindows)
{
    builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate(options =>
    {
        // F-18: a failed Windows (Kerberos/NTLM) handshake is a security signal for the SIEM stream (5101).
        options.Events = new Microsoft.AspNetCore.Authentication.Negotiate.NegotiateEvents
        {
            OnAuthenticationFailed = ctx =>
            {
                ctx.HttpContext.RequestServices
                    .GetService<IncidentManager.Application.Security.ISecurityEventSink>()
                    ?.Emit(IncidentManager.Application.Security.SecurityEvents.AuthenticationFailed(ctx.Exception?.Message));
                return Task.CompletedTask;
            }
        };
    });
    builder.Services.AddScoped<Microsoft.AspNetCore.Authentication.IClaimsTransformation, RoleClaimsTransformer>();
}
else
{
    builder.Services.AddAuthentication(DevAuthenticationHandler.SchemeName)
        .AddScheme<AuthenticationSchemeOptions, DevAuthenticationHandler>(DevAuthenticationHandler.SchemeName, _ => { });
}

// PROD-34: the API-token scheme, registered in both auth modes. It does not change the default scheme —
// interactive requests still use Windows/Dev — endpoints opt into it via AuthenticationSchemes.
builder.Services.AddAuthentication()
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiKeyAuthenticationHandler.SchemeName, _ => { });

builder.Services.AddAuthorization(options =>
{
    foreach (var (policy, permission) in Policies.Required)
    {
        options.AddPolicy(policy, p =>
            p.RequireClaim(AppClaimTypes.Permission, permission.ToString()));
    }
    // Everything requires an authenticated user by default.
    options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
});
builder.Services.AddCascadingAuthenticationState();

// --- H-09: health/readiness probes for IIS / load balancer / uptime monitoring ---
// Two anonymous endpoints (mapped below): /health/live is a bare liveness signal (the process is up and
// serving), /health (readiness) additionally verifies DB connectivity and evidence-store reachability.
// Both return status only — no case data, no sensitive detail.
builder.Services.AddHealthChecks()
    .AddCheck<IncidentManager.Web.HealthChecks.DatabaseHealthCheck>("database", tags: ["ready"])
    .AddCheck<IncidentManager.Web.HealthChecks.EvidenceStoreHealthCheck>("evidence-store", tags: ["ready"]);

var app = builder.Build();

// X-02: wire the (global) taxonomy display-label provider into the static Ui helpers, so every
// Ui.Label(...) call site reflects an admin rename with no per-site change.
IncidentManager.Web.Components.Shared.Ui.UseTaxonomy(
    app.Services.GetRequiredService<IncidentManager.Application.Abstractions.ITaxonomyDisplay>());

// --- Ensure the local data directory exists (SQLite won't create it) ---
// Only the file-based provider (SQLite: dev/default) needs a writable App_Data under the content root.
// Production runs on SQL Server with every file store (evidence, reports, branding, keys, seals, dp-keys,
// ops) pointed at the ACL'd DataRoot, so the web root can stay fully read-only (H-07) — don't create a
// stray App_Data there.
if (!(app.Configuration.GetValue<string>("Database:Provider") ?? "Sqlite")
        .Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
    Directory.CreateDirectory(Path.Combine(app.Environment.ContentRootPath, "App_Data"));

// --- Initialize / migrate the database (and seed demo data outside production) ---
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var clock = scope.ServiceProvider.GetRequiredService<IClock>();
    await DevDataSeeder.InitializeAsync(db, clock, seedDemoData: app.Environment.IsDevelopment());

    // Seed system roles (from code) and migrate the file-based AD mapping into the DB on first run,
    // then prime the in-memory role directory so authentication resolves permissions immediately.
    var roleMapping = scope.ServiceProvider
        .GetRequiredService<Microsoft.Extensions.Options.IOptions<IncidentManager.Infrastructure.Security.RoleMappingOptions>>().Value;
    await IncidentManager.Infrastructure.Persistence.RoleSeeder.SeedAsync(db, clock, roleMapping);
    scope.ServiceProvider.GetRequiredService<IRoleDirectory>().Invalidate();

    // Prime the user directory mirror from any seeded/known users so ids resolve to names immediately.
    scope.ServiceProvider.GetRequiredService<IUserDirectory>().Invalidate();
}

// Now the schema exists, re-read the DB settings provider so any persisted operational overrides
// apply from the first request (its initial load may have run before the table existed).
(app.Configuration as Microsoft.Extensions.Configuration.IConfigurationRoot)?.Reload();

// S-02: the DB settings provider ignores any AppSettings row whose key is not an editable operational
// setting, so a tampered/injected row can never override server-side config (connection strings, auth
// mode, signing keys, the SIEM endpoint/token). Such a row can't be written through the audited
// AdminSettingsService — its presence is a tamper signal. Surface it once, post-reload: a Critical log
// line plus a non-blocking 5002 event on the SIEM stream.
{
    var rejectedKeys = IncidentManager.Infrastructure.Configuration.DbSettingsConfigurationProvider.RejectedKeys;
    if (rejectedKeys.Count > 0)
    {
        using var alertScope = app.Services.CreateScope();
        var logger = alertScope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Security.Settings");
        var sink = alertScope.ServiceProvider.GetService<IncidentManager.Application.Security.ISecurityEventSink>();
        foreach (var key in rejectedKeys)
        {
            logger.LogCritical(
                "Non-whitelisted setting override present in AppSettings and ignored on load: {Key}. " +
                "This row bypassed the audited settings write path — investigate for tampering.", key);
            sink?.Emit(IncidentManager.Application.Security.SecurityEvents.RejectedSettingOverride(key));
        }
    }
}

// --- HTTP pipeline ---
if (!app.Environment.IsDevelopment())
{
    // FR-12: on an unhandled exception, capture the correlation id and hand off to the branded /Error page
    // with it in the query string. The page renders interactively (Routes is InteractiveServer), so the
    // cascading HttpContext — and thus TraceIdentifier — is null there; passing the id via the query is the
    // reliable way to show a Request ID for support. Development still gets the developer exception page.
    app.UseExceptionHandler(errorApp => errorApp.Run(context =>
    {
        var id = System.Diagnostics.Activity.Current?.Id ?? context.TraceIdentifier;
        context.Response.Redirect($"/Error?ref={Uri.EscapeDataString(id)}");
        return Task.CompletedTask;
    }));
    app.UseHsts();
    app.UseHttpsRedirection();
}

// Friendly page for authenticated-but-unprovisioned users (U-28). A page's [Authorize(Policy)] is
// enforced at the Blazor endpoint, so a signed-in user with no mapped AD-group role gets a bare 403
// before any component renders (the <NotAuthorized> in Routes.razor never runs for endpoint denials).
// Turn that specific 403 into a redirect to /access-denied, which shows who they're signed in as and
// what to do. Scoped to page GETs: the Blazor circuit endpoints, non-GETs, and the target itself are
// left alone so we can't loop or disrupt the websocket.
app.UseStatusCodePages(context =>
{
    var http = context.HttpContext;
    if (http.Response.StatusCode == StatusCodes.Status403Forbidden
        && HttpMethods.IsGet(http.Request.Method)
        && !http.Request.Path.StartsWithSegments("/_blazor")
        && !http.Request.Path.StartsWithSegments("/access-denied"))
    {
        // F-18: stream the authorization denial (best-effort, non-blocking).
        var siem = http.RequestServices.GetService<IncidentManager.Application.Security.ISecurityEventSink>();
        siem?.Emit(IncidentManager.Application.Security.SecurityEvents.AuthorizationDenied(
            http.User?.Identity?.Name ?? "anonymous",
            http.User?.FindFirst(System.Security.Claims.ClaimTypes.Upn)?.Value,
            http.Request.Path.Value ?? ""));

        http.Response.Redirect("/access-denied");
    }
    return Task.CompletedTask;
});

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseStaticFiles();
app.UseAuthentication();
app.UseMiddleware<UserMirrorMiddleware>();
app.UseAuthorization();
app.UseAntiforgery();
// After auth so the limiter partitions per authenticated user (F-13).
app.UseRateLimiter();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// --- H-09: health probes (anonymous — the default FallbackPolicy would otherwise 401 the monitor) ---
// Liveness: process is up and the pipeline responds; runs no dependency checks.
app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();
// Readiness: DB + evidence-store reachable. The default response writer emits just the status word
// ("Healthy"/"Unhealthy") with 200/503 — no per-check names, paths, or exception detail.
var readyOptions = new HealthCheckOptions { Predicate = c => c.Tags.Contains("ready") };
app.MapHealthChecks("/health", readyOptions).AllowAnonymous();
app.MapHealthChecks("/health/ready", readyOptions).AllowAnonymous();

// E-03b: the deployment branding logo for branded emails. Anonymous — mail clients fetch it without a
// session, and it is only the org's branding image (no case data). 404 when no logo is configured.
app.MapGet("/branding/logo", async (IncidentManager.Application.Abstractions.IReportBrandingStore branding, CancellationToken ct) =>
{
    var logo = await branding.GetLogoAsync(ct);
    return logo is null ? Results.NotFound() : Results.File(logo.Bytes, logo.ContentType);
}).AllowAnonymous();

// --- E-39: agenda calendar (ICS) feeds ---
// Shared builder: the caller's due, open after-action items as an iCalendar document.
static async Task<string> BuildAgendaIcsAsync(
    IncidentManager.Application.Work.AgendaService agenda, IConfiguration cfg, IncidentManager.Application.Abstractions.IClock clock,
    string userId, CancellationToken ct)
{
    var items = await agenda.GetFeedItemsAsync(userId, ct);
    var baseUrl = (cfg["App:BaseUrl"] ?? "").TrimEnd('/');
    var events = items.Select(i => new IncidentManager.Application.Work.IcsEvent(
        Uid: $"{i.ActionItemId}@casebook",
        StartUtc: i.DueAtUtc!.Value,
        Summary: $"[{i.CaseNumber}] {i.Title}",
        Description: i.CaseTitle,
        Url: baseUrl.Length == 0 ? null : $"{baseUrl}/cases/{i.CaseId}",
        Overdue: i.DueAtUtc!.Value < clock.UtcNow));
    return IncidentManager.Application.Work.IcsWriter.Write("CaseBook — my after-action items", events, clock.UtcNow);
}

// Authenticated one-shot download for the signed-in user (import into any calendar).
app.MapGet("/agenda/agenda.ics", async (IncidentManager.Application.Work.AgendaService agenda,
    IncidentManager.Application.Abstractions.ICurrentUser user, IConfiguration cfg,
    IncidentManager.Application.Abstractions.IClock clock, CancellationToken ct) =>
{
    var ics = await BuildAgendaIcsAsync(agenda, cfg, clock, user.UserId, ct);
    return Results.File(System.Text.Encoding.UTF8.GetBytes(ics), "text/calendar", "casebook-agenda.ics");
}).RequireAuthorization(Policies.ViewCases);

// Subscribable live feed — token-authenticated (the token IS the credential), so anonymous. Disabled
// (404) until Agenda:FeedKey is configured; an invalid/forged token is also 404. Exposes only that user's
// own task titles + case numbers. Served inline so calendar clients can poll it.
app.MapGet("/agenda/feed.ics", async (string? token, IncidentManager.Application.Abstractions.IAgendaFeedTokens tokens,
    IncidentManager.Application.Work.AgendaService agenda, IConfiguration cfg,
    IncidentManager.Application.Abstractions.IClock clock, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(token) || !tokens.TryValidate(token, out var userId))
        return Results.NotFound();
    var ics = await BuildAgendaIcsAsync(agenda, cfg, clock, userId, ct);
    return Results.Text(ics, "text/calendar", System.Text.Encoding.UTF8);
}).AllowAnonymous().RequireRateLimiting("downloads");

// --- Evidence download (streamed, records a chain-of-custody event) ---
app.MapGet("/evidence/{id:guid}", async (Guid id, EvidenceService evidence,
    IncidentManager.Application.Access.IAccessLogService access, CancellationToken ct) =>
{
    var (item, stream) = await evidence.OpenAsync(id, recordDownload: true, ct);
    // C-05: record the sensitive-artifact access (best-effort, out of the tamper-evident chain).
    await access.RecordArtifactAsync(IncidentManager.Domain.Enums.AccessType.EvidenceDownload,
        item.CaseId, item.OriginalFileName, item.Id, ct);
    return Results.File(stream, item.ContentType, item.OriginalFileName);
}).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads");

// --- Inline evidence image (U-40): renders a linked screenshot as a timeline thumbnail ---
// Same need-to-know enforcement as the download (OpenAsync scopes to ForUser cases). Restricted to
// image/* so this can't be used to fetch arbitrary evidence unlogged; served INLINE (no attachment
// filename). Passive thumbnail views are deliberately NOT recorded — neither a C-05 access-log row nor
// (S-03) a chain-of-custody "Downloaded" event: opening the Timeline tab must not flood the access log
// or fabricate custody entries. The explicit Download button remains the logged, custody-recorded access.
app.MapGet("/evidence/{id:guid}/inline", async (Guid id, EvidenceService evidence, CancellationToken ct) =>
{
    var (_, stream) = await evidence.OpenAsync(id, recordDownload: false, ct);

    // S-04: this path renders bytes in the browser (no attachment disposition), so trust the ACTUAL
    // bytes, not the stored/client Content-Type. Sniff the header and serve only a genuine raster image,
    // with the sniffed type — an SVG (active content) or a mislabeled file is refused, so stored content
    // can't ride this endpoint as script even if the CSP were relaxed.
    var header = new byte[12];
    var read = await stream.ReadAsync(header, ct);
    var sniffed = IncidentManager.Application.Evidence.ImageSniffer.RasterContentType(header.AsSpan(0, read));
    if (sniffed is null || !stream.CanSeek)
    {
        await stream.DisposeAsync();
        return Results.NotFound();
    }
    stream.Position = 0; // rewind past the sniffed header before streaming the file
    return Results.File(stream, sniffed); // sniffed type, no download name => inline rendering
}).RequireAuthorization(Policies.ViewCases);

// --- Report download ---
app.MapGet("/reports/{id:guid}", async (Guid id, IncidentManager.Application.Reporting.ReportService reports,
    IncidentManager.Application.Access.IAccessLogService access, CancellationToken ct) =>
{
    var (report, stream) = await reports.OpenAsync(id, ct);
    await access.RecordArtifactAsync(IncidentManager.Domain.Enums.AccessType.ReportDownload,
        report.CaseId, report.FileName, report.Id, ct);
    var contentType = report.Format == IncidentManager.Domain.Enums.ReportFormat.Pdf
        ? "application/pdf"
        : "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    return Results.File(stream, contentType, report.FileName);
}).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads");

// --- E-07: per-case entity-graph export as a STIX 2.1 bundle (shareable investigation graph) ---
// Need-to-know scoped by the service (ForUser); 404 for a case the caller can't see. Audited as an Export
// (C-05) — case data leaving the system. Plain JSON attachment (no JS).
app.MapGet("/cases/{id:guid}/graph.stix.json", async (Guid id,
    IncidentManager.Application.Export.StixExportService stix,
    IncidentManager.Application.Access.IAccessLogService access, CancellationToken ct) =>
{
    var result = await stix.BuildAsync(id, ct);
    if (result is null) return Results.NotFound();
    var json = System.Text.Json.JsonSerializer.Serialize(result.Bundle,
        new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    var fileName = $"case-{result.CaseNumber}-graph.stix.json";
    await access.RecordArtifactAsync(IncidentManager.Domain.Enums.AccessType.Export, id, fileName, null, ct);
    return Results.File(System.Text.Encoding.UTF8.GetBytes(json), "application/json", fileName);
}).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads");

// --- Campaign rollup export (E-29): the cross-case rollup for the campaign a case belongs to, as JSON ---
// Need-to-know scoped by the service (ForUser walk); 404 for a case the caller can't see. Audited as an
// Export (C-05) — campaign data leaving the system. Plain JSON attachment (no JS).
app.MapGet("/campaigns/{id:guid}/rollup.json", async (Guid id,
    IncidentManager.Application.Campaigns.CampaignService campaigns,
    IncidentManager.Application.Access.IAccessLogService access, CancellationToken ct) =>
{
    var rollup = await campaigns.GetRollupAsync(id, ct);
    if (rollup is null) return Results.NotFound();
    var anchorNumber = rollup.Members.FirstOrDefault(m => m.CaseId == rollup.AnchorCaseId)?.CaseNumber
                       ?? rollup.AnchorCaseId.ToString();
    var json = System.Text.Json.JsonSerializer.Serialize(rollup,
        new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
        });
    var fileName = $"campaign-{anchorNumber}-rollup.json";
    await access.RecordArtifactAsync(IncidentManager.Domain.Enums.AccessType.Export, id, fileName, null, ct);
    return Results.File(System.Text.Encoding.UTF8.GetBytes(json), "application/json", fileName);
}).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads");

// --- Metrics export for board / regulatory reporting packs (E-11) ---
// Scoped to the caller's visible cases via DashboardService; plain CSV attachment (no JS).
app.MapGet("/export/metrics.csv", async (
    IncidentManager.Application.Dashboards.DashboardService dashboard,
    IncidentManager.Application.Access.IAccessLogService access,
    IClock clock, CancellationToken ct) =>
{
    var metrics = await dashboard.GetAsync(ct);
    var csv = IncidentManager.Application.Dashboards.MetricsCsv.Build(metrics, clock.UtcNow);
    var fileName = $"incident-metrics-{clock.UtcNow.UtcDateTime:yyyyMMdd-HHmm}.csv";
    await access.RecordArtifactAsync(IncidentManager.Domain.Enums.AccessType.Export, null, fileName, null, ct);
    return Results.File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", fileName);
}).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads");

// --- E-31: quarterly program-metrics report as a two-period CSV (board / exam packs). Need-to-know scoped by
// the service; access-logged and rate-limited like every export. ---
app.MapGet("/export/program-report.csv", async (
    int year, int quarter, bool? exercises,
    IncidentManager.Application.Dashboards.ProgramReportService program,
    IncidentManager.Application.Access.IAccessLogService access,
    IncidentManager.Application.Abstractions.ISeverityLabels sevLabels,
    CancellationToken ct) =>
{
    if (IncidentManager.Application.Dashboards.ProgramPeriod.TryCreate(year, quarter) is not { } period)
        return Results.BadRequest("Unknown quarter.");
    var report = await program.BuildAsync(period, exercises ?? false, ct);
    var csv = IncidentManager.Application.Dashboards.ProgramReportService.ToCsv(report,
        c => c switch { null => "Complex Event", IncidentManager.Domain.Enums.Classification.AdverseEvent => "Adverse Event", var x => x.ToString()! },
        sevLabels.For);
    var fileName = $"program-report-{period.Year}-Q{period.Quarter}.csv";
    await access.RecordArtifactAsync(IncidentManager.Domain.Enums.AccessType.Export, null, fileName, null, ct);
    return Results.File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", fileName);
}).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads");

// --- Improvement-action register (E-26/PROD-41): the cross-case follow-up register as CSV, honouring the
// page's scope + exercise filters (free-text search is deliberately not a URL parameter — it would land in
// request logs). Need-to-know scoped by LessonsService; access-logged like every export. Plain attachment.
app.MapGet("/export/improvement-actions.csv", async (
    string? scope, bool? exercises,
    IncidentManager.Application.Lessons.LessonsService lessons,
    IncidentManager.Application.Access.IAccessLogService access,
    IClock clock, CancellationToken ct) =>
{
    var filter = new IncidentManager.Application.Lessons.RegisterFilter(
        Enum.TryParse<IncidentManager.Application.Lessons.RegisterScope>(scope, ignoreCase: true, out var s)
            ? s : IncidentManager.Application.Lessons.RegisterScope.Open,
        null, exercises ?? false);
    var csv = await lessons.ExportRegisterCsvAsync(filter, ct);
    var fileName = $"improvement-actions-{clock.UtcNow.UtcDateTime:yyyyMMdd-HHmm}.csv";
    await access.RecordArtifactAsync(IncidentManager.Domain.Enums.AccessType.Export, null, fileName, null, ct);
    return Results.File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", fileName);
}).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads");

// --- Malicious-IOC blocklist feed (E-13): curated confirmed IOCs across the caller's visible cases ---
// Flat CSV to push to SIEM / firewalls / EDR — closes the detection loop. Need-to-know scoped by the
// service (joins to ForUser cases); ViewCases-gated like the metrics export. Plain attachment (no JS).
app.MapGet("/export/iocs.csv", async (
    IncidentManager.Application.Export.IocFeedService feed,
    IncidentManager.Application.Access.IAccessLogService access,
    IClock clock, CancellationToken ct) =>
{
    var rows = await feed.GetMaliciousIocsAsync(ct);
    var csv = IncidentManager.Application.Export.IocFeedCsv.Build(rows, clock.UtcNow);
    var fileName = $"malicious-iocs-{clock.UtcNow.UtcDateTime:yyyyMMdd-HHmm}.csv";
    await access.RecordArtifactAsync(IncidentManager.Domain.Enums.AccessType.Export, null, fileName, null, ct);
    return Results.File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", fileName);
}).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads");

// --- Per-case audit-trail export (E-24): the hash-chained trail for one case, filtered, as CSV ---
// Scoped: the caller must be able to view the case (need-to-know), mirroring the workspace Audit tab.
// UTC is the exported truth; `to` is inclusive to the end of that day. Plain attachment (no JS).
app.MapGet("/export/case-audit.csv", async (
    string? @case, string? actor, string? action, string? entity, string? from, string? to,
    IncidentManager.Application.Cases.CaseService cases, IncidentManager.Application.Integrity.IntegrityService integrity,
    IncidentManager.Application.Access.IAccessLogService access,
    IClock clock, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(@case) || !await cases.CanViewAsync(@case, ct))
        return Results.NotFound();

    var inv = System.Globalization.CultureInfo.InvariantCulture;
    var styles = System.Globalization.DateTimeStyles.None;

    var filter = new IncidentManager.Application.Integrity.AuditQueryFilter
    {
        CaseNumber = @case,
        Actor = string.IsNullOrWhiteSpace(actor) ? null : actor,
        Action = Enum.TryParse<IncidentManager.Domain.Enums.AuditAction>(action, out var a) ? a : null,
        EntityType = string.IsNullOrWhiteSpace(entity) ? null : entity,
        FromUtc = DateOnly.TryParse(from, inv, styles, out var fd)
            ? new DateTimeOffset(fd.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero) : null,
        ToUtc = DateOnly.TryParse(to, inv, styles, out var td)
            ? new DateTimeOffset(td.ToDateTime(TimeOnly.MaxValue), TimeSpan.Zero) : null
    };

    var rows = await integrity.QueryAsync(filter, take: 100_000, ct);
    var csv = IncidentManager.Application.Integrity.AuditCsv.Build(rows, clock.UtcNow, @case);
    var safe = @case.Replace('/', '-').Replace('\\', '-');
    var fileName = $"case-audit-{safe}-{clock.UtcNow.UtcDateTime:yyyyMMdd-HHmm}.csv";
    await access.RecordArtifactAsync(IncidentManager.Domain.Enums.AccessType.Export, null, fileName, null, ct);
    return Results.File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", fileName);
}).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads");

// --- Access-log export (C-05): the out-of-chain read/access telemetry, filtered, as CSV ---
// Administer-gated like the console; UTC times; `to` inclusive to end of day. Plain attachment (no JS).
app.MapGet("/export/access-log.csv", async (
    string? actor, string? @case, string? type, string? restricted, string? from, string? to,
    IncidentManager.Application.Access.IAccessLogService access, IClock clock, CancellationToken ct) =>
{
    var inv = System.Globalization.CultureInfo.InvariantCulture;
    var styles = System.Globalization.DateTimeStyles.None;

    var filter = new IncidentManager.Application.Access.AccessLogFilter
    {
        Actor = string.IsNullOrWhiteSpace(actor) ? null : actor,
        CaseNumber = string.IsNullOrWhiteSpace(@case) ? null : @case,
        AccessType = Enum.TryParse<IncidentManager.Domain.Enums.AccessType>(type, out var t) ? t : null,
        RestrictedOnly = string.Equals(restricted, "true", StringComparison.OrdinalIgnoreCase),
        FromUtc = DateOnly.TryParse(from, inv, styles, out var fd)
            ? new DateTimeOffset(fd.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero) : null,
        ToUtc = DateOnly.TryParse(to, inv, styles, out var td)
            ? new DateTimeOffset(td.ToDateTime(TimeOnly.MaxValue), TimeSpan.Zero) : null
    };

    var rows = await access.QueryAsync(filter, take: 100_000, ct);
    var csv = IncidentManager.Application.Access.AccessLogCsv.Build(rows, clock.UtcNow);
    var fileName = $"access-log-{clock.UtcNow.UtcDateTime:yyyyMMdd-HHmm}.csv";
    return Results.File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", fileName);
}).RequireAuthorization(Policies.Administer).RequireRateLimiting("downloads");

// --- Compliance evidence bundle (C-01): audit-chain segment + covering seals + verification, zipped ---
// Administer-gated: the package contains the whole cross-case audit record (including before/after
// values that can reference restricted-case fields), so it aligns with the existing integrity ops.
// The export is recorded in the audit trail by the service. Dates are yyyy-MM-dd (UTC); `to` inclusive.
app.MapGet("/export/compliance-bundle.zip", async (
    string? from, string? to,
    IncidentManager.Application.Compliance.ComplianceBundleService bundles,
    IncidentManager.Application.Access.IAccessLogService access,
    IClock clock, CancellationToken ct) =>
{
    var inv = System.Globalization.CultureInfo.InvariantCulture;
    var styles = System.Globalization.DateTimeStyles.None;
    var today = clock.UtcNow.UtcDateTime.Date;

    var fromDate = DateOnly.TryParse(from, inv, styles, out var fd)
        ? fd : new DateOnly(today.Year, 1, 1);           // default: start of the current year
    var toDate = DateOnly.TryParse(to, inv, styles, out var td)
        ? td : DateOnly.FromDateTime(today);             // default: today

    var fromUtc = new DateTimeOffset(fromDate.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero);
    var toUtc = new DateTimeOffset(toDate.ToDateTime(TimeOnly.MaxValue), TimeSpan.Zero); // inclusive end of day

    var bundle = await bundles.BuildAsync(fromUtc, toUtc, ct);
    await access.RecordArtifactAsync(IncidentManager.Domain.Enums.AccessType.Export, null, bundle.FileName, null, ct);
    return Results.File(bundle.Content, "application/zip", bundle.FileName);
}).RequireAuthorization(Policies.Administer).RequireRateLimiting("downloads");

// X-07: download the editable-configuration "seed pack" as a signed, versioned JSON bundle. The export
// is audited inside the service; SysAdmin-only like the other admin exports.
app.MapGet("/export/config-bundle.json", async (
    IncidentManager.Application.Config.ConfigBundleService config, CancellationToken ct) =>
{
    var export = await config.ExportAsync(ct);
    return Results.File(export.Content, "application/json", export.FileName);
}).RequireAuthorization(Policies.Administer).RequireRateLimiting("downloads");

// PROD-33: programmatic case import. A producer (an XSIAM/SOAR playbook, a script) POSTs a case-import
// document; it is validated and STAGED as a pending import for a human to review and confirm in CaseBook —
// the API never writes case state directly (the human gate). Requires EditCases (the caller authenticates as
// a principal in the right role); rate-limited like the exports. Converges with PROD-05.
app.MapPost("/api/import/cases", async (
    HttpRequest request,
    IncidentManager.Application.Import.CaseImportService import,
    CancellationToken ct) =>
{
    using var reader = new StreamReader(request.Body);
    var json = await reader.ReadToEndAsync(ct);

    var parsed = IncidentManager.Application.Import.CaseImportService.Parse(json);
    if (!parsed.Ok)
        return Results.BadRequest(new { error = parsed.Error });

    var (id, preview) = await import.SubmitAsync(json, parsed.Document!, ct);
    return Results.Created($"/cases/import?pending={id}", new
    {
        pendingImportId = id,
        status = "pending",
        message = "Accepted for review. A human must confirm this import in CaseBook before anything is written.",
        itemCount = preview.IncludedItemCount,
        warnings = preview.Warnings
    });
}).RequireAuthorization(new AuthorizeAttribute
{
    Policy = Policies.EditCases,
    AuthenticationSchemes = ApiKeyAuthenticationHandler.SchemeName
}).RequireRateLimiting("downloads");

// PROD-35: the machine-readable JSON Schema for the import format, so producers can validate/generate against
// it and editors can autocomplete. A public contract (no data), served anonymously and generated from the
// model so it can never drift from what the importer accepts.
app.MapGet("/api/import/cases/schema", () =>
        Results.Text(IncidentManager.Application.Import.CaseImportSchema.Build(), "application/json"))
    .AllowAnonymous().RequireRateLimiting("downloads");

await app.RunAsync();   // S6966: async host run

public partial class Program;
