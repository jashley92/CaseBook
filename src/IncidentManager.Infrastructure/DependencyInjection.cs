using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Reporting;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using IncidentManager.Infrastructure.Time;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IncidentManager.Infrastructure;

public static class DependencyInjection
{
    /// <summary>Registers persistence, security, storage and integrity services.</summary>
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        services.Configure<EvidenceStoreOptions>(config.GetSection("EvidenceStore"));
        services.Configure<ReportOutputOptions>(config.GetSection("ReportOutput"));
        services.Configure<ReportBrandingOptions>(config.GetSection("ReportBranding"));
        services.Configure<RoleMappingOptions>(config.GetSection("RoleMapping"));
        services.Configure<SealSigningOptions>(config.GetSection("Integrity"));
        services.Configure<Notifications.EmailOptions>(config.GetSection("Email"));
        services.Configure<Siem.SiemWebhookOptions>(config.GetSection("Siem:Webhook"));
        services.Configure<Siem.SiemSyslogOptions>(config.GetSection("Siem:Syslog"));

        // One sender that decides log-vs-send per message from the live options, so an administered
        // change to Email:Enabled / From / relay takes effect at runtime (A-08) without a restart.
        services.AddSingleton<IEmailSender, Notifications.EmailSender>();
        // E-03b: renders branded HTML emails from admin-editable templates + the console theme.
        services.AddSingleton<IEmailComposer, Notifications.EmailComposer>();
        services.AddSingleton<ICaseNotifications, Notifications.CaseNotifications>();
        // F-16: raises the audit-chain tamper alarm (critical SIEM/log event + email distribution).
        services.AddSingleton<IIntegrityAlertNotifier, Notifications.IntegrityAlertNotifier>();
        // F-17: raises the evidence-at-rest drift alarm (same channels + shared recipient distribution).
        services.AddSingleton<IEvidenceIntegrityAlertNotifier, Notifications.EvidenceIntegrityAlertNotifier>();

        // F-18: outbound security-event stream. The queue enqueues (non-blocking); the Web-hosted
        // SecurityEventDispatcher fans out to the enabled transports. Syslog (CEF) lives here; the
        // webhook transport is registered in Web (it needs IHttpClientFactory).
        services.AddSingleton<Siem.ISecurityEventTransport, Siem.SyslogTransport>();
        services.AddSingleton<Siem.SecurityEventQueue>(sp => new Siem.SecurityEventQueue(
            sp.GetServices<Siem.ISecurityEventTransport>(),
            sp.GetRequiredService<IClock>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<Siem.SecurityEventQueue>>(),
            config.GetValue("Siem:QueueCapacity", 2048)));
        services.AddSingleton<Application.Security.ISecurityEventSink>(
            sp => sp.GetRequiredService<Siem.SecurityEventQueue>());

        // F-19: secret-resolution seam. Default is passthrough (secrets read literally from config/env);
        // enabling Secrets:CyberArk swaps in the CCP-backed provider that fetches @cyberark: references at
        // runtime so no secret need be stored in config. Opt-in and per-secret (a value stays literal unless
        // it is written as a reference).
        services.Configure<Secrets.CyberArkOptions>(config.GetSection("Secrets:CyberArk"));
        // Always registered so the Admin health panel can read it even when CyberArk is disabled.
        services.AddSingleton<ISecretResolutionHealth, SecretResolutionHealth>();
        if (config.GetValue("Secrets:CyberArk:Enabled", false))
            services.AddSingleton<ISecretProvider, Secrets.CyberArkCcpSecretProvider>();
        else
            services.AddSingleton<ISecretProvider, Secrets.PassthroughSecretProvider>();

        // Lets a settings write signal the configuration root to re-read the DB provider (A-08).
        services.AddSingleton<ISettingsReloader, Configuration.ConfigurationReloader>();

        services.AddSingleton<IClock, SystemClock>();
        // E-16: reads per-severity SLA targets from live config (appsettings + DB override) on demand.
        services.AddSingleton<Application.Sla.ISlaTargetsProvider, Sla.ConfigurationSlaTargetsProvider>();
        services.AddSingleton<Application.Abstractions.ISeverityLabels, Severities.ConfigurationSeverityLabels>();
        // X-02: admin-set taxonomy display labels, read live from config (same mechanism as severity labels).
        services.AddSingleton<Application.Abstractions.ITaxonomyDisplay, Taxonomy.ConfigurationTaxonomyDisplay>();
        services.AddSingleton<IHashChainService, HashChainService>();
        services.AddSingleton<ICaseChangeNotifier, Realtime.CaseChangeNotifier>();
        services.AddSingleton<ICasePresenceService, Realtime.CasePresenceService>();
        services.AddSingleton<ISealSigner, RsaSealSigner>();
        services.AddSingleton<ISealStore, FileSealStore>();
        services.AddSingleton<IEvidenceStore, FileEvidenceStore>();
        services.AddSingleton<IReportStore, FileReportStore>();
        services.AddSingleton<IReportBrandingStore, FileReportBrandingStore>();
        services.AddSingleton<IReportGenerator, ReportGenerator>();
        services.AddSingleton<IRoleDirectory, Security.RoleDirectory>();
        services.AddSingleton<IUserDirectory, Security.UserDirectory>();
        // E-39: signs/validates the per-user agenda calendar (ICS) feed token. Stateless (HMAC over the
        // user id, keyed by Agenda:FeedKey); disabled until the secret is set.
        services.AddSingleton<IAgendaFeedTokens, Agenda.AgendaFeedTokenService>();

        services.AddScoped<AuditChainInterceptor>();
        services.AddScoped<ICaseNumberGenerator, CaseNumberGenerator>();
        services.AddScoped<IAuditWriter, Security.AuditWriter>();

        // C-05 access/read log: policy reads live config (scope + window); the service records
        // out-of-chain view-sessions. Scoped so the recorder sees the current user.
        services.AddSingleton<Application.Access.IAccessLogPolicy, Access.ConfigurationAccessLogPolicy>();
        services.AddScoped<Application.Access.IAccessLogService, Access.AccessLogService>();

        var provider = config.GetValue<string>("Database:Provider") ?? "Sqlite";
        var connectionString = config.GetConnectionString("Default");

        // H-08: a context FACTORY, not a shared context. Blazor Server shares one DI scope for a whole
        // circuit, so a held context is used concurrently by components rendering in the same pass ->
        // "A second operation was started on this context" (DbContext isn't thread-safe). Services take
        // IAppDbContextFactory and create a short-lived context per operation instead. The factory is
        // registered scoped so the delegate's `sp` is the circuit's scoped provider and each created
        // context carries the scoped audit-chain interceptor (which reads the current user).
        void ConfigureProvider(IServiceProvider sp, DbContextOptionsBuilder options)
        {
            if (provider.Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
            {
                options.UseSqlServer(
                    connectionString
                        ?? throw new InvalidOperationException("A SqlServer connection string is required."),
                    // Production migrations live in their own assembly (see AppDbContextFactory) so the
                    // startup MigrateAsync() applies the SQL Server set, not the SQLite dev set.
                    sql => sql.MigrationsAssembly(Persistence.AppDbContextFactory.SqlServerMigrationsAssembly));
            }
            else
            {
                options.UseSqlite(connectionString ?? "Data Source=App_Data/incidentmanager.db");
            }

            options.AddInterceptors(sp.GetRequiredService<AuditChainInterceptor>());
        }

        services.AddDbContextFactory<AppDbContext>(ConfigureProvider, lifetime: ServiceLifetime.Scoped);
        services.AddScoped<IAppDbContextFactory, Persistence.AppDbContextFactoryAdapter>();

        // A scoped context bridge for the few Infrastructure consumers that still resolve AppDbContext
        // directly and manage their own short scopes (RoleDirectory/UserDirectory create a scope per
        // refresh; CaseNumberGenerator/AuditWriter run inside one operation). They are not part of the
        // shared-context concurrency problem, so they keep a per-scope context unchanged.
        services.AddScoped<AppDbContext>(sp => sp.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext());
        services.AddScoped<IAppDbContext>(sp => sp.GetRequiredService<AppDbContext>());

        return services;
    }
}
