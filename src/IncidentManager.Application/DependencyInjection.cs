using FluentValidation;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Content;
using IncidentManager.Application.Dashboards;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Reporting;
using Microsoft.Extensions.DependencyInjection;

namespace IncidentManager.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddScoped<CaseService>();
        services.AddScoped<Admin.AdminSettingsService>();
        services.AddScoped<Admin.RoleService>();
        services.AddScoped<Admin.CaseTemplateService>();
        services.AddScoped<Admin.ReportProfileService>();
        services.AddScoped<Admin.StageGateService>();
        services.AddScoped<Admin.AccessReviewService>();
        services.AddScoped<Admin.TaxonomyAdminService>();
        services.AddScoped<Admin.DataElementService>();
        services.AddScoped<Config.ConfigBundleService>();
        services.AddScoped<EvidenceService>();
        services.AddScoped<DashboardService>();
        services.AddScoped<Work.MyWorkService>();
        services.AddScoped<Work.TeamWorkloadService>();
        services.AddScoped<Activity.ActivityFeedService>();
        services.AddScoped<IntegrityService>();
        // F-17: re-hashes evidence at rest and alarms on drift. Scoped (creates a DbContext per pass);
        // driven by the EvidenceIntegrityHostedService and reusable by a future "verify now" action.
        services.AddScoped<Integrity.EvidenceIntegrityVerifier>();
        services.AddScoped<Compliance.ComplianceBundleService>();
        services.AddScoped<Export.IocFeedService>();
        services.AddScoped<ReportService>();
        // E-03b: overdue after-action scan. Scoped (creates a DbContext per pass, driven by the hosted
        // service); the notify-once tracker is a singleton so "already reminded" survives between passes.
        services.AddScoped<Notifications.OverdueActionItemScanner>();
        services.AddSingleton<Notifications.IOverdueActionItemTracker, Notifications.OverdueActionItemTracker>();

        services.AddSingleton<IMarkdownService, MarkdownService>();

        // Stage-gate evaluation is stateless (operates on a passed-in context), so a singleton is fine.
        services.AddSingleton<StageGates.IStageGateEvaluator, StageGates.StageGateEvaluator>();

        // App-wide latest-integrity-status holder for the tamper-alert banner (F-16). Singleton so the
        // background monitor and every circuit share one view of the chain's health.
        services.AddSingleton<Integrity.IIntegrityMonitor, Integrity.IntegrityMonitor>();

        // F-17: app-wide latest evidence-at-rest verification status, for the drift banner/panel. Singleton
        // so the background verifier and every circuit share one view.
        services.AddSingleton<Integrity.IEvidenceIntegrityMonitor, Integrity.EvidenceIntegrityMonitor>();

        services.AddScoped<IValidator<CreateCaseRequest>, CreateCaseValidator>();

        return services;
    }
}
