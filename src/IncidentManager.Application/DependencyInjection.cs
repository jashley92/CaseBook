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
        services.AddScoped<CaseCommentService>();            // PROD-04: durable threaded case discussion
        services.AddScoped<ActionItemCommentService>();      // append-only commentary on follow-up tasks
        services.AddScoped<Lessons.LessonsService>();         // E-26/PROD-41: post-incident review + improvement-action register
        services.AddScoped<Admin.AdminSettingsService>();
        services.AddScoped<Admin.RoleService>();
        services.AddScoped<Admin.CaseTemplateService>();
        services.AddScoped<Admin.ReportProfileService>();
        services.AddScoped<Admin.StageGateService>();
        services.AddScoped<Admin.AccessReviewService>();
        services.AddScoped<Admin.TaxonomyAdminService>();
        services.AddScoped<Admin.EmailTemplateAdminService>();
        services.AddScoped<Admin.DataElementService>();
        services.AddScoped<Admin.NotificationRuleService>();          // PROD-07: per-jurisdiction deadline rules
        services.AddScoped<Compliance.NotificationDeadlineService>(); // PROD-07: per-case deadline evaluation
        services.AddScoped<Config.ConfigBundleService>();
        services.AddScoped<Import.CaseImportService>();    // PROD-31: structured case import (schema + importer)
        services.AddScoped<ApiTokens.ApiTokenService>();   // PROD-34: API-token auth (personal + system tokens)
        services.AddScoped<EvidenceService>();
        services.AddScoped<DashboardService>();
        services.AddScoped<Work.MyWorkService>();
        services.AddScoped<Work.TeamWorkloadService>();
        services.AddScoped<Work.AgendaService>();
        services.AddScoped<Campaigns.CampaignService>();   // E-29: cross-case campaign rollup + export
        services.AddScoped<Views.SavedViewService>();      // PROD-09: named/shared case-queue filter views
        services.AddScoped<CaseShortcutService>();         // PROD-20: recent + pinned cases for the palette / My Work
        services.AddScoped<Activity.ActivityFeedService>();
        services.AddScoped<IntegrityService>();
        // F-17: re-hashes evidence at rest and alarms on drift. Scoped (creates a DbContext per pass);
        // driven by the EvidenceIntegrityHostedService and reusable by a future "verify now" action.
        services.AddScoped<Integrity.EvidenceIntegrityVerifier>();
        services.AddScoped<Compliance.ComplianceBundleService>();
        services.AddScoped<Export.IocFeedService>();
        services.AddScoped<Intel.IndicatorService>();        // PROD-10: cross-case indicator pivot
        services.AddScoped<Export.StixExportService>();   // E-07: per-case entity graph → STIX 2.1 bundle
        services.AddScoped<ReportService>();
        // E-03b: overdue after-action scan. Scoped (creates a DbContext per pass, driven by the hosted
        // service); the notify-once tracker is a singleton so "already reminded" survives between passes.
        services.AddScoped<Notifications.OverdueActionItemScanner>();
        services.AddSingleton<Notifications.IOverdueActionItemTracker, Notifications.OverdueActionItemTracker>();
        // E-03d: due-soon after-action scan (fires ahead of the deadline). Same shape as the overdue scan;
        // a separate tracker so the "due soon" and "overdue" reminders for one item are independent episodes.
        services.AddScoped<Notifications.DueSoonActionItemScanner>();
        services.AddSingleton<Notifications.IDueSoonActionItemTracker, Notifications.DueSoonActionItemTracker>();
        // PROD-37: regulatory notification-deadline scan (the deadline-clock sibling of the two above). Scoped
        // (a DbContext + a scoped NotificationDeadlineService per pass); a singleton tracker so "already
        // reminded for this band" survives between passes, like the other reminder trackers.
        services.AddScoped<Notifications.NotificationDeadlineScanner>();
        services.AddSingleton<Notifications.IDeadlineReminderTracker, Notifications.DeadlineReminderTracker>();
        // PROD-38: stale-case nudge (open cases that have gone quiet past their severity's threshold). Same
        // shape as the reminder scanners above; a singleton tracker so "already nudged this quiet spell"
        // survives between passes and re-arms when the case sees new activity.
        services.AddScoped<Notifications.StaleCaseScanner>();
        services.AddSingleton<Notifications.IStaleCaseTracker, Notifications.StaleCaseTracker>();
        // PROD-39: per-user consolidated work digest. The preferences service backs the self-service opt-in;
        // the scanner assembles each subscriber's agenda and sends one grouped email on their cadence. Scoped
        // (DbContext + scoped AgendaService per pass); a singleton tracker so "already sent this period"
        // survives between passes.
        services.AddScoped<Notifications.UserNotificationPreferenceService>();
        services.AddScoped<Notifications.DigestScanner>();
        services.AddSingleton<Notifications.IDigestTracker, Notifications.DigestTracker>();

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
