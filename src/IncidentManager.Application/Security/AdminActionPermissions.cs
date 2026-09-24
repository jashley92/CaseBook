using System.Runtime.CompilerServices;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Security;

/// <summary>
/// F-23: the admin/config sibling of <see cref="Cases.CaseActionPermissions"/>. The one reviewed source of
/// truth for the <see cref="Permission"/> each admin/config <em>write</em> requires, asserted at the service
/// boundary via <see cref="Require{TService}"/> — belt-and-suspenders behind the <c>Administer</c> page
/// policy, and the guarantee any future non-UI caller (a management API, bulk-config import, scripted
/// seeding) inherits for free.
/// <para>
/// Keys are <c>Service.Method</c>. Reads are deliberately absent: several (active templates, data elements,
/// report profiles, the effective taxonomy) feed ordinary case pages, so they are never gated here. A write
/// with no entry fails closed, and a unit test asserts every public method on the <see cref="GuardedServices"/>
/// is either mapped or explicitly read-only, so a newly added write can't ship unguarded.
/// </para>
/// </summary>
public static class AdminActionPermissions
{
    /// <summary>The admin/config services whose writes are asserted here (the unit test walks these).</summary>
    public static readonly IReadOnlyList<Type> GuardedServices =
    [
        typeof(AdminSettingsService), typeof(CaseTemplateService), typeof(DataElementService),
        typeof(EmailTemplateAdminService), typeof(NotificationRuleService), typeof(ReportProfileService),
        typeof(RoleService), typeof(StageGateService), typeof(TaxonomyAdminService), typeof(IntegrityService),
    ];

    public static readonly IReadOnlyDictionary<string, Permission> Required =
        new Dictionary<string, Permission>(StringComparer.Ordinal)
        {
            // Operational settings (A-02)
            [Key<AdminSettingsService>(nameof(AdminSettingsService.SetAsync))] = Permission.Administer,
            [Key<AdminSettingsService>(nameof(AdminSettingsService.ResetAsync))] = Permission.Administer,

            // Roles & AD-group mapping
            [Key<RoleService>(nameof(RoleService.CreateRoleAsync))] = Permission.Administer,
            [Key<RoleService>(nameof(RoleService.UpdateRoleAsync))] = Permission.Administer,
            [Key<RoleService>(nameof(RoleService.DeleteRoleAsync))] = Permission.Administer,
            [Key<RoleService>(nameof(RoleService.AddMappingAsync))] = Permission.Administer,
            [Key<RoleService>(nameof(RoleService.RemoveMappingAsync))] = Permission.Administer,

            // Reference data & templates
            [Key<DataElementService>(nameof(DataElementService.SaveAsync))] = Permission.Administer,
            [Key<DataElementService>(nameof(DataElementService.SetArchivedAsync))] = Permission.Administer,
            [Key<DataElementService>(nameof(DataElementService.DeleteAsync))] = Permission.Administer,
            [Key<CaseTemplateService>(nameof(CaseTemplateService.CreateAsync))] = Permission.Administer,
            [Key<CaseTemplateService>(nameof(CaseTemplateService.UpdateAsync))] = Permission.Administer,
            [Key<CaseTemplateService>(nameof(CaseTemplateService.DeleteAsync))] = Permission.Administer,
            [Key<ReportProfileService>(nameof(ReportProfileService.CreateAsync))] = Permission.Administer,
            [Key<ReportProfileService>(nameof(ReportProfileService.UpdateAsync))] = Permission.Administer,
            [Key<ReportProfileService>(nameof(ReportProfileService.DeleteAsync))] = Permission.Administer,
            [Key<StageGateService>(nameof(StageGateService.CreateAsync))] = Permission.Administer,
            [Key<StageGateService>(nameof(StageGateService.UpdateAsync))] = Permission.Administer,
            [Key<StageGateService>(nameof(StageGateService.DeleteAsync))] = Permission.Administer,
            [Key<TaxonomyAdminService>(nameof(TaxonomyAdminService.SetLabelAsync))] = Permission.Administer,
            [Key<TaxonomyAdminService>(nameof(TaxonomyAdminService.SetVisibilityOrderAsync))] = Permission.Administer,
            [Key<TaxonomyAdminService>(nameof(TaxonomyAdminService.ResetAsync))] = Permission.Administer,

            // Notification rules & email templates
            [Key<NotificationRuleService>(nameof(NotificationRuleService.SaveAsync))] = Permission.Administer,
            [Key<NotificationRuleService>(nameof(NotificationRuleService.SetArchivedAsync))] = Permission.Administer,
            [Key<NotificationRuleService>(nameof(NotificationRuleService.DeleteAsync))] = Permission.Administer,
            [Key<EmailTemplateAdminService>(nameof(EmailTemplateAdminService.SaveAsync))] = Permission.Administer,
            [Key<EmailTemplateAdminService>(nameof(EmailTemplateAdminService.ResetAsync))] = Permission.Administer,

            // Integrity ops: an on-demand seal. (SealIfDueAsync is the background job's system path — see the
            // read-only/system allowlist in the unit test.)
            [Key<IntegrityService>(nameof(IntegrityService.SealAsync))] = Permission.Administer,
        };

    /// <summary>
    /// Asserts the current user holds the permission mapped for <typeparamref name="TService"/>.<paramref name="action"/>.
    /// Fails closed: an unmapped action throws <see cref="InvalidOperationException"/>; a missing permission
    /// throws <see cref="ForbiddenException"/>.
    /// </summary>
    public static void Require<TService>(ICurrentUser user, [CallerMemberName] string action = "")
    {
        var key = Key<TService>(action);
        if (!Required.TryGetValue(key, out var permission))
            throw new InvalidOperationException(
                $"No admin-action permission is defined for '{key}'. Add it to {nameof(AdminActionPermissions)}.");
        if (!user.Has(permission))
            throw new ForbiddenException(permission, key);
    }

    public static string Key<TService>(string action) => Key(typeof(TService), action);

    public static string Key(Type service, string action) => $"{service.Name}.{action}";
}
