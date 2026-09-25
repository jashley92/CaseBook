using System.Reflection;
using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// F-23: keeps the admin/config write-authorization map honest, exactly as <see cref="CaseActionPermissionsTests"/>
/// does for case writes — every public use case on a guarded service is either mapped or explicitly read-only,
/// so a newly added admin write can never ship unguarded.
/// </summary>
public sealed class AdminActionPermissionsTests
{
    /// <summary>
    /// Reads (and the one system path) on the guarded services — deliberately unmapped. Several reads feed
    /// ordinary case pages (active templates, data elements, report profiles, the effective taxonomy, the
    /// notification rule set), so gating them on Administer would break analysts.
    /// </summary>
    private static readonly HashSet<string> ReadOnlyOrSystem = new(StringComparer.Ordinal)
    {
        K<AdminSettingsService>(nameof(AdminSettingsService.GetEffectiveAsync)),
        K<CaseTemplateService>(nameof(CaseTemplateService.ListActiveAsync)),
        K<CaseTemplateService>(nameof(CaseTemplateService.ListAllAsync)),
        K<CaseTemplateService>(nameof(CaseTemplateService.GetAsync)),
        K<DataElementService>(nameof(DataElementService.ListAllAsync)),
        K<DataElementService>(nameof(DataElementService.ListActiveAsync)),
        K<EmailTemplateAdminService>(nameof(EmailTemplateAdminService.GetAllAsync)),
        K<EmailTemplateAdminService>(nameof(EmailTemplateAdminService.GetAsync)),
        K<NotificationRuleService>(nameof(NotificationRuleService.ListAllAsync)),
        K<NotificationRuleService>(nameof(NotificationRuleService.LoadRuleSetAsync)),
        K<ReportProfileService>(nameof(ReportProfileService.ListActiveAsync)),
        K<ReportProfileService>(nameof(ReportProfileService.ListAllAsync)),
        K<ReportProfileService>(nameof(ReportProfileService.GetAsync)),
        K<ReportTemplateService>(nameof(ReportTemplateService.ListAllAsync)),
        K<ReportTemplateService>(nameof(ReportTemplateService.ListActiveAsync)),
        K<ReportTemplateService>(nameof(ReportTemplateService.GetFileAsync)),       // PROD-47: download for editing
        K<RoleService>(nameof(RoleService.ListRolesAsync)),
        K<RoleService>(nameof(RoleService.ListMappingsAsync)),
        K<StageGateService>(nameof(StageGateService.ListAllAsync)),
        K<StageGateService>(nameof(StageGateService.GetAsync)),
        K<TaxonomyAdminService>(nameof(TaxonomyAdminService.GetEffectiveAsync)),
        K<IntegrityService>(nameof(IntegrityService.VerifyAsync)),
        K<IntegrityService>(nameof(IntegrityService.VerifyAndTrackAsync)),
        K<IntegrityService>(nameof(IntegrityService.VerifyOnDemandAsync)),
        K<IntegrityService>(nameof(IntegrityService.VerifyLatestSealAsync)),
        K<IntegrityService>(nameof(IntegrityService.LatestSealAtUtc)),
        K<IntegrityService>(nameof(IntegrityService.AuditCountAsync)),
        K<IntegrityService>(nameof(IntegrityService.RecentAsync)),
        K<IntegrityService>(nameof(IntegrityService.QueryAsync)),
        K<IntegrityService>(nameof(IntegrityService.AuditFacetsAsync)),
        K<IntegrityService>(nameof(IntegrityService.VerifySealAsync)),
        K<IntegrityService>(nameof(IntegrityService.RecentSealsAsync)),
        // The background seal job's cadence path — a system act, not an admin action.
        K<IntegrityService>(nameof(IntegrityService.SealIfDueAsync)),
        // S-18: building/previewing a bundle reads configuration only; the page itself is Administer-gated.
        K<IncidentManager.Application.Config.ConfigBundleService>(nameof(IncidentManager.Application.Config.ConfigBundleService.BuildBundleAsync)),
        K<IncidentManager.Application.Config.ConfigBundleService>(nameof(IncidentManager.Application.Config.ConfigBundleService.PreviewAsync)),
    };

    private static string K<T>(string method) => AdminActionPermissions.Key<T>(method);

    private static IEnumerable<string> PublicUseCases() =>
        AdminActionPermissions.GuardedServices.SelectMany(t => t
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => !m.IsSpecialName)
            .Where(m => typeof(Task).IsAssignableFrom(m.ReturnType))
            .Select(m => AdminActionPermissions.Key(t, m.Name)))
            .Distinct();

    [Fact]
    public void Every_admin_use_case_is_either_permission_mapped_or_explicitly_read_only()
    {
        foreach (var key in PublicUseCases())
        {
            var mapped = AdminActionPermissions.Required.ContainsKey(key);
            var readOnly = ReadOnlyOrSystem.Contains(key);
            (mapped ^ readOnly).Should().BeTrue(
                $"{key} must be in exactly one of the admin permission map or the read-only allowlist " +
                $"(mapped={mapped}, readOnly={readOnly}). A new admin write needs an AdminActionPermissions entry.");
        }
    }

    [Fact]
    public void Map_keys_all_resolve_to_a_real_method()
    {
        var methods = PublicUseCases().ToHashSet(StringComparer.Ordinal);
        foreach (var key in AdminActionPermissions.Required.Keys)
            methods.Should().Contain(key, $"permission map key '{key}' has no matching method (stale entry).");
    }

    [Fact]
    public void Every_admin_write_requires_Administer()
    {
        AdminActionPermissions.Required.Values.Should().OnlyContain(p => p == Permission.Administer);
    }

    [Fact]
    public void An_unmapped_action_fails_closed()
    {
        var act = () => AdminActionPermissions.Require<RoleService>(new FakeUser(Permission.Administer), action: "NotARealAction");
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void A_user_without_Administer_is_refused()
    {
        var siem = new CapturingSink();
        var act = () => AdminActionPermissions.Require<RoleService>(new FakeUser(Permission.EditCases), siem,
            nameof(RoleService.AddMappingAsync));
        act.Should().Throw<ForbiddenException>().Which.Required.Should().Be(Permission.Administer);
        // S-19: the refusal is streamed to the SIEM.
        siem.Events.Should().ContainSingle(e => e.EventId == SecurityEventIds.ActionRefused
                                               && e.Detail!.Contains("RoleService.AddMappingAsync"));

        var ok = () => AdminActionPermissions.Require<RoleService>(new FakeUser(Permission.Administer),
            action: nameof(RoleService.AddMappingAsync));
        ok.Should().NotThrow();
    }

    private sealed class FakeUser(params Permission[] held) : IncidentManager.Application.Abstractions.ICurrentUser
    {
        public string UserId => "u";
        public string DisplayName => "U";
        public string? UserPrincipalName => null;
        public string? Email => null;
        public bool IsAuthenticated => true;
        public IReadOnlySet<AppRole> Roles => new HashSet<AppRole>();
        public bool IsInRole(AppRole role) => false;
        public IReadOnlySet<Permission> Permissions => held.ToHashSet();
        public bool Has(Permission permission) => held.Contains(permission);
    }

    private sealed class CapturingSink : ISecurityEventSink
    {
        public List<SecurityEvent> Events { get; } = new();
        public void Emit(SecurityEvent e) => Events.Add(e);
    }
}
