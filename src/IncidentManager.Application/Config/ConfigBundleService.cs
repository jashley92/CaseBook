using System.Text;
using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Config;

/// <summary>The exported bundle file, ready to stream to the admin.</summary>
public sealed record ConfigExport(byte[] Content, string FileName, ConfigBundleEnvelope Envelope);

/// <summary>
/// Exports (X-07 slice 1) an instance's editable configuration as a signed, versioned, diff-able bundle —
/// the "seed pack". Scope is deliberately the <b>editable</b> configuration only: operational + taxonomy
/// settings (bounded by the same whitelist the admin console writes, so connection strings, auth mode,
/// signing keys and the SIEM endpoint are never included), roles + AD mappings, case templates, stage gates,
/// report profiles and their Word templates, data elements and notification rules. Cases, evidence and the audit chain are records, not configuration,
/// and are never exported. The export itself is recorded in the tamper-evident audit trail.
/// </summary>
public sealed partial class ConfigBundleService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ISealSigner _signer;
    private readonly IAuditWriter _audit;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ISettingsReloader? _reloader;
    private readonly IRoleDirectory? _roles;
    private readonly ISecurityEventSink? _siem;
    private readonly Reporting.IReportTemplateEngine? _templateEngine;   // PROD-47
    private readonly Reporting.IReportTemplateStore? _templateStore;

    public ConfigBundleService(IAppDbContextFactory factory, ISealSigner signer, IAuditWriter audit,
        ICurrentUser user, IClock clock, ISettingsReloader? reloader = null, IRoleDirectory? roles = null,
        ISecurityEventSink? siem = null, Reporting.IReportTemplateEngine? templateEngine = null,
        Reporting.IReportTemplateStore? templateStore = null)
    {
        _templateEngine = templateEngine;
        _templateStore = templateStore;
        _factory = factory;
        _signer = signer;
        _audit = audit;
        _user = user;
        _clock = clock;
        _reloader = reloader;
        _roles = roles;
        _siem = siem;
    }

    /// <summary>Gathers the editable configuration into a deterministically-ordered <see cref="ConfigBundle"/>.</summary>
    public async Task<ConfigBundle> BuildBundleAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();

        // Settings: only the whitelisted operational keys and the taxonomy-override key space — never a
        // non-editable/security key, even if one somehow sits in the table (S-02).
        var settingRows = await db.AppSettings.AsNoTracking()
            .OrderBy(s => s.Key)
            .ToListAsync(ct);
        var settings = settingRows
            .Where(s => SettingsCatalog.IsEditable(s.Key)
                        || s.Key.StartsWith(TaxonomyCatalog.KeyPrefix, StringComparison.OrdinalIgnoreCase))
            .Select(s => new ConfigSetting(s.Key, s.Value))
            .ToList();

        var roles = await db.Roles.AsNoTracking().OrderBy(r => r.Name)
            .Select(r => new ConfigRole(r.Name, r.Description, r.IsSystem, r.PermissionsCsv))
            .ToListAsync(ct);

        var mappings = await db.RoleMappings.AsNoTracking()
            .OrderBy(m => m.AdGroup).ThenBy(m => m.RoleName)
            .Select(m => new ConfigRoleMapping(m.AdGroup, m.RoleName))
            .ToListAsync(ct);

        var caseTemplateRows = await db.CaseTemplates.AsNoTracking().Include(t => t.Steps)
            .OrderBy(t => t.SortOrder).ThenBy(t => t.Name).ToListAsync(ct);
        var templates = caseTemplateRows.Select(ToConfig).ToList();

        var gateRows = await db.StageGates.AsNoTracking().Include(g => g.Requirements)
            .OrderBy(g => g.Trigger).ThenBy(g => g.Name).ToListAsync(ct);
        var gates = gateRows.Select(ToConfig).ToList();

        // PROD-47: the Word template library travels with its files, so a profile's default still resolves after a
        // promotion. Without a template store (a host with templates off) neither the library nor defaults are carried.
        var templateRows = _templateStore is null ? null
            : await db.ReportTemplates.AsNoTracking().OrderBy(t => t.Name).ToListAsync(ct);
        List<ConfigReportTemplate>? reportTemplates = null;
        if (templateRows is not null)
        {
            reportTemplates = [];
            foreach (var t in templateRows)
            {
                var bytes = await _templateStore!.GetAsync(t.Id, ct)
                    ?? throw new InvalidOperationException(
                        $"The file for Word template \"{t.Name}\" is missing from the template store. Replace or delete the template, then export again.");
                reportTemplates.Add(new ConfigReportTemplate(t.Name, t.FileName, t.IsActive, t.Sha256, Convert.ToBase64String(bytes)));
            }
        }
        var templateNames = templateRows?.ToDictionary(t => t.Id, t => t.Name) ?? [];

        var profileRows = await db.ReportProfiles.AsNoTracking()
            .OrderBy(p => p.SortOrder).ThenBy(p => p.Name).ToListAsync(ct);
        var profiles = profileRows
            .Select(p => new ConfigReportProfile(p.Name, p.Description, p.IsActive, p.SortOrder, p.SectionLayout,
                p.TemplateId is { } id && templateNames.TryGetValue(id, out var n) ? n : null))
            .ToList();

        var dataElements = await db.DataElements.AsNoTracking().OrderBy(e => e.SortOrder).ThenBy(e => e.Key)
            .Select(e => new ConfigDataElement(e.Key, e.Label, e.SortOrder, e.IsActive, e.IsSystem, e.NotificationJurisdictions))
            .ToListAsync(ct);

        var notificationRules = await db.NotificationRules.AsNoTracking().OrderBy(r => r.Code)
            .Select(r => new ConfigNotificationRule(r.Code, r.Label, r.WindowHours, r.IsActive, r.IsSystem))
            .ToListAsync(ct);

        return new ConfigBundle(settings, roles, mappings, templates, gates, profiles, dataElements, notificationRules,
            reportTemplates);
    }

    /// <summary>Builds, signs, and packages the bundle for download, recording the export in the audit trail.</summary>
    public async Task<ConfigExport> ExportAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ConfigBundleService>(_user, _siem);   // S-18
        var bundle = await BuildBundleAsync(ct);

        var signature = _signer.Sign(ConfigBundleJson.Canonicalize(bundle));
        var envelope = new ConfigBundleEnvelope(
            Format: ConfigBundleJson.FormatTag,
            SchemaVersion: ConfigBundleJson.CurrentSchemaVersion,
            AppVersion: AppVersion(),
            ExportedAtUtc: _clock.UtcNow,
            ExportedBy: _user.UserId,
            SourceHost: Environment.MachineName,
            Algorithm: _signer.Algorithm,
            KeyId: _signer.KeyId,
            PublicKeyPem: _signer.PublicKeyPem,
            Signature: signature,
            Bundle: bundle);

        var json = JsonSerializer.Serialize(envelope, ConfigBundleJson.File);
        var bytes = Encoding.UTF8.GetBytes(json);
        var fileName = $"casebook-config-{_clock.UtcNow.UtcDateTime:yyyyMMdd-HHmmss}.json";

        await _audit.RecordAsync(AuditAction.Export, "ConfigBundle", null, null,
            $"Exported configuration bundle ({bundle.Settings.Count} settings, {bundle.Roles.Count} roles, " +
            $"{bundle.CaseTemplates.Count} templates, {bundle.StageGates.Count} gates, " +
            $"{bundle.ReportProfiles.Count} report profiles, {bundle.ReportTemplates?.Count ?? 0} Word templates, " +
            $"{bundle.DataElements.Count} data elements, " +
            $"{bundle.NotificationRules.Count} notification rules)", ct);

        return new ConfigExport(bytes, fileName, envelope);
    }

    private static string AppVersion() =>
        typeof(ConfigBundleService).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    // Projectors shared by export and import-diff, so a template/gate exported and re-imported compares equal
    // (records with nested collections lack structural equality — the import diffs on the canonical JSON of
    // these projections instead).
    internal static ConfigCaseTemplate ToConfig(CaseTemplate t) => new(
        t.Name, t.Description, t.IsActive, t.SortOrder,
        t.DefaultClassification?.ToString(), t.DefaultSeverity?.ToString(),
        t.DefaultDataTypes, t.SummaryBoilerplate,
        t.Steps.OrderBy(s => s.Order)
            .Select(s => new ConfigTemplateStep(s.Order, s.Title, s.Description, s.OwnerHint, s.DueOffsetHours))
            .ToList());

    internal static ConfigStageGate ToConfig(StageGate g) => new(
        g.Trigger.ToString(), g.IsActive, g.Name, g.Description,
        g.Requirements.OrderBy(r => r.Order)
            .Select(r => new ConfigGateRequirement(r.Order, r.Kind.ToString(), r.CheckKey, r.CheckParam, r.Label, r.IsBlocking))
            .ToList(),
        g.CommentaryMinLength);
}
