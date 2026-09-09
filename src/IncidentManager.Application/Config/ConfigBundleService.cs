using System.Text;
using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
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
/// report profiles, and data elements. Cases, evidence and the audit chain are records, not configuration,
/// and are never exported. The export itself is recorded in the tamper-evident audit trail.
/// </summary>
public sealed partial class ConfigBundleService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ISealSigner _signer;
    private readonly IAuditWriter _audit;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public ConfigBundleService(IAppDbContextFactory factory, ISealSigner signer, IAuditWriter audit,
        ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _signer = signer;
        _audit = audit;
        _user = user;
        _clock = clock;
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

        var templateRows = await db.CaseTemplates.AsNoTracking().Include(t => t.Steps)
            .OrderBy(t => t.SortOrder).ThenBy(t => t.Name).ToListAsync(ct);
        var templates = templateRows.Select(ToConfig).ToList();

        var gateRows = await db.StageGates.AsNoTracking().Include(g => g.Requirements)
            .OrderBy(g => g.Trigger).ThenBy(g => g.Name).ToListAsync(ct);
        var gates = gateRows.Select(ToConfig).ToList();

        var profiles = await db.ReportProfiles.AsNoTracking()
            .OrderBy(p => p.SortOrder).ThenBy(p => p.Name)
            .Select(p => new ConfigReportProfile(p.Name, p.Description, p.IsActive, p.SortOrder, p.SectionLayout))
            .ToListAsync(ct);

        var dataElements = await db.DataElements.AsNoTracking().OrderBy(e => e.SortOrder).ThenBy(e => e.Key)
            .Select(e => new ConfigDataElement(e.Key, e.Label, e.SortOrder, e.IsActive, e.IsSystem, e.NotificationJurisdictions))
            .ToListAsync(ct);

        return new ConfigBundle(settings, roles, mappings, templates, gates, profiles, dataElements);
    }

    /// <summary>Builds, signs, and packages the bundle for download, recording the export in the audit trail.</summary>
    public async Task<ConfigExport> ExportAsync(CancellationToken ct = default)
    {
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
            $"{bundle.ReportProfiles.Count} report profiles, {bundle.DataElements.Count} data elements)", ct);

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
