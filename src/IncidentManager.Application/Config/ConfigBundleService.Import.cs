using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Config;

// X-07 slice 2: import. Parse + verify an uploaded bundle, preview the diff against live config, and apply it
// as a non-destructive upsert matched on stable natural keys. Nothing is ever deleted (deactivation is the
// admin's "remove"), so an import can seed a fresh instance or promote changes without wiping unrelated
// config. Every applied change flows through the audit-chain interceptor; a summary line is recorded too.
public sealed partial class ConfigBundleService
{
    /// <summary>
    /// Parses the uploaded file and verifies its embedded-key signature. Rejects an unrecognised format, a
    /// newer schema than this app understands, or a broken/tampered signature. A promoted bundle is signed by
    /// the source instance's key (carried in the file), so verification uses that embedded key — and reports
    /// whether it is this instance's own key (a same-instance re-import) or another's (a cross-instance promotion).
    /// </summary>
    public (ConfigBundleEnvelope Envelope, ConfigVerification Verification) ParseAndVerify(byte[] fileBytes)
    {
        ConfigBundleEnvelope? env;
        try
        {
            env = JsonSerializer.Deserialize<ConfigBundleEnvelope>(Encoding.UTF8.GetString(fileBytes), ConfigBundleJson.File);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("This file is not a valid configuration bundle (unreadable JSON).", ex);
        }

        if (env is null || env.Format != ConfigBundleJson.FormatTag || env.Bundle is null)
            throw new InvalidOperationException("This file is not a CaseBook configuration bundle.");
        if (env.SchemaVersion > ConfigBundleJson.CurrentSchemaVersion)
            throw new InvalidOperationException(
                $"This bundle is schema v{env.SchemaVersion}, newer than this app supports (v{ConfigBundleJson.CurrentSchemaVersion}). Upgrade CaseBook first.");

        var signatureValid = VerifyWithEmbeddedKey(
            ConfigBundleJson.Canonicalize(env.Bundle), env.Signature, env.PublicKeyPem);

        var verification = new ConfigVerification(
            SignatureValid: signatureValid,
            SignedByThisInstance: string.Equals(env.KeyId, _signer.KeyId, StringComparison.Ordinal),
            KeyId: env.KeyId,
            ExportedBy: env.ExportedBy,
            ExportedAtUtc: env.ExportedAtUtc,
            SchemaVersion: env.SchemaVersion,
            AppVersion: env.AppVersion,
            SourceHost: env.SourceHost);

        return (env, verification);
    }

    // Verifies an RSASSA-PKCS1-v1_5-SHA256 signature against a caller-supplied SubjectPublicKeyInfo PEM.
    private static bool VerifyWithEmbeddedKey(string content, string signatureBase64, string publicKeyPem)
    {
        if (string.IsNullOrWhiteSpace(signatureBase64) || string.IsNullOrWhiteSpace(publicKeyPem)) return false;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            return rsa.VerifyData(Encoding.UTF8.GetBytes(content), Convert.FromBase64String(signatureBase64),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>Previews applying a bundle: classifies every item add / update / unchanged against live config.</summary>
    public async Task<ConfigDiff> PreviewAsync(ConfigBundle incoming, CancellationToken ct = default)
    {
        var live = await BuildBundleAsync(ct);
        var items = new List<ConfigDiffItem>();

        Diff("Setting", incoming.Settings.Where(IsImportableSetting), live.Settings, s => s.Key, items);
        Diff("Role", incoming.Roles.Where(r => !r.IsSystem), live.Roles, r => r.Name, items);
        Diff("AD mapping", incoming.RoleMappings, live.RoleMappings, m => $"{m.AdGroup} → {m.RoleName}", items);
        Diff("Case template", incoming.CaseTemplates, live.CaseTemplates, t => t.Name, items);
        Diff("Stage gate", incoming.StageGates, live.StageGates, g => g.Name, items);
        Diff("Report profile", incoming.ReportProfiles, live.ReportProfiles, p => p.Name, items);

        // Data elements match on Key (codes are per-instance), so compare a code-agnostic shape.
        var liveByKey = live.DataElements.ToDictionary(e => e.Key, StringComparer.Ordinal);
        foreach (var d in incoming.DataElements)
        {
            var change = !liveByKey.TryGetValue(d.Key, out var l) ? ConfigChange.Add
                : SameElement(d, l) ? ConfigChange.Unchanged : ConfigChange.Update;
            items.Add(new ConfigDiffItem("Data element", d.Label, change));
        }

        return new ConfigDiff(items);
    }

    // Generic diff by natural key. Compares on the canonical JSON of each item so nested collections
    // (template steps, gate requirements) are compared structurally, not by list reference.
    private static void Diff<T>(string section, IEnumerable<T> incoming, IEnumerable<T> live,
        Func<T, string> key, List<ConfigDiffItem> acc) where T : notnull
    {
        var byKey = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var l in live) byKey[key(l)] = Canon(l);
        foreach (var i in incoming)
        {
            var change = !byKey.TryGetValue(key(i), out var canonLive) ? ConfigChange.Add
                : Canon(i) == canonLive ? ConfigChange.Unchanged : ConfigChange.Update;
            acc.Add(new ConfigDiffItem(section, key(i), change));
        }
    }

    private static string Canon<T>(T item) => System.Text.Json.JsonSerializer.Serialize(item, ConfigBundleJson.Canonical);

    private static bool SameElement(ConfigDataElement a, ConfigDataElement b) =>
        a.Label == b.Label && a.SortOrder == b.SortOrder && a.IsActive == b.IsActive
        && a.NotificationJurisdictions == b.NotificationJurisdictions;

    // Only whitelisted operational keys and the taxonomy key space are ever importable — defence in depth so a
    // crafted bundle can't smuggle a server-side/security key into the settings table (S-02).
    private static bool IsImportableSetting(ConfigSetting s) =>
        SettingsCatalog.IsEditable(s.Key) || s.Key.StartsWith(TaxonomyCatalog.KeyPrefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Applies a bundle as a non-destructive upsert (nothing is deleted). Existing items are matched by natural
    /// key and updated only when they differ; missing items are created. System roles' code-owned permissions
    /// are never overwritten; new custom data elements get the next unused local code. Every write is audited.
    /// </summary>
    public async Task<ConfigImportResult> ImportAsync(ConfigBundle bundle, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var now = _clock.UtcNow;
        var actor = _user.UserId;
        int added = 0, updated = 0, unchanged = 0;
        void Tally(bool isNew, bool changed) { if (isNew) added++; else if (changed) updated++; else unchanged++; }

        // --- Settings (whitelisted + taxonomy only) ---
        var settings = await db.AppSettings.ToDictionaryAsync(s => s.Key, StringComparer.OrdinalIgnoreCase, ct);
        foreach (var s in bundle.Settings.Where(IsImportableSetting))
        {
            if (settings.TryGetValue(s.Key, out var row))
            {
                var changed = row.Value != s.Value;
                if (changed) { row.Value = s.Value; row.UpdatedAtUtc = now; row.UpdatedBy = actor; }
                Tally(false, changed);
            }
            else
            {
                db.AppSettings.Add(new AppSetting { Key = s.Key, Value = s.Value, UpdatedAtUtc = now, UpdatedBy = actor });
                Tally(true, true);
            }
        }

        // --- Roles (custom only; system roles are code-owned) ---
        var roles = await db.Roles.ToListAsync(ct);
        foreach (var r in bundle.Roles.Where(r => !r.IsSystem))
        {
            var existing = roles.FirstOrDefault(x => x.Name == r.Name);
            if (existing is null)
            {
                db.Roles.Add(new Role { Name = r.Name, Description = r.Description, IsSystem = false,
                    PermissionsCsv = r.PermissionsCsv, UpdatedAtUtc = now, UpdatedBy = actor });
                Tally(true, true);
            }
            else if (existing.IsSystem) { unchanged++; }   // never touch a system role via import
            else
            {
                var changed = existing.Description != r.Description || existing.PermissionsCsv != r.PermissionsCsv;
                if (changed) { existing.Description = r.Description; existing.PermissionsCsv = r.PermissionsCsv; existing.UpdatedAtUtc = now; existing.UpdatedBy = actor; }
                Tally(false, changed);
            }
        }

        // --- AD mappings (existence grants; create if missing) ---
        var mappings = await db.RoleMappings.ToListAsync(ct);
        foreach (var m in bundle.RoleMappings)
        {
            var exists = mappings.Any(x => x.AdGroup == m.AdGroup && x.RoleName == m.RoleName);
            if (!exists)
            {
                db.RoleMappings.Add(new AdGroupRoleMapping { AdGroup = m.AdGroup, RoleName = m.RoleName, UpdatedAtUtc = now, UpdatedBy = actor });
                Tally(true, true);
            }
            else unchanged++;
        }

        // --- Case templates (upsert fields + replace steps wholesale) ---
        var templates = await db.CaseTemplates.Include(t => t.Steps).ToListAsync(ct);
        foreach (var t in bundle.CaseTemplates)
        {
            var cls = ParseEnum<Classification>(t.DefaultClassification);
            var sev = ParseEnum<Severity>(t.DefaultSeverity);
            var existing = templates.FirstOrDefault(x => x.Name == t.Name);
            if (existing is null)
            {
                var created = new CaseTemplate { Name = t.Name, Description = t.Description, IsActive = t.IsActive,
                    SortOrder = t.SortOrder, DefaultClassification = cls, DefaultSeverity = sev,
                    DefaultDataTypes = t.DefaultDataTypes, SummaryBoilerplate = t.SummaryBoilerplate,
                    CreatedBy = actor, CreatedAtUtc = now };
                created.Steps = t.Steps.Select(s => new CaseTemplateStep { TemplateId = created.Id, Order = s.Order,
                    Title = s.Title, Description = s.Description, OwnerHint = s.OwnerHint, DueOffsetHours = s.DueOffsetHours }).ToList();
                db.CaseTemplates.Add(created);
                Tally(true, true);
            }
            else if (Canon(t) == Canon(ToConfig(existing))) { unchanged++; }
            else
            {
                existing.Description = t.Description; existing.IsActive = t.IsActive; existing.SortOrder = t.SortOrder;
                existing.DefaultClassification = cls; existing.DefaultSeverity = sev;
                existing.DefaultDataTypes = t.DefaultDataTypes; existing.SummaryBoilerplate = t.SummaryBoilerplate;
                existing.ModifiedBy = actor; existing.ModifiedAtUtc = now;
                db.CaseTemplateSteps.RemoveRange(existing.Steps);
                existing.Steps.Clear();
                foreach (var s in t.Steps)
                    existing.Steps.Add(new CaseTemplateStep { TemplateId = existing.Id, Order = s.Order, Title = s.Title,
                        Description = s.Description, OwnerHint = s.OwnerHint, DueOffsetHours = s.DueOffsetHours });
                Tally(false, true);
            }
        }

        // --- Stage gates (upsert fields + replace requirements wholesale) ---
        var gates = await db.StageGates.Include(g => g.Requirements).ToListAsync(ct);
        foreach (var g in bundle.StageGates)
        {
            if (ParseEnum<StageGateTrigger>(g.Trigger) is not { } trigger) continue; // skip an unknown transition
            var existing = gates.FirstOrDefault(x => x.Name == g.Name);
            if (existing is null)
            {
                var created = new StageGate { Trigger = trigger, IsActive = g.IsActive, Name = g.Name,
                    Description = g.Description, CommentaryMinLength = g.CommentaryMinLength,
                    CreatedBy = actor, CreatedAtUtc = now };
                created.Requirements = g.Requirements.Select(r => NewRequirement(created.Id, r)).ToList();
                db.StageGates.Add(created);
                Tally(true, true);
            }
            else if (Canon(g) == Canon(ToConfig(existing))) { unchanged++; }
            else
            {
                existing.Trigger = trigger; existing.IsActive = g.IsActive; existing.Description = g.Description;
                existing.CommentaryMinLength = g.CommentaryMinLength;
                existing.ModifiedBy = actor; existing.ModifiedAtUtc = now;
                db.StageGateRequirements.RemoveRange(existing.Requirements);
                existing.Requirements.Clear();
                foreach (var r in g.Requirements) existing.Requirements.Add(NewRequirement(existing.Id, r));
                Tally(false, true);
            }
        }

        // --- Report profiles ---
        var profiles = await db.ReportProfiles.ToListAsync(ct);
        foreach (var p in bundle.ReportProfiles)
        {
            var existing = profiles.FirstOrDefault(x => x.Name == p.Name);
            if (existing is null)
            {
                db.ReportProfiles.Add(new ReportProfile { Name = p.Name, Description = p.Description, IsActive = p.IsActive,
                    SortOrder = p.SortOrder, SectionLayout = p.SectionLayout, CreatedBy = actor, CreatedAtUtc = now });
                Tally(true, true);
            }
            else
            {
                var changed = existing.Description != p.Description || existing.IsActive != p.IsActive
                    || existing.SortOrder != p.SortOrder || existing.SectionLayout != p.SectionLayout;
                if (changed) { existing.Description = p.Description; existing.IsActive = p.IsActive;
                    existing.SortOrder = p.SortOrder; existing.SectionLayout = p.SectionLayout;
                    existing.ModifiedBy = actor; existing.ModifiedAtUtc = now; }
                Tally(false, changed);
            }
        }

        // --- Data elements (match by stable Key) ---
        var elements = await db.DataElements.ToListAsync(ct);
        foreach (var d in bundle.DataElements)
        {
            var existing = elements.FirstOrDefault(x => x.Key == d.Key);
            if (existing is null)
            {
                db.DataElements.Add(new DataElement { Key = d.Key, Label = d.Label,
                    SortOrder = d.SortOrder, IsActive = d.IsActive, IsSystem = d.IsSystem,
                    NotificationJurisdictions = d.NotificationJurisdictions, CreatedBy = actor, CreatedAtUtc = now });
                Tally(true, true);
            }
            else
            {
                var changed = existing.Label != d.Label || existing.SortOrder != d.SortOrder
                    || existing.IsActive != d.IsActive || existing.NotificationJurisdictions != d.NotificationJurisdictions;
                if (changed) { existing.Label = d.Label; existing.SortOrder = d.SortOrder; existing.IsActive = d.IsActive;
                    existing.NotificationJurisdictions = d.NotificationJurisdictions;
                    existing.ModifiedBy = actor; existing.ModifiedAtUtc = now; }
                Tally(false, changed);
            }
        }

        await db.SaveChangesAsync(ct);
        await _audit.RecordAsync(AuditAction.Update, "ConfigBundle", null, null,
            $"Imported configuration bundle ({added} added, {updated} updated, {unchanged} unchanged)", ct);

        return new ConfigImportResult(added, updated, unchanged);
    }

    private static StageGateRequirement NewRequirement(Guid gateId, ConfigGateRequirement r) => new()
    {
        GateId = gateId,
        Order = r.Order,
        Kind = ParseEnum<GateRequirementKind>(r.Kind) ?? GateRequirementKind.Attestation,
        // The bundle carries the machine check as its stable registry key (the ConfigGateRequirement
        // field is still named Check). An unrecognised key is preserved verbatim — the evaluator treats
        // it as unmet and flags it for review, rather than dropping it, so a cross-version bundle is safe.
        CheckKey = string.IsNullOrWhiteSpace(r.Check) ? null : r.Check,
        CheckParam = r.CheckParam,
        Label = r.Label,
        IsBlocking = r.IsBlocking
    };

    private static TEnum? ParseEnum<TEnum>(string? value) where TEnum : struct, Enum =>
        Enum.TryParse<TEnum>(value, out var v) ? v : null;
}
