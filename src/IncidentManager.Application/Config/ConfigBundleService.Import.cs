using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Security;
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
            throw new InvalidOperationException("This file isn't a valid configuration bundle. Its JSON couldn't be read.", ex);
        }

        if (env is null || env.Format != ConfigBundleJson.FormatTag || env.Bundle is null)
            throw new InvalidOperationException("This file is not a CaseBook configuration bundle.");
        if (env.SchemaVersion > ConfigBundleJson.CurrentSchemaVersion)
            throw new InvalidOperationException(
                $"This bundle is schema v{env.SchemaVersion}, newer than this app supports (v{ConfigBundleJson.CurrentSchemaVersion}). Upgrade CaseBook first.");

        RefuseBorrowedKeyId(env);
        var verification = new ConfigVerification(
            SignatureValid: SignatureValid(env),
            SignedByThisInstance: HeldByThisServer(env.PublicKeyPem),
            KeyId: env.KeyId,
            ExportedBy: env.ExportedBy,
            ExportedAtUtc: env.ExportedAtUtc,
            SchemaVersion: env.SchemaVersion,
            AppVersion: env.AppVersion,
            SourceHost: env.SourceHost);

        return (env, verification);
    }

    // BUG-221: "signed by this instance" is decided by the key the bundle carries (the one its signature was checked
    // against), never by the key id it states: the id is public (every export, the compliance bundle, the seals), so
    // anyone could copy it into a bundle signed with their own key and skip the "source I trust" confirmation.
    private bool HeldByThisServer(string publicKeyPem)
    {
        var carried = SubjectPublicKeyInfo(publicKeyPem);
        return carried is not null && _signer.VerificationKeys.Any(k =>
            SubjectPublicKeyInfo(k.PublicKeyPem) is { } held && held.AsSpan().SequenceEqual(carried));
    }

    private static byte[]? SubjectPublicKeyInfo(string? pem)
    {
        if (string.IsNullOrWhiteSpace(pem)) return null;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa.ExportSubjectPublicKeyInfo();
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            return null;
        }
    }

    // A bundle that names one of this server's key ids but carries a different key is made to look like a re-import.
    private void RefuseBorrowedKeyId(ConfigBundleEnvelope env)
    {
        if (_signer.VerificationKeys.Any(k => string.Equals(k.KeyId, env.KeyId, StringComparison.OrdinalIgnoreCase))
            && !HeldByThisServer(env.PublicKeyPem))
            throw new InvalidOperationException(
                $"This bundle says it was signed with this server's key ({env.KeyId}), but the key it carries is a different " +
                "one, so it was made to look like this server's own export. Nothing was imported.");
    }

    private static bool SignatureValid(ConfigBundleEnvelope env) =>
        VerifyWithEmbeddedKey(ConfigBundleJson.Canonicalize(env.Bundle), env.Signature, env.PublicKeyPem, env.Algorithm);

    // Verifies a signature against a caller-supplied SubjectPublicKeyInfo PEM, by the algorithm the bundle records
    // (RSASSA-PSS now; RSASSA-PKCS1-v1_5 from releases before v1.4.0).
    private static bool VerifyWithEmbeddedKey(string content, string signatureBase64, string publicKeyPem, string? algorithm)
    {
        if (string.IsNullOrWhiteSpace(signatureBase64) || string.IsNullOrWhiteSpace(publicKeyPem)) return false;
        if (SealAlgorithms.PaddingFor(algorithm) is not { } padding) return false;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            return rsa.VerifyData(Encoding.UTF8.GetBytes(content), Convert.FromBase64String(signatureBase64),
                HashAlgorithmName.SHA256, padding);
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
        var (_, warnings) = await CheckReportTemplatesAsync(incoming, ct);   // a bad template stops the import here, before the preview
        CheckSettings(incoming);                         // so does a setting outside its limits
        CheckNaturalKeys(incoming);                      // and two items that differ only in case
        var items = new List<ConfigDiffItem>();

        Diff("Setting", incoming.Settings.Where(IsImportableSetting), live.Settings, s => s.Key, items);
        Diff("Role", incoming.Roles.Where(r => !r.IsSystem), live.Roles, r => r.Name, items);
        Diff("AD mapping", incoming.RoleMappings, live.RoleMappings, m => $"{m.AdGroup} → {m.RoleName}", items);
        Diff("Case template", incoming.CaseTemplates, live.CaseTemplates, t => t.Name, items);
        Diff("Stage gate", incoming.StageGates, live.StageGates, g => g.Name, items);
        Diff("Word template", incoming.ReportTemplates ?? [], live.ReportTemplates ?? [], t => t.Name, items);
        Diff("Report profile", incoming.ReportProfiles, live.ReportProfiles, p => p.Name, items);
        // Notification rules match on their portable jurisdiction Code (null when importing a pre-v2 bundle).
        Diff("Notification rule", incoming.NotificationRules ?? [], live.NotificationRules, r => r.Code, items);
        // HR-01: outcomes match on their stable Key (null when importing a pre-v4 bundle).
        Diff("Case outcome", incoming.CaseOutcomes ?? [], live.CaseOutcomes ?? [], o => o.Key, items);

        // Data elements match on Key (codes are per-instance), so compare a code-agnostic shape.
        var liveByKey = live.DataElements.ToDictionary(e => e.Key, StringComparer.OrdinalIgnoreCase);
        foreach (var d in incoming.DataElements)
        {
            var change = !liveByKey.TryGetValue(d.Key, out var l) ? ConfigChange.Add
                : SameElement(d, l) ? ConfigChange.Unchanged : ConfigChange.Update;
            items.Add(new ConfigDiffItem("Data element", d.Label, change));
        }

        return new ConfigDiff(items, warnings);
    }

    // Generic diff by natural key. Compares on the canonical JSON of each item so nested collections
    // (template steps, gate requirements) are compared structurally, not by list reference.
    private static void Diff<T>(string section, IEnumerable<T> incoming, IEnumerable<T> live,
        Func<T, string> key, List<ConfigDiffItem> acc) where T : notnull
    {
        // BUG-200: natural keys match regardless of case, as the database's unique indexes do on SQL Server.
        var byKey = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
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

    // Every importable setting must pass the same rules as the Administration form (limits, listed choices). Throws with
    // every problem listed, so nothing is written and the admin sees them all at the preview.
    private static void CheckSettings(ConfigBundle bundle)
    {
        var problems = bundle.Settings.Where(IsImportableSetting)
            .Select(s => SettingsCatalog.ByKey.TryGetValue(s.Key, out var def) ? SettingsCatalog.Problem(def, s.Value) : null)
            .OfType<string>().ToList();
        if (problems.Count > 0)
            throw new ArgumentException("This bundle can't be imported: " + string.Join(" ", problems));
    }

    // BUG-200: items match live ones by name or key regardless of case (SQL Server's unique indexes ignore it), so two in
    // one bundle that differ only in case would both land on the same row. Throws with each such pair.
    private static void CheckNaturalKeys(ConfigBundle bundle)
    {
        static IEnumerable<string> Check<T>(string section, IEnumerable<T>? items, Func<T, string?> key) =>
            (items ?? []).Select(key).OfType<string>().GroupBy(k => k, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.Distinct(StringComparer.Ordinal).ToList())
                .Where(names => names.Count > 1)
                .Select(names => $"{section} \"{string.Join("\" and \"", names)}\" differ only in case.");
        var problems = Check("Case templates", bundle.CaseTemplates, t => t.Name)
            .Concat(Check("Stage gates", bundle.StageGates, g => g.Name))
            .Concat(Check("Report profiles", bundle.ReportProfiles, p => p.Name))
            .Concat(Check("Data elements", bundle.DataElements, d => d.Key))
            .Concat(Check("Notification rules", bundle.NotificationRules, r => r.Code))
            .Concat(Check("Case outcomes", bundle.CaseOutcomes, o => o.Key))
            .ToList();
        if (problems.Count > 0)
            throw new ArgumentException("This bundle can't be imported: " + string.Join(" ", problems) + " Rename one, then export again.");
    }

    /// <summary>
    /// Applies a signed bundle (the envelope <see cref="ParseAndVerify"/> returned) as a non-destructive upsert
    /// (nothing is deleted). The signature must verify against the key carried in the file, here and not only on
    /// the page, so no caller can apply a bundle whose content was altered after export. Existing items are matched
    /// by natural key and updated only when they differ; missing items are created. System roles' code-owned
    /// permissions are never overwritten; new custom data elements get the next unused local code. Every write is
    /// audited.
    /// </summary>
    /// <exception cref="InvalidOperationException">Not a bundle this app reads, or the signature doesn't verify.</exception>
    /// <param name="sourceTrusted">BUG-19: the administrator confirms the bundle came from a source they trust. Required when
    /// it's signed with a key this server doesn't hold: the signature is checked against the key inside the bundle, so it
    /// proves the bundle wasn't changed after signing, not who signed it.</param>
    public async Task<ConfigImportResult> ImportAsync(ConfigBundleEnvelope envelope, bool sourceTrusted = false, CancellationToken ct = default)
    {
        // S-18: an import can grant roles and AD mappings, so it's asserted here, not just by the Administer page.
        AdminActionPermissions.Require<ConfigBundleService>(_user, _siem);
        if (envelope is not { Format: ConfigBundleJson.FormatTag, Bundle: not null }
            || envelope.SchemaVersion > ConfigBundleJson.CurrentSchemaVersion)
            throw new InvalidOperationException("This file is not a CaseBook configuration bundle this version can import.");
        if (!SignatureValid(envelope))
            throw new InvalidOperationException(
                "This bundle's signature doesn't verify, so it was altered after export. Nothing was imported.");
        RefuseBorrowedKeyId(envelope);
        var foreignKey = !HeldByThisServer(envelope.PublicKeyPem);
        if (foreignKey && !sourceTrusted)
            throw new InvalidOperationException(
                "This bundle is signed with a key this server doesn't hold, so its signature can't show who made it. " +
                "Confirm it came from a source you trust to import it. Nothing was imported.");

        var bundle = envelope.Bundle;
        var changedSettings = new List<string>();
        var changedRoles = new List<string>();
        var addedMappings = new List<string>();

        var (templateFiles, _) = await CheckReportTemplatesAsync(bundle, ct);
        CheckSettings(bundle);
        CheckNaturalKeys(bundle);

        using var db = _factory.CreateDbContext();
        var now = _clock.UtcNow;
        var actor = _user.UserId;
        int added = 0, updated = 0, unchanged = 0;
        void Tally(bool isNew, bool changed) { if (isNew) added++; else if (changed) updated++; else unchanged++; }

        // --- Settings (whitelisted + taxonomy only) ---
        var settings = await db.AppSettings.ToDictionaryAsync(s => s.Key, StringComparer.OrdinalIgnoreCase, ct);
        foreach (var s in bundle.Settings.Where(IsImportableSetting))
        {
            // S-18: validate an operational setting exactly as the settings page does, so a bundle can't write a
            // value the page would refuse. (Taxonomy labels are free text.)
            var value = SettingsCatalog.ByKey.TryGetValue(s.Key, out var def) ? SettingsCatalog.Normalize(def, s.Value) : s.Value;
            if (settings.TryGetValue(s.Key, out var row))
            {
                var changed = row.Value != value;
                if (changed) { row.Value = value; row.UpdatedAtUtc = now; row.UpdatedBy = actor; changedSettings.Add(s.Key); }
                Tally(false, changed);
            }
            else
            {
                db.AppSettings.Add(new AppSetting { Key = s.Key, Value = value, UpdatedAtUtc = now, UpdatedBy = actor });
                changedSettings.Add(s.Key);
                Tally(true, true);
            }
        }

        // --- Roles (custom only; system roles are code-owned) ---
        var roles = await db.Roles.ToListAsync(ct);
        var adminBefore = AdministerMapped(roles, await db.RoleMappings.AsNoTracking().ToListAsync(ct));
        foreach (var r in bundle.Roles.Where(r => !r.IsSystem))
        {
            // BUG-18: matched regardless of case, like the role directory, so "sysadmin" is SysAdmin, not a new role.
            var existing = roles.FirstOrDefault(x => string.Equals(x.Name, r.Name, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                if (Role.NameProblem(r.Name) is { } problem) throw new ArgumentException($"Role '{r.Name}': {problem}");
                db.Roles.Add(new Role { Name = r.Name, Description = r.Description, IsSystem = false,
                    PermissionsCsv = r.PermissionsCsv, UpdatedAtUtc = now, UpdatedBy = actor });
                changedRoles.Add(r.Name);
                Tally(true, true);
            }
            else if (existing.IsSystem) { unchanged++; }   // never touch a system role via import
            else
            {
                var changed = existing.Description != r.Description || existing.PermissionsCsv != r.PermissionsCsv;
                if (changed) { existing.Description = r.Description; existing.PermissionsCsv = r.PermissionsCsv; existing.UpdatedAtUtc = now; existing.UpdatedBy = actor; changedRoles.Add(r.Name); }
                Tally(false, changed);
            }
        }

        // --- AD mappings (existence grants; create if missing) ---
        var mappings = await db.RoleMappings.ToListAsync(ct);
        foreach (var m in bundle.RoleMappings)
        {
            // BUG-136: AD group and role names match ignoring case, as SQL Server's unique index does (and AD itself).
            var exists = mappings.Any(x => string.Equals(x.AdGroup, m.AdGroup, StringComparison.OrdinalIgnoreCase)
                                           && string.Equals(x.RoleName, m.RoleName, StringComparison.OrdinalIgnoreCase));
            if (!exists)
            {
                var mapping = new AdGroupRoleMapping { AdGroup = m.AdGroup, RoleName = m.RoleName, UpdatedAtUtc = now, UpdatedBy = actor };
                db.RoleMappings.Add(mapping);
                mappings.Add(mapping);   // a bundle that lists the same mapping twice, in two casings, adds it once
                addedMappings.Add($"{m.AdGroup} → {m.RoleName}");
                Tally(true, true);
            }
            else unchanged++;
        }

        // BUG-17: the S-17 anti-lockout rule applies to an import too. A bundle whose version of a role drops
        // Administer must not leave no AD group with administrator access.
        if (adminBefore && !AdministerMapped(db.Roles.Local, db.RoleMappings.Local))
            throw new InvalidOperationException("This bundle would remove the last administrator access: no AD group would map to a " +
                "role with Administer. Grant Administer to a mapped role first, or edit the bundle.");

        // --- Case templates (upsert fields + replace steps wholesale) ---
        var templates = await db.CaseTemplates.Include(t => t.Steps).ToListAsync(ct);
        foreach (var t in bundle.CaseTemplates)
        {
            var cls = ParseEnum<Classification>(t.DefaultClassification);
            var sev = ParseEnum<Severity>(t.DefaultSeverity);
            var existing = templates.FirstOrDefault(x => string.Equals(x.Name, t.Name, StringComparison.OrdinalIgnoreCase));   // BUG-200
            if (existing is null)
            {
                var created = new CaseTemplate { Name = t.Name, Description = t.Description, IsActive = t.IsActive,
                    SortOrder = t.SortOrder, DefaultClassification = cls, DefaultSeverity = sev,
                    DefaultDataTypes = t.DefaultDataTypes, SummaryBoilerplate = t.SummaryBoilerplate,
                    CreatedBy = actor, CreatedAtUtc = now };
                created.Steps = t.Steps.Select(s => new CaseTemplateStep { TemplateId = created.Id, Order = s.Order,
                    Title = s.Title, Description = s.Description, OwnerHint = s.OwnerHint, DueOffsetHours = s.DueOffsetHours, Kind = s.Kind }).ToList();
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
                        Description = s.Description, OwnerHint = s.OwnerHint, DueOffsetHours = s.DueOffsetHours, Kind = s.Kind });
                Tally(false, true);
            }
        }

        // --- Stage gates (upsert fields + replace requirements wholesale) ---
        var gates = await db.StageGates.Include(g => g.Requirements).ToListAsync(ct);
        foreach (var g in bundle.StageGates)
        {
            if (ParseEnum<StageGateTrigger>(g.Trigger) is not { } trigger) continue; // skip an unknown transition
            var existing = gates.FirstOrDefault(x => string.Equals(x.Name, g.Name, StringComparison.OrdinalIgnoreCase));
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

        // --- Word templates (PROD-47; match by name, ignoring case; files were checked above) ---
        var libraryRows = await db.ReportTemplates.ToListAsync(ct);
        var staged = new List<Reporting.StagedTemplate>();   // BUG-199: put in place only once the import is saved
        var library = libraryRows.ToDictionary(t => t.Name, StringComparer.OrdinalIgnoreCase);
        foreach (var t in bundle.ReportTemplates ?? [])
        {
            var bytes = templateFiles[t.Name];
            var fileName = Path.GetFileName(t.FileName);
            if (!library.TryGetValue(t.Name, out var existing))
            {
                var created = new ReportTemplate { Name = t.Name, FileName = fileName, IsActive = t.IsActive,
                    IsLessonsDefault = t.LessonsDefault,
                    Sha256 = t.Sha256.ToLowerInvariant(), SizeBytes = bytes.LongLength, CreatedBy = actor, CreatedAtUtc = now };
                staged.Add(await _templateStore!.StageAsync(created.Id, bytes, ct));
                db.ReportTemplates.Add(created);
                library[t.Name] = created;
                Tally(true, true);
            }
            else
            {
                var fileChanged = !string.Equals(existing.Sha256, t.Sha256, StringComparison.OrdinalIgnoreCase);
                var changed = fileChanged || existing.Name != t.Name || existing.FileName != fileName
                    || existing.IsActive != t.IsActive || existing.IsLessonsDefault != t.LessonsDefault;
                if (fileChanged) staged.Add(await _templateStore!.StageAsync(existing.Id, bytes, ct));
                if (changed) { existing.Name = t.Name; existing.FileName = fileName; existing.IsActive = t.IsActive;
                    existing.IsLessonsDefault = t.LessonsDefault;
                    existing.Sha256 = t.Sha256.ToLowerInvariant(); existing.SizeBytes = bytes.LongLength;
                    existing.ModifiedBy = actor; existing.ModifiedAtUtc = now; }
                Tally(false, changed);
            }
        }

        // At most one lessons-learned default: when the bundle names one, a live template outside the bundle stops being it.
        if (bundle.ReportTemplates?.Any(t => t.LessonsDefault) == true)
            foreach (var other in libraryRows.Where(r => r.IsLessonsDefault
                         && !bundle.ReportTemplates.Any(t => t.Name.Equals(r.Name, StringComparison.OrdinalIgnoreCase))))
            {
                other.IsLessonsDefault = false; other.ModifiedBy = actor; other.ModifiedAtUtc = now;
            }

        // --- Report profiles ---
        // A bundle that carries the template library (v3) also sets each profile's default template (null = the built-in
        // layout). An older bundle leaves defaults as they are.
        var carriesTemplates = bundle.ReportTemplates is not null;
        Guid? TemplateIdFor(ConfigReportProfile p) => p.Template is null ? null : library[p.Template].Id;
        var profiles = await db.ReportProfiles.ToListAsync(ct);
        foreach (var p in bundle.ReportProfiles)
        {
            var existing = profiles.FirstOrDefault(x => string.Equals(x.Name, p.Name, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                db.ReportProfiles.Add(new ReportProfile { Name = p.Name, Description = p.Description, IsActive = p.IsActive,
                    SortOrder = p.SortOrder, SectionLayout = p.SectionLayout,
                    TemplateId = carriesTemplates ? TemplateIdFor(p) : null, CreatedBy = actor, CreatedAtUtc = now });
                Tally(true, true);
            }
            else
            {
                var templateId = carriesTemplates ? TemplateIdFor(p) : existing.TemplateId;
                var changed = existing.Description != p.Description || existing.IsActive != p.IsActive
                    || existing.SortOrder != p.SortOrder || existing.SectionLayout != p.SectionLayout
                    || existing.TemplateId != templateId;
                if (changed) { existing.Description = p.Description; existing.IsActive = p.IsActive;
                    existing.SortOrder = p.SortOrder; existing.SectionLayout = p.SectionLayout; existing.TemplateId = templateId;
                    existing.ModifiedBy = actor; existing.ModifiedAtUtc = now; }
                Tally(false, changed);
            }
        }

        // --- Case outcomes (HR-01; match by stable Key; absent from a pre-v4 bundle) ---
        var outcomeRows = await db.CaseOutcomes.ToListAsync(ct);
        foreach (var o in bundle.CaseOutcomes ?? [])
        {
            var existing = outcomeRows.FirstOrDefault(x => string.Equals(x.Key, o.Key, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                db.CaseOutcomes.Add(new CaseOutcome { Key = o.Key, Label = o.Label, Description = o.Description,
                    SortOrder = o.SortOrder, IsActive = o.IsActive, IsSystem = o.IsSystem, CreatedBy = actor, CreatedAtUtc = now });
                Tally(true, true);
            }
            else
            {
                var changed = existing.Label != o.Label || existing.Description != o.Description
                    || existing.SortOrder != o.SortOrder || existing.IsActive != o.IsActive;
                if (changed) { existing.Label = o.Label; existing.Description = o.Description; existing.SortOrder = o.SortOrder;
                    existing.IsActive = o.IsActive; existing.ModifiedBy = actor; existing.ModifiedAtUtc = now; }
                Tally(false, changed);
            }
        }

        // --- Data elements (match by stable Key) ---
        var elements = await db.DataElements.ToListAsync(ct);
        foreach (var d in bundle.DataElements)
        {
            var existing = elements.FirstOrDefault(x => string.Equals(x.Key, d.Key, StringComparison.OrdinalIgnoreCase));
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

        // --- Notification rules (match by portable jurisdiction Code; absent on a pre-v2 bundle) ---
        var rules = await db.NotificationRules.ToListAsync(ct);
        foreach (var r in bundle.NotificationRules ?? [])
        {
            var existing = rules.FirstOrDefault(x => string.Equals(x.Code, r.Code, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                db.NotificationRules.Add(new NotificationRule { Code = r.Code, Label = r.Label,
                    WindowHours = r.WindowHours, IsActive = r.IsActive, IsSystem = r.IsSystem,
                    CreatedBy = actor, CreatedAtUtc = now });
                Tally(true, true);
            }
            else
            {
                var changed = existing.Label != r.Label || existing.WindowHours != r.WindowHours
                    || existing.IsActive != r.IsActive;
                if (changed) { existing.Label = r.Label; existing.WindowHours = r.WindowHours;
                    existing.IsActive = r.IsActive; existing.ModifiedBy = actor; existing.ModifiedAtUtc = now; }
                Tally(false, changed);
            }
        }

        try { await db.SaveChangesAsync(ct); }
        catch
        {
            foreach (var s in staged) await _templateStore!.DiscardAsync(s);
            throw;
        }
        foreach (var s in staged) await _templateStore!.CommitAsync(s, ct);
        await _audit.RecordAsync(AuditAction.Update, "ConfigBundle", null, null,
            $"Imported configuration bundle ({added} added, {updated} updated, {unchanged} unchanged)" +
            (foreignKey ? $", signed with key {envelope.KeyId} (not this server's), source confirmed trusted" : ""), ct);

        // S-18: take effect now (as the settings and roles pages do) rather than at the next restart, and stream each
        // access-affecting change to the SIEM exactly as the per-item pages would, so an import can't hide one.
        if (changedSettings.Count > 0) _reloader?.Reload();
        if (changedRoles.Count > 0 || addedMappings.Count > 0) _roles?.Invalidate();
        foreach (var key in changedSettings)
            _siem?.Emit(SecurityEvents.SettingChanged(key, _user.UserId, _user.UserPrincipalName));
        foreach (var role in changedRoles)
            _siem?.Emit(SecurityEvents.RoleChanged("RoleImported", _user.UserId, _user.UserPrincipalName, role));
        foreach (var mapping in addedMappings)
            _siem?.Emit(SecurityEvents.MappingChanged("AdGroupMappingImported", _user.UserId, _user.UserPrincipalName, mapping));

        return new ConfigImportResult(added, updated, unchanged, _roles?.IsCurrent ?? true);
    }

    /// <summary>
    /// PROD-47: checks a bundle's Word templates exactly as an upload is checked (a plain .docx within the size limit,
    /// no macros, embedded objects or externally loaded content, known placeholders only), that each file matches its
    /// recorded SHA-256, and that after the import every report profile's default template exists and is active.
    /// Returns the decoded files by name. Throws with every problem listed, so nothing is written. BUG-151: a template that
    /// is safe but won't fill correctly (stored before v1.5.2 without {{report.tlp}}, say) doesn't stop the import, so an
    /// instance's own export can be restored; it's returned as a warning, and generation refuses an unmarked one.
    /// </summary>
    private async Task<(Dictionary<string, byte[]> Files, List<string> Warnings)> CheckReportTemplatesAsync(ConfigBundle bundle,
        CancellationToken ct)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>();
        if (bundle.ReportTemplates is null) return (files, warnings);   // an older bundle: the library is left alone
        if (bundle.ReportTemplates.Count > 0 && (_templateEngine is null || _templateStore is null))
            throw new InvalidOperationException("This bundle includes Word templates, but Word templates aren't available on this server.");

        var problems = new List<string>();
        foreach (var t in bundle.ReportTemplates)
        {
            var label = string.IsNullOrWhiteSpace(t.Name) ? "(unnamed)" : t.Name;
            if (string.IsNullOrWhiteSpace(t.Name) || t.Name.Trim() != t.Name || t.Name.Length > 200)
            { problems.Add($"Word template \"{label}\": the name must be 1 to 200 characters with no leading or trailing spaces."); continue; }
            if (files.ContainsKey(t.Name)) { problems.Add($"Word template \"{label}\" appears more than once."); continue; }
            if (t.FileName is null || !t.FileName.EndsWith(".docx", StringComparison.OrdinalIgnoreCase))
            { problems.Add($"Word template \"{label}\": only .docx files are accepted."); continue; }

            byte[] bytes;
            try { bytes = Convert.FromBase64String(t.ContentBase64 ?? ""); }
            catch (FormatException) { problems.Add($"Word template \"{label}\": the file content couldn't be read."); continue; }
            if (bytes.Length == 0 || bytes.Length > Admin.ReportTemplateService.MaxTemplateBytes)
            { problems.Add($"Word template \"{label}\": the file must be non-empty and {Admin.ReportTemplateService.MaxTemplateBytes / 1024 / 1024} MB or smaller."); continue; }
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(bytes)), t.Sha256, StringComparison.OrdinalIgnoreCase))
            { problems.Add($"Word template \"{label}\": the file doesn't match its recorded SHA-256."); continue; }

            var check = _templateEngine!.Check(bytes);
            if (!check.Safe) { problems.Add($"Word template \"{label}\": {string.Join(" ", check.Problems)}"); continue; }
            if (!check.Ok)
                warnings.Add($"Word template \"{label}\" is imported, but: {string.Join(" ", check.Problems)} Replace its file before using it.");
            files[t.Name] = bytes;
        }

        // Every profile's default must resolve to an active template once the import is applied: the bundle's version of
        // a template wins over the live one, and the bundle's profiles set their default (other live profiles keep theirs).
        using var db = _factory.CreateDbContext();
        var liveTemplates = await db.ReportTemplates.AsNoTracking().Select(t => new { t.Id, t.Name, t.IsActive }).ToListAsync(ct);
        var active = liveTemplates.ToDictionary(t => t.Name, t => t.IsActive, StringComparer.OrdinalIgnoreCase);
        foreach (var t in bundle.ReportTemplates.Where(t => files.ContainsKey(t.Name ?? ""))) active[t.Name] = t.IsActive;
        var liveNames = liveTemplates.ToDictionary(t => t.Id, t => t.Name);
        var defaults = (await db.ReportProfiles.AsNoTracking().Where(p => p.TemplateId != null)
                .Select(p => new { p.Name, p.TemplateId }).ToListAsync(ct))
            .ToDictionary(p => p.Name, p => liveNames.GetValueOrDefault(p.TemplateId!.Value), StringComparer.Ordinal);
        foreach (var p in bundle.ReportProfiles) defaults[p.Name] = p.Template;
        foreach (var (profile, template) in defaults.Where(d => d.Value is not null).OrderBy(d => d.Key, StringComparer.Ordinal))
        {
            if (!active.TryGetValue(template!, out var isActive))
                problems.Add($"Report profile \"{profile}\" uses the Word template \"{template}\", which isn't in the bundle or on this server.");
            else if (!isActive)
                problems.Add($"Report profile \"{profile}\" uses the Word template \"{template}\", which would be archived. A profile's default template must be active.");
        }

        // The lessons-learned default: at most one, and it must be active.
        var lessons = bundle.ReportTemplates.Where(t => t.LessonsDefault).ToList();
        if (lessons.Count > 1)
            problems.Add($"More than one Word template is marked as the lessons-learned default ({string.Join(", ", lessons.Select(t => $"\"{t.Name}\""))}).");
        else if (lessons is [{ IsActive: false } archivedLessons])
            problems.Add($"The lessons-learned default, \"{archivedLessons.Name}\", is archived. The default must be active.");

        if (problems.Count > 0)
            throw new InvalidOperationException("This bundle can't be imported. " + string.Join(" ", problems));
        return (files, warnings);
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

    /// <summary>Whether some AD-group mapping grants a role holding Administer (names matched regardless of case).</summary>
    private static bool AdministerMapped(IEnumerable<Role> roles, IEnumerable<AdGroupRoleMapping> mappings)
    {
        var admin = roles.Where(r => r.GetPermissions().Contains(Permission.Administer)).Select(r => r.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return mappings.Any(m => admin.Contains(m.RoleName));
    }
}
