using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Security;
using IncidentManager.Application.StageGates;
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

    // BUG-335: a bundle from v1.0.x / v1.1.x was signed without step kinds (all General then), so it's checked against that
    // form as well. Any other change to the payload still fails both.
    private static bool SignatureValid(ConfigBundleEnvelope env) =>
        VerifyWithEmbeddedKey(ConfigBundleJson.Canonicalize(env.Bundle), env.Signature, env.PublicKeyPem, env.Algorithm)
        || VerifyWithEmbeddedKey(ConfigBundleJson.CanonicalizeWithoutDefaultStepKind(env.Bundle), env.Signature,
            env.PublicKeyPem, env.Algorithm);

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
        incoming = WithCommaJurisdictions(incoming);
        var live = await BuildBundleAsync(ct);
        var (_, warnings) = await CheckReportTemplatesAsync(incoming, ct);   // a bad template stops the import here, before the preview
        CheckSettings(incoming);                         // so does a setting outside its limits
        CheckNaturalKeys(incoming);                      // and two items that differ only in case
        CheckSingleActiveGates(incoming, live);          // and a second active gate on one transition
        CheckItems(incoming, live);                      // and an item the admin pages would refuse
        CheckTaxonomy(incoming, live);                   // WF-45: taxonomy keys too
        var items = new List<ConfigDiffItem>();

        Diff("Setting", incoming.Settings.Where(IsImportableSetting), live.Settings, s => s.Key, items);
        Diff("Role", incoming.Roles.Where(r => !r.IsSystem), live.Roles, r => r.Name, items);
        // WF-45: a mapping with no group or to a role neither here nor in the bundle isn't imported (a dormant grant a later
        // role of that name would pick up), so the preview doesn't count it and says so.
        var unusable = UnusableMappings(incoming, live.Roles.Select(r => r.Name));
        Diff("AD mapping", incoming.RoleMappings.Except(unusable), live.RoleMappings, m => $"{m.AdGroup} → {m.RoleName}", items);
        if (unusable.Count > 0)
            warnings.Add($"{Common.Plural.Of(unusable.Count, "AD mapping")} won't be imported: " +
                         string.Join(", ", unusable.Select(m => $"\"{m.AdGroup} → {m.RoleName}\"")) +
                         " (no AD group, or a role that doesn't exist here or in the bundle).");
        Diff("Case template", incoming.CaseTemplates, live.CaseTemplates, t => t.Name, items);
        // REV-54: a gate for a transition this version doesn't know is skipped on import, so the preview doesn't count it.
        var unknownGates = incoming.StageGates.Where(g => ParseEnum<StageGateTrigger>(g.Trigger) is null).Select(g => g.Name).ToList();
        Diff("Stage gate", incoming.StageGates.Where(g => ParseEnum<StageGateTrigger>(g.Trigger) is not null), live.StageGates, g => g.Name, items);
        if (unknownGates.Count > 0)
            warnings.Add($"{Common.Plural.Of(unknownGates.Count, "stage gate")} won't be imported: \"{string.Join("\", \"", unknownGates)}\" " +
                         "guard a transition this version of CaseBook doesn't have.");
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

    // BUG-404: ";" separates a case's kept jurisdictions from its elements, so it's never stored inside a code; a bundle
    // using it (an export from before that rule, which stored it as given) is read with commas, as the admin page saves it.
    private static ConfigBundle WithCommaJurisdictions(ConfigBundle bundle) =>
        bundle.DataElements.Any(d => d.NotificationJurisdictions?.Contains(';') == true)
            ? bundle with
            {
                DataElements = bundle.DataElements.Select(d => d.NotificationJurisdictions?.Contains(';') == true
                    ? d with { NotificationJurisdictions = string.Join(",", Compliance.NotificationDeadlineService.SplitCodes(d.NotificationJurisdictions)) }
                    : d).ToList()
            }
            : bundle;

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
    // BUG-237: one active gate per transition, as the Stage gates page enforces (BUG-139). The import matches gates by
    // name, so a bundle's active "Closure checks" next to a live active "Close-out gate" would leave both governing
    // Closing, and which one a close is judged against would be whichever row the database returned first.
    private static void CheckSingleActiveGates(ConfigBundle incoming, ConfigBundle live)
    {
        // BUG-538: two live gates with one name, ignoring case (saved at once before the name check ran under GuardGate),
        // can't be matched by name: a bundle gate of that name stops the import with the name, not a raw "same key" error.
        // A duplicate the bundle doesn't carry is left alone, and both rows still count below.
        var imported = incoming.StageGates.Where(g => ParseEnum<StageGateTrigger>(g.Trigger) is not null).ToList();
        var importedNames = imported.Select(g => g.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var ambiguous = live.StageGates.GroupBy(g => g.Name, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1 && importedNames.Contains(g.Key))
            .Select(g => importedNames.TryGetValue(g.Key, out var asImported) ? asImported : g.Key).Order(StringComparer.Ordinal).ToList();
        if (ambiguous.Count > 0)
            throw new ArgumentException("This bundle can't be imported: " + string.Join(" ", ambiguous.Select(DuplicateLiveGate)));
        var after = live.StageGates.Where(g => !importedNames.Contains(g.Name)).Concat(imported);
        var clashes = after.Where(g => g.IsActive)
            .GroupBy(g => ParseEnum<StageGateTrigger>(g.Trigger))
            .Where(t => t.Key is not null && t.Count() > 1)
            .Select(t => $"\"{StageGateTriggers.Label(t.Key!.Value)}\" would have {t.Count()} active gates " +
                         $"(\"{string.Join("\", \"", t.Select(g => g.Name).Order(StringComparer.OrdinalIgnoreCase))}\").")
            .ToList();
        if (clashes.Count > 0)
            throw new ArgumentException("This bundle can't be imported: " + string.Join(" ", clashes) +
                " A transition has one active gate. Deactivate one (here or in the bundle's source), then try again.");
    }

    private static string DuplicateLiveGate(string name) =>
        $"More than one stage gate on this server is named \"{name}\" (names match regardless of case). Rename one on the " +
        "Stage gates page, then import again.";

    // REV-49: S-18 says a bundle mustn't write what the admin pages would refuse; CheckSettings did that for settings only.
    // The rest came in as given: a notification rule with a window of 0 (every case it triggers past its deadline at once,
    // reminders sent) or a lower-case code (which, on SQLite, let the page add the upper-case one beside it, and the rule
    // set then threw on the duplicate), blank labels, and outcomes all inactive (no case could be closed).
    private static void CheckItems(ConfigBundle incoming, ConfigBundle live)
    {
        var problems = new List<string>();
        foreach (var r in incoming.NotificationRules ?? [])
        {
            var code = (r.Code ?? "").Trim();
            if (code.Length is 0 or > NotificationRuleService.MaxCodeLength)
                problems.Add($"A notification rule's code must be 1 to {NotificationRuleService.MaxCodeLength} characters (\"{code}\").");
            if (string.IsNullOrWhiteSpace(r.Label) || r.Label.Trim().Length > NotificationRuleService.MaxLabelLength)
                problems.Add($"Notification rule {code} needs a label of 1 to {NotificationRuleService.MaxLabelLength} characters.");
            if (r.WindowHours is <= 0 or > NotificationRuleService.MaxWindowHours)
                problems.Add($"Notification rule {code}'s window must be 1 to {NotificationRuleService.MaxWindowHours} hours (it's {r.WindowHours}).");
        }
        // BUG-267: playbook steps and gates get the pages' rules too.
        foreach (var t in incoming.CaseTemplates)
            foreach (var s in t.Steps)
            {
                if (string.IsNullOrWhiteSpace(s.Title)) problems.Add($"Playbook \"{t.Name}\" has a step with no title.");
                if (s.DueOffsetHours is < 0 or > CaseTemplateStep.MaxDueOffsetHours)
                    problems.Add($"Playbook \"{t.Name}\" step \"{s.Title}\": the due time must be 0 to {CaseTemplateStep.MaxDueOffsetHours:N0} hours.");
            }
        foreach (var g in incoming.StageGates.Where(g => g.CommentaryMinLength > StageGate.MaxCommentaryMinLength))
            problems.Add($"Stage gate \"{g.Name}\" asks for {g.CommentaryMinLength:N0} characters of commentary; the most is {StageGate.MaxCommentaryMinLength:N0}.");
        if ((incoming.CaseOutcomes ?? []).Any(o => string.IsNullOrWhiteSpace(o.Label)))
            problems.Add("Every case outcome needs a label.");
        if (incoming.DataElements.Any(d => string.IsNullOrWhiteSpace(d.Label)))
            problems.Add("Every data element needs a label.");
        // BUG-353: a key longer than its column was refused only at the save, as a generic length error.
        foreach (var d in incoming.DataElements.Where(d => d.Key is { Length: > DataElementService.MaxKeyLength }))
            problems.Add($"Data element \"{d.Label}\" has a key longer than {DataElementService.MaxKeyLength} characters.");
        foreach (var o in (incoming.CaseOutcomes ?? []).Where(o => o.Key is { Length: > CaseOutcomeService.MaxKeyLength }))
            problems.Add($"Case outcome \"{o.Label}\" has a key longer than {CaseOutcomeService.MaxKeyLength} characters.");
        if (incoming.CaseOutcomes is { Count: > 0 } outcomes)
        {
            var active = (live.CaseOutcomes ?? []).ToDictionary(o => o.Key, o => o.IsActive, StringComparer.OrdinalIgnoreCase);
            foreach (var o in outcomes) active[o.Key] = o.IsActive;
            if (!active.Values.Any(a => a)) problems.Add("It would leave no case outcome active, so no case could be closed.");
        }
        if (problems.Count > 0)
            throw new ArgumentException("This bundle can't be imported: " + string.Join(" ", problems));
    }

    /// <summary>
    /// WF-45: taxonomy keys get the Taxonomy page's rules, not free text: a label of at most its length, hiding and
    /// ordering only for a list that allows it, an order naming each member once, and at least one option left visible.
    /// A key for a list this version doesn't know is left alone (a newer server's bundle).
    /// </summary>
    private static void CheckTaxonomy(ConfigBundle incoming, ConfigBundle live)
    {
        var problems = new List<string>();
        var hidden = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var x in live.Settings.Where(x => x.Key.StartsWith(TaxonomyCatalog.KeyPrefix, StringComparison.OrdinalIgnoreCase)))
            hidden[x.Key] = string.Equals(x.Value?.Trim(), "true", StringComparison.OrdinalIgnoreCase);
        foreach (var x in incoming.Settings.Where(x => x.Key.StartsWith(TaxonomyCatalog.KeyPrefix, StringComparison.OrdinalIgnoreCase)))
        {
            var parts = x.Key.Split(':');
            var kind = parts.Length > 2 ? TaxonomyCatalog.Kinds.FirstOrDefault(k => string.Equals(k.Id, parts[1], StringComparison.OrdinalIgnoreCase)) : null;
            if (kind is null) continue;
            var value = x.Value?.Trim() ?? "";
            switch (parts[2].ToLowerInvariant())
            {
                case "label" when value.Length > TaxonomyAdminService.MaxLabelLength:
                    problems.Add($"A {kind.Title} label is longer than {TaxonomyAdminService.MaxLabelLength} characters.");
                    break;
                case "hidden" or "order" when !kind.AllowVisibilityOrder:
                    problems.Add($"{kind.Title} can't be hidden or reordered.");
                    break;
                case "hidden":
                    hidden[x.Key] = string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);
                    break;
                case "order":
                    var listed = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                    var members = kind.Members.Select(m => m.Value).ToHashSet(StringComparer.Ordinal);
                    // BUG-424: not necessarily all of them. An order saved before an option was added (Command line) lists the
                    // rest, and the option goes after them, as the admin page reads it (TaxonomyAdminService.OrderMembers).
                    if (value.Length > 0 && (!listed.All(members.Contains) || listed.Distinct(StringComparer.Ordinal).Count() != listed.Length))
                        problems.Add($"The order for {kind.Title} must list only its own options, each at most once.");
                    break;
            }
        }
        foreach (var kind in TaxonomyCatalog.Kinds.Where(k => k.AllowVisibilityOrder))
            if (kind.Members.All(m => hidden.GetValueOrDefault(TaxonomyCatalog.HiddenKey(kind.Id, m.Value))))
                problems.Add($"It would hide every {kind.Title} option; at least one must stay visible.");
        if (problems.Count > 0)
            throw new ArgumentException("This bundle can't be imported: " + string.Join(" ", problems.Distinct()));
    }

    private static List<ConfigRoleMapping> UnusableMappings(ConfigBundle incoming, IEnumerable<string> liveRoles)
    {
        var roles = liveRoles.Concat(incoming.Roles.Select(r => r.Name)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return incoming.RoleMappings.Where(m => string.IsNullOrWhiteSpace(m.AdGroup) || !roles.Contains(m.RoleName?.Trim() ?? "")).ToList();
    }

    private static void CheckNaturalKeys(ConfigBundle bundle)
    {
        static IEnumerable<string> Check<T>(string section, IEnumerable<T>? items, Func<T, string?> key) =>
            (items ?? []).Select(key).OfType<string>().GroupBy(k => k, StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Count() > 1)
                .Select(g => g.Distinct(StringComparer.Ordinal).ToList())
                // BUG-265: the same name twice is as ambiguous as two differing in case; both land on one row.
                .Select(names => names.Count > 1
                    ? $"{section} \"{string.Join("\" and \"", names)}\" differ only in case."
                    : $"{section}: \"{names[0]}\" appears more than once.");
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
        using var guard = await Admin.GuardGate.EnterAsync(ct);   // BUG-268: its last-admin and outcome checks, with the save
        // BUG-403: template files are staged and moved under the gate uploads and replaces hold (taken after GuardGate).
        using var files = await Admin.ReportTemplateService.EnterFileGateAsync(ct);
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

        var bundle = WithCommaJurisdictions(envelope.Bundle);   // after the signature check, which covers the bundle as signed
        var changedSettings = new List<string>();
        var changedRoles = new List<string>();
        var addedMappings = new List<string>();

        var (templateFiles, _) = await CheckReportTemplatesAsync(bundle, ct);
        CheckSettings(bundle);
        CheckNaturalKeys(bundle);
        var liveBefore = await BuildBundleAsync(ct);
        CheckSingleActiveGates(bundle, liveBefore);
        CheckItems(bundle, liveBefore);
        CheckTaxonomy(bundle, liveBefore);

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
                    PermissionsCsv = PermissionNames(r.PermissionsCsv), UpdatedAtUtc = now, UpdatedBy = actor });
                changedRoles.Add(r.Name);
                Tally(true, true);
            }
            else if (existing.IsSystem) { unchanged++; }   // never touch a system role via import
            else
            {
                var perms = PermissionNames(r.PermissionsCsv);
                var changed = existing.Description != r.Description
                              || !existing.GetPermissions().SetEquals(Role.ParsePermissions(perms));
                if (changed) { existing.Description = r.Description; existing.PermissionsCsv = perms; existing.UpdatedAtUtc = now; existing.UpdatedBy = actor; changedRoles.Add(r.Name); }
                Tally(false, changed);
            }
        }

        // --- AD mappings (existence grants; create if missing) ---
        var mappings = await db.RoleMappings.ToListAsync(ct);
        foreach (var raw in bundle.RoleMappings)
        {
            // WF-45: as the Roles page: a mapping needs an AD group and a role that exists (one this bundle adds counts),
            // stored with the role's own spelling. A dormant grant would otherwise wait for a later role of that name.
            // Skipped as the preview said it would be.
            var group = (raw.AdGroup ?? "").Trim();
            if (group.Length == 0) { unchanged++; continue; }
            var role = db.Roles.Local.FirstOrDefault(x => string.Equals(x.Name, raw.RoleName?.Trim(), StringComparison.OrdinalIgnoreCase));
            if (role is null) { unchanged++; continue; }
            var m = raw with { AdGroup = group, RoleName = role.Name };
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
                existing.Name = t.Name;   // BUG-240: matched ignoring case; take the bundle's, or every import updates it again
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
                    Description = g.Description, CommentaryMinLength = StageGate.ClampCommentary(g.CommentaryMinLength),
                    CreatedBy = actor, CreatedAtUtc = now };
                created.Requirements = g.Requirements.Select(r => NewRequirement(created.Id, r)).ToList();
                db.StageGates.Add(created);
                Tally(true, true);
            }
            else if (Canon(g) == Canon(ToConfig(existing))) { unchanged++; }
            else
            {
                existing.Name = g.Name;   // BUG-240: as for case templates
                existing.Trigger = trigger; existing.IsActive = g.IsActive; existing.Description = g.Description;
                existing.CommentaryMinLength = StageGate.ClampCommentary(g.CommentaryMinLength);
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
        // BUG-238: each staged file's row and what it described before, to put back if the file can't be put in place.
        var stagedRows = new Dictionary<Reporting.StagedTemplate, (ReportTemplate Row, (string FileName, string Sha256, long Size)? Before)>();
        // BUG-524: duplicate live names were refused by CheckReportTemplatesAsync when the bundle carries templates (only then
        // is the library matched by name); an older bundle leaves the library alone, so a duplicate doesn't stop it.
        var library = new Dictionary<string, ReportTemplate>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in libraryRows)
            if (!library.TryAdd(row.Name, row) && bundle.ReportTemplates is not null)
                throw new InvalidOperationException("This bundle can't be imported. " + DuplicateLiveTemplate(row.Name));
        foreach (var t in bundle.ReportTemplates ?? [])
        {
            var bytes = templateFiles[t.Name];
            var fileName = Path.GetFileName(t.FileName);
            if (!library.TryGetValue(t.Name, out var existing))
            {
                var created = new ReportTemplate { Name = t.Name, FileName = fileName, IsActive = t.IsActive,
                    IsLessonsDefault = t.LessonsDefault,
                    Sha256 = t.Sha256.ToLowerInvariant(), SizeBytes = bytes.LongLength, CreatedBy = actor, CreatedAtUtc = now };
                var s = await _templateStore!.StageAsync(created.Id, bytes, ct);
                staged.Add(s);
                stagedRows[s] = (created, null);
                db.ReportTemplates.Add(created);
                library[t.Name] = created;
                Tally(true, true);
            }
            else
            {
                var fileChanged = !string.Equals(existing.Sha256, t.Sha256, StringComparison.OrdinalIgnoreCase);
                var changed = fileChanged || existing.Name != t.Name || existing.FileName != fileName
                    || existing.IsActive != t.IsActive || existing.IsLessonsDefault != t.LessonsDefault;
                if (fileChanged)
                {
                    var s = await _templateStore!.StageAsync(existing.Id, bytes, ct);
                    staged.Add(s);
                    stagedRows[s] = (existing, (existing.FileName, existing.Sha256, existing.SizeBytes));
                }
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
                    SortOrder = o.SortOrder, IsActive = o.IsActive, IsSystem = false, CreatedBy = actor, CreatedAtUtc = now });   // WF-45: built-ins are seeded, not imported
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
        var rescoped = new List<string>();
        foreach (var d in bundle.DataElements)
        {
            var existing = elements.FirstOrDefault(x => string.Equals(x.Key, d.Key, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                db.DataElements.Add(new DataElement { Key = d.Key, Label = d.Label,
                    SortOrder = d.SortOrder, IsActive = d.IsActive, IsSystem = false,   // WF-45: built-ins are seeded, not imported
                   
                    NotificationJurisdictions = d.NotificationJurisdictions, CreatedBy = actor, CreatedAtUtc = now });
                Tally(true, true);
            }
            else
            {
                var changed = existing.Label != d.Label || existing.SortOrder != d.SortOrder
                    || existing.IsActive != d.IsActive || existing.NotificationJurisdictions != d.NotificationJurisdictions;
                if (changed && !string.Equals(existing.NotificationJurisdictions ?? "", d.NotificationJurisdictions ?? "", StringComparison.OrdinalIgnoreCase))
                    rescoped.Add(existing.Key);   // WF-11
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
                // REV-49: codes are upper-case, as the page saves them.
                db.NotificationRules.Add(new NotificationRule { Code = r.Code.Trim().ToUpperInvariant(), Label = r.Label.Trim(),
                    WindowHours = r.WindowHours, IsActive = r.IsActive, IsSystem = false,   // WF-45: built-ins are seeded, not imported
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

        try
        {
            // WF-11: as the Data elements page: cases not yet reported are judged on the imported jurisdictions. BUG-390: in
            // the import's own save, so a recheck that fails can't leave the import saved and the cases never rechecked.
            await Compliance.NotificationDeadlineService.RecheckUnreportedAsync(db, rescoped, db.DataElements.Local, actor, now, ct);
            await db.SaveChangesAsync(ct);
        }
        catch
        {
            foreach (var s in staged) await _templateStore!.DiscardAsync(s);
            throw;
        }
        // BUG-390: committed, so the settings reload, the role-cache invalidation and the SIEM events happen whatever fails
        // after this point (the template row put back, the audit line), not only when all of it works.
        var notPlaced = new List<string>();
        try
        {
            // BUG-238: a file that can't be put in place (open, read-only) mustn't stop what follows: the roles, mappings and
            // settings are already saved, so they're applied and streamed to the SIEM whatever happens to a template file.
            // Its row goes back to the file still there (or, for a new template, is archived until a file is uploaded).
            foreach (var s in staged)
            {
                try { await _templateStore!.CommitAsync(s, ct); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    var (row, before) = stagedRows[s];
                    notPlaced.Add(row.Name);
                    try { await _templateStore!.DiscardAsync(s); } catch (Exception d) when (d is IOException or UnauthorizedAccessException) { }
                    if (before is { } b) (row.FileName, row.Sha256, row.SizeBytes) = b;
                    else { row.IsActive = false; row.IsLessonsDefault = false; }
                }
            }
            if (notPlaced.Count > 0) await db.SaveChangesAsync(CancellationToken.None);
            await _audit.RecordAsync(AuditAction.Update, "ConfigBundle", null, null,
                $"Imported configuration bundle ({added} added, {updated} updated, {unchanged} unchanged)" +
                (foreignKey ? $", signed with key {envelope.KeyId} (not this server's), source confirmed trusted" : "") +
                (notPlaced.Count > 0 ? $"; the file for {string.Join(", ", notPlaced)} couldn't be put in place and was left as it was" : ""),
                CancellationToken.None);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new InvalidOperationException("The bundle was imported and is in effect, but a step after saving it failed: " +
                ex.Message, ex);
        }
        finally
        {
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
        }

        return new ConfigImportResult(added, updated, unchanged, _roles?.IsCurrent ?? true, notPlaced,
            changedSettings.Count > 0 ? _reloader?.LastError : null);   // BUG-270
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
        // BUG-524: two live templates with one name, ignoring case (stored before the name check ran under the library
        // gate) can't be matched by name, so the import stops with their name instead of a raw "same key" error.
        foreach (var dup in liveTemplates.GroupBy(t => t.Name, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1)
                     .Select(g => g.Key).Order(StringComparer.Ordinal))
            problems.Add(DuplicateLiveTemplate(dup));
        var active = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in liveTemplates) active.TryAdd(t.Name, t.IsActive);
        foreach (var t in bundle.ReportTemplates.Where(t => files.ContainsKey(t.Name ?? ""))) active[t.Name] = t.IsActive;
        var liveNames = liveTemplates.ToDictionary(t => t.Id, t => t.Name);
        var defaults = (await db.ReportProfiles.AsNoTracking().Where(p => p.TemplateId != null)
                .Select(p => new { p.Name, p.TemplateId }).ToListAsync(ct))
            .ToDictionary(p => p.Name, p => liveNames.GetValueOrDefault(p.TemplateId!.Value), StringComparer.OrdinalIgnoreCase);   // BUG-240
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

    // BUG-524: names the duplicate and what to do, for the check above and the import's library lookup.
    private static string DuplicateLiveTemplate(string name) =>
        $"More than one Word template on this server is named \"{name}\" (names match regardless of case). Rename one under Word templates " +
        "on the Administration page, then import again.";

    // WF-45: a known check's threshold is clamped to its floor (defaulted when absent) and a parameterless one carries none,
    // as on the Gates page: "at least 0 evidence items" passed every case. An unknown check keeps its value for review.
    private static int? Threshold(ConfigGateRequirement r) =>
        GateCheckRegistry.Param(r.Check) is { } spec ? Math.Max(spec.Min, r.CheckParam ?? spec.Default)
        : GateCheckRegistry.IsKnown(r.Check) ? null : r.CheckParam;

    // WF-45: permissions by name, as the Roles page writes them.
    private static string PermissionNames(string? csv) => Role.ToCsv(Role.ParsePermissions(csv));

    private static StageGateRequirement NewRequirement(Guid gateId, ConfigGateRequirement r) => new()
    {
        GateId = gateId,
        Order = r.Order,
        Kind = ParseEnum<GateRequirementKind>(r.Kind) ?? GateRequirementKind.Attestation,
        // The bundle carries the machine check as its stable registry key (the ConfigGateRequirement
        // field is still named Check). An unrecognised key is preserved verbatim — the evaluator treats
        // it as unmet and flags it for review, rather than dropping it, so a cross-version bundle is safe.
        CheckKey = string.IsNullOrWhiteSpace(r.Check) ? null : r.Check,
        CheckParam = Threshold(r),
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
