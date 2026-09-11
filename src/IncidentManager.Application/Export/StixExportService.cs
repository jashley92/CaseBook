using System.Globalization;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentManager.Application.Export;

/// <summary>A serialized STIX 2.1 bundle plus the source case number, for naming the download.</summary>
public sealed record StixBundleResult(string CaseNumber, IReadOnlyDictionary<string, object?> Bundle);

/// <summary>
/// Exports a case's entity-relationship investigation graph as a STIX 2.1 bundle (E-07) — a shareable,
/// standards-based artifact a SOC can hand to a partner or ingest into XSIAM / a TIP / MISP. Entities become
/// cyber-observable objects (SCOs), relationships become relationship SROs, and a <c>report</c> SDO ties
/// them together with the case metadata. Need-to-know scoped via <see cref="CaseQueryExtensions.ForUser"/>;
/// read-only (records nothing, out of the audit chain). The analyst verdict and provenance ride along as
/// <c>x_casebook_*</c> custom properties so no fidelity is lost while the bundle stays spec-valid.
/// </summary>
public sealed class StixExportService
{
    private const string Spec = "2.1";

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IOptionsMonitor<ReportingOptions> _reporting;

    public StixExportService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        IOptionsMonitor<ReportingOptions> reporting)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _reporting = reporting;
    }

    private string OrgName => string.IsNullOrWhiteSpace(_reporting.CurrentValue.OrganizationName)
        ? "CaseBook" : _reporting.CurrentValue.OrganizationName!.Trim();

    /// <summary>Builds the bundle for a visible case, or <c>null</c> if the case is not found / not visible.</summary>
    public async Task<StixBundleResult?> BuildAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();

        var c = await db.Cases.AsNoTracking().ForUser(_user)
            .Where(x => x.Id == caseId)
            .Select(x => new { x.Id, x.CaseNumber, x.Title, x.Summary, x.Classification, x.Severity })
            .FirstOrDefaultAsync(ct);
        if (c is null) return null;

        var entities = await db.CaseEntities.AsNoTracking().Where(e => e.CaseId == caseId).ToListAsync(ct);
        var relationships = await db.EntityRelationships.AsNoTracking().Where(r => r.CaseId == caseId).ToListAsync(ct);

        var now = _clock.UtcNow;
        var objects = new List<Dictionary<string, object?>>();

        // created-by identity (the exporting org).
        var org = OrgName;
        var identityId = $"identity--{Deterministic("identity", org)}";
        objects.Add(Prune(new()
        {
            ["type"] = "identity",
            ["spec_version"] = Spec,
            ["id"] = identityId,
            ["created"] = Ts(now),
            ["modified"] = Ts(now),
            ["name"] = org,
            ["identity_class"] = "organization",
        }));

        // One SCO per entity; remember the mapped STIX id so relationships can reference it.
        var stixIdByEntity = new Dictionary<Guid, string>();
        foreach (var e in entities.OrderBy(e => e.CreatedAtUtc))
        {
            var sco = MapEntity(e);
            stixIdByEntity[e.Id] = (string)sco["id"]!;
            objects.Add(sco);
        }

        // Relationship SROs — only those whose both endpoints are present in this case's export.
        foreach (var r in relationships.OrderBy(r => r.CreatedAtUtc))
        {
            if (!stixIdByEntity.TryGetValue(r.SourceEntityId, out var src)) continue;
            if (!stixIdByEntity.TryGetValue(r.TargetEntityId, out var tgt)) continue;
            objects.Add(Prune(new()
            {
                ["type"] = "relationship",
                ["spec_version"] = Spec,
                ["id"] = $"relationship--{r.Id}",
                ["created"] = Ts(r.CreatedAtUtc),
                ["modified"] = Ts(r.CreatedAtUtc),
                ["relationship_type"] = Kebab(r.Type.ToString()),
                ["source_ref"] = src,
                ["target_ref"] = tgt,
                ["description"] = Nullify(r.Description),
                ["created_by_ref"] = identityId,
            }));
        }

        // report SDO tying the graph together with the case metadata.
        var objectRefs = objects.Select(o => (string)o["id"]!).ToList();
        objects.Insert(1, Prune(new()   // right after the identity, before the SCOs, for readability
        {
            ["type"] = "report",
            ["spec_version"] = Spec,
            ["id"] = $"report--{c.Id}",
            ["created"] = Ts(now),
            ["modified"] = Ts(now),
            ["created_by_ref"] = identityId,
            ["name"] = $"{c.CaseNumber} — {c.Title}",
            ["description"] = Nullify(c.Summary),
            ["report_types"] = new[] { "threat-report" },
            ["published"] = Ts(now),
            ["object_refs"] = objectRefs,
            ["x_casebook_case_number"] = c.CaseNumber,
            ["x_casebook_classification"] = c.Classification?.ToString(),
            ["x_casebook_severity"] = c.Severity.ToString(),
        }));

        var bundle = new Dictionary<string, object?>
        {
            ["type"] = "bundle",
            ["id"] = $"bundle--{Guid.NewGuid()}",
            ["objects"] = objects,
        };
        return new StixBundleResult(c.CaseNumber, bundle);
    }

    /// <summary>Maps a case entity to the closest STIX 2.1 cyber-observable object.</summary>
    private static Dictionary<string, object?> MapEntity(CaseEntity e)
    {
        var (stixType, props) = Observable(e);
        var o = new Dictionary<string, object?>
        {
            ["type"] = stixType,
            ["spec_version"] = Spec,
            ["id"] = $"{stixType}--{e.Id}",
        };
        foreach (var (k, v) in props) o[k] = v;

        // Analyst verdict + provenance travel as spec-legal custom properties.
        o["x_casebook_entity_type"] = e.Type.ToString();
        o["x_casebook_disposition"] = e.Disposition.ToString();
        if (!string.IsNullOrWhiteSpace(e.Label)) o["x_casebook_label"] = e.Label!.Trim();
        if (!string.IsNullOrWhiteSpace(e.Source)) o["x_casebook_source"] = e.Source!.Trim();
        if (!string.IsNullOrWhiteSpace(e.Description)) o["x_casebook_description"] = e.Description!.Trim();
        return Prune(o);
    }

    /// <summary>The STIX SCO type + its identifying properties for an entity. Falls back to a custom SCO.</summary>
    private static (string Type, Dictionary<string, object?> Props) Observable(CaseEntity e)
    {
        var v = e.Value.Trim();
        return e.Type switch
        {
            EntityType.IpAddress => (v.Contains(':') ? "ipv6-addr" : "ipv4-addr", new() { ["value"] = v }),
            EntityType.Domain => ("domain-name", new() { ["value"] = v }),
            EntityType.Url => ("url", new() { ["value"] = v }),
            EntityType.EmailAddress => ("email-addr", new() { ["value"] = v }),
            EntityType.FileHash => ("file", new() { ["hashes"] = HashDict(v) }),
            EntityType.FileName => ("file", new() { ["name"] = v }),
            EntityType.RegistryKey => ("windows-registry-key", new() { ["key"] = v }),
            EntityType.Account => ("user-account", new() { ["account_login"] = v }),
            EntityType.Process => ("process", new() { ["command_line"] = v }),
            // Host and Other have no native SCO — emit a spec-legal custom SCO so the node still exports.
            _ => ("x-casebook-artifact", new() { ["value"] = v }),
        };
    }

    /// <summary>Guesses the hash algorithm from the digest length (MD5/SHA-1/SHA-256), else labels it generically.</summary>
    private static Dictionary<string, object?> HashDict(string digest)
    {
        var key = digest.Trim().Length switch { 32 => "MD5", 40 => "SHA-1", 64 => "SHA-256", _ => "x_casebook_hash" };
        return new Dictionary<string, object?> { [key] = digest.Trim() };
    }

    private static string Ts(DateTimeOffset t) =>
        t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    private static string Kebab(string pascal)
    {
        var sb = new System.Text.StringBuilder(pascal.Length + 4);
        for (var i = 0; i < pascal.Length; i++)
        {
            var ch = pascal[i];
            if (char.IsUpper(ch) && i > 0) sb.Append('-');
            sb.Append(char.ToLowerInvariant(ch));
        }
        return sb.ToString();
    }

    private static string? Nullify(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    // A stable UUID (v5-style, name-based) so the org identity id is deterministic across exports.
    // SHA-1 here is the algorithm RFC 4122 §4.3 specifies for name-based (v5) UUIDs — a deterministic
    // identifier, not a security primitive; there is nothing secret to protect.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms",
        Justification = "RFC 4122 name-based UUID derivation, not a security use.")]
    private static Guid Deterministic(string ns, string name)
    {
        var bytes = System.Security.Cryptography.SHA1.HashData(
            System.Text.Encoding.UTF8.GetBytes($"casebook:{ns}:{name}"));
        var g = new byte[16];
        Array.Copy(bytes, g, 16);
        return new Guid(g);
    }

    private static Dictionary<string, object?> Prune(Dictionary<string, object?> o)
    {
        foreach (var k in o.Where(kv => kv.Value is null).Select(kv => kv.Key).ToList()) o.Remove(k);
        return o;
    }
}
