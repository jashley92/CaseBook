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

    // BUG-41: TLP 2.0 marking definitions, as published by OASIS (cti-stix-common-objects, extension-definition tlp-2.0).
    private const string Tlp2Extension = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d";
    private static readonly IReadOnlyDictionary<TlpLevel, (string Id, string Name, string Value)> TlpMarkings =
        new Dictionary<TlpLevel, (string, string, string)>
        {
            [TlpLevel.Clear] = ("marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", "TLP:CLEAR", "clear"),
            [TlpLevel.Green] = ("marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb", "TLP:GREEN", "green"),
            [TlpLevel.Amber] = ("marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421", "TLP:AMBER", "amber"),
            [TlpLevel.AmberStrict] = ("marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003", "TLP:AMBER+STRICT", "amber+strict"),
            [TlpLevel.Red] = ("marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1", "TLP:RED", "red"),
        };

    private static string[]? MarkingRefs(TlpLevel? tlp) => tlp is { } t ? [TlpMarkings[t].Id] : null;

    private static Dictionary<string, object?> MarkingDefinition(TlpLevel t) => new()
    {
        ["type"] = "marking-definition",
        ["spec_version"] = Spec,
        ["id"] = TlpMarkings[t].Id,
        ["created"] = "2022-10-01T00:00:00.000Z",
        ["name"] = TlpMarkings[t].Name,
        ["extensions"] = new Dictionary<string, object?>
        {
            [Tlp2Extension] = new Dictionary<string, object?> { ["extension_type"] = "property-extension", ["tlp_2_0"] = TlpMarkings[t].Value }
        },
    };

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
            .Select(x => new { x.Id, x.CaseNumber, x.Title, x.Summary, x.Classification, x.Severity, x.CreatedAtUtc })
            .FirstOrDefaultAsync(ct);
        if (c is null) return null;

        var entities = await db.CaseEntities.AsNoTracking().Where(e => e.CaseId == caseId).ToListAsync(ct);
        var relationships = await db.EntityRelationships.AsNoTracking().Where(r => r.CaseId == caseId).ToListAsync(ct);

        var now = _clock.UtcNow;
        var objects = new List<Dictionary<string, object?>>();
        var identityId = IdentityId;

        // One SCO per entity; remember the mapped STIX id so relationships can reference it.
        var stixIdByEntity = new Dictionary<Guid, string>();
        // BUG-73: an entity without its own marking carries the default, as it does in the Word report, so a bundle never
        // goes out unmarked (a TIP reads no marking as unrestricted).
        var fallback = _reporting.CurrentValue.EffectiveDefaultTlp;
        var tlpByEntity = entities.ToDictionary(e => e.Id, e => (TlpLevel?)(e.Tlp ?? fallback));
        foreach (var e in entities.OrderBy(e => e.CreatedAtUtc))
        {
            var sco = MapEntity(e, tlpByEntity[e.Id]);
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
                // A relationship is as sensitive as the more restricted of its two ends.
                ["object_marking_refs"] = MarkingRefs(Max(tlpByEntity.GetValueOrDefault(r.SourceEntityId), tlpByEntity.GetValueOrDefault(r.TargetEntityId))),
            }));
        }

        var used = tlpByEntity.Values.Select(t => t!.Value).Append(fallback).Distinct().Order().ToList();
        // report SDO tying the graph together with the case metadata.
        var bundle = Bundle(objects, used, objectRefs => new()
        {
            ["type"] = "report",
            ["spec_version"] = Spec,
            ["id"] = $"report--{c.Id}",
            ["created"] = Ts(c.CreatedAtUtc),   // BUG-248: one report per case, first created with the case; each export a new version
            ["modified"] = Ts(now < c.CreatedAtUtc ? c.CreatedAtUtc : now),
            ["created_by_ref"] = identityId,
            ["name"] = $"{c.CaseNumber} — {c.Title}",
            ["description"] = Nullify(c.Summary),
            ["report_types"] = new[] { "threat-report" },
            ["published"] = Ts(now),
            ["object_refs"] = objectRefs,
            ["x_casebook_case_number"] = c.CaseNumber,
            ["x_casebook_classification"] = c.Classification?.ToString(),
            ["x_casebook_severity"] = c.Severity.ToString(),
            // The report carries the most restricted marking of anything it contains, and at least the default (its
            // title and summary are the case's).
            ["object_marking_refs"] = MarkingRefs(used.Max()),
        });
        return new StixBundleResult(c.CaseNumber, bundle);
    }

    /// <summary>
    /// CAP-09: the IOC feed (<see cref="IocFeedService"/>) as a STIX 2.1 bundle: one cyber-observable per indicator, across
    /// the cases the feed drew on, each with its own marking (WF-37/79: the most restrictive of its occurrences, the default
    /// where none was set), its case numbers, sources and first and last seen. An indicator's id is derived from its type and
    /// value, so it's the same object in every pull and a TIP updates it rather than adding another. A report SDO ties them
    /// together and says what narrowed the feed (a delta's start, a cut).
    /// </summary>
    public IReadOnlyDictionary<string, object?> BuildFeed(IocFeed feed)
    {
        var now = _clock.UtcNow;
        var fallback = _reporting.CurrentValue.EffectiveDefaultTlp;
        var objects = new List<Dictionary<string, object?>>();
        foreach (var r in feed.Rows)
        {
            var tlp = r.Tlp ?? fallback;
            var o = Sco(Deterministic("indicator", $"{r.Type}:{r.Value.Trim().ToLowerInvariant()}").ToString(), r.Type, r.Value, tlp);
            o["x_casebook_disposition"] = nameof(EntityDisposition.Malicious);
            o["x_casebook_cases"] = r.Cases;
            if (r.Sources.Count > 0) o["x_casebook_sources"] = r.Sources;
            o["x_casebook_first_seen"] = Ts(r.FirstSeenUtc);
            o["x_casebook_last_seen"] = Ts(r.LastSeenUtc);
            objects.Add(Prune(o));
        }

        var used = feed.Rows.Select(r => r.Tlp ?? fallback).Append(fallback).Distinct().Order().ToList();
        var org = OrgName;
        return Bundle(objects, used, objectRefs => Prune(new()
        {
            ["type"] = "report",
            ["spec_version"] = Spec,
            ["id"] = $"report--{Deterministic("ioc-feed", org)}",
            // As the identity (BUG-248): the same report every pull, each a new version of it.
            ["created"] = IdentityCreated,
            ["modified"] = Ts(now),
            ["created_by_ref"] = IdentityId,
            ["name"] = $"{org} malicious-IOC feed",
            ["description"] = FeedDescription(feed),
            ["report_types"] = new[] { "indicator" },
            ["published"] = Ts(now),
            ["object_refs"] = objectRefs,
            ["x_casebook_since"] = feed.Since is { } since ? Ts(since) : null,
            ["x_casebook_truncated"] = feed.Cut ? true : null,
            ["object_marking_refs"] = MarkingRefs(used.Max()),
        }));
    }

    /// <summary>
    /// CAP-09: <see cref="IocFeed.Fingerprint"/> for this format, which also names the organization. CAP-09 review: and the
    /// default marking, which the bundle always lists (and which marks the report when it's the strictest), so changing it
    /// isn't answered 304 even where every indicator carries a marking of its own.
    /// </summary>
    public string Fingerprint(IocFeed feed) =>
        feed.Fingerprint(string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"stix|{OrgName}|{(int)_reporting.CurrentValue.EffectiveDefaultTlp}"));

    private static string FeedDescription(IocFeed feed)
    {
        var text = "Confirmed-malicious indicators across the cases this feed's token can see (exercises excluded).";
        if (feed.Since is { } since)
            text += $" Only those added or changed since {Ts(since)}; indicators that left the feed aren't listed.";
        if (feed.Cut)
            text += string.Create(CultureInfo.InvariantCulture,
                $" Cut: more than {feed.Limit:N0} indicator occurrences match, so this holds the most recently changed indicators, each whole, up to {feed.Limit:N0} occurrences.");
        return text;
    }

    // The organization's identity: the same id (derived from its name) in every export.
    private string IdentityId => $"identity--{Deterministic("identity", OrgName)}";

    /// <summary>
    /// The bundle around <paramref name="body"/> (SCOs and SROs): the exporting organization's identity first, then the
    /// report <paramref name="report"/> builds from every object's id, then the marking definitions
    /// <paramref name="used"/>, so a consumer that doesn't know TLP 2.0 can still read them, then the body.
    /// </summary>
    private Dictionary<string, object?> Bundle(List<Dictionary<string, object?>> body, IReadOnlyList<TlpLevel> used,
        Func<List<string>, Dictionary<string, object?>> report)
    {
        var objects = new List<Dictionary<string, object?>>
        {
            Prune(new()
            {
                ["type"] = "identity",
                ["spec_version"] = Spec,
                ["id"] = IdentityId,
                // BUG-248: the same object every export (its id is derived from the name), so the same created and modified:
                // STIX 2.1 says created never changes across versions, and a TIP sees a new one as a conflicting object.
                ["created"] = IdentityCreated,
                ["modified"] = IdentityCreated,
                ["name"] = OrgName,
                ["identity_class"] = "organization",
            }),
        };
        objects.AddRange(used.Select(MarkingDefinition));
        objects.AddRange(body);
        objects.Insert(1, Prune(report(objects.Select(o => (string)o["id"]!).ToList())));   // right after the identity, for readability

        return new Dictionary<string, object?>
        {
            ["type"] = "bundle",
            ["id"] = $"bundle--{Guid.NewGuid()}",
            ["objects"] = objects,
        };
    }

    /// <summary>Maps a case entity to the closest STIX 2.1 cyber-observable object.</summary>
    private static Dictionary<string, object?> MapEntity(CaseEntity e, TlpLevel? tlp)
    {
        var o = Sco(e.Id.ToString(), e.Type, e.Value, tlp);
        o["x_casebook_disposition"] = e.Disposition.ToString();
        if (!string.IsNullOrWhiteSpace(e.Label)) o["x_casebook_label"] = e.Label!.Trim();
        if (!string.IsNullOrWhiteSpace(e.Source)) o["x_casebook_source"] = e.Source!.Trim();
        if (!string.IsNullOrWhiteSpace(e.Description)) o["x_casebook_description"] = e.Description!.Trim();
        return Prune(o);
    }

    /// <summary>CAP-09: an indicator as the closest STIX 2.1 cyber-observable, marked, with its CaseBook type; whoever
    /// calls adds the rest of what rides along (verdict, provenance) as custom properties.</summary>
    private static Dictionary<string, object?> Sco(string uuid, EntityType type, string value, TlpLevel? tlp)
    {
        var (stixType, props) = Observable(type, value);
        var o = new Dictionary<string, object?>
        {
            ["type"] = stixType,
            ["spec_version"] = Spec,
            ["id"] = $"{stixType}--{uuid}",
        };
        foreach (var (k, v) in props) o[k] = v;

        o["object_marking_refs"] = MarkingRefs(tlp);   // BUG-41: the indicator's TLP, so a TLP:RED IOC isn't shared unmarked
        // Analyst verdict + provenance travel as spec-legal custom properties.
        o["x_casebook_entity_type"] = type.ToString();
        return o;
    }

    /// <summary>The STIX SCO type + its identifying properties for an entity. Falls back to a custom SCO.</summary>
    private static (string Type, Dictionary<string, object?> Props) Observable(EntityType type, string value)
    {
        var v = value.Trim();
        return type switch
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
            EntityType.CommandLine => ("process", new() { ["command_line"] = v }),   // BUG-415
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
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S4790:Using weak hashing algorithms is security-sensitive",
        Justification = "RFC 4122 name-based UUID derivation, not a security use.")]
    internal static Guid Deterministic(string ns, string name)
    {
        // BUG-201: a real name-based (v5) UUID, in the URL namespace. STIX 2.1 requires an RFC 4122 UUID, and SHA-1 bytes
        // copied straight into a Guid carry no version or variant, so strict consumers refused the bundle.
        var input = UrlNamespace.ToByteArray(bigEndian: true)
            .Concat(System.Text.Encoding.UTF8.GetBytes($"urn:casebook:{ns}:{name}")).ToArray();
        var g = System.Security.Cryptography.SHA1.HashData(input)[..16];
        g[6] = (byte)((g[6] & 0x0F) | 0x50);   // version 5
        g[8] = (byte)((g[8] & 0x3F) | 0x80);   // the RFC 4122 variant
        return new Guid(g, bigEndian: true);
    }

    private static readonly Guid UrlNamespace = new("6ba7b811-9dad-11d1-80b4-00c04fd430c8");   // RFC 4122 appendix C

    // BUG-248: a fixed time for the organization's identity object (any constant will do; it never changes).
    private const string IdentityCreated = "2026-01-01T00:00:00.000Z";

    private static TlpLevel? Max(TlpLevel? a, TlpLevel? b) => a is null ? b : b is null ? a : (TlpLevel)Math.Max((int)a, (int)b);

    private static Dictionary<string, object?> Prune(Dictionary<string, object?> o)
    {
        foreach (var k in o.Where(kv => kv.Value is null).Select(kv => kv.Key).ToList()) o.Remove(k);
        return o;
    }
}
