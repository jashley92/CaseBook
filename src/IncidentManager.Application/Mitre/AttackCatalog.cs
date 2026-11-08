using System.Collections.Immutable;
using System.Text.Json;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Mitre;

/// <summary>
/// The embedded MITRE ATT&amp;CK Enterprise catalog (v19.1), loaded once from a generated JSON
/// resource. Backs the technique picker: exact-id lookup (<see cref="Find"/>) and a ranked
/// type-ahead (<see cref="Search"/>). Pure reference data — no DB, no network (the app is
/// on-prem / air-gapped); refresh by regenerating <c>Mitre/attack-techniques.json</c>.
/// </summary>
public static class AttackCatalog
{
    /// <summary>The ATT&amp;CK version the embedded catalog was generated from.</summary>
    public const string Version = "v19.1";

    private static readonly Lazy<ImmutableArray<AttackTechnique>> _all = new(Load);
    private static readonly Lazy<Dictionary<string, RetiredTechnique>> _retired = new(LoadRetired);

    /// <summary>
    /// A technique ATT&amp;CK revoked or deprecated (null for a live or unknown id), with the live technique that replaced
    /// it if any. Reporting keeps citing old ids (T1574.002, merged into T1574.001), so the picker says where one went
    /// rather than only keeping it as a custom id. From <c>attack-retired.json</c>, generated with the catalog.
    /// </summary>
    public static RetiredTechnique? Retired(string? techniqueId) =>
        string.IsNullOrWhiteSpace(techniqueId) ? null : _retired.Value.GetValueOrDefault(techniqueId.Trim());

    /// <summary>"T1574.002 (DLL Side-Loading) is no longer in ATT&amp;CK v19.1: it was replaced by T1574.001 DLL.", or that
    /// it has no replacement.</summary>
    public static string RetiredText(RetiredTechnique r) => r.ReplacedBy is { } by
        ? $"{r.Id} ({r.Name}) is no longer in ATT&CK {Version}: it was replaced by {by.Id} {by.Name}."
        : $"{r.Id} ({r.Name}) is no longer in ATT&CK {Version}: it was deprecated with no replacement.";

    /// <summary>
    /// The tactic a retired id's tag moves to when it's replaced: the one it had, if the replacement is under that tactic
    /// too, else the replacement's primary (first in matrix order) tactic. A tag is a technique under a tactic, and the
    /// replacement may not sit under the old one.
    /// </summary>
    public static MitreTactic ReplacementTactic(AttackTechnique replacement, MitreTactic had) =>
        replacement.Tactics.Contains(had) ? had : replacement.PrimaryTactic;

    /// <summary>Every live (non-revoked, non-deprecated) technique and sub-technique, ordered by id.</summary>
    public static ImmutableArray<AttackTechnique> All => _all.Value;

    /// <summary>Exact technique-id lookup (case-insensitive), e.g. <c>t1566.001</c>. Null if not in the catalog.</summary>
    public static AttackTechnique? Find(string? techniqueId)
    {
        if (string.IsNullOrWhiteSpace(techniqueId)) return null;
        var id = techniqueId.Trim();
        foreach (var t in All)
            if (string.Equals(t.Id, id, StringComparison.OrdinalIgnoreCase))
                return t;
        return null;
    }

    /// <summary>
    /// Type-ahead over the catalog: matches an id prefix or a name substring (case-insensitive),
    /// ranked so the most useful hits come first (exact id → id-prefix → name-prefix → name/id
    /// contains), capped at <paramref name="limit"/>. An empty query returns the top-level techniques.
    /// </summary>
    public static IReadOnlyList<AttackTechnique> Search(string? query, int limit = 20)
    {
        if (limit <= 0) return Array.Empty<AttackTechnique>();
        var q = (query ?? string.Empty).Trim();
        if (q.Length == 0)
            return All.Where(t => !t.IsSubtechnique).Take(limit).ToList();

        var ql = q.ToLowerInvariant();
        return All
            .Select(t => (t, score: MatchScore(t, ql)))
            .Where(x => x.score < int.MaxValue)
            .OrderBy(x => x.score)
            .ThenBy(x => x.t.Id, StringComparer.OrdinalIgnoreCase)
            .Take(limit)
            .Select(x => x.t)
            .ToList();
    }

    private static int MatchScore(AttackTechnique t, string ql)
    {
        var id = t.Id.ToLowerInvariant();
        var name = t.Name.ToLowerInvariant();
        if (id == ql) return 0;
        if (id.StartsWith(ql, StringComparison.Ordinal)) return 1;
        if (name.StartsWith(ql, StringComparison.Ordinal)) return 2;
        if (name.Contains(ql, StringComparison.Ordinal)) return 3;
        if (id.Contains(ql, StringComparison.Ordinal)) return 4;
        return int.MaxValue;
    }

    /// <summary>Whether a technique matches <paramref name="filter"/>: its id or name contains it, ignoring case.
    /// Everything matches an empty one. <see cref="Search"/> ranks matches; the matrix picker (AttackMatrixView) shows them.</summary>
    public static bool Matches(AttackTechnique t, string filter) =>
        filter.Length == 0
        || t.Id.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || t.Name.Contains(filter, StringComparison.OrdinalIgnoreCase);

    private static ImmutableArray<AttackTechnique> Load()
    {
        var asm = typeof(AttackCatalog).Assembly;
        var resourceName = Array.Find(asm.GetManifestResourceNames(),
                n => n.EndsWith("attack-techniques.json", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Embedded ATT&CK catalog resource not found.");

        using var stream = asm.GetManifestResourceStream(resourceName)!;
        var dtos = JsonSerializer.Deserialize<List<Dto>>(stream, JsonOpts) ?? new List<Dto>();

        return dtos
            .Select(d => new AttackTechnique(
                d.Id,
                d.Name,
                (d.Tactics ?? new List<string>())
                    .Select(ParseTactic)
                    .Where(t => t != MitreTactic.Unspecified)
                    .ToImmutableArray(),
                d.Sub))
            .ToImmutableArray();
    }

    private static Dictionary<string, RetiredTechnique> LoadRetired()
    {
        var asm = typeof(AttackCatalog).Assembly;
        var resourceName = Array.Find(asm.GetManifestResourceNames(),
                n => n.EndsWith("attack-retired.json", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Embedded ATT&CK retired-technique resource not found.");
        using var stream = asm.GetManifestResourceStream(resourceName)!;
        var dtos = JsonSerializer.Deserialize<List<RetiredDto>>(stream, JsonOpts) ?? new List<RetiredDto>();
        return dtos.ToDictionary(d => d.Id, d => new RetiredTechnique(d.Id, d.Name, Find(d.By)), StringComparer.OrdinalIgnoreCase);
    }

    private sealed class RetiredDto
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string? By { get; set; }
    }

    private static MitreTactic ParseTactic(string s) =>
        Enum.TryParse<MitreTactic>(s, ignoreCase: true, out var t) ? t : MitreTactic.Unspecified;

    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    private sealed class Dto
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public List<string>? Tactics { get; set; }
        public bool Sub { get; set; }
    }
}
