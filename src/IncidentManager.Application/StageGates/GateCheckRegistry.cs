namespace IncidentManager.Application.StageGates;

/// <summary>
/// The parameter a parameterized machine check takes — an integer threshold supplied by the admin when
/// composing the gate (X-06 (b) stage 2). The <see cref="GateCheckParamSpec.Label"/> captions the input;
/// <see cref="Default"/> is used when none is supplied (and keeps a pre-stage-2 requirement's behaviour
/// unchanged); <see cref="Min"/> is the floor the authoring service clamps to. A check with no spec is
/// parameterless.
/// </summary>
public sealed record GateCheckParamSpec(string Label, int Default = 1, int Min = 1);

/// <summary>
/// One machine check in the registry: a stable string <see cref="Key"/> (the identity stored on a
/// requirement and carried in a config bundle), a <see cref="Label"/> factory (the default requirement
/// wording, given the effective parameter), and a pure <see cref="Predicate"/> over a
/// <see cref="GateCaseFacts"/> snapshot plus that parameter. When <see cref="Param"/> is set the check is
/// a reviewed <b>family</b> whose threshold is admin-supplied data — new rules without a release, while
/// the predicate itself stays code (X-06 (b) stages 1–2). Descriptors are defined in code, never authored
/// at runtime, so every automatic check keeps defined, testable, examiner-defensible semantics.
/// </summary>
public sealed record GateCheckDescriptor(
    string Key,
    Func<int, string> Label,
    Func<GateCaseFacts, int, bool> Predicate,
    GateCheckParamSpec? Param = null)
{
    public bool IsParameterized => Param is not null;

    /// <summary>The threshold to evaluate/label with: the supplied value, else the spec default, else 0.</summary>
    public int Effective(int? arg) => arg ?? Param?.Default ?? 0;

    public bool IsSatisfied(GateCaseFacts facts, int? arg) => Predicate(facts, Effective(arg));

    public string LabelFor(int? arg) => Label(Effective(arg));
}

/// <summary>
/// The stable keys of the built-in machine checks. Kept as constants (not an enum) so the set is
/// <b>additive</b>: a new reviewed check is one <see cref="GateCheckRegistry"/> entry, no enum churn, no
/// switch edit, and the key travels verbatim in a config bundle. The counting keys existed before stage 2
/// (their values match the historical <c>GateCheck</c> enum member names, so older bundles import
/// unchanged) and simply gained an optional threshold parameter.
/// </summary>
public static class GateCheckKeys
{
    public const string SummaryPresent = nameof(SummaryPresent);
    public const string AffectedIndividualsCountSet = nameof(AffectedIndividualsCountSet);
    public const string DataElementsSet = nameof(DataElementsSet);
    public const string AffectedStatesSet = nameof(AffectedStatesSet);
    public const string DetectionCaseIdSet = nameof(DetectionCaseIdSet);
    public const string AtLeastOneEntity = nameof(AtLeastOneEntity);
    public const string AtLeastOneMaliciousEntity = nameof(AtLeastOneMaliciousEntity);
    public const string AtLeastOneEvidence = nameof(AtLeastOneEvidence);
    public const string AtLeastOneReport = nameof(AtLeastOneReport);
    public const string IncidentCommanderAssigned = nameof(IncidentCommanderAssigned);
    /// <summary>Stage 2: a threshold on the recorded affected-individual count (e.g. an org's notification floor).</summary>
    public const string MinAffectedIndividuals = nameof(MinAffectedIndividuals);
}

/// <summary>
/// The code-defined catalog of machine checks a stage-gate requirement can evaluate (X-06 (b) stages 1–2).
/// Replaces the closed <c>GateCheck</c> enum + switch: the set is open for reviewed extension, but every
/// predicate is still code — only the <i>composition</i> of checks into gates, and a parameterized check's
/// <i>threshold</i>, are admin data. A key an instance doesn't recognise (e.g. from a bundle authored on a
/// newer build) degrades gracefully — treated as unmet and labelled for review, never a crash.
/// </summary>
public static class GateCheckRegistry
{
    // "At least N" wording that reads naturally at the N=1 default.
    private static Func<int, string> AtLeast(string oneForm, string manyNoun) =>
        n => n > 1 ? $"At least {n} {manyNoun}" : oneForm;

    private static GateCheckParamSpec MinCount(string label) => new(label, Default: 1, Min: 1);

    // Insertion order is the authoring-UI display order (was enum ordinal); the stage-2 family trails.
    private static readonly IReadOnlyList<GateCheckDescriptor> _all =
    [
        new(GateCheckKeys.SummaryPresent, _ => "Case summary recorded", (f, _) => f.HasSummary),
        new(GateCheckKeys.AffectedIndividualsCountSet, _ => "Affected-individual count recorded", (f, _) => f.HasAffectedCount),
        new(GateCheckKeys.DataElementsSet, _ => "Data elements involved recorded", (f, _) => f.HasDataElements),
        new(GateCheckKeys.AffectedStatesSet, _ => "Affected states / jurisdictions recorded", (f, _) => f.HasAffectedStates),
        new(GateCheckKeys.DetectionCaseIdSet, _ => "Detection-source case id recorded", (f, _) => f.HasDetectionCaseId),
        new(GateCheckKeys.AtLeastOneEntity,
            AtLeast("At least one entity / IOC added", "entities / IOCs added"),
            (f, n) => f.EntityCount >= n, MinCount("Minimum entities")),
        new(GateCheckKeys.AtLeastOneMaliciousEntity,
            AtLeast("At least one confirmed malicious IOC", "confirmed malicious IOCs"),
            (f, n) => f.MaliciousEntityCount >= n, MinCount("Minimum malicious IOCs")),
        new(GateCheckKeys.AtLeastOneEvidence,
            AtLeast("At least one evidence item attached", "evidence items attached"),
            (f, n) => f.EvidenceCount >= n, MinCount("Minimum evidence items")),
        new(GateCheckKeys.AtLeastOneReport,
            AtLeast("A report has been generated", "reports generated"),
            (f, n) => f.ReportCount >= n, MinCount("Minimum reports")),
        new(GateCheckKeys.IncidentCommanderAssigned, _ => "An Incident Commander is assigned", (f, _) => f.HasIncidentCommander),
        new(GateCheckKeys.MinAffectedIndividuals,
            n => $"Affected-individual count is at least {n}",
            (f, n) => f.HasAffectedCount && f.AffectedIndividualsCount >= n,
            new GateCheckParamSpec("Minimum affected individuals", Default: 1, Min: 1)),
    ];

    private static readonly IReadOnlyDictionary<string, GateCheckDescriptor> _byKey =
        _all.ToDictionary(d => d.Key, StringComparer.Ordinal);

    /// <summary>Every registered check, in authoring-display order.</summary>
    public static IReadOnlyList<GateCheckDescriptor> All => _all;

    public static bool IsKnown(string? key) => key is not null && _byKey.ContainsKey(key);

    public static GateCheckDescriptor? Find(string? key) =>
        key is not null && _byKey.TryGetValue(key, out var d) ? d : null;

    /// <summary>The parameter spec for a check, or null when it takes no parameter (or is unknown).</summary>
    public static GateCheckParamSpec? Param(string? key) => Find(key)?.Param;

    /// <summary>The default requirement wording for a key (given the effective parameter); a for-review
    /// label if the key is unknown.</summary>
    public static string Label(string? key, int? arg = null) => Find(key)?.LabelFor(arg) ?? $"Unknown check '{key}' (needs review)";

    /// <summary>
    /// Whether the check is satisfied by the given facts and parameter. An unknown key is <b>never</b>
    /// satisfied — an instance can't vouch for a predicate it doesn't define, so it must not silently pass
    /// a gate.
    /// </summary>
    public static bool IsSatisfied(string? key, GateCaseFacts facts, int? arg = null) =>
        Find(key)?.IsSatisfied(facts, arg) ?? false;
}
