namespace IncidentManager.Application.Admin;

/// <summary>One member of a taxonomy, with its built-in default label.</summary>
/// <param name="Value">The stable canonical value (the enum member name), used to build the override key.</param>
public sealed record TaxonomyMember(string Value, string DefaultLabel);

/// <summary>A code-defined taxonomy whose member labels an admin may override for IRP alignment (X-02).</summary>
public sealed record TaxonomyKind(string Id, string Title, string Description, IReadOnlyList<TaxonomyMember> Members)
{
    /// <summary>
    /// Whether members of this kind may also be <b>hidden</b> and <b>reordered</b> in the pick-lists that
    /// offer them (X-02 slice 3). Off for the load-bearing ladder and phases — their order and completeness
    /// drive escalation and SLA logic (see X-05) — and on for the entity/timeline pick-lists, where hiding an
    /// unused option or reordering is purely a data-entry convenience. Hiding never rewrites stored values, so
    /// a case already carrying a now-hidden member still displays it; only new selection is affected.
    /// </summary>
    public bool AllowVisibilityOrder { get; init; }
}

/// <summary>
/// The taxonomies whose <b>display labels</b> are admin-editable (X-02). Labels-only, by design: the sets
/// themselves stay code-defined and the stored value is always the canonical member name, so renaming is
/// purely cosmetic — the classification ladder, escalation rules, breach logic, phase order and SLA
/// milestones are all unchanged (see backlog X-05). Overrides are stored as <c>Taxonomy:{Kind}:Label:{Member}</c>
/// rows in the audited settings table and read live via <see cref="Abstractions.ITaxonomyDisplay"/>.
/// </summary>
public static class TaxonomyCatalog
{
    public static readonly IReadOnlyList<TaxonomyKind> Kinds = new[]
    {
        new TaxonomyKind("Classification", "Classification ladder",
            "The formal IRP classifications a case is promoted through. Ladder order, escalation rules and breach-notification logic don't change.",
            new TaxonomyMember[]
            {
                new("ComplexEvent", "Complex Event"),
                new("AdverseEvent", "Adverse Event"),
                new("Incident", "Incident"),
                new("Breach", "Breach"),
            }),
        new TaxonomyKind("CasePhase", "Lifecycle phases",
            "Investigation lifecycle phases, aligned to NIST SP 800-61. Phase order and the SLA milestones tied to them don't change.",
            new TaxonomyMember[]
            {
                new("New", "New"),
                new("Triage", "Triage"),
                new("Containment", "Containment"),
                new("Eradication", "Eradication"),
                new("Recovery", "Recovery"),
                new("PostIncident", "Post-Incident"),
                new("Closed", "Closed"),
            }),
        new TaxonomyKind("EntityType", "Entity types",
            "Kinds of artifact or observable an analyst records on a case, as offered in the entity picker.",
            new TaxonomyMember[]
            {
                new("Account", "Account"),
                new("Host", "Host"),
                new("IpAddress", "IP address"),
                new("Domain", "Domain"),
                new("Url", "URL"),
                new("FileHash", "File hash"),
                new("FileName", "File name"),
                new("EmailAddress", "Email address"),
                new("Process", "Process"),
                new("RegistryKey", "Registry key"),
                new("Other", "Other"),
            }) { AllowVisibilityOrder = true },
        new TaxonomyKind("EntityDisposition", "Entity dispositions",
            "The analyst's verdict on an entity. Graph colors don't change.",
            new TaxonomyMember[]
            {
                new("Unknown", "Unknown"),
                new("Benign", "Benign"),
                new("Suspicious", "Suspicious"),
                new("Malicious", "Malicious"),
                new("Compromised", "Compromised"),
            }) { AllowVisibilityOrder = true },
        new TaxonomyKind("TimelineEntryType", "Timeline entry types",
            "The category of a timeline entry, used for filtering.",
            new TaxonomyMember[]
            {
                new("Detection", "Detection"),
                new("Analysis", "Analysis"),
                new("Containment", "Containment"),
                new("Eradication", "Eradication"),
                new("Recovery", "Recovery"),
                new("Communication", "Communication"),
                new("Evidence", "Evidence"),
                new("Escalation", "Escalation"),
                new("Note", "Note"),
                new("Other", "Other"),
                // FR-23: third-party disclosure milestones (Disclosure timeline).
                new("Notified", "Vendor notified us"),
                new("ScopeConfirmed", "Scope confirmed"),
                new("DataConfirmed", "Our data confirmed in scope"),
                new("Remediation", "Remediation"),
                new("RegulatoryNotification", "Regulatory notification"),
            }) { AllowVisibilityOrder = true },
        new TaxonomyKind("EntityRelationshipType", "Entity relationships",
            "How one entity relates to another in the investigation graph.",
            new TaxonomyMember[]
            {
                new("RelatedTo", "related to"),
                new("CommunicatedWith", "communicated with"),
                new("ConnectedTo", "connected to"),
                new("ResolvedTo", "resolved to"),
                new("LoggedInTo", "logged in to"),
                new("Executed", "executed"),
                new("Downloaded", "downloaded"),
                new("Dropped", "dropped"),
                new("Contacted", "contacted"),
                new("Contains", "contains"),
                new("Redirected", "redirected to"),
                new("ChildOf", "child of"),
                new("Accessed", "accessed"),
                new("Impersonated", "impersonated"),
            }) { AllowVisibilityOrder = true },
    };

    /// <summary>The built-in default label for a member, used as the fallback wherever an override is unset
    /// (e.g. the report generator, which has no access to the <c>Ui</c> helpers).</summary>
    public static string DefaultLabel(string kind, string member) =>
        Kinds.FirstOrDefault(k => k.Id == kind)?.Members.FirstOrDefault(m => m.Value == member)?.DefaultLabel ?? member;

    /// <summary>The settings-table key an override for this member is stored under.</summary>
    public static string LabelKey(string kind, string member) => $"Taxonomy:{kind}:Label:{member}";

    /// <summary>The key a member's hidden flag is stored under (present + "true" = hidden from pick-lists).</summary>
    public static string HiddenKey(string kind, string member) => $"Taxonomy:{kind}:Hidden:{member}";

    /// <summary>The key a kind's custom pick-list order is stored under (a comma-separated list of member values).</summary>
    public static string OrderKey(string kind) => $"Taxonomy:{kind}:Order";

    /// <summary>The prefix every taxonomy override key shares — used by the config loader to recognise them.</summary>
    public const string KeyPrefix = "Taxonomy:";
}
