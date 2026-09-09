namespace IncidentManager.Application.Config;

/// <summary>How one item in an incoming bundle compares to the live configuration.</summary>
public enum ConfigChange { Add, Update, Unchanged }

/// <summary>One line of an import preview: a section, the item's natural key, and how it would change.</summary>
public sealed record ConfigDiffItem(string Section, string Name, ConfigChange Change);

/// <summary>The full preview of applying a bundle: every item classified add / update / unchanged.</summary>
public sealed record ConfigDiff(IReadOnlyList<ConfigDiffItem> Items)
{
    public int Added => Items.Count(i => i.Change == ConfigChange.Add);
    public int Updated => Items.Count(i => i.Change == ConfigChange.Update);
    public int Unchanged => Items.Count(i => i.Change == ConfigChange.Unchanged);

    /// <summary>Only the items that would actually change (add or update), for a compact review list.</summary>
    public IReadOnlyList<ConfigDiffItem> Changes => Items.Where(i => i.Change != ConfigChange.Unchanged).ToList();
    public bool HasChanges => Added > 0 || Updated > 0;
}

/// <summary>
/// The result of parsing and verifying an uploaded bundle: whether its embedded-key signature checks out,
/// whether that key is this very instance's (a same-instance re-import) or another's (a cross-instance
/// promotion), and the provenance the file carries. Import is refused unless <see cref="SignatureValid"/>.
/// </summary>
public sealed record ConfigVerification(
    bool SignatureValid, bool SignedByThisInstance, string KeyId, string ExportedBy,
    DateTimeOffset ExportedAtUtc, int SchemaVersion, string AppVersion, string SourceHost);

/// <summary>Counts applied by an import, per outcome.</summary>
public sealed record ConfigImportResult(int Added, int Updated, int Unchanged)
{
    public int Changed => Added + Updated;
}
