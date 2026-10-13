namespace IncidentManager.Application.Config;

/// <summary>How one item in an incoming bundle compares to the live configuration.</summary>
public enum ConfigChange { Add, Update, Unchanged }

/// <summary>One line of an import preview: a section, the item's natural key, and how it would change.</summary>
public sealed record ConfigDiffItem(string Section, string Name, ConfigChange Change);

/// <summary>The full preview of applying a bundle: every item classified add / update / unchanged.</summary>
public sealed record ConfigDiff(IReadOnlyList<ConfigDiffItem> Items, IReadOnlyList<string>? Warnings = null)
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
/// <param name="RolesInEffect">BUG-193: false when the import changed roles or mappings that the role directory couldn't
/// reload yet (it keeps retrying).</param>
public sealed record ConfigImportResult(int Added, int Updated, int Unchanged, bool RolesInEffect = true,
    IReadOnlyList<string>? TemplatesNotPlaced = null)
{
    public int Changed => Added + Updated;

    /// <summary>BUG-238: what to tell the admin about template files that couldn't be put in place, or null.</summary>
    public string? TemplatesNotPlacedMessage => TemplatesNotPlaced is { Count: > 0 } names
        ? $"The Word file for {string.Join(", ", names.Select(n => $"\"{n}\""))} couldn't be put in place (it may have been " +
          "open, or the folder is read-only), so that template was left as it was (a new one is archived). The rest of " +
          "the bundle was imported. Replace the file from Administration › Report templates."
        : null;
}
