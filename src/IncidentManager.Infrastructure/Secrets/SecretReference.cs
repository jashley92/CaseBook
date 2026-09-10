using System.Diagnostics.CodeAnalysis;

namespace IncidentManager.Infrastructure.Secrets;

/// <summary>
/// A parsed <c>@cyberark:</c> secret reference (F-19). The text after the scheme is a <c>;</c>-separated
/// list of <c>Key=Value</c> pairs that become CyberArk CCP query parameters (e.g. <c>Safe</c>, <c>Folder</c>,
/// <c>Object</c>). The install-wide <c>AppID</c> is NOT part of the reference — it comes from configuration —
/// so a reference names only the location of the secret, never a credential.
/// </summary>
public sealed class SecretReference
{
    public const string Scheme = "@cyberark:";

    /// <summary>CCP query parameters parsed from the reference, in declaration order.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Query { get; }

    private SecretReference(IReadOnlyList<KeyValuePair<string, string>> query) => Query = query;

    /// <summary>True if <paramref name="value"/> is a CyberArk reference rather than a literal secret.</summary>
    public static bool IsReference([NotNullWhen(true)] string? value) =>
        value is not null && value.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Parses a reference. Returns false (no throw) for a null/literal value or a malformed reference —
    /// callers fail such a value closed. A valid reference has at least one <c>Key=Value</c> pair.
    /// </summary>
    public static bool TryParse(string? value, [NotNullWhen(true)] out SecretReference? reference)
    {
        reference = null;
        if (!IsReference(value)) return false;

        var body = value[Scheme.Length..];
        var pairs = new List<KeyValuePair<string, string>>();
        foreach (var part in body.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) return false;                       // no key, or "=value"
            var key = part[..eq].Trim();
            var val = part[(eq + 1)..].Trim();
            if (key.Length == 0 || val.Length == 0) return false;
            pairs.Add(new KeyValuePair<string, string>(key, val));
        }

        if (pairs.Count == 0) return false;
        reference = new SecretReference(pairs);
        return true;
    }

    /// <summary>A cache key / log label that identifies the location without revealing the secret.</summary>
    public override string ToString() => Scheme + string.Join(';', Query.Select(p => $"{p.Key}={p.Value}"));
}
