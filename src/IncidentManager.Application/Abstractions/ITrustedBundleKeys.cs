namespace IncidentManager.Application.Abstractions;

/// <summary>CAP-16: a public key a configuration bundle may be signed with and import as this server's own would. Its id
/// is the first 16 hex characters of the SHA-256 of its SubjectPublicKeyInfo, as a seal key's is.</summary>
public sealed record TrustedBundleKey(string KeyId, string FileName, string PublicKeyPem);

/// <summary>
/// CAP-16: the configuration-bundle signing keys this server trusts besides its own, read at startup from the folder in
/// <c>Config:TrustedBundleKeys</c> (server configuration only, never in-app, so the people an import could give access to
/// can't add a key). Public keys only; none is secret.
/// </summary>
public interface ITrustedBundleKeys
{
    /// <summary>The folder the keys were read from, or null when none is configured.</summary>
    string? Folder { get; }

    IReadOnlyList<TrustedBundleKey> Keys { get; }
}

/// <summary>No trusted keys: a bundle imports without asking only when this server signed it.</summary>
public sealed class NoTrustedBundleKeys : ITrustedBundleKeys
{
    public static readonly NoTrustedBundleKeys Instance = new();
    public string? Folder => null;
    public IReadOnlyList<TrustedBundleKey> Keys => [];
}
