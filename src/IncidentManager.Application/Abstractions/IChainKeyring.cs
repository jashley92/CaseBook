namespace IncidentManager.Application.Abstractions;

/// <summary>
/// F-25: the secret keys the audit chain is hashed with (HMAC-SHA256), when the chain key is turned on. Held in memory
/// only. The current key hashes new entries; retired keys are kept so entries written under them still verify. Key ids
/// are derived from the keys and reveal nothing about them. Empty when the chain key is off.
/// </summary>
public interface IChainKeyring
{
    /// <summary>The key new entries are hashed with, or null when the chain key is off.</summary>
    string? CurrentKeyId { get; }

    /// <summary>The key with this id (current or retired), or null when this server doesn't hold it.</summary>
    byte[]? Key(string keyId);

    /// <summary>Every key id held, current first.</summary>
    IReadOnlyList<string> KeyIds { get; }

    /// <summary>Where the keys came from, for the Integrity page and Diagnostics (no secrets), or null when off.</summary>
    string? Source { get; }
}

/// <summary>A keyring with no keys: the chain key is off, and every entry gets the plain hash.</summary>
public sealed class NoChainKeys : IChainKeyring
{
    public static readonly NoChainKeys Instance = new();
    public string? CurrentKeyId => null;
    public byte[]? Key(string keyId) => null;
    public IReadOnlyList<string> KeyIds => [];
    public string? Source => null;
}
