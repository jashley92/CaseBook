namespace IncidentManager.Domain.Common;

/// <summary>
/// A record whose business fields are hashed for point-in-time tamper detection.
/// The entity declares its canonical content; the crypto lives in the infrastructure
/// hash-chain service so the domain stays dependency-free.
/// </summary>
public interface IHashableEntity
{
    /// <summary>SHA-256 of <see cref="BuildCanonicalContent"/>, set by the hash-chain service.</summary>
    string? RowHash { get; set; }

    /// <summary>
    /// A deterministic, order-stable projection of the business fields that must not change silently.
    /// Must never include the hash itself or volatile audit metadata.
    /// </summary>
    string BuildCanonicalContent();
}
