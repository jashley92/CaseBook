namespace IncidentManager.Application.Abstractions;

/// <summary>A public key that seals can be verified with, by the id seals record.</summary>
public sealed record SealPublicKey(string KeyId, string PublicKeyPem, bool Current);

/// <summary>
/// Signs and verifies integrity-seal payloads with an asymmetric key, so a seal's authenticity can
/// be checked independently of the database it protects. Development uses a locally-generated RSA
/// key; production should supply a key from the Windows certificate store / DPAPI / an HSM.
/// </summary>
public interface ISealSigner
{
    /// <summary>Identifier of the signature algorithm (e.g. "RSASSA-PSS-SHA256").</summary>
    string Algorithm { get; }

    /// <summary>Stable thumbprint of the public key, so a seal records which key signed it.</summary>
    string KeyId { get; }

    /// <summary>Where the signing key came from (F-23), e.g. "File (…)", "Certificate store (…)", "CyberArk". No secrets.</summary>
    string KeySource { get; }

    /// <summary>
    /// The public half of the signing key in PEM (SubjectPublicKeyInfo) form, so a seal signature can
    /// be verified independently of this application — e.g. bundled into a compliance export for an
    /// examiner to check offline. Never exposes the private key.
    /// </summary>
    string PublicKeyPem { get; }

    /// <summary>Signs the content, returning a base64 signature.</summary>
    string Sign(string content);

    /// <summary>
    /// Verifies a base64 signature against the content with the key the seal names (<paramref name="keyId"/>: the
    /// current key, or a retired one kept for verification; none means the current key), by the algorithm the seal
    /// recorded (<see cref="SealAlgorithms"/>; none means the current one). An unknown key id never verifies.
    /// </summary>
    bool Verify(string content, string signatureBase64, string? algorithm = null, string? keyId = null);

    /// <summary>Every public key a seal can be verified with: the current key first, then retired keys kept so seals
    /// signed before a key change still verify (F-24). Public halves only.</summary>
    IReadOnlyList<SealPublicKey> VerificationKeys { get; }
}
