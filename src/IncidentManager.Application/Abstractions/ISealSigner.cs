namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Signs and verifies integrity-seal payloads with an asymmetric key, so a seal's authenticity can
/// be checked independently of the database it protects. Development uses a locally-generated RSA
/// key; production should supply a key from the Windows certificate store / DPAPI / an HSM.
/// </summary>
public interface ISealSigner
{
    /// <summary>Identifier of the signature algorithm (e.g. "RSASSA-PKCS1-v1_5-SHA256").</summary>
    string Algorithm { get; }

    /// <summary>Stable thumbprint of the public key, so a seal records which key signed it.</summary>
    string KeyId { get; }

    /// <summary>
    /// The public half of the signing key in PEM (SubjectPublicKeyInfo) form, so a seal signature can
    /// be verified independently of this application — e.g. bundled into a compliance export for an
    /// examiner to check offline. Never exposes the private key.
    /// </summary>
    string PublicKeyPem { get; }

    /// <summary>Signs the content, returning a base64 signature.</summary>
    string Sign(string content);

    /// <summary>Verifies a base64 signature against the content using the current key.</summary>
    bool Verify(string content, string signatureBase64);
}
