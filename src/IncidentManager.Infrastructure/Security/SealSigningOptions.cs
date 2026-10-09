namespace IncidentManager.Infrastructure.Security;

/// <summary>Configuration for integrity-seal signing and out-of-band export (config section "Integrity").</summary>
public sealed class SealSigningOptions
{
    /// <summary>
    /// Path to the PEM-encoded RSA private key used to sign seals. In production this points at a key
    /// provisioned out of band (DPAPI/HSM-protected), never generated on the app server. If the file is
    /// missing, a key is generated here only when <see cref="AllowKeyGeneration"/> is set; otherwise startup fails.
    /// </summary>
    public string SigningKeyPath { get; set; } = "App_Data/keys/seal-signing.pem";

    /// <summary>
    /// Whether a missing key may be generated. Not read from configuration: <c>Program.cs</c> sets it from the
    /// environment (Development only), so no setting can turn on key generation on a server.
    /// </summary>
    public bool AllowKeyGeneration { get; set; }

    /// <summary>
    /// F-24: a folder of PEM public keys (SubjectPublicKeyInfo) from earlier signing keys, kept so seals signed before a
    /// key change still verify. Blank means a <c>retired</c> folder beside the signing key. Public keys aren't secret.
    /// </summary>
    public string RetiredPublicKeysPath { get; set; } = "";

    /// <summary>Directory to export each seal to, separate from the database (ideally restricted/WORM/offsite).</summary>
    public string ExportPath { get; set; } = "seals";
}
