namespace IncidentManager.Infrastructure.Security;

/// <summary>Configuration for integrity-seal signing and out-of-band export (config section "Integrity").</summary>
public sealed class SealSigningOptions
{
    /// <summary>
    /// Path to the PEM-encoded RSA private key used to sign seals. If absent, a key is generated on
    /// first use and written here. In production this should point at a key protected by DPAPI/HSM
    /// and provisioned out of band, not generated on the app server.
    /// </summary>
    public string SigningKeyPath { get; set; } = "App_Data/keys/seal-signing.pem";

    /// <summary>Directory to export each seal to, separate from the database (ideally restricted/WORM/offsite).</summary>
    public string ExportPath { get; set; } = "seals";
}
