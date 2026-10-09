namespace IncidentManager.Infrastructure.Security;

/// <summary>Where the seal signing key comes from (F-23).</summary>
public enum SigningKeySource
{
    /// <summary>A PEM file at <see cref="SealSigningOptions.SigningKeyPath"/> (the default).</summary>
    File,
    /// <summary>A certificate in the Windows certificate store, by thumbprint; Windows signs with its private key.</summary>
    CertificateStore,
    /// <summary>A PEM fetched from CyberArk through an <c>@cyberark:</c> reference and held only in memory.</summary>
    CyberArk
}

/// <summary>F-23: the signing key's source (config section <c>Integrity:SigningKey</c>). Server configuration only.</summary>
public sealed class SigningKeyOptions
{
    public SigningKeySource Source { get; set; } = SigningKeySource.File;

    /// <summary><see cref="SigningKeySource.CertificateStore"/>: the certificate's thumbprint (SHA-1 hex; spaces allowed).</summary>
    public string CertificateThumbprint { get; set; } = "";

    /// <summary><see cref="SigningKeySource.CertificateStore"/>: <c>LocalMachine</c> (default) or <c>CurrentUser</c>; the store is <c>My</c>.</summary>
    public string StoreLocation { get; set; } = "LocalMachine";

    /// <summary><see cref="SigningKeySource.CyberArk"/>: an <c>@cyberark:Safe=…;Object=…</c> reference to the PEM private key.</summary>
    public string Secret { get; set; } = "";
}

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

    /// <summary>F-23: where the signing key comes from; the file at <see cref="SigningKeyPath"/> unless set.</summary>
    public SigningKeyOptions SigningKey { get; set; } = new();

    /// <summary>
    /// F-24: a folder of PEM public keys (SubjectPublicKeyInfo) from earlier signing keys, kept so seals signed before a
    /// key change still verify. Blank means a <c>retired</c> folder beside the signing key. Public keys aren't secret.
    /// </summary>
    public string RetiredPublicKeysPath { get; set; } = "";

    /// <summary>Directory to export each seal to, separate from the database (ideally restricted/WORM/offsite).</summary>
    public string ExportPath { get; set; } = "seals";
}
