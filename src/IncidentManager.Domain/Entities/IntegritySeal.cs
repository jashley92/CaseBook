using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A periodic signed seal of the audit chain head. Written to a restricted/WORM location so
/// that any later tampering with historical entries is detectable by re-verifying against a
/// prior seal, independent of the live database.
/// </summary>
public class IntegritySeal : Entity
{
    public DateTimeOffset SealedAtUtc { get; set; }

    /// <summary>The chain head (highest audit <see cref="AuditLogEntry.Sequence"/>) covered by this seal.</summary>
    public long UpToSequence { get; set; }
    public string ChainHeadHash { get; set; } = string.Empty;

    /// <summary>Signature over the canonical seal payload (base64). RSA in dev; HSM/DPAPI-backed in prod.</summary>
    public string Signature { get; set; } = string.Empty;

    /// <summary>Signature algorithm identifier (e.g. "RSASSA-PSS-SHA256").</summary>
    public string Algorithm { get; set; } = string.Empty;

    /// <summary>Thumbprint of the public key that produced <see cref="Signature"/>.</summary>
    public string KeyId { get; set; } = string.Empty;

    public string SealedBy { get; set; } = string.Empty;

    /// <summary>
    /// BUG-142: from this audit entry on, every entry is hashed with the chain key: the first keyed entry, or, when the
    /// server keys entries but none is keyed yet, the one after this seal. Null when the chain key is off. Signed with the
    /// rest, so a later rewrite of keyed entries with the plain hash is caught even after a restart, before any seal
    /// covers a keyed entry.
    /// </summary>
    public long? KeyedFromSequence { get; set; }

    /// <summary>
    /// Canonical payload that is signed and later re-verified. Binding sequence, head hash, time and
    /// signer means none of them can be swapped without invalidating the signature. BUG-142: "|keyedfrom|N" is appended
    /// only when set, so seals made before it existed verify as they were signed.
    /// </summary>
    public string BuildCanonicalContent() =>
        string.Join('|', UpToSequence, ChainHeadHash, SealedAtUtc.ToString("o"), SealedBy)
        + (KeyedFromSequence is { } k ? "|keyedfrom|" + k.ToString(System.Globalization.CultureInfo.InvariantCulture) : "");
}
