namespace IncidentManager.Domain.Entities;

/// <summary>
/// PROD-57: the database's copy of an evidence-key envelope, so every database backup carries it. The envelope holds the
/// evidence key only in encrypted forms (to the server's certificate, to recovery certificates), so the copy opens nothing
/// on its own. Outside the audit chain (operational, like held mail); creating or changing one is recorded in the audit
/// trail by the keyring, and a copy that disagrees with the keys folder's is reported, not trusted.
/// </summary>
public class KeyEnvelopeRecord
{
    /// <summary>The evidence key's id (16 hex digits).</summary>
    public string KeyId { get; set; } = "";

    /// <summary>The envelope, as written to the keys folder.</summary>
    public string EnvelopeJson { get; set; } = "";

    public DateTimeOffset UpdatedAtUtc { get; set; }
}
