namespace IncidentManager.Domain.Entities;

/// <summary>
/// CAP-40: a secret an administrator entered under Administration in place of a server configuration value, used when the
/// server's configuration sets none. One row per secret, keyed by the configuration key it stands in for (<see cref="Name"/>:
/// <c>Chat:Webhook:WebhookUrl</c>, <c>Siem:Webhook:Token</c>). The value is kept only encrypted with ASP.NET Core Data
/// Protection, under a purpose of its own per secret, whose key ring is in <c>DataProtection:KeyPath</c>: a database
/// restored without that folder can't open it, and the form asks for it again. Outside the audit chain, the settings list
/// and the configuration bundle, as <see cref="SmtpSignInRecord"/> is (CAP-05); a change is recorded in the audit trail by
/// the service that saves it (who, when, which secret and whether it was set, replaced or cleared), never the value or its
/// ciphertext.
/// </summary>
public class StoredSecretRecord
{
    public const int NameMax = 64;

    /// <summary>The configuration key the secret stands in for, e.g. <c>Siem:Webhook:Token</c>.</summary>
    public string Name { get; set; } = "";

    /// <summary>The value, protected with Data Protection; null once cleared (the row stays, with who cleared it).</summary>
    public string? ProtectedValue { get; set; }

    public DateTimeOffset? SetAtUtc { get; set; }
    public string? SetBy { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = "";
}
