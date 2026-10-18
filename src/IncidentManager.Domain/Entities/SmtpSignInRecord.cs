namespace IncidentManager.Domain.Entities;

/// <summary>
/// CAP-05: the mail relay sign-in an administrator saved under Administration → Settings → Notifications, used when the
/// server's configuration sets none. One row (<see cref="SingletonId"/>). The password is kept only encrypted with ASP.NET
/// Core Data Protection (purpose "CaseBook.Secrets.Smtp.v1"), whose key ring is in <c>DataProtection:KeyPath</c>: a
/// database restored without that folder can't open it, and the form asks for it again. Outside the audit chain and the
/// configuration bundle, like the evidence-key envelope (PROD-57); a change is recorded in the audit trail by the
/// service that saves it (who, when, the mode and whether the password changed), never the password or its ciphertext.
/// </summary>
public class SmtpSignInRecord
{
    public const int SingletonId = 1;
    public const int UsernameMax = 256;

    public int Id { get; set; } = SingletonId;

    /// <summary>"None", "Password" or "Integrated" (a name, read with <c>EnumNames</c>).</summary>
    public string Mode { get; set; } = "None";

    public string Username { get; set; } = "";

    /// <summary>The password, protected with Data Protection; null when none is set.</summary>
    public string? ProtectedPassword { get; set; }

    public DateTimeOffset? PasswordSetAtUtc { get; set; }
    public string? PasswordSetBy { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = "";
}
