namespace IncidentManager.Infrastructure.Notifications;

/// <summary>Email delivery configuration (config section "Email").</summary>
public sealed class EmailOptions
{
    /// <summary>When false (the default), email is logged rather than sent — safe for dev.</summary>
    public bool Enabled { get; set; }

    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 25;

    /// <summary>
    /// Encrypt the SMTP connection (STARTTLS). True by default — notifications carry personal/case data,
    /// so mail must not leave in cleartext. Server-side config only (with the relay host/port, not the
    /// admin settings catalog); set false only for a relay that terminates TLS itself, e.g. a trusted
    /// localhost submission agent on a port that doesn't offer STARTTLS.
    /// </summary>
    public bool EnableSsl { get; set; } = true;

    public string From { get; set; } = "incident-manager@localhost";

    /// <summary>Recipients notified when a case is escalated to a Breach (Legal/Privacy distribution).</summary>
    public string[] LegalDistribution { get => _legal; set => _legal = Addresses(value); }
    private string[] _legal = [];

    /// <summary>E-03b: when true, email a person when they are assigned to a case. Off by default.</summary>
    public bool AssignmentNotifications { get; set; }

    /// <summary>Recipients alerted when the audit hash-chain fails verification (F-16). Usually SysAdmins / SecOps.</summary>
    public string[] IntegrityAlertDistribution { get => _integrity; set => _integrity = Addresses(value); }
    private string[] _integrity = [];

    // BUG-98: an administered list blanks the file's longer list past its end; blank entries aren't recipients.
    private static string[] Addresses(string[]? value) =>
        (value ?? []).Where(a => !string.IsNullOrWhiteSpace(a)).Select(a => a.Trim()).ToArray();
}
