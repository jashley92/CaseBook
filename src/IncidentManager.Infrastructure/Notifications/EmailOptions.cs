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

    /// <summary>
    /// CAP-05: the account to sign in to the relay as (AUTH), e.g. <c>casebook@contoso.com</c>. Blank (the default) sends
    /// without signing in, as before. Server-side config only (ADR 0007), with <see cref="SmtpPassword"/>.
    /// </summary>
    public string SmtpUsername { get; set; } = "";

    /// <summary>
    /// CAP-05: <see cref="SmtpUsername"/>'s password, resolved through the secret provider at each send: a
    /// <c>@protected:</c> value (encrypted to a certificate in the store, ADR 0018), an <c>@cyberark:</c> reference, or a
    /// literal (plain text in the file; Diagnostics warns). Never logged or shown.
    /// </summary>
    public string SmtpPassword { get; set; } = "";

    /// <summary>
    /// CAP-05: sign in as the app-pool account (a gMSA) with integrated Windows authentication (NTLM/Kerberos), with no
    /// password anywhere: for on-premises Exchange. Off by default; can't be used with <see cref="SmtpUsername"/>.
    /// </summary>
    public bool SmtpUseDefaultCredentials { get; set; }

    /// <summary>CAP-05: how long a send may take before it's given up as not reached (BUG-99); 5 to 300, default 30.</summary>
    public int SmtpTimeoutSeconds { get; set; } = 30;

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
    // BUG-241: a list written in the file as "a@x; b@x" is split too (the admin page splits and checks it).
    private static string[] Addresses(string[]? value) =>
        (value ?? []).SelectMany(a => (a ?? "").Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .ToArray();
}
