namespace IncidentManager.Infrastructure.Notifications;

/// <summary>Email delivery configuration (config section "Email").</summary>
public sealed class EmailOptions
{
    /// <summary>When false (the default), email is logged rather than sent — safe for dev.</summary>
    public bool Enabled { get; set; }

    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 25;
    public string From { get; set; } = "incident-manager@localhost";

    /// <summary>Recipients notified when a case is escalated to a Breach (Legal/Privacy distribution).</summary>
    public string[] LegalDistribution { get; set; } = [];

    /// <summary>E-03b: when true, email a person when they are assigned to a case. Off by default.</summary>
    public bool AssignmentNotifications { get; set; }

    /// <summary>Recipients alerted when the audit hash-chain fails verification (F-16). Usually SysAdmins / SecOps.</summary>
    public string[] IntegrityAlertDistribution { get; set; } = [];
}
