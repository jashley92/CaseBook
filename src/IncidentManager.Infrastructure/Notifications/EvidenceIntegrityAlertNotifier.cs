using System.Globalization;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// Turns detected evidence-at-rest drift into an active alarm (F-17). Two channels, both out-of-band of
/// the database and the evidence store the drift may be attacking:
/// <list type="bullet">
///   <item>A <see cref="LogLevel.Critical"/> event with a stable <c>EventId</c> (5003) — the signal the
///     SIEM ingests from the Windows event/app log — plus the same event on the F-18 stream.</item>
///   <item>Email to the configured integrity-alert distribution, carrying the offender list (skipped, but
///     still logged, if no distribution is set).</item>
/// </list>
/// Never throws: a notification failure must not mask the integrity failure that triggered it. Mirrors
/// <see cref="IntegrityAlertNotifier"/> (the F-16 audit-chain alarm) and shares its recipient list.
/// </summary>
public sealed class EvidenceIntegrityAlertNotifier : IEvidenceIntegrityAlertNotifier
{
    // Stable id so the SIEM can pin a correlation/detection rule to it.
    private static readonly EventId EvidenceIntegrityDrift = new(5003, nameof(EvidenceIntegrityDrift));

    private readonly IEmailSender _email;
    private readonly IOptionsMonitor<EmailOptions> _options;
    private readonly ISecurityEventSink _siem;
    private readonly ILogger<EvidenceIntegrityAlertNotifier> _logger;

    public EvidenceIntegrityAlertNotifier(IEmailSender email, IOptionsMonitor<EmailOptions> options,
        ISecurityEventSink siem, ILogger<EvidenceIntegrityAlertNotifier> logger)
    {
        _email = email;
        _options = options;
        _siem = siem;
        _logger = logger;
    }

    public async Task OnDriftDetectedAsync(EvidenceVerificationResult result, CancellationToken ct = default)
    {
        // Always emit the SIEM/critical signal first, regardless of email configuration. No filenames or
        // case content on this channel — counts only.
        _logger.LogCritical(EvidenceIntegrityDrift,
            "EVIDENCE INTEGRITY FAILURE: {DriftCount} of {CheckedCount} stored evidence item(s) no longer " +
            "match their recorded SHA-256 (mismatch, missing, or unreadable). The evidence store may have " +
            "suffered bit-rot or tampering — investigate immediately.",
            result.Drifts.Count, result.CheckedCount);

        _siem.Emit(SecurityEvents.EvidenceIntegrityDrift(result.Drifts.Count, result.CheckedCount));

        var recipients = _options.CurrentValue.IntegrityAlertDistribution;
        if (recipients.Length == 0) return; // no distribution configured; the critical log above still fired

        var subject = $"[CaseBook] ALERT: evidence-at-rest integrity failure ({result.Drifts.Count} item(s))";
        var body = BuildBody(result);

        try
        {
            await _email.SendAsync(recipients, subject, body, ct);
        }
        catch (Exception ex)
        {
            // Contract: never throw. The critical log already carries the alarm.
            _logger.LogError(ex, "Failed to email the evidence-integrity alert to the configured distribution.");
        }
    }

    private static string BuildBody(EvidenceVerificationResult result)
    {
        var c = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.AppendLine("CaseBook re-verified evidence at rest and found stored bytes that no longer match their recorded SHA-256.");
        sb.AppendLine();
        sb.AppendLine(c, $"Checked: {result.CheckedCount}");
        sb.AppendLine(c, $"Drifted: {result.Drifts.Count}");
        sb.AppendLine(c, $"Verified at (UTC): {result.CheckedAtUtc:u}");
        sb.AppendLine();
        sb.AppendLine("Affected evidence:");
        foreach (var d in result.Drifts)
        {
            sb.AppendLine(c, $"  - [{d.Kind}] case {d.CaseNumber ?? d.CaseId.ToString()} · evidence {d.EvidenceId} · {d.OriginalFileName}");
            sb.AppendLine(c, $"      {d.Detail}");
        }
        sb.AppendLine();
        sb.AppendLine("The recorded hash is itself protected by the audit hash-chain, so a drift here means the");
        sb.AppendLine("stored file changed after it was recorded — bit-rot, a substituted file, or a deletion.");
        sb.AppendLine("Treat it as a potential integrity/security incident:");
        sb.AppendLine("  1. Preserve the current evidence store and database; do not overwrite.");
        sb.AppendLine("  2. Compare against your out-of-band evidence backups to recover the original bytes.");
        sb.AppendLine("  3. Follow the incident-response procedures in OPERATIONS.md.");
        return sb.ToString();
    }
}
