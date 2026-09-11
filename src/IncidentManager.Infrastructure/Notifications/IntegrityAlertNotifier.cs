using System.Globalization;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// Turns a detected audit-chain break into an active alarm (F-16). Two channels, both out-of-band of the
/// database the chain protects — so a tamper that deletes rows can't also suppress the alarm:
/// <list type="bullet">
///   <item>A <see cref="LogLevel.Critical"/> event with a stable <c>EventId</c> — the signal the SIEM
///     (SIEM) ingests from the Windows event/app log.</item>
///   <item>Email to the configured integrity-alert distribution (skipped, but still logged, if none is set).</item>
/// </list>
/// Never throws: a notification failure must not mask the integrity failure that triggered it.
/// </summary>
public sealed class IntegrityAlertNotifier : IIntegrityAlertNotifier
{
    // Stable id so the SIEM can pin a correlation/detection rule to it.
    private static readonly EventId AuditChainBroken = new(5001, nameof(AuditChainBroken));

    private readonly IEmailSender _email;
    private readonly IEmailComposer _composer;
    private readonly IConfiguration _config;
    private readonly IOptionsMonitor<EmailOptions> _options;
    private readonly ISecurityEventSink _siem;
    private readonly ILogger<IntegrityAlertNotifier> _logger;

    public IntegrityAlertNotifier(IEmailSender email, IEmailComposer composer, IConfiguration config,
        IOptionsMonitor<EmailOptions> options, ISecurityEventSink siem, ILogger<IntegrityAlertNotifier> logger)
    {
        _email = email;
        _composer = composer;
        _config = config;
        _options = options;
        _siem = siem;
        _logger = logger;
    }

    public async Task OnChainBrokenAsync(ChainVerificationResult result, CancellationToken ct = default)
    {
        // Always emit the SIEM/critical signal first, regardless of email configuration.
        _logger.LogCritical(AuditChainBroken,
            "AUDIT CHAIN INTEGRITY FAILURE: first break at sequence {FirstBrokenSequence}. {Detail} " +
            "The tamper-evident audit log may have been altered, truncated, or reordered — investigate immediately.",
            result.FirstBrokenSequence, result.Detail);

        // F-18: also carry the tamper alarm on the unified security-event stream (id 5001).
        _siem.Emit(new SecurityEvent
        {
            EventId = SecurityEventIds.AuditChainBroken,
            Category = "Integrity",
            Action = "AuditChainBroken",
            Outcome = SecurityOutcome.Failure,
            Severity = SecuritySeverity.Critical,
            Actor = "system",
            Detail = $"first break at sequence {result.FirstBrokenSequence}"
        });

        var recipients = _options.CurrentValue.IntegrityAlertDistribution;
        if (recipients.Length == 0) return; // no distribution configured; the critical log above still fired

        var baseUrl = (_config["App:BaseUrl"] ?? "").TrimEnd('/');
        var integrityUrl = baseUrl.Length == 0 ? null : $"{baseUrl}/integrity";
        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["FirstBrokenSequence"] = result.FirstBrokenSequence?.ToString(CultureInfo.InvariantCulture) ?? "",
            ["Detail"] = result.Detail ?? "",
            ["IntegrityUrl"] = integrityUrl ?? "",
        };

        try
        {
            var message = await _composer.ComposeAsync("audit-chain-alarm", recipients, tokens, integrityUrl, null, ct);
            await _email.SendAsync(message, ct);
        }
        catch (Exception ex)
        {
            // Contract: never throw. The critical log already carries the alarm.
            _logger.LogError(ex, "Failed to email the audit-chain integrity alert to the configured distribution.");
        }
    }
}
