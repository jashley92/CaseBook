using System.Globalization;
using System.Net;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Security;
using Microsoft.Extensions.Configuration;
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
    private readonly IEmailComposer _composer;
    private readonly IConfiguration _config;
    private readonly IOptionsMonitor<EmailOptions> _options;
    private readonly ISecurityEventSink _siem;
    private readonly ILogger<EvidenceIntegrityAlertNotifier> _logger;

    public EvidenceIntegrityAlertNotifier(IEmailSender email, IEmailComposer composer, IConfiguration config,
        IOptionsMonitor<EmailOptions> options, ISecurityEventSink siem, ILogger<EvidenceIntegrityAlertNotifier> logger)
    {
        _email = email;
        _composer = composer;
        _config = config;
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

        var baseUrl = (_config["App:BaseUrl"] ?? "").TrimEnd('/');
        var integrityUrl = baseUrl.Length == 0 ? null : $"{baseUrl}/integrity";
        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["DriftCount"] = result.Drifts.Count.ToString(CultureInfo.InvariantCulture),
            ["CheckedCount"] = result.CheckedCount.ToString(CultureInfo.InvariantCulture),
            ["VerifiedAtUtc"] = result.CheckedAtUtc.ToString("u"),
            ["IntegrityUrl"] = integrityUrl ?? "",
        };
        var htmlTokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["DriftList"] = RenderDriftList(result),
        };

        try
        {
            var message = await _composer.ComposeAsync("evidence-drift-alarm", recipients, tokens, integrityUrl, htmlTokens, ct);
            await _email.SendAsync(message, ct);
        }
        catch (Exception ex)
        {
            // Contract: never throw. The critical log already carries the alarm.
            _logger.LogError(ex, "Failed to email the evidence-integrity alert to the configured distribution.");
        }
    }

    // Composer-rendered safe HTML: every field is HTML-encoded here.
    private static string RenderDriftList(EvidenceVerificationResult result)
    {
        var lis = result.Drifts.Select(d =>
            $"<li>[{WebUtility.HtmlEncode(d.Kind.ToString())}] {WebUtility.HtmlEncode(d.CaseNumber ?? d.CaseId.ToString())} — " +
            $"{WebUtility.HtmlEncode(d.OriginalFileName)}: {WebUtility.HtmlEncode(d.Detail)}</li>");
        return "<ul>" + string.Join("", lis) + "</ul>";
    }
}
