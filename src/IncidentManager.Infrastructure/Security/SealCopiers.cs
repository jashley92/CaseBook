using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Notifications;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Security;

/// <summary>F-27: the optional extra seal copies (config section <c>Integrity:SealCopies</c>). Each is off unless set.</summary>
public sealed class SealCopyOptions
{
    /// <summary>Addresses (comma- or semicolon-separated) to mail each seal's digest to, e.g. a mailbox under retention.</summary>
    public string EmailTo { get; set; } = "";

    /// <summary>An internal RFC 3161 timestamp authority. Only addresses inside the organization are accepted.</summary>
    public string TimestampAuthorityUrl { get; set; } = "";

    public int TimestampTimeoutSeconds { get; set; } = 10;
}

/// <summary>F-27: mails each seal's digest (sequence, chain-head hash, key, time, signature). Needs email turned on in-app.</summary>
public sealed class EmailSealCopier(IEmailSender email, IOptionsMonitor<EmailOptions> emailOptions, IOptions<SealCopyOptions> options)
    : ISealCopier
{
    public string Name => "Email";

    private IReadOnlyCollection<string> To => options.Value.EmailTo
        .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public async Task CopyAsync(IntegritySeal seal, CancellationToken ct = default)
    {
        // A copy that silently didn't go isn't a copy: email off counts as a failure, so the status says so.
        if (!emailOptions.CurrentValue.Enabled)
            throw new InvalidOperationException("Email is turned off (Administration -> Settings -> Email), so the digest wasn't sent.");
        var body = string.Join("\n",
            "A CaseBook integrity seal was recorded. Keep this message: it's a copy held outside CaseBook.",
            "",
            $"Sealed through sequence : {seal.UpToSequence}",
            $"Chain-head hash        : {seal.ChainHeadHash}",
            $"Sealed at (UTC)        : {seal.SealedAtUtc.UtcDateTime.ToString("o", CultureInfo.InvariantCulture)}",
            $"Sealed by              : {seal.SealedBy}",
            $"Algorithm / key id     : {seal.Algorithm} / {seal.KeyId}",
            $"Signature              : {seal.Signature}");
        await email.SendAsync(To, $"CaseBook integrity seal #{seal.UpToSequence}", body, ct);
    }
}

/// <summary>
/// F-27: asks an internal RFC 3161 timestamp authority to timestamp each seal, and saves the token beside the seal's
/// JSON copy in the export folder (<c>seal-…tsr</c>), so a seal can't later be backdated even with the signing key.
/// Only addresses inside the organization are accepted (CaseBook doesn't reach the internet).
/// </summary>
public sealed class TimestampSealCopier : ISealCopier, IDisposable
{
    private readonly Uri _url;
    private readonly string _folder;
    private readonly HttpClient _http;

    public string Name => "Timestamp authority";

    public TimestampSealCopier(IOptions<SealCopyOptions> options, IOptions<SealSigningOptions> signing, HttpMessageHandler? handler = null)
    {
        _url = RequireInternal(options.Value.TimestampAuthorityUrl);
        _folder = Path.GetFullPath(signing.Value.ExportPath);
        _http = handler is null ? new HttpClient() : new HttpClient(handler);
        _http.Timeout = TimeSpan.FromSeconds(options.Value.TimestampTimeoutSeconds > 0 ? options.Value.TimestampTimeoutSeconds : 10);
    }

    public async Task CopyAsync(IntegritySeal seal, CancellationToken ct = default)
    {
        var data = Encoding.UTF8.GetBytes(seal.BuildCanonicalContent());
        var request = Rfc3161TimestampRequest.CreateFromData(data, HashAlgorithmName.SHA256,
            requestSignerCertificates: true, nonce: RandomNumberGenerator.GetBytes(8));
        using var content = new ByteArrayContent(request.Encode());
        content.Headers.ContentType = new("application/timestamp-query");
        using var response = await _http.PostAsync(_url, content, ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"The timestamp authority answered {(int)response.StatusCode}.");

        var bytes = await response.Content.ReadAsByteArrayAsync(ct);
        Rfc3161TimestampToken token;
        try { token = request.ProcessResponse(bytes, out _); }
        catch (CryptographicException ex) { throw new InvalidOperationException($"The timestamp authority's answer wasn't a valid timestamp: {ex.Message}"); }
        if (!token.VerifySignatureForData(data, out _))
            throw new InvalidOperationException("The timestamp's signature doesn't verify.");

        Directory.CreateDirectory(_folder);
        var name = $"seal-{seal.UpToSequence:D9}-{seal.SealedAtUtc:yyyyMMddTHHmmssZ}.tsr";
        await File.WriteAllBytesAsync(Path.Combine(_folder, name), token.AsSignedCms().Encode(), ct);
    }

    /// <summary>
    /// The URL, if it's http(s) and every address its host resolves to is private, loopback or link-local; otherwise
    /// throws. CaseBook sends nothing outside the organization.
    /// </summary>
    public static Uri RequireInternal(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            throw new InvalidOperationException($"Integrity:SealCopies:TimestampAuthorityUrl '{url}' isn't an http(s) URL.");
        IPAddress[] addresses;
        try { addresses = IPAddress.TryParse(uri.Host, out var ip) ? [ip] : Dns.GetHostAddresses(uri.DnsSafeHost); }
        catch (SocketException ex) { throw new InvalidOperationException($"Integrity:SealCopies:TimestampAuthorityUrl: '{uri.Host}' doesn't resolve ({ex.Message})."); }
        if (addresses.Length == 0 || addresses.Any(a => !IsInternal(a)))
            throw new InvalidOperationException($"Integrity:SealCopies:TimestampAuthorityUrl: '{uri.Host}' isn't an internal address. " +
                "CaseBook only sends seals to timestamp authorities inside the organization.");
        return uri;
    }

    public static bool IsInternal(IPAddress a)
    {
        if (IPAddress.IsLoopback(a)) return true;
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        if (a.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = a.GetAddressBytes();
            return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
        }
        return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6UniqueLocal;
    }

    public void Dispose() => _http.Dispose();
}
