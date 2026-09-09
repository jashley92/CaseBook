namespace IncidentManager.Application.Abstractions;

/// <summary>A stored report-header logo: the raw image bytes and its content type (image/png or image/jpeg).</summary>
public sealed record ReportLogo(byte[] Bytes, string ContentType);

/// <summary>
/// Persists the single organisation logo embedded in the header of generated Word/PDF reports (deployment
/// branding, not per-case content). One image for the whole install; replacing it overwrites the previous
/// one. Kept out of source and off the case hash-chain — it is presentation branding, set by an admin.
/// </summary>
public interface IReportBrandingStore
{
    /// <summary>The current logo, or null if none has been uploaded.</summary>
    Task<ReportLogo?> GetLogoAsync(CancellationToken ct = default);

    /// <summary>Stores (replacing any existing) the logo. <paramref name="contentType"/> must be image/png or image/jpeg.</summary>
    Task SaveLogoAsync(byte[] bytes, string contentType, CancellationToken ct = default);

    /// <summary>Removes the logo so reports fall back to a text-only header. No-op if none is set.</summary>
    Task ClearLogoAsync(CancellationToken ct = default);
}
