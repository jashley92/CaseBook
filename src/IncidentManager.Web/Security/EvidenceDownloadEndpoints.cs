using ICSharpCode.SharpZipLib.Zip;
using IncidentManager.Application.Access;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using Microsoft.AspNetCore.Http.Features;

namespace IncidentManager.Web.Security;

/// <summary>
/// The evidence downloads: the file as stored, and PROD-58's safe download, the file inside a zip with the password
/// "infected" so a double-click can't run it and the analyst's antivirus doesn't delete it on arrival. Both need
/// permission to view the case (the service scopes to it), are rate-limited, refuse passive and cross-site loads, and
/// record a chain-of-custody event and an access-log row. Evidence is always sent as an attachment of no particular
/// type, with a sandboxing CSP, so nothing the browser opens from it runs in CaseBook's origin.
/// </summary>
public static class EvidenceDownloadEndpoints
{
    public static void MapEvidenceDownloads(this IEndpointRouteBuilder app)
    {
        app.MapGet("/evidence/{id:guid}", async (Guid id, EvidenceService evidence, IAccessLogService access, HttpContext http,
            CancellationToken ct) =>
        {
            var (item, stream, refused) = await OpenAsync(evidence, id, null, ct);
            if (refused is not null) return refused;
            await access.RecordArtifactAsync(AccessType.EvidenceDownload, item!.CaseId, item.OriginalFileName, item.Id, ct);
            Harden(http);
            // PROD-58: the type the uploader's browser claimed is never sent back; the file is just bytes to save.
            return Results.File(stream!, "application/octet-stream", item.OriginalFileName);
        }).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads").RefusePassiveLoads();

        app.MapGet("/evidence/{id:guid}/safe", async (Guid id, EvidenceService evidence, IAccessLogService access, HttpContext http,
            CancellationToken ct) =>
        {
            var (item, stream, refused) = await OpenAsync(evidence, id,
                $"in a zip with the password \"{EvidenceRisk.ZipPassword}\"", ct);
            if (refused is not null) return refused;
            await access.RecordArtifactAsync(AccessType.EvidenceDownload, item!.CaseId, item.OriginalFileName + " (in a password-protected zip)",
                item.Id, ct);
            Harden(http);
            // SharpZipLib writes synchronously; this response streams straight from the store (no plain copy on disk).
            if (http.Features.Get<IHttpBodyControlFeature>() is { } body) body.AllowSynchronousIO = true;
            var entryName = EvidenceRisk.EntryName(item.OriginalFileName);
            var size = item.SizeBytes;
            var modified = item.CreatedAtUtc.UtcDateTime;
            return Results.Stream(async output =>
            {
                await using var content = stream!;
                using var zip = new ZipOutputStream(output) { IsStreamOwner = false, Password = EvidenceRisk.ZipPassword };
                // Classic zip encryption (ZipCrypto), which Windows Explorer and every zip tool open; it stops accidental
                // execution and antivirus deletion, not a determined reader. Deflated with a data descriptor, so it streams.
                zip.UseZip64 = size >= uint.MaxValue - 1024 ? UseZip64.On : UseZip64.Off;
                zip.SetLevel(1);
                zip.PutNextEntry(new ZipEntry(entryName) { DateTime = modified, Size = size, AESKeySize = 0 });
                await content.CopyToAsync(zip, 1 << 16);
                zip.CloseEntry();
                zip.Finish();
            }, "application/zip", entryName + ".zip");
        }).RequireAuthorization(Policies.ViewCases).RequireRateLimiting("downloads").RefusePassiveLoads();
    }

    // Opened (and its custody event recorded) or the answer to send instead: gone or not theirs, missing, store unreadable.
    private static async Task<(IncidentManager.Domain.Entities.Evidence?, Stream?, IResult?)> OpenAsync(EvidenceService evidence,
        Guid id, string? details, CancellationToken ct)
    {
        try
        {
            var (item, stream) = await evidence.OpenAsync(id, recordDownload: true, downloadDetails: details, ct: ct);
            return (item, stream, null);
        }
        catch (Application.Common.NotFoundException) { return (null, null, Results.NotFound()); }   // REV-64: gone, or not theirs to see
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            // BUG-197: the record is there but its file isn't (the evidence check reports it as missing).
            return (null, null, Results.Problem("This evidence file is missing from the evidence store. Nothing was downloaded; " +
                "ask an administrator to restore it.", statusCode: StatusCodes.Status404NotFound));
        }
        catch (IncidentManager.Application.Abstractions.EvidenceKeyUnavailableException ex)
        {
            // PROD-57: the file is fine; its key isn't available on this server (administrators have been alerted).
            return (null, null, Results.Problem(ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable));
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // BUG-712: the file starts like an encrypted one but its header doesn't read (damaged, or a file stored as it
            // arrived that happens to begin that way). Worded, as the evidence check words it, not the error page.
            return (null, null, Results.Problem("This evidence file doesn't open: it begins like an encrypted file, but its " +
                "header can't be read. Nothing was downloaded; ask an administrator to run the evidence check (Administration › " +
                "Diagnostics).", statusCode: StatusCodes.Status409Conflict));
        }
        catch (IOException)
        {
            // PROD-56: the store itself couldn't be read (a share that's down, permissions): nothing was downloaded or recorded.
            return (null, null, Results.Problem("The evidence store couldn't be read just now. Nothing was downloaded. Try again; if " +
                "it keeps failing, ask an administrator to check the evidence store (Administration › Diagnostics).",
                statusCode: StatusCodes.Status503ServiceUnavailable));
        }
    }

    // PROD-58: whatever the browser makes of the response, it runs in an opaque origin with nothing allowed.
    private static void Harden(HttpContext http) => http.Response.Headers.ContentSecurityPolicy = "sandbox; default-src 'none'";
}
