using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using ICSharpCode.SharpZipLib.Zip;
using IncidentManager.Application.Access;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using Microsoft.AspNetCore.Http.Features;

namespace IncidentManager.Web.Security;

/// <summary>
/// CAP-12: the evidence package download. A package prepared on the Evidence tab (<c>CaseService.StageEvidencePackageAsync</c>)
/// is fetched once, by its ticket, as one zip with the password "infected" (PROD-58's path: ZipCrypto, deflated, a data
/// descriptor, Zip64 when large) streamed straight from the store, decrypted as it's read (ADR 0017), with a MANIFEST.txt
/// last. Each file's bytes are checked against its recorded SHA-256 on the way. The custody events, the audit entry, the
/// access-log row and the SIEM event (5308) are written only once the whole package has been written: a store or key
/// outage part-way, a file that doesn't match its record, or a download cut off records nothing, and the response is
/// aborted so no zip that opens arrives without its record (<see cref="EvidencePackageWriter"/>).
/// </summary>
public static class EvidencePackageEndpoints
{
    public static void MapEvidencePackages(this IEndpointRouteBuilder app)
    {
        app.MapGet("/evidence/package/{ticket}", async (string ticket, EvidenceService evidence, IAccessLogService access,
            ILoggerFactory logs, HttpContext http, CancellationToken ct) =>
        {
            EvidencePackage package;
            try { package = await evidence.OpenPackageAsync(ticket, ct); }
            catch (Application.Common.NotFoundException ex) { return Results.Problem(ex.Message, statusCode: StatusCodes.Status404NotFound); }
            catch (ForbiddenException ex) { return Results.Problem(ex.Message, statusCode: StatusCodes.Status403Forbidden); }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
            {
                return Results.Problem(ex.Message, statusCode: StatusCodes.Status409Conflict);   // withdrawn or gone since, too large
            }
            var manifest = evidence.ManifestOf(package);
            var log = logs.CreateLogger(typeof(EvidencePackageEndpoints));
            http.Response.Headers.ContentSecurityPolicy = "sandbox; default-src 'none'";
            // SharpZipLib writes synchronously; the response streams straight from the store (no plain copy on disk).
            if (http.Features.Get<IHttpBodyControlFeature>() is { } body) body.AllowSynchronousIO = true;
            return Results.Stream(async output =>
            {
                // C10: bounded. A package sent slower than about 1 MB/s on average (after a quarter of an hour) is stopped.
                using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
                limit.CancelAfter(EvidencePackageWriter.TimeLimit(package.TotalBytes));
                var recorded = false;
                try
                {
                    await EvidencePackageWriter.WriteAsync(package, manifest, evidence.OpenPackagedFileAsync, output,
                        async (packageSha, manifestSha) =>
                        {
                            await evidence.RecordPackageAsync(package, packageSha, manifestSha, CancellationToken.None);
                            recorded = true;
                            await access.RecordArtifactAsync(AccessType.EvidencePackage, package.CaseId,
                                $"Evidence package: {Application.Common.Plural.Of(package.Files.Count, "file", "files")}, {EvidenceRoom.Size(package.TotalBytes)}",
                                package.Id, CancellationToken.None);
                        }, limit.Token);
                }
                catch (Exception ex) when (!recorded)
                {
                    // Nothing was recorded; the browser shows the download as failed rather than saving part of a zip.
                    log.LogWarning(ex, "Evidence package {PackageId} for case {CaseNumber} stopped before it finished; nothing was recorded.",
                        package.Id, package.CaseNumber);
                    http.Abort();
                }
                catch (Exception ex)
                {
                    // Every file and the manifest went out and the transfer is recorded; only the zip's last bytes (its
                    // directory) didn't reach the browser, so its copy won't open. The record stands: the bytes left.
                    log.LogWarning(ex, "Evidence package {PackageId} for case {CaseNumber} was recorded, but its last bytes didn't reach the browser.",
                        package.Id, package.CaseNumber);
                    http.Abort();
                }
            }, "application/zip", package.FileName);
        }).RequireAuthorization(Policies.EditCases).RequireRateLimiting("downloads").RefusePassiveLoads();
    }
}

/// <summary>
/// CAP-12: writes an evidence package as one password-protected zip, and calls <c>record</c> with the package's SHA-256
/// (of every byte of the zip, as sent) and the manifest's before the zip's last bytes (its central directory) go out.
/// A failure before then (a file that can't be read, one whose bytes don't match its record, the record itself) throws,
/// and the zip sent so far has no central directory, so it doesn't open; nothing is recorded for it.
/// </summary>
public static class EvidencePackageWriter
{
    /// <summary>A quarter of an hour, plus a second for each MB.</summary>
    public static TimeSpan TimeLimit(long bytes) => TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(bytes / (1024d * 1024));

    public static async Task WriteAsync(EvidencePackage package, string manifest,
        Func<EvidencePackageFile, CancellationToken, Task<Stream>> open, Stream output, Func<string, string, Task> record,
        CancellationToken ct)
    {
        var manifestBytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(manifest);
        using var whole = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await using var tap = new HoldingStream(output, whole);
        var buffer = ArrayPool<byte>.Shared.Rent(1 << 16);
        try
        {
            var zip = new ZipOutputStream(tap) { IsStreamOwner = false, Password = EvidenceRisk.ZipPassword };
            try
            {
                // Classic zip encryption (ZipCrypto), as the safe download: Windows Explorer and every zip tool open it.
                zip.UseZip64 = package.TotalBytes + manifestBytes.Length >= uint.MaxValue - (64L << 20) ? UseZip64.On : UseZip64.Off;
                zip.SetLevel(1);
                foreach (var f in package.Files)
                {
                    using var file = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    long read = 0;
                    await using (var content = await open(f, ct))
                    {
                        zip.PutNextEntry(new ZipEntry(f.EntryName)
                        {
                            DateTime = f.Evidence.CreatedAtUtc.UtcDateTime, Size = f.Evidence.SizeBytes, AESKeySize = 0
                        });
                        int n;
                        while ((n = await content.ReadAsync(buffer.AsMemory(), ct)) > 0)
                        {
                            file.AppendData(buffer, 0, n);
                            zip.Write(buffer, 0, n);
                            read += n;
                        }
                    }
                    zip.CloseEntry();
                    if (read != f.Evidence.SizeBytes
                        || !string.Equals(Convert.ToHexString(file.GetHashAndReset()), f.Evidence.Sha256, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException($"{f.Evidence.OriginalFileName} doesn't match its recorded SHA-256 any more, so the " +
                            "package was stopped. The evidence check reports it; ask an administrator.");
                }
                zip.PutNextEntry(new ZipEntry(EvidencePackage.ManifestName)
                {
                    DateTime = package.PreparedAtUtc.UtcDateTime, Size = manifestBytes.Length, AESKeySize = 0
                });
                zip.Write(manifestBytes, 0, manifestBytes.Length);
                zip.CloseEntry();
                tap.Hold();   // the central directory is kept back until the package is recorded
                zip.Finish();
            }
            catch
            {
                // Closing the zip writes its directory: never to the response. An unfinished entry may refuse to close; the
                // first failure is the one reported.
                tap.Hold();
                try { zip.Dispose(); }
                catch (Exception e) when (e is ZipException or IOException or InvalidOperationException) { /* the zip is abandoned */ }
                throw;
            }
            zip.Dispose();
            var packageSha = Convert.ToHexString(whole.GetHashAndReset()).ToLowerInvariant();
            var manifestSha = Convert.ToHexString(SHA256.HashData(manifestBytes)).ToLowerInvariant();
            await record(packageSha, manifestSha);
            await tap.ReleaseAsync(ct);
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }

    // Passes every byte on (hashing it) until Hold, then keeps the rest until Release: the zip's central directory waits
    // for the package's record.
    private sealed class HoldingStream(Stream inner, IncrementalHash hash) : Stream
    {
        private MemoryStream? _held;

        public void Hold() => _held ??= new MemoryStream();

        public async Task ReleaseAsync(CancellationToken ct)
        {
            if (_held is { } held)
            {
                _held = null;
                held.Position = 0;
                await held.CopyToAsync(inner, ct);
                await held.DisposeAsync();
            }
            await inner.FlushAsync(ct);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            hash.AppendData(buffer, offset, count);
            if (_held is { } held) held.Write(buffer, offset, count);
            else inner.Write(buffer, offset, count);
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            hash.AppendData(buffer.Span);
            if (_held is { } held) held.Write(buffer.Span);
            else await inner.WriteAsync(buffer, cancellationToken);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Flush()
        {
            if (_held is null) inner.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            _held is null ? inner.FlushAsync(cancellationToken) : Task.CompletedTask;

        public override bool CanRead => false;
        public override bool CanSeek => false;   // so the zip writes a data descriptor after each entry, as it streams
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override async ValueTask DisposeAsync()
        {
            if (_held is { } held) await held.DisposeAsync();
            _held = null;
            await base.DisposeAsync();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _held?.Dispose();
            _held = null;
            base.Dispose(disposing);
        }
    }
}
