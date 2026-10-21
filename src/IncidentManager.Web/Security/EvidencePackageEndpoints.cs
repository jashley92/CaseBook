using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using ICSharpCode.SharpZipLib.Zip;
using IncidentManager.Application.Abstractions;
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
/// last. CAP-12 review: a data-descriptor zip can be read from its local headers without its directory (SharpZipLib's
/// ZipInputStream, 7-Zip), so every file sent before a cut reaches the recipient. So the transfer is recorded before its
/// first byte ("Transfer begun" on each file and an audit entry with the package id and the hand-over, with the access-log
/// row and SIEM 5308), and how it ended after: sent in full (with the package's and the manifest's SHA-256, before the
/// zip's directory goes out), or stopped after N files, naming which went out in full, in part, or not at all. A begun
/// record with no end after it (the server stopped) is a partial transfer. Each file is checked against its recorded
/// SHA-256 before any of it is sent (<see cref="EvidencePackageWriter"/>).
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
            // CAP-12 review: the record comes first. Without it, nothing is sent.
            try { await evidence.RecordPackageBegunAsync(package, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log.LogWarning(ex, "Evidence package {PackageId} for case {CaseNumber} wasn't sent: its hand-over couldn't be recorded.",
                    package.Id, package.CaseNumber);
                return Results.Problem("The hand-over couldn't be recorded, so nothing was sent. Prepare the package again in a moment.",
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }
            // As it begins, so a package cut part-way is in the access log and the SIEM stream too (never throws).
            await access.RecordArtifactAsync(AccessType.EvidencePackage, package.CaseId,
                $"Evidence package: {Application.Common.Plural.Of(package.Files.Count, "file", "files")}, {EvidenceRoom.Size(package.TotalBytes)}",
                package.Id, CancellationToken.None);
            http.Response.Headers.ContentSecurityPolicy = "sandbox; default-src 'none'";
            // SharpZipLib writes synchronously; the response streams straight from the store (no plain copy on disk).
            if (http.Features.Get<IHttpBodyControlFeature>() is { } body) body.AllowSynchronousIO = true;
            return Results.Stream(async output =>
            {
                // The browser shows a download that didn't finish as failed rather than saving part of a zip.
                if (!await SendAsync(package, manifest, evidence, log, output, ct)) http.Abort();
            }, "application/zip", package.FileName);
        }).RequireAuthorization(Policies.EditCases).RequireRateLimiting("downloads").RefusePassiveLoads();
    }

    /// <summary>
    /// CAP-12 review: sends a package whose start is recorded (<see cref="EvidenceService.RecordPackageBegunAsync"/>) and
    /// records how it ended: sent in full, before the zip's directory; or stopped, as far as it got. The log says which,
    /// and whether that record was written. False when the zip didn't arrive whole (the caller aborts the response).
    /// </summary>
    public static async Task<bool> SendAsync(EvidencePackage package, string manifest, EvidenceService evidence, ILogger log,
        Stream output, CancellationToken ct)
    {
        // C10: bounded. A package sent slower than about 1 MB/s on average (after a quarter of an hour) is stopped.
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(EvidencePackageWriter.TimeLimit(package.TotalBytes));
        var progress = new EvidencePackageProgress(package.Files.Count);
        bool recording = false, recorded = false;
        try
        {
            await EvidencePackageWriter.WriteAsync(package, manifest, evidence.OpenPackagedFileAsync, output, progress,
                async (packageSha, manifestSha) =>
                {
                    recording = true;
                    await evidence.RecordPackageSentAsync(package, progress, packageSha, manifestSha, CancellationToken.None);
                    recorded = true;
                }, limit.Token);
            return true;
        }
        catch (Exception ex) when (recorded)
        {
            // Every file and the manifest went out and the transfer is recorded as sent in full; only the zip's last bytes
            // (its directory) didn't reach the browser. The record stands: the bytes left.
            log.LogWarning(ex, "Evidence package {PackageId} for case {CaseNumber} was sent in full and recorded, but its last bytes didn't reach the browser.",
                package.Id, package.CaseNumber);
            return false;
        }
        catch (Exception ex)
        {
            var why = recording ? "its completion couldn't be recorded"
                : ex switch
                {
                    OperationCanceledException when ct.IsCancellationRequested => "the download was canceled or cut off",
                    OperationCanceledException => "it ran past its time limit",
                    InvalidDataException => "a file didn't match its recorded SHA-256",
                    EvidenceKeyUnavailableException => "the evidence key wasn't available",
                    IOException => "the evidence store or the connection failed",
                    _ => "an error stopped it",
                };
            var sent = progress.SentInFull;
            try
            {
                await evidence.RecordPackageStoppedAsync(package, progress, why, CancellationToken.None);
                log.LogWarning(ex, "Evidence package {PackageId} for case {CaseNumber} stopped after {Sent} of {Files} files ({Why}); it's recorded as partial.",
                    package.Id, package.CaseNumber, sent, package.Files.Count, why);
            }
            catch (Exception failed)
            {
                log.LogError(failed, "Evidence package {PackageId} for case {CaseNumber} stopped after {Sent} of {Files} files ({Why}), and how far it got " +
                    "couldn't be recorded: the record shows only that it began, which reads as partial. What stopped it: {Stopped}",
                    package.Id, package.CaseNumber, sent, package.Files.Count, why, ex.GetType().Name);
            }
            return false;
        }
    }
}

/// <summary>
/// CAP-12: writes an evidence package as one password-protected zip. CAP-12 review: each file is read and checked against
/// its recorded SHA-256 (and size) before any of its bytes are written, then read again as it's sent (one more read,
/// decrypt and hash per file, as the upload's read-back check: integrity.md has the cost), so a file that doesn't match
/// is never sent; one that changes between the two reads is hashed again as it goes and recorded as sent and not
/// matching. <paramref name="progress"/> says how far each file got. <c>record</c> is called with the package's SHA-256 (of
/// every byte of the zip, as sent) and the manifest's before the zip's last bytes (its central directory) go out; a
/// failure before then throws, and the central directory never goes out.
/// </summary>
public static class EvidencePackageWriter
{
    /// <summary>A quarter of an hour, plus a second for each MB.</summary>
    public static TimeSpan TimeLimit(long bytes) => TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(bytes / (1024d * 1024));

    public static async Task WriteAsync(EvidencePackage package, string manifest,
        Func<EvidencePackageFile, CancellationToken, Task<Stream>> open, Stream output, EvidencePackageProgress progress,
        Func<string, string, Task> record, CancellationToken ct)
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
                for (var i = 0; i < package.Files.Count; i++)
                {
                    var f = package.Files[i];
                    // CAP-12 review: checked before any byte of it leaves (a zip that stops can still be read up to there).
                    using (var check = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                    {
                        long seen = 0;
                        await using (var content = await open(f, ct))
                        {
                            int n;
                            while ((n = await content.ReadAsync(buffer.AsMemory(), ct)) > 0)
                            {
                                check.AppendData(buffer, 0, n);
                                seen += n;
                            }
                        }
                        if (!Matches(f, seen, check))
                        {
                            progress.Mark(i, PackagedFileOutcome.HeldBack);
                            throw Mismatch(f);
                        }
                    }
                    using var file = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    long read = 0;
                    await using (var content = await open(f, ct))
                    {
                        await zip.PutNextEntryAsync(new ZipEntry(f.EntryName)
                        {
                            DateTime = f.Evidence.CreatedAtUtc.UtcDateTime, Size = f.Evidence.SizeBytes, AESKeySize = 0
                        }, ct);
                        int n;
                        while ((n = await content.ReadAsync(buffer.AsMemory(), ct)) > 0)
                        {
                            file.AppendData(buffer, 0, n);
                            if (read == 0) progress.Mark(i, PackagedFileOutcome.PartlySent);
                            await zip.WriteAsync(buffer.AsMemory(0, n), ct);
                            read += n;
                        }
                    }
                    // Checked before CloseEntry: a file whose length changed since the check read makes CloseEntry throw
                    // (its declared size), which would read as "partly sent" rather than sent and not matching.
                    if (!Matches(f, read, file))
                    {
                        progress.Mark(i, PackagedFileOutcome.SentNotMatching);
                        throw Mismatch(f);
                    }
                    await zip.CloseEntryAsync(ct);
                    progress.Mark(i, PackagedFileOutcome.Sent);
                }
                await zip.PutNextEntryAsync(new ZipEntry(EvidencePackage.ManifestName)
                {
                    DateTime = package.PreparedAtUtc.UtcDateTime, Size = manifestBytes.Length, AESKeySize = 0
                }, ct);
                await zip.WriteAsync(manifestBytes, ct);
                await zip.CloseEntryAsync(ct);
                progress.ManifestSent = true;
                tap.Hold();   // the central directory is kept back until the package is recorded
                await zip.FinishAsync(ct);
            }
            catch
            {
                // Closing the zip writes its directory: never to the response. An unfinished entry may refuse to close; the
                // first failure is the one reported.
                tap.Hold();
                try { await zip.DisposeAsync(); }
                catch (Exception e) when (e is ZipException or IOException or InvalidOperationException) { /* the zip is abandoned */ }
                throw;
            }
            await zip.DisposeAsync();
            var packageSha = Convert.ToHexString(whole.GetHashAndReset()).ToLowerInvariant();
            var manifestSha = Convert.ToHexString(SHA256.HashData(manifestBytes)).ToLowerInvariant();
            await record(packageSha, manifestSha);
            await tap.ReleaseAsync(ct);
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }

    private static bool Matches(EvidencePackageFile f, long read, IncrementalHash hash) =>
        read == f.Evidence.SizeBytes
        && string.Equals(Convert.ToHexString(hash.GetHashAndReset()), f.Evidence.Sha256, StringComparison.OrdinalIgnoreCase);

    private static InvalidDataException Mismatch(EvidencePackageFile f) =>
        new($"{f.Evidence.OriginalFileName} doesn't match its recorded SHA-256 any more, so the package was stopped. The evidence " +
            "check reports it; ask an administrator.");

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
