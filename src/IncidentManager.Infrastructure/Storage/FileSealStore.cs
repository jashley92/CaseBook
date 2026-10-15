using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Security;
using Microsoft.Extensions.Options;

namespace IncidentManager.Infrastructure.Storage;

/// <summary>
/// Writes each integrity seal to a directory outside the database as an append-only JSON file. In
/// production this path should be a restricted/WORM or offsite share so the out-of-band copy can be
/// trusted even if the database is compromised.
/// </summary>
public sealed class FileSealStore : ISealStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private readonly string _root;

    public FileSealStore(IOptions<SealSigningOptions> options)
    {
        _root = Path.GetFullPath(options.Value.ExportPath);
        Directory.CreateDirectory(_root);
    }

    public async Task ExportAsync(IntegritySeal seal, CancellationToken ct = default)
    {
        var record = new
        {
            seal.UpToSequence,
            seal.ChainHeadHash,
            SealedAtUtc = seal.SealedAtUtc.ToString("o"),
            seal.SealedBy,
            seal.Algorithm,
            seal.KeyId,
            seal.KeyedFromSequence,   // BUG-142: part of the signed payload when set
            seal.Signature
        };

        await WriteNewAsync(Path.Combine(_root, FileName(seal, "json")), System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record, Json)), ct);
    }

    /// <summary>
    /// REV-07: one file per seal, never overwritten. Two seals over the same head in the same second (a double click,
    /// or a manual seal beside the background job) each keep their copy: the name carries the seal's id.
    /// </summary>
    internal static string FileName(IntegritySeal seal, string extension) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture,   // BUG-531: Gregorian on any server culture
            $"seal-{seal.UpToSequence:D9}-{seal.SealedAtUtc.UtcDateTime:yyyyMMddTHHmmssZ}-{seal.Id.ToString("N")[..8]}.{extension}");

    internal static async Task WriteNewAsync(string path, byte[] content, CancellationToken ct)
    {
        await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await file.WriteAsync(content, ct);
    }
}
