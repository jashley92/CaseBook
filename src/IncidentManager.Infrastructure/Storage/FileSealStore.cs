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
            seal.Signature
        };

        var name = $"seal-{seal.UpToSequence:D9}-{seal.SealedAtUtc:yyyyMMddTHHmmssZ}.json";
        var path = Path.Combine(_root, name);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(record, Json), ct);
    }
}
