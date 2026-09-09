using IncidentManager.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// Allocates the next per-year IRP sequence — the max over classified (IRP-ladder) auto-numbered cases,
/// plus one. Classified cases never de-classify, so the counter only grows and a sequence is never reused;
/// Complex Events are date-numbered and excluded. The partial unique <c>(Year, Sequence)</c> index guards
/// against duplicates under concurrency; callers retry on the rare conflict.
/// </summary>
public sealed class CaseNumberGenerator : ICaseNumberGenerator
{
    private readonly AppDbContext _db;

    public CaseNumberGenerator(AppDbContext db) => _db = db;

    public async Task<int> NextSequenceAsync(int year, CancellationToken ct = default)
    {
        var max = await _db.Cases
            .Where(c => c.Year == year && c.Classification != null && !c.HasCustomNumber)
            .Select(c => (int?)c.Sequence)
            .MaxAsync(ct);
        return (max ?? 0) + 1;
    }
}
