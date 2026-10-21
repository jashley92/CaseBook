using IncidentManager.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// Allocates the next per-year IRP sequence — the max over classified (IRP-ladder) cases, plus one. Classified
/// cases never de-classify, so the counter only grows and a sequence is never reused; Complex Events are
/// date-numbered and excluded. BUG-145: a case renumbered to a custom number keeps its sequence and still counts,
/// so renaming the latest case doesn't free its sequence (a case numbered custom from the start has none). The partial unique <c>(Year, Sequence)</c> index guards
/// against duplicates under concurrency; callers retry on the rare conflict.
/// </summary>
public sealed class CaseNumberGenerator : ICaseNumberGenerator
{
    private readonly AppDbContext? _db;
    private readonly IAppDbContextFactory? _factory;

    public CaseNumberGenerator(AppDbContext db) => _db = db;

    /// <summary>
    /// REV-20: what the app uses. In Blazor Server a scope is the whole circuit, so a scoped context would be shared by
    /// every operation in it (two promotions in one circuit could overlap on it). Each allocation reads on its own.
    /// </summary>
    public CaseNumberGenerator(IAppDbContextFactory factory) => _factory = factory;

    public async Task<int> NextSequenceAsync(int year, CancellationToken ct = default)
    {
        using var owned = _factory?.CreateDbContext();
        var cases = owned?.Cases ?? _db!.Cases;
        // A removed case keeps its sequence until it's purged (it can still be restored); a purged one gives it up, so the
        // next case can take the number again.
        var max = await cases.IgnoreQueryFilters()
            .Where(c => c.Year == year && c.Classification != null && c.PurgedAtUtc == null)
            .Select(c => (int?)c.Sequence)
            .MaxAsync(ct);
        return (max ?? 0) + 1;
    }
}
