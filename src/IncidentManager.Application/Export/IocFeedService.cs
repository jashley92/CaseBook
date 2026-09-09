using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Export;

/// <summary>
/// A single confirmed-malicious indicator ready to push to SIEM / firewalls / EDR (E-13).
/// Deduped across the caller's visible cases by (type, value); carries first/last-seen and the
/// source case(s) so the blocklist is defensible back to the investigation it came from.
/// </summary>
public sealed record IocFeedRow(
    EntityType Type,
    string Value,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    IReadOnlyList<string> Cases,
    IReadOnlyList<string> Sources);

/// <summary>
/// Curated malicious-IOC feed: the confirmed-<see cref="EntityDisposition.Malicious"/>, IOC-like
/// indicators across every case the caller is entitled to see, deduped into a flat blocklist.
/// Distinct from the full entity graph (E-07) — this is the flat, pushable detection feed (E-13).
/// </summary>
public sealed class IocFeedService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;

    public IocFeedService(IAppDbContextFactory factory, ICurrentUser user)
    {
        _factory = factory;
        _user = user;
    }

    /// <summary>
    /// IOC-like types worth pushing to a blocklist. Assets (Account/Host) and free-form artifacts
    /// (FileName/Process/RegistryKey/EmailAddress/Other) are deliberately excluded — mirrors the
    /// UI's <c>Ui.IsIocLike</c> so the feed carries only network/file indicators a control can act on.
    /// </summary>
    private static readonly EntityType[] IocTypes =
        [EntityType.IpAddress, EntityType.Domain, EntityType.Url, EntityType.FileHash];

    public async Task<IReadOnlyList<IocFeedRow>> GetMaliciousIocsAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();

        // Join to the caller's visible cases so restricted-case IOCs never leak into the feed;
        // an indicator present on both a visible and a restricted case surfaces only its visible
        // occurrences (first/last-seen and source list are computed over those alone).
        var rows = await (
            from e in db.CaseEntities.AsNoTracking()
            where e.Disposition == EntityDisposition.Malicious && IocTypes.Contains(e.Type)
            join c in db.Cases.AsNoTracking().ForUser(_user) on e.CaseId equals c.Id
            select new { e.Type, e.Value, e.Source, e.CreatedAtUtc, c.CaseNumber }
        ).ToListAsync(ct);

        // Dedupe by (type, value) in memory — case-insensitive to match the E-08 overlap engine,
        // and to keep DateTimeOffset aggregation off SQLite (see F-08).
        return rows
            .GroupBy(r => (r.Type, Key: r.Value.ToLowerInvariant()))
            .Select(g =>
            {
                var ordered = g.OrderByDescending(x => x.CreatedAtUtc).ToList();
                return new IocFeedRow(
                    Type: g.Key.Type,
                    Value: ordered[0].Value, // representative casing: the most recent occurrence
                    FirstSeenUtc: g.Min(x => x.CreatedAtUtc),
                    LastSeenUtc: g.Max(x => x.CreatedAtUtc),
                    Cases: g.Select(x => x.CaseNumber).Distinct().OrderBy(x => x).ToList(),
                    Sources: g.Select(x => x.Source)
                              .Where(s => !string.IsNullOrWhiteSpace(s))
                              .Select(s => s!.Trim())
                              .Distinct(StringComparer.OrdinalIgnoreCase)
                              .OrderBy(s => s)
                              .ToList());
            })
            .OrderBy(r => r.Type)
            .ThenBy(r => r.Value, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
