using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

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
    IReadOnlyList<string> Sources,
    TlpLevel? Tlp = null);   // WF-37: the most restrictive marking any occurrence carries

/// <summary>CAP-09: the feed's rows, and whether it was cut at <paramref name="Limit"/> occurrences.</summary>
/// <param name="Since">The delta's start, when it is one (<see cref="IocFeedService.GetFeedAsync"/>).</param>
public sealed record IocFeed(IReadOnlyList<IocFeedRow> Rows, bool Cut, int Limit, DateTimeOffset? Since)
{
    /// <summary>
    /// CAP-09: a digest of everything the feed says (each row, the cut and the delta's start), plus <paramref name="writer"/>
    /// for what its format adds, so a scheduled pull that would get the same feed again is answered 304 (the API's ETag).
    /// Not the generated time, which every pull has its own.
    /// </summary>
    public string Fingerprint(string writer)
    {
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        var text = new System.Text.StringBuilder(writer).Append('\n')
            .Append(Cut).Append('|').Append(Limit.ToString(inv)).Append('|').Append(Since?.UtcTicks.ToString(inv)).Append('\n');
        foreach (var r in Rows)
            text.Append((int)r.Type).Append('|').Append(r.Value).Append('|').Append(r.FirstSeenUtc.UtcTicks.ToString(inv)).Append('|')
                .Append(r.LastSeenUtc.UtcTicks.ToString(inv)).Append('|').Append(string.Join('\u001f', r.Cases)).Append('|')
                .Append(string.Join('\u001f', r.Sources)).Append('|').Append(r.Tlp is { } t ? ((int)t).ToString(inv) : "").Append('\n');
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text.ToString())))[..32]
            .ToLowerInvariant();
    }
}

/// <summary>
/// Curated malicious-IOC feed: the confirmed-<see cref="EntityDisposition.Malicious"/>, IOC-like
/// indicators across every case the caller is entitled to see, deduped into a flat blocklist.
/// Distinct from the full entity graph (E-07) — this is the flat, pushable detection feed (E-13).
/// </summary>
public sealed class IocFeedService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IOptionsMonitor<ReportingOptions>? _reporting;

    public IocFeedService(IAppDbContextFactory factory, ICurrentUser user, IOptionsMonitor<ReportingOptions>? reporting = null)
    {
        _factory = factory;
        _user = user;
        _reporting = reporting;
    }

    /// <summary>
    /// IOC-like types worth pushing to a blocklist. Assets (Account/Host) and free-form artifacts
    /// (FileName/Process/CommandLine/RegistryKey/EmailAddress/Other) are deliberately excluded — mirrors the
    /// UI's <c>Ui.IsIocLike</c> so the feed carries only network/file indicators a control can act on.
    /// </summary>
    private static readonly EntityType[] IocTypes =
        [EntityType.IpAddress, EntityType.Domain, EntityType.Url, EntityType.FileHash];

    /// <summary>CAP-09: the most indicator occurrences one feed reads (C10). Past it, the feed holds the most recently
    /// changed ones and says it was cut.</summary>
    public const int MaxOccurrences = 100_000;

    public async Task<IReadOnlyList<IocFeedRow>> GetMaliciousIocsAsync(CancellationToken ct = default) =>
        (await GetFeedAsync(since: null, ct: ct)).Rows;

    /// <summary>
    /// CAP-09: the feed, with <paramref name="since"/> narrowing it to the indicators with an occurrence added or changed
    /// (a verdict, a marking, an edit) at or after that time: a delta for a scheduled pull. A delta can't say what left the
    /// feed (an indicator removed or cleared, or its case restricted or made an exercise since), so a consumer takes a full
    /// pull now and then. CAP-09 review: <paramref name="since"/> picks which indicators are in the delta, never what they
    /// say: each one's marking, cases and first/last seen are over all its visible occurrences, so a delta never downgrades a
    /// TLP:RED indicator to the looser marking of the occurrence that changed, nor replaces its case list with that one case.
    /// Reads at most <paramref name="limit"/> occurrences, cut by whole indicators (the most recently changed first), never
    /// part of one's occurrences; <see cref="IocFeed.Cut"/> says when there were more.
    /// </summary>
    public async Task<IocFeed> GetFeedAsync(DateTimeOffset? since, int limit = MaxOccurrences, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();

        // Join to the caller's visible cases so restricted-case IOCs never leak into the feed;
        // an indicator present on both a visible and a restricted case surfaces only its visible
        // occurrences (first/last-seen and source list are computed over those alone). CAP-09 review: Key is the indicator's
        // dedupe key as the database folds it (SQL LOWER(), as the E-08/E-23 matchers), so the delta's and the cut's selection
        // and the grouping below agree on what one indicator is.
#pragma warning disable CA1304, CA1311 // EF Core translates ToLower() to SQL; the invariant overload doesn't translate.
        var occurrences =
            from e in db.CaseEntities.AsNoTracking()
            where e.Disposition == EntityDisposition.Malicious && IocTypes.Contains(e.Type)
            join c in db.Cases.AsNoTracking().ForUser(_user).ExcludingExercises() on e.CaseId equals c.Id // PROD-43: no drill IOCs in the pushed feed
            select new { e.Id, e.Type, e.Value, Key = e.Value.ToLower(), e.Source, e.CreatedAtUtc, Changed = e.ModifiedAtUtc ?? e.CreatedAtUtc, c.CaseNumber, e.Tlp };
#pragma warning restore CA1304, CA1311
        var query = occurrences;
        // CAP-09 review: the delta is every occurrence of an indicator that has one changed since then, not only the changed ones.
        // R2: the changed indicators' keys are picked once (a grouped derived table) and joined to, not looked for again per
        // occurrence (a correlated EXISTS, which SQLite ran in O(n²): over a minute for 20,000 occurrences).
        if (since is { } from)
        {
            var changed = occurrences.GroupBy(y => new { y.Type, y.Key })
                .Where(g => g.Max(y => y.Changed) >= from).Select(g => g.Key);
            query = from x in occurrences
                    join k in changed on new { x.Type, x.Key } equals new { k.Type, k.Key }
                    select x;
        }
        // CAP-09 (C10): bounded, the most recently changed first, so a cut keeps what a blocking control most needs.
        var rows = await query.OrderByDescending(x => x.Changed).ThenBy(x => x.Id).Take(limit + 1).ToListAsync(ct);
        var cut = rows.Count > limit;
        if (cut)
        {
            // CAP-09 review: cut by whole indicators. The indicators by their latest change (a row each: bounded by the limit,
            // as each has an occurrence), as many as fit whole; then the occurrences of exactly those, picked in the database
            // by where the last one taken stands in that order (latest change, type, key), so no list of keys is sent back.
            var keys = await query.GroupBy(x => new { x.Type, x.Key })
                .Select(g => new { g.Key.Type, g.Key.Key, Count = g.Count(), Latest = g.Max(x => x.Changed) })
                .OrderByDescending(k => k.Latest).ThenBy(k => k.Type).ThenBy(k => k.Key)
                .Take(limit).ToListAsync(ct);
            var (taken, fit) = (0, 0);
            foreach (var k in keys)
            {
                if (taken + k.Count > limit) break;
                taken += k.Count;
                fit++;
            }
            if (fit == 0) rows = [];
            else
            {
                var last = keys[fit - 1];
                var (at, type, key) = (last.Latest, last.Type, last.Key);
                // string.Compare is the SQL comparison (the database's collation, as its ORDER BY above); Ordinal doesn't translate.
                // R2: the indicators that fit, grouped once with their latest change and joined to (each such key is in the
                // delta too, as its latest change is at or after the last one's, which is). Ordered as the keys were, so if a
                // change since then brings more than fit, the read is cut at the end and the indicator it splits dropped whole.
#pragma warning disable CA1309
                var fitting = occurrences.GroupBy(y => new { y.Type, y.Key })
                    .Select(g => new { g.Key.Type, g.Key.Key, Latest = g.Max(y => y.Changed) })
                    .Where(k => k.Latest > at || (k.Latest == at && (k.Type < type || (k.Type == type && string.Compare(k.Key, key) <= 0))));
#pragma warning restore CA1309
                rows = await (from x in occurrences
                              join k in fitting on new { x.Type, x.Key } equals new { k.Type, k.Key }
                              orderby k.Latest descending, k.Type, k.Key, x.Id
                              select x)
                    .Take(limit + 1).ToListAsync(ct);
                if (rows.Count > limit)
                {
                    var split = rows[limit];
                    rows = rows.Take(limit).Where(x => x.Type != split.Type || x.Key != split.Key).ToList();
                }
            }
        }

        // WF-79: an occurrence without its own marking carries the default (as in the report and STIX, BUG-73), so it isn't
        // outranked by a looser marking elsewhere, and an indicator marked nowhere still goes out marked.
        var fallback = (_reporting?.CurrentValue ?? new ReportingOptions()).EffectiveDefaultTlp;

        // Dedupe by (type, value) in memory — case-insensitive to match the E-08 overlap engine,
        // and to keep DateTimeOffset aggregation off SQLite (see F-08).
        var deduped = rows
            .GroupBy(r => (r.Type, r.Key))   // CAP-09 review: the database's fold, as the selection above used
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
                              .ToList(),
                    Tlp: g.Max(x => (TlpLevel?)(x.Tlp ?? fallback)));
            })
            .OrderBy(r => r.Type)
            .ThenBy(r => r.Value, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return new IocFeed(deduped, cut, limit, since);
    }
}
