using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Campaigns;

/// <summary>One case belonging to a campaign, flattened for the rollup.</summary>
public sealed record CampaignMember(
    Guid CaseId, string CaseNumber, string Title, Classification? Classification, CasePhase Phase,
    Severity Severity, CaseOrigin Origin, string? IncidentCommander, bool IsRestricted,
    DateTimeOffset? DetectedAtUtc, DateTimeOffset? ContainedAtUtc, DateTimeOffset? ResolvedAtUtc,
    DateTimeOffset? ClosedAtUtc)
{
    /// <summary>Open = not yet closed. Drives the "still active" count on the rollup.</summary>
    public bool IsOpen => Phase != CasePhase.Closed;
}

/// <summary>
/// An indicator (entity) seen across the campaign, grouped by type + value. <see cref="CaseCount"/> is how
/// many member cases it appears on; a value greater than one is a genuine pivot linking the cases together.
/// </summary>
public sealed record CampaignIoc(
    EntityType Type, string Value, string? Label, EntityDisposition Disposition,
    int CaseCount, IReadOnlyList<string> CaseNumbers);

/// <summary>A MITRE ATT&amp;CK technique seen across the campaign, with how many member cases carry it.</summary>
public sealed record CampaignTechnique(string TechniqueId, string Name, MitreTactic Tactic, int CaseCount);

/// <summary>One event-timeline step from a member case, placed on the merged campaign timeline.</summary>
public sealed record CampaignTimelineItem(
    DateTimeOffset OccurredAtUtc, Guid CaseId, string CaseNumber, TimelineEntryType Type,
    string Description, string? Source, string? TechniqueId);

/// <summary>
/// The cross-case rollup for one campaign: its member cases, the indicators and techniques they share, a
/// merged event timeline, and the aggregate posture (highest severity/classification, span, open count).
/// </summary>
public sealed record CampaignRollup(
    Guid AnchorCaseId,
    IReadOnlyList<CampaignMember> Members,
    IReadOnlyList<CampaignIoc> SharedIocs,
    IReadOnlyList<CampaignTechnique> Techniques,
    IReadOnlyList<CampaignTimelineItem> Timeline,
    int MemberCount,
    int OpenCount,
    Severity? HighestSeverity,
    Classification? HighestClassification,
    DateTimeOffset? EarliestDetectedAtUtc,
    DateTimeOffset? LatestActivityUtc,
    int? TotalAffectedIndividuals,
    IReadOnlyList<string> AffectedStates);

/// <summary>
/// One campaign on the index (E-29): a linked group of cases summarised for the list. The anchor is the
/// lowest-numbered visible member — a stable, meaningful entry point (the rollup is the same from any member).
/// </summary>
public sealed record CampaignSummary(
    Guid AnchorCaseId, string AnchorCaseNumber, int MemberCount, int OpenCount,
    Severity? HighestSeverity, Classification? HighestClassification,
    DateTimeOffset? LatestActivityUtc, IReadOnlyList<string> MemberCaseNumbers);

/// <summary>
/// The campaign rollup (E-29). A campaign is not a first-class record: it is the connected component of
/// cases joined by <see cref="CaseLinkType.PartOfCampaign"/> links. Given any member case, this walks that
/// component and rolls the members up into one cross-case picture — shared IOCs, combined ATT&amp;CK
/// coverage, a merged event timeline and aggregate posture — so an analyst can see the whole attack wave in
/// one place and export it. Every read is need-to-know scoped via <see cref="CaseQueryExtensions.ForUser"/>:
/// the walk only ever traverses edges whose <em>both</em> ends are visible to the caller, so a restricted
/// case the caller isn't on never appears and never bridges two components. Read-only (out of the audit
/// chain); the export endpoint records the download as an access-log Export.
/// </summary>
public sealed class CampaignService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;

    public CampaignService(IAppDbContextFactory factory, ICurrentUser user)
    {
        _factory = factory;
        _user = user;
    }

    /// <summary>
    /// Builds the rollup for the campaign the given case belongs to, or <c>null</c> if the case is not found
    /// or not visible to the caller. A case with no campaign links yields a single-member rollup (the page
    /// treats that as "not part of a campaign yet").
    /// </summary>
    public async Task<CampaignRollup?> GetRollupAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();

        // The anchor must itself be visible; otherwise reveal nothing (same as a missing case).
        var anchorVisible = await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct);
        if (!anchorVisible) return null;

        var memberIds = await ResolveMemberIdsAsync(db, caseId, ct);

        var members = await db.Cases.AsNoTracking().ForUser(_user)
            .Where(c => memberIds.Contains(c.Id))
            .Select(c => new CampaignMember(
                c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, c.Severity, c.Origin,
                c.IncidentCommander, c.IsRestricted,
                c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc, c.ClosedAtUtc))
            .ToListAsync(ct);
        members = members
            .OrderBy(m => m.CaseNumber, StringComparer.Ordinal)
            .ToList();

        // Aggregate impact facts (affected individuals / states) come off the case rows directly.
        var impact = await db.Cases.AsNoTracking().ForUser(_user)
            .Where(c => memberIds.Contains(c.Id))
            .Select(c => new { c.AffectedIndividualsCount, c.AffectedStates })
            .ToListAsync(ct);

        var entities = await db.CaseEntities.AsNoTracking()
            .Where(e => memberIds.Contains(e.CaseId))
            .Select(e => new { e.CaseId, e.Type, e.Value, e.Label, e.Disposition })
            .ToListAsync(ct);

        var techniques = await db.CaseTechniques.AsNoTracking()
            .Where(t => memberIds.Contains(t.CaseId))
            .Select(t => new { t.CaseId, t.TechniqueId, t.Name, t.Tactic })
            .ToListAsync(ct);

        var timelineRows = await db.TimelineEntries.AsNoTracking()
            .Where(t => memberIds.Contains(t.CaseId) && t.Kind == TimelineKind.Event)
            .Select(t => new { t.CaseId, t.OccurredAtUtc, t.Type, t.Description, t.Source, t.TechniqueId })
            .ToListAsync(ct);

        var caseNumbers = members.ToDictionary(m => m.CaseId, m => m.CaseNumber);

        // Shared IOCs: group entities by type + trimmed value, count the distinct member cases each appears
        // on, and keep only those on more than one case — the pivots that actually connect the campaign.
        var sharedIocs = entities
            .GroupBy(e => new { e.Type, Value = e.Value.Trim() })
            .Select(g => new CampaignIoc(
                g.Key.Type,
                g.Key.Value,
                g.Select(x => x.Label).FirstOrDefault(l => !string.IsNullOrWhiteSpace(l)),
                g.Max(x => x.Disposition),                        // strongest verdict wins (Compromised > Malicious > …)
                g.Select(x => x.CaseId).Distinct().Count(),
                g.Select(x => x.CaseId).Distinct()
                    .Select(id => caseNumbers.TryGetValue(id, out var n) ? n : null)
                    .Where(n => n is not null).Select(n => n!)
                    .OrderBy(n => n, StringComparer.Ordinal).ToList()))
            .Where(i => i.CaseCount > 1)
            .OrderByDescending(i => i.CaseCount)
            .ThenByDescending(i => i.Disposition)
            .ThenBy(i => i.Value, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var techniqueRollup = techniques
            .GroupBy(t => t.TechniqueId, StringComparer.OrdinalIgnoreCase)
            .Select(g => new CampaignTechnique(
                g.Key,
                g.Select(x => x.Name).FirstOrDefault(n => !string.IsNullOrWhiteSpace(n)) ?? g.Key,
                g.Select(x => x.Tactic).FirstOrDefault(),
                g.Select(x => x.CaseId).Distinct().Count()))
            .OrderByDescending(t => t.CaseCount)
            .ThenBy(t => t.TechniqueId, StringComparer.Ordinal)
            .ToList();

        var timeline = timelineRows
            .Select(t => new CampaignTimelineItem(
                t.OccurredAtUtc, t.CaseId,
                caseNumbers.TryGetValue(t.CaseId, out var n) ? n : "",
                t.Type, t.Description, t.Source, t.TechniqueId))
            .OrderBy(t => t.OccurredAtUtc)
            .ThenBy(t => t.CaseNumber, StringComparer.Ordinal)
            .ToList();

        // Aggregate posture.
        var openCount = members.Count(m => m.IsOpen);
        Severity? highestSeverity = members.Count > 0 ? members.Max(m => m.Severity) : null;

        var classified = members.Where(m => m.Classification is not null)
            .Select(m => m.Classification!.Value).ToList();
        Classification? highestClassification = classified.Count > 0 ? classified.Max() : null;

        var detectedTimes = members.Where(m => m.DetectedAtUtc is not null)
            .Select(m => m.DetectedAtUtc!.Value).ToList();
        DateTimeOffset? earliest = detectedTimes.Count > 0 ? detectedTimes.Min() : null;

        // Latest activity: the most recent of any member lifecycle timestamp or campaign timeline step.
        var activityTimes = new List<DateTimeOffset>();
        activityTimes.AddRange(timeline.Select(t => t.OccurredAtUtc));
        foreach (var m in members)
        {
            if (m.DetectedAtUtc is { } d) activityTimes.Add(d);
            if (m.ContainedAtUtc is { } cn) activityTimes.Add(cn);
            if (m.ResolvedAtUtc is { } r) activityTimes.Add(r);
            if (m.ClosedAtUtc is { } cl) activityTimes.Add(cl);
        }
        DateTimeOffset? latest = activityTimes.Count > 0 ? activityTimes.Max() : null;

        var affectedTotals = impact.Where(x => x.AffectedIndividualsCount is not null)
            .Select(x => x.AffectedIndividualsCount!.Value).ToList();
        int? totalAffected = affectedTotals.Count > 0 ? affectedTotals.Sum() : null;

        var states = impact
            .Where(x => !string.IsNullOrWhiteSpace(x.AffectedStates))
            .SelectMany(x => x.AffectedStates!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(s => s.ToUpperInvariant())
            .Distinct()
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToList();

        return new CampaignRollup(
            caseId, members, sharedIocs, techniqueRollup, timeline,
            members.Count, openCount, highestSeverity, highestClassification,
            earliest, latest, totalAffected, states);
    }

    /// <summary>
    /// Lists every campaign visible to the caller: each connected component of two or more cases joined by
    /// visible-both PartOfCampaign edges, summarised for the index. A group that only hangs together through a
    /// case the caller can't see splits accordingly (an invisible case never bridges), and a case whose only
    /// campaign link is to an invisible case simply doesn't surface. Ordered by highest severity, then most
    /// recent activity. Read-only and need-to-know scoped.
    /// </summary>
    public async Task<IReadOnlyList<CampaignSummary>> ListAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();

        var links = await db.CaseLinks.AsNoTracking()
            .Where(l => l.Type == CaseLinkType.PartOfCampaign)
            .Select(l => new { l.CaseId, l.RelatedCaseId })
            .ToListAsync(ct);
        if (links.Count == 0) return [];

        var participantIds = links
            .SelectMany(l => new[] { l.CaseId, l.RelatedCaseId })
            .Distinct().ToList();

        var cases = await db.Cases.AsNoTracking().ForUser(_user)
            .Where(c => participantIds.Contains(c.Id))
            .Select(c => new CampaignCaseRow(
                c.Id, c.CaseNumber, c.Classification, c.Phase, c.Severity,
                c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc, c.ClosedAtUtc))
            .ToListAsync(ct);
        var visible = cases.ToDictionary(c => c.Id);
        if (visible.Count == 0) return [];

        // Adjacency over visible-both edges only.
        var adjacency = new Dictionary<Guid, List<Guid>>();
        void Edge(Guid a, Guid b) => (adjacency.TryGetValue(a, out var l) ? l : adjacency[a] = new()).Add(b);
        foreach (var l in links)
            if (visible.ContainsKey(l.CaseId) && visible.ContainsKey(l.RelatedCaseId))
            { Edge(l.CaseId, l.RelatedCaseId); Edge(l.RelatedCaseId, l.CaseId); }

        // Walk each connected component once; keep those with two or more members (a genuine campaign).
        var seen = new HashSet<Guid>();
        var summaries = new List<CampaignSummary>();
        foreach (var startId in visible.Keys)
        {
            if (!seen.Add(startId)) continue;
            var component = new List<Guid> { startId };
            var stack = new Stack<Guid>();
            stack.Push(startId);
            while (stack.Count > 0)
            {
                var id = stack.Pop();
                if (!adjacency.TryGetValue(id, out var neighbours)) continue;
                foreach (var n in neighbours)
                    if (seen.Add(n)) { component.Add(n); stack.Push(n); }
            }
            if (component.Count < 2) continue;

            var members = component.Select(id => visible[id])
                .OrderBy(c => c.CaseNumber, StringComparer.Ordinal).ToList();
            var anchor = members[0];

            var classified = members.Where(m => m.Classification is not null)
                .Select(m => m.Classification!.Value).ToList();

            var activity = new List<DateTimeOffset>();
            foreach (var m in members)
            {
                if (m.DetectedAtUtc is { } d) activity.Add(d);
                if (m.ContainedAtUtc is { } cn) activity.Add(cn);
                if (m.ResolvedAtUtc is { } r) activity.Add(r);
                if (m.ClosedAtUtc is { } cl) activity.Add(cl);
            }

            summaries.Add(new CampaignSummary(
                anchor.Id, anchor.CaseNumber, members.Count,
                members.Count(m => m.Phase != CasePhase.Closed),
                members.Max(m => m.Severity),
                classified.Count > 0 ? classified.Max() : null,
                activity.Count > 0 ? activity.Max() : null,
                members.Select(m => m.CaseNumber).ToList()));
        }

        return summaries
            .OrderByDescending(s => s.HighestSeverity)
            .ThenByDescending(s => s.LatestActivityUtc ?? DateTimeOffset.MinValue)
            .ThenBy(s => s.AnchorCaseNumber, StringComparer.Ordinal)
            .ToList();
    }

    private sealed record CampaignCaseRow(
        Guid Id, string CaseNumber, Classification? Classification, CasePhase Phase, Severity Severity,
        DateTimeOffset? DetectedAtUtc, DateTimeOffset? ContainedAtUtc, DateTimeOffset? ResolvedAtUtc,
        DateTimeOffset? ClosedAtUtc);

    /// <summary>
    /// Resolves the visible-reachable campaign component containing <paramref name="anchorId"/>. Walks the
    /// PartOfCampaign link graph in memory (the on-prem link set is small), then restricts to the sub-graph
    /// whose edges have both ends visible to the caller — so a restricted case never bridges two components.
    /// </summary>
    private async Task<HashSet<Guid>> ResolveMemberIdsAsync(IAppDbContext db, Guid anchorId, CancellationToken ct)
    {
        var links = await db.CaseLinks.AsNoTracking()
            .Where(l => l.Type == CaseLinkType.PartOfCampaign)
            .Select(l => new { l.CaseId, l.RelatedCaseId })
            .ToListAsync(ct);

        // Adjacency over all PartOfCampaign edges (visibility not yet applied).
        var adjacency = new Dictionary<Guid, List<Guid>>();
        void Link(Guid a, Guid b)
        {
            (adjacency.TryGetValue(a, out var list) ? list : adjacency[a] = new()).Add(b);
        }
        foreach (var l in links) { Link(l.CaseId, l.RelatedCaseId); Link(l.RelatedCaseId, l.CaseId); }

        // Raw component containing the anchor — the candidate set to check visibility for.
        var candidates = new HashSet<Guid> { anchorId };
        var stack = new Stack<Guid>();
        stack.Push(anchorId);
        while (stack.Count > 0)
        {
            var id = stack.Pop();
            if (!adjacency.TryGetValue(id, out var neighbours)) continue;
            foreach (var n in neighbours)
                if (candidates.Add(n)) stack.Push(n);
        }

        if (candidates.Count == 1) return candidates; // lone case, no campaign links — nothing to scope

        var visible = (await db.Cases.AsNoTracking().ForUser(_user)
            .Where(c => candidates.Contains(c.Id))
            .Select(c => c.Id).ToListAsync(ct)).ToHashSet();

        // Re-walk from the anchor using only edges whose both ends are visible.
        var members = new HashSet<Guid> { anchorId };
        stack.Push(anchorId);
        while (stack.Count > 0)
        {
            var id = stack.Pop();
            if (!adjacency.TryGetValue(id, out var neighbours)) continue;
            foreach (var n in neighbours)
                if (visible.Contains(n) && members.Add(n)) stack.Push(n);
        }
        return members;
    }
}
