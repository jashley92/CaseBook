using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Intel;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Search;

/// <summary>The kinds of thing Find returns, in the order it shows them.</summary>
public enum FindKind { Entities, Cases, Entries, Tasks, Evidence, Notes }

/// <summary>One case an entity appears on, with its verdict there.</summary>
public sealed record FindEntityCase(Guid CaseId, string CaseNumber, CasePhase Phase, Classification? Classification,
    EntityDisposition Verdict, Guid EntityId);

/// <summary>An entity, deduplicated across the caller's cases (like the indicator library), with its verdict on each.</summary>
public sealed record FindEntity(EntityType Type, string Value, string? Label, IReadOnlyList<FindEntityCase> Cases);

/// <summary>A case, with how it ended when it's closed.</summary>
public sealed record FindCase(Guid Id, string CaseNumber, string Title, Classification? Classification, Severity Severity,
    CasePhase Phase, DateTimeOffset OpenedAtUtc, DateTimeOffset? ClosedAtUtc, string? ClosingLine, bool IsExercise);

/// <summary>A record entry (or a closed case's closing brief), quoting the record.</summary>
public sealed record FindEntry(Guid Id, Guid CaseId, string CaseNumber, TimelineKind Kind, TimelineEntryType? Type,
    bool IsClosingBrief, DateTimeOffset AtUtc, string Text, string? Why);

public sealed record FindTask(Guid Id, Guid CaseId, string CaseNumber, string Title, string? Owner, DateTimeOffset? DueAtUtc,
    ActionItemStatus Status);

public sealed record FindEvidence(Guid Id, Guid CaseId, string CaseNumber, string FileName, string? Description,
    DateTimeOffset AddedAtUtc, bool HashMatch);

public sealed record FindNote(Guid Id, Guid CaseId, string CaseNumber, DateTimeOffset AtUtc, string By, string Text);

/// <summary>
/// What Find made of the query and what it found. <see cref="ReadAs"/> and <see cref="Reading"/> say how it read the words;
/// <see cref="Filters"/> say the filters back in words; counts are totals, the lists are capped.
/// </summary>
public sealed record FindResult(
    FindQuery Query, FindReadAs ReadAs, string Reading, IReadOnlyList<string> Filters,
    IReadOnlyDictionary<FindKind, int> Counts,
    IReadOnlyList<FindEntity> Entities, IReadOnlyList<FindCase> Cases, IReadOnlyList<FindEntry> Entries,
    IReadOnlyList<FindTask> Tasks, IReadOnlyList<FindEvidence> Evidence, IReadOnlyList<FindNote> Notes)
{
    public int Total => Counts.Values.Sum();
    public static FindResult Empty(FindQuery q) => new(q, FindReadAs.Nothing, "", [], new Dictionary<FindKind, int>(),
        [], [], [], [], [], []);
}

/// <summary>
/// RD-20: Find. One query, typed results across entities, cases, record entries (closing briefs included), tasks,
/// evidence names and, when asked, working notes. Read only. Need-to-know scoped by the same rule as the case list (a case
/// the caller can't see contributes nothing and nothing hints it exists); exercises left out unless asked for. Matching is
/// exact and literal: words must each appear (ignoring case); an indicator matches entities by its exact value; there is
/// no fuzzy matching, no related-indicator expansion and no AI reading of the question, only <see cref="FindQuery"/>'s
/// documented grammar.
/// </summary>
public sealed class FindService
{
    /// <summary>The most results of one kind listed; counts always cover all of them.</summary>
    public const int DefaultLimit = 25;

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IUserDirectory _users;
    private readonly IOrganizationTimeZone? _zone;

    public FindService(IAppDbContextFactory factory, ICurrentUser user, IUserDirectory users, IOrganizationTimeZone? zone = null)
    {
        _factory = factory;
        _user = user;
        _users = users;
        _zone = zone;
    }

    public async Task<FindResult> FindAsync(string? raw, int limit = DefaultLimit, CancellationToken ct = default)
    {
        var q = FindQuery.Parse(raw);
        if (q.IsEmpty) return FindResult.Empty(q);

        using var db = _factory.CreateDbContext();
        var zone = _zone?.Current ?? TimeZoneInfo.Utc;
        DateTimeOffset? from = q.After is { } a ? ZonedDays.StartUtc(a, zone) : null;   // on or after the day
        DateTimeOffset? to = q.Before is { } b ? ZonedDays.StartUtc(b, zone) : null;                 // before the day
        var filters = new List<string>();
        var unread = q.Unread.ToList();

        // People named by by: / owner:, resolved against the directory ("me" is the caller).
        var by = Person(q.By, unread, "by");
        var owner = Person(q.Owner, unread, "owner");

        // The cases in play: visible, not exercises unless asked, then the case-level filters.
        var cases = db.Cases.AsNoTracking().ForUser(_user);
        if (!q.Exercises) cases = cases.ExcludingExercises();
        else filters.Add("exercises included");
        if (q.Open == true) { cases = cases.Where(c => c.Phase != CasePhase.Closed); filters.Add("open cases"); }
        if (q.Open == false) { cases = cases.Where(c => c.Phase == CasePhase.Closed); filters.Add("closed cases"); }
        if (q.ClassFilter)
        {
            var cls = q.Class;
            cases = cls is null ? cases.Where(c => c.Classification == null) : cases.Where(c => c.Classification == cls);
            filters.Add(cls switch
            {
                null => "Complex Events", Classification.AdverseEvent => "Adverse Events",
                Classification.Incident => "Incidents", _ => "Breaches"
            });
        }
        if (q.State is { } st)
        {
            var token = "," + st + ",";
            cases = cases.Where(c => c.AffectedStates != null
                                     && ("," + c.AffectedStates.Replace(" ", "").ToUpper() + ",").Contains(token));
            filters.Add($"residents of {st} affected");
        }

        // The entity filter: the visible occurrences of that exact value (ignoring case), and the cases they're on.
        List<Guid> entityIds = [];
        if (q.Entity is { } ev)
        {
            var key = ev.ToLower();
#pragma warning disable CA1304, CA1311, CA1862 // EF Core translates ToLower(); culture overloads don't translate.
            entityIds = await db.CaseEntities.AsNoTracking()
                .Where(e => cases.Select(c => c.Id).Contains(e.CaseId) && e.Value.Trim().ToLower() == key)
                .Select(e => e.Id).ToListAsync(ct);
#pragma warning restore CA1304, CA1311, CA1862
            var onCases = await db.CaseEntities.AsNoTracking().Where(e => entityIds.Contains(e.Id)).Select(e => e.CaseId).ToListAsync(ct);
            cases = cases.Where(c => onCases.Contains(c.Id));
            filters.Add($"about {ev}");
        }
        if (by is not null) filters.Add($"recorded by {_users.DisplayFor(by)}");
        if (owner is not null) filters.Add($"tasks of {_users.DisplayFor(owner)}");
        if (q.EntryType is { } et) filters.Add(et == TimelineEntryType.Decision ? "decisions" : et == TimelineEntryType.Handoff ? "handoffs" : $"{et} entries");
        else if (q.EntryKind is { } ek) filters.Add(ek == TimelineKind.Event ? "adversary steps" : "response entries");
        if (q.After is { } af) filters.Add($"from {af:d MMM yyyy}");
        if (q.Before is { } bf) filters.Add($"before {bf:d MMM yyyy}");
        if (q.Notes) filters.Add("working notes included");
        filters.AddRange(unread.Select(u => $"not understood: {u}"));

        // How the words read.
        var text = q.Text;
        var (readAs, iocType) = FindQuery.ReadShape(text);
        string? personId = null;
        if (readAs == FindReadAs.Words && PersonNamed(text) is { } p)
        {
            readAs = FindReadAs.Person;
            personId = p.UserId;
        }
        if (readAs == FindReadAs.Words && !text.Contains(' ')
            && await cases.AnyAsync(c => c.CaseNumber == text || c.CaseNumber.StartsWith(text + "_"), ct))
            readAs = FindReadAs.CaseNumber;
        var reading = readAs switch
        {
            FindReadAs.Nothing => "filters only",
            FindReadAs.CaseNumber => "a case number",
            FindReadAs.Indicator => Article(TypeWords(iocType!.Value)),
            FindReadAs.Person => $"a person: {_users.DisplayFor(personId)}",
            _ => q.Terms.Count == 1 ? "a word in the record" : "words in the record",
        };

        var terms = q.Terms.Select(t => t.ToLowerInvariant()).ToList();
        var counts = new Dictionary<FindKind, int>();
        var caseIds = cases.Select(c => c.Id);

        // --- Entities: an indicator by its exact value; words by value or label; the entity: filter by itself.
        List<FindEntity> entities = [];
        // Entry-, task- and person-only filters are about the record, not the entities in it.
        var entitiesApply = (readAs is FindReadAs.Indicator or FindReadAs.Words || q.Entity is not null)
                            && by is null && owner is null && q.EntryKind is null && q.EntryType is null;
        if (entitiesApply)
        {
            var src = db.CaseEntities.AsNoTracking().Where(e => caseIds.Contains(e.CaseId));
#pragma warning disable CA1304, CA1311, CA1862
            if (q.Entity is not null) src = src.Where(e => entityIds.Contains(e.Id));
            if (readAs == FindReadAs.Indicator)
            {
                var exact = IocObservable.Refang(text).ToLower();
                src = src.Where(e => e.Value.Trim().ToLower() == exact);
            }
            else if (readAs == FindReadAs.Words)
                foreach (var t in terms)
                    src = src.Where(e => e.Value.ToLower().Contains(t) || (e.Label != null && e.Label.ToLower().Contains(t)));
#pragma warning restore CA1304, CA1311, CA1862
            var rows = await src.Join(db.Cases, e => e.CaseId, c => c.Id, (e, c) => new
            {
                e.Id, e.Type, e.Value, e.Label, e.Disposition, e.CreatedAtUtc, CaseId = c.Id, c.CaseNumber, c.Phase, c.Classification
            }).Take(2000).ToListAsync(ct);
            var grouped = rows
                .GroupBy(r => (IocObservable.MatchFamily(r.Type), r.Value.Trim().ToLowerInvariant()))
                .Select(g =>
                {
                    var latest = g.OrderByDescending(x => x.CreatedAtUtc).First();
                    var perCase = g.GroupBy(x => x.CaseId)
                        .Select(cg => cg.OrderByDescending(x => IndicatorService.Severity(x.Disposition)).First())
                        .OrderByDescending(x => x.CreatedAtUtc)
                        .Select(x => new FindEntityCase(x.CaseId, x.CaseNumber, x.Phase, x.Classification, x.Disposition, x.Id))
                        .ToList();
                    return new FindEntity(latest.Type, latest.Value.Trim(), g.Select(x => x.Label).FirstOrDefault(l => l is not null), perCase);
                })
                .OrderByDescending(e => e.Cases.Count)
                .ThenBy(e => e.Value, StringComparer.OrdinalIgnoreCase)
                .ToList();
            counts[FindKind.Entities] = grouped.Count;
            entities = grouped.Take(limit).ToList();
        }

        // --- Cases.
        var caseQ = cases;
#pragma warning disable CA1304, CA1311, CA1862
        if (q.After is not null) caseQ = caseQ.Where(c => c.CreatedAtUtc >= from);
        if (q.Before is not null) caseQ = caseQ.Where(c => c.CreatedAtUtc < to);
        switch (readAs)
        {
            case FindReadAs.CaseNumber:
                var n = text.ToLower();
                caseQ = caseQ.Where(c => c.CaseNumber.ToLower().Contains(n));
                break;
            case FindReadAs.Person:
                caseQ = caseQ.Where(c => c.IncidentCommander == personId || c.Assignments.Any(a => a.UserId == personId));
                break;
            case FindReadAs.Indicator:
                var exact = IocObservable.Refang(text).ToLower();
                caseQ = caseQ.Where(c => c.Entities.Any(e => e.Value.Trim().ToLower() == exact)
                                         || c.Title.ToLower().Contains(exact) || (c.Summary != null && c.Summary.ToLower().Contains(exact)));
                break;
            case FindReadAs.Words:
                foreach (var t in terms)
                    caseQ = caseQ.Where(c => c.CaseNumber.ToLower().Contains(t) || c.Title.ToLower().Contains(t)
                                             || (c.Summary != null && c.Summary.ToLower().Contains(t))
                                             || c.Briefs.Any(b => b.IsCurrent && ((b.Summary != null && b.Summary.ToLower().Contains(t))
                                                                                  || (b.WorkingAssessment != null && b.WorkingAssessment.ToLower().Contains(t)))));
                break;
        }
#pragma warning restore CA1304, CA1311, CA1862
        // Entry-, task- and person-only filters don't narrow the case list; the record entries carry those.
        var casesApply = by is null && owner is null && q.EntryKind is null && q.EntryType is null;
        List<FindCase> foundCases = [];
        if (casesApply)
        {
            counts[FindKind.Cases] = await caseQ.CountAsync(ct);
            var caseRows = await caseQ.OrderByDescending(c => c.CreatedAtUtc).Take(limit)
                .Select(c => new { c.Id, c.CaseNumber, c.Title, c.Classification, c.Severity, c.Phase, c.CreatedAtUtc, c.ClosedAtUtc, c.IsExercise, c.OutcomeKey })
                .ToListAsync(ct);
            var closing = await ClosingLinesAsync(db, caseRows.Where(c => c.Phase == CasePhase.Closed).Select(c => c.Id).ToList(), ct);
            foundCases = caseRows.Select(c => new FindCase(c.Id, c.CaseNumber, c.Title, c.Classification, c.Severity, c.Phase,
                c.CreatedAtUtc, c.ClosedAtUtc, closing.GetValueOrDefault(c.Id), c.IsExercise)).ToList();
        }

        // --- Record entries (current versions), then closing briefs.
        var entriesApply = readAs is FindReadAs.Indicator or FindReadAs.Words or FindReadAs.Person
                           || q.Entity is not null || by is not null || q.EntryKind is not null || q.EntryType is not null;
        List<FindEntry> entries = [];
        if (entriesApply)
        {
            var eq = db.TimelineEntries.AsNoTracking().Where(e => e.IsCurrent && caseIds.Contains(e.CaseId));
#pragma warning disable CA1304, CA1311, CA1862
            if (readAs is FindReadAs.Indicator or FindReadAs.Words)
                foreach (var t in readAs == FindReadAs.Indicator ? [IocObservable.Refang(text).ToLower()] : terms)
                    eq = eq.Where(e => e.Description.ToLower().Contains(t) || (e.Rationale != null && e.Rationale.ToLower().Contains(t)));
            if (readAs == FindReadAs.Person) eq = eq.Where(e => e.CreatedBy == personId);
            if (q.Entity is { } ent)
            {
                var v = ent.ToLower();
                eq = eq.Where(e => (e.ActorEntityId != null && entityIds.Contains(e.ActorEntityId.Value))
                                   || (e.TargetEntityId != null && entityIds.Contains(e.TargetEntityId.Value))
                                   || e.Description.ToLower().Contains(v));
            }
#pragma warning restore CA1304, CA1311, CA1862
            if (by is not null) eq = eq.Where(e => e.CreatedBy == by);
            if (q.EntryKind is { } k) eq = eq.Where(e => e.Kind == k);
            if (q.EntryType is { } ty) eq = eq.Where(e => e.Type == ty);
            if (from is not null) eq = eq.Where(e => e.OccurredAtUtc >= from);
            if (to is not null) eq = eq.Where(e => e.OccurredAtUtc < to);
            var entryCount = await eq.CountAsync(ct);
            var rows = await eq.OrderByDescending(e => e.OccurredAtUtc).Take(limit)
                .Join(db.Cases, e => e.CaseId, c => c.Id, (e, c) => new { e.Id, e.CaseId, c.CaseNumber, e.Kind, e.Type, e.OccurredAtUtc, e.Description, e.Rationale })
                .ToListAsync(ct);
            entries = rows.Select(r => new FindEntry(r.Id, r.CaseId, r.CaseNumber, r.Kind, r.Type, false, r.OccurredAtUtc,
                Clip(Content.RichText.ToText(r.Description)), r.Rationale is null ? null : Clip(r.Rationale))).ToList();

            // A closed case's conclusion is part of its record too (and today only reachable by opening the case).
            var briefs = new List<FindEntry>();
            if (q.EntryKind is null && q.EntryType is null && by is null && readAs is FindReadAs.Indicator or FindReadAs.Words)
            {
                var bq = db.CaseBriefs.AsNoTracking().Where(b => b.IsCurrent && b.WorkingAssessment != null
                    && cases.Where(c => c.Phase == CasePhase.Closed && c.OutcomeKey != null).Select(c => c.Id).Contains(b.CaseId));
#pragma warning disable CA1304, CA1311, CA1862
                foreach (var t in readAs == FindReadAs.Indicator ? [IocObservable.Refang(text).ToLower()] : terms)
                    bq = bq.Where(b => b.WorkingAssessment!.ToLower().Contains(t) || (b.Summary != null && b.Summary.ToLower().Contains(t)));
                if (q.Entity is { } ent2) { var v = ent2.ToLower(); bq = bq.Where(b => b.WorkingAssessment!.ToLower().Contains(v)); }
#pragma warning restore CA1304, CA1311, CA1862
                var brows = await bq.Join(db.Cases, b => b.CaseId, c => c.Id,
                        (b, c) => new { b.Id, b.CaseId, c.CaseNumber, c.ClosedAtUtc, b.CreatedAtUtc, b.WorkingAssessment })
                    .ToListAsync(ct);
                briefs = brows
                    .Where(b => (from is null || (b.ClosedAtUtc ?? b.CreatedAtUtc) >= from) && (to is null || (b.ClosedAtUtc ?? b.CreatedAtUtc) < to))
                    .Select(b => new FindEntry(b.Id, b.CaseId, b.CaseNumber, TimelineKind.Investigation, null, true,
                        b.ClosedAtUtc ?? b.CreatedAtUtc, Clip(b.WorkingAssessment!), null)).ToList();
            }
            counts[FindKind.Entries] = entryCount + briefs.Count;
            entries = briefs.Concat(entries).OrderByDescending(e => e.AtUtc).Take(limit).ToList();
        }

        // --- Tasks.
        var tasksApply = readAs is FindReadAs.Indicator or FindReadAs.Words or FindReadAs.Person || owner is not null
                         || (q.Entity is not null && q.EntryKind is null && q.EntryType is null && by is null);
        List<FindTask> tasks = [];
        if (tasksApply && q.EntryKind is null && q.EntryType is null && by is null)
        {
            var tq = db.ActionItems.AsNoTracking().Where(t => caseIds.Contains(t.CaseId));
#pragma warning disable CA1304, CA1311, CA1862
            if (readAs is FindReadAs.Indicator or FindReadAs.Words)
                foreach (var t in readAs == FindReadAs.Indicator ? [IocObservable.Refang(text).ToLower()] : terms)
                    tq = tq.Where(x => x.Title.ToLower().Contains(t) || (x.Description != null && x.Description.ToLower().Contains(t)));
            if (q.Entity is { } ent3)
            {
                var v = ent3.ToLower();
                tq = tq.Where(x => x.Title.ToLower().Contains(v) || (x.Description != null && x.Description.ToLower().Contains(v)));
            }
#pragma warning restore CA1304, CA1311, CA1862
            if (readAs == FindReadAs.Person) tq = tq.Where(x => x.Owner == personId);
            if (owner is not null) tq = tq.Where(x => x.Owner == owner);
            if (from is not null) tq = tq.Where(x => x.CreatedAtUtc >= from);
            if (to is not null) tq = tq.Where(x => x.CreatedAtUtc < to);
            counts[FindKind.Tasks] = await tq.CountAsync(ct);
            // Open first (by when they're due), then done.
            tasks = (await tq.Join(db.Cases, t => t.CaseId, c => c.Id, (t, c) => new { t.Id, t.CaseId, c.CaseNumber, t.Title, t.Owner, t.DueAtUtc, t.Status, t.CreatedAtUtc })
                    .ToListAsync(ct))
                .OrderBy(t => t.Status is ActionItemStatus.Done or ActionItemStatus.Cancelled)
                .ThenBy(t => t.DueAtUtc ?? DateTimeOffset.MaxValue)
                .Take(limit)
                .Select(t => new FindTask(t.Id, t.CaseId, t.CaseNumber, t.Title, t.Owner, t.DueAtUtc, t.Status)).ToList();
        }

        // --- Evidence names (and a file hash matches the file's own SHA-256).
        List<FindEvidence> evidence = [];
        if (readAs is FindReadAs.Indicator or FindReadAs.Words && q.EntryKind is null && q.EntryType is null && owner is null)
        {
            var xq = db.Evidence.AsNoTracking().Where(x => caseIds.Contains(x.CaseId));
            var hash = readAs == FindReadAs.Indicator && iocType == EntityType.FileHash ? text.Trim().ToLowerInvariant() : null;
#pragma warning disable CA1304, CA1311, CA1862
            if (hash is not null) xq = xq.Where(x => x.Sha256.ToLower() == hash);
            else
                foreach (var t in readAs == FindReadAs.Indicator ? [IocObservable.Refang(text).ToLower()] : terms)
                    xq = xq.Where(x => x.OriginalFileName.ToLower().Contains(t) || (x.Description != null && x.Description.ToLower().Contains(t)));
#pragma warning restore CA1304, CA1311, CA1862
            if (by is not null) xq = xq.Where(x => x.CreatedBy == by);
            if (from is not null) xq = xq.Where(x => x.CreatedAtUtc >= from);
            if (to is not null) xq = xq.Where(x => x.CreatedAtUtc < to);
            counts[FindKind.Evidence] = await xq.CountAsync(ct);
            evidence = (await xq.Join(db.Cases, x => x.CaseId, c => c.Id, (x, c) => new { x.Id, x.CaseId, c.CaseNumber, x.OriginalFileName, x.Description, x.CreatedAtUtc })
                    .ToListAsync(ct))
                .OrderByDescending(x => x.CreatedAtUtc).Take(limit)
                .Select(x => new FindEvidence(x.Id, x.CaseId, x.CaseNumber, x.OriginalFileName, x.Description, x.CreatedAtUtc, hash is not null))
                .ToList();
        }

        // --- Working notes: only when asked for (they're working reasoning, not the record).
        List<FindNote> notes = [];
        if (q.Notes && (readAs is FindReadAs.Indicator or FindReadAs.Words or FindReadAs.Person || by is not null || q.Entity is not null))
        {
            var nq = db.Notes.AsNoTracking().Where(n => n.IsCurrent && caseIds.Contains(n.CaseId));
#pragma warning disable CA1304, CA1311, CA1862
            if (readAs is FindReadAs.Indicator or FindReadAs.Words)
                foreach (var t in readAs == FindReadAs.Indicator ? [IocObservable.Refang(text).ToLower()] : terms)
                    nq = nq.Where(n => n.Body.ToLower().Contains(t));
            if (q.Entity is { } ent4) { var v = ent4.ToLower(); nq = nq.Where(n => n.Body.ToLower().Contains(v)); }
#pragma warning restore CA1304, CA1311, CA1862
            if (readAs == FindReadAs.Person) nq = nq.Where(n => n.CreatedBy == personId);
            if (by is not null) nq = nq.Where(n => n.CreatedBy == by);
            if (from is not null) nq = nq.Where(n => n.CreatedAtUtc >= from);
            if (to is not null) nq = nq.Where(n => n.CreatedAtUtc < to);
            counts[FindKind.Notes] = await nq.CountAsync(ct);
            notes = (await nq.Join(db.Cases, n => n.CaseId, c => c.Id, (n, c) => new { n.Id, n.CaseId, c.CaseNumber, n.CreatedAtUtc, n.CreatedBy, n.Body })
                    .ToListAsync(ct))
                .OrderByDescending(n => n.CreatedAtUtc).Take(limit)
                .Select(n => new FindNote(n.Id, n.CaseId, n.CaseNumber, n.CreatedAtUtc, _users.DisplayFor(n.CreatedBy), Clip(Content.RichText.ToText(n.Body))))
                .ToList();
        }

        return new FindResult(q, readAs, reading, filters, counts, entities, foundCases, entries, tasks, evidence, notes);
    }

    // "me", or a person the directory knows by name, sign-in name, or first name when only one person has it.
    private string? Person(string? name, List<string> unread, string key)
    {
        if (name is null) return null;
        if (name.Equals("me", StringComparison.OrdinalIgnoreCase)) return _user.UserId;
        if (PersonNamed(name) is { } p) return p.UserId;
        unread.Add($"{key}:{name} (no one by that name)");
        return null;
    }

    private UserSummary? PersonNamed(string text)
    {
        var t = text.Trim();
        if (t.Length < 2) return null;
        var all = _users.All();
        var exact = all.Where(u => u.DisplayName.Equals(t, StringComparison.OrdinalIgnoreCase)
                                   || (u.UserPrincipalName is { } upn && (upn.Equals(t, StringComparison.OrdinalIgnoreCase)
                                       || upn.Split('@')[0].Equals(t, StringComparison.OrdinalIgnoreCase)))).ToList();
        if (exact.Count == 1) return exact[0];
        if (t.Contains(' ')) return null;
        var first = all.Where(u => u.DisplayName.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?
            .Equals(t, StringComparison.OrdinalIgnoreCase) == true).ToList();
        return first.Count == 1 ? first[0] : null;
    }

    // How each closed case ended: its closing brief's conclusion, else the reason given when it closed.
    private static async Task<Dictionary<Guid, string>> ClosingLinesAsync(IAppDbContext db, List<Guid> ids, CancellationToken ct)
    {
        var lines = new Dictionary<Guid, string>();
        if (ids.Count == 0) return lines;
        var briefs = await db.CaseBriefs.AsNoTracking()
            .Where(b => ids.Contains(b.CaseId) && b.IsCurrent && b.WorkingAssessment != null
                        && db.Cases.Any(c => c.Id == b.CaseId && c.OutcomeKey != null))
            .Select(b => new { b.CaseId, b.WorkingAssessment }).ToListAsync(ct);
        var closes = await db.StatusChanges.AsNoTracking()
            .Where(s => ids.Contains(s.CaseId) && s.To == CasePhase.Closed && s.Reason != null)
            .Select(s => new { s.CaseId, s.Reason, s.ChangedAtUtc }).ToListAsync(ct);
        foreach (var id in ids)
        {
            var line = briefs.FirstOrDefault(b => b.CaseId == id)?.WorkingAssessment
                       ?? closes.Where(s => s.CaseId == id).OrderByDescending(s => s.ChangedAtUtc).FirstOrDefault()?.Reason;
            if (!string.IsNullOrWhiteSpace(line)) lines[id] = TaskResults.Excerpt(line, 220);
        }
        return lines;
    }

    private static string Clip(string s) => TaskResults.Excerpt(string.Join(' ', s.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)), 260);

    private static string TypeWords(EntityType t) => t switch
    {
        EntityType.IpAddress => "IP address", EntityType.Domain => "domain", EntityType.Url => "URL",
        EntityType.FileHash => "file hash", EntityType.EmailAddress => "email address", EntityType.Account => "account",
        _ => "indicator"
    };

    private static string Article(string w) => ("aeiouAEIOU".Contains(w[0]) && !w.StartsWith("URL") ? "an " : "a ") + w;
}
