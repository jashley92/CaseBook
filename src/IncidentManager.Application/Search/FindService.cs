using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Intel;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.Observables;
using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Search;

/// <summary>The kinds of thing Find returns, in the order it shows them.</summary>
public enum FindKind { Entities, Cases, Entries, Tasks, Evidence, Notes }

/// <summary>One case an entity appears on, with its verdict there.</summary>
public sealed record FindEntityCase(Guid CaseId, string CaseNumber, CasePhase Phase, Classification? Classification,
    EntityDisposition Verdict, Guid EntityId, bool IsArchived = false, bool IsExercise = false);   // WF-85: the markers

/// <summary>An entity, deduplicated across the caller's cases (like the indicator library), with its verdict on each.</summary>
public sealed record FindEntity(EntityType Type, string Value, string? Label, IReadOnlyList<FindEntityCase> Cases);

/// <summary>A case, with how it ended when it's closed.</summary>
public sealed record FindCase(Guid Id, string CaseNumber, string Title, Classification? Classification, Severity Severity,
    CasePhase Phase, DateTimeOffset OpenedAtUtc, DateTimeOffset? ClosedAtUtc, string? ClosingLine, bool IsExercise,
    bool IsArchived = false);   // WF-07: labelled in the results

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
        // WF-04: owner: narrows tasks, and type: / by: narrow record entries, which have no owner. Together nothing would
        // apply owner:, so it's said back as not used rather than shown as a filter it isn't.
        if (owner is not null && (q.EntryKind is not null || q.EntryType is not null || q.By is not null))
        {
            unread.Add($"owner:{q.Owner} (tasks only; it doesn't combine with type: or by:)");
            owner = null;
        }

        // The cases in play: visible, not exercises unless asked, then the case-level filters.
        var cases = db.Cases.AsNoTracking().ForUser(_user);
        if (!q.Exercises) cases = cases.ExcludingExercises();
        else filters.Add("exercises included");
        // WF-07: open means open, as in the case list, My work and the reminders: an archived case isn't.
        if (q.Open == true) { cases = cases.Where(c => c.Phase != CasePhase.Closed && !c.IsArchived); filters.Add("open cases"); }
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
#pragma warning disable CA1304, CA1311 // EF Core translates ToUpper(); culture overloads don't translate.
            cases = cases.Where(c => c.AffectedStates != null
                                     && ("," + c.AffectedStates.Replace(" ", "").ToUpper() + ",").Contains(token));
#pragma warning restore CA1304, CA1311
            filters.Add($"residents of {st} affected");
        }

        // The entity filter: the visible occurrences of that exact value (ignoring case), and the cases they're on.
        List<Guid> entityIds = [];
        if (q.Entity is { } ev)
        {
            var key = IocObservable.Normalize(IocObservable.DetectType(ev), ev).ToLowerInvariant();   // WF-03
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
        if (q.DroppedTerms > 0) filters.Add($"only the first {FindQuery.MaxTerms} words used");

        // How the words read.
        var text = q.Text;
        var (readAs, iocType) = FindQuery.ReadShape(text);
        string? personId = null;
        if (readAs == FindReadAs.Words && !q.Quoted && PersonNamed(text) is { } p)   // WF-10: "admin" in quotes is a word
        {
            readAs = FindReadAs.Person;
            personId = p.UserId;
        }
        if (readAs == FindReadAs.Words && !text.Contains(' ')
            && await cases.AnyAsync(c => c.CaseNumber == text || c.CaseNumber.StartsWith(text + "_"), ct))
            readAs = FindReadAs.CaseNumber;
        // WF-02: CVE-2024-3094 or a ticket reference has a case number's shape. Read it as one only when a case number
        // the caller can see holds it; otherwise it's words, so the record is searched for it.
#pragma warning disable CA1304, CA1311, CA1862
        else if (readAs == FindReadAs.CaseNumber && text.ToLower() is var asNumber
                 && !await cases.AnyAsync(c => c.CaseNumber.ToLower().Contains(asNumber), ct))
            readAs = FindReadAs.Words;
#pragma warning restore CA1304, CA1311, CA1862
        // WF-89: an email address or account that is a colleague's sign-in name is read as both: the indicator, and the
        // person (their cases, the tasks they own and the entries they recorded are listed with the indicator's).
        string? alsoPersonId = readAs == FindReadAs.Indicator && iocType is EntityType.EmailAddress or EntityType.Account
                               && !q.Quoted && SignInNamed(text) is { } signIn ? signIn.UserId : null;
        var reading = readAs switch
        {
            FindReadAs.Nothing => "filters only",
            FindReadAs.CaseNumber => "a case number",
            FindReadAs.Indicator => Article(TypeWords(iocType!.Value)),
            FindReadAs.Person => $"a person: {_users.DisplayFor(personId)}",
            _ => q.Terms.Count == 1 ? "a word in the record" : "words in the record",
        };
        if (alsoPersonId is not null) reading += $", and a person: {_users.DisplayFor(alsoPersonId)}";
        List<string> alsoOwner = alsoPersonId is null ? [] : OwnerKeys(alsoPersonId);
        List<Guid> alsoRecorded = alsoPersonId is null ? [] : await EditedEntriesFirstRecordedByAsync(db, cases.Select(c => c.Id), alsoPersonId, ct);

        var terms = q.Terms.Select(t => t.ToLowerInvariant()).ToList();
        // WF-84: stored text holds link targets the reader never sees ([name](entity:<id>), evidence:, a GUID's hex), so
        // a word that could be part of one is checked again against the text as shown before a match counts.
        var recheck = readAs == FindReadAs.Words && terms.Any(CouldBeHidden);
        var counts = new Dictionary<FindKind, int>();
        var caseIds = cases.Select(c => c.Id);

        // WF-83: an entity is tagged in text as [label](entity:<id>), by its label as often as its value, and a task can be
        // about it; the entity filter and an indicator search find those too (as the timeline's entity filter does).
        List<string> tagRefs = [];
        if (q.Entity is not null) tagRefs = entityIds.Take(MaxTagRefs).Select(id => $"entity:{id}").ToList();
        else if (readAs == FindReadAs.Indicator)
        {
#pragma warning disable CA1304, CA1311, CA1862
            var exact = IocObservable.Normalize(iocType!.Value, text).ToLower();
            tagRefs = (await db.CaseEntities.AsNoTracking().Where(e => caseIds.Contains(e.CaseId) && e.Value.Trim().ToLower() == exact)
                .Select(e => e.Id).Take(MaxTagRefs).ToListAsync(ct)).Select(id => $"entity:{id}").ToList();
#pragma warning restore CA1304, CA1311, CA1862
        }

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
            // WF-08: after:/before: are when the entity was added to the case, as for evidence and tasks.
            if (from is not null) src = src.Where(e => e.CreatedAtUtc >= from);
            if (to is not null) src = src.Where(e => e.CreatedAtUtc < to);
            if (readAs == FindReadAs.Indicator)
            {
                // WF-03: compared in the form entities are stored in (IPv6 canonical, no trailing dot on a domain).
                var exact = IocObservable.Normalize(iocType!.Value, text).ToLower();
                src = src.Where(e => e.Value.Trim().ToLower() == exact);
            }
            else if (readAs == FindReadAs.Words)
                foreach (var t in terms)
                    src = src.Where(e => e.Value.ToLower().Contains(t) || (e.Label != null && e.Label.ToLower().Contains(t)));
#pragma warning restore CA1304, CA1311, CA1862
            // WF-06: grouped and counted in the database (an email address matches an account, as everywhere), so the count
            // covers every entity and the ones listed are the most widespread, not whichever 2,000 rows came back first.
#pragma warning disable CA1304, CA1311, CA1862
            var groups = await src
                .GroupBy(e => new { Family = e.Type == EntityType.EmailAddress ? EntityType.Account : e.Type, Key = e.Value.Trim().ToLower() })
                .Select(g => new { g.Key.Family, g.Key.Key, Cases = g.Select(x => x.CaseId).Distinct().Count() })
                .ToListAsync(ct);
#pragma warning restore CA1304, CA1311, CA1862
            counts[FindKind.Entities] = groups.Count;
            var top = groups.OrderByDescending(g => g.Cases).ThenBy(g => g.Key, StringComparer.Ordinal).Take(limit).ToList();
            var topKeys = top.Select(g => g.Key).Distinct().ToList();
            var wanted = top.Select(g => (g.Family, g.Key)).ToHashSet();
#pragma warning disable CA1304, CA1311, CA1862
            var rows = (await src.Where(e => topKeys.Contains(e.Value.Trim().ToLower()))
                    .Join(db.Cases, e => e.CaseId, c => c.Id, (e, c) => new
                    {
                        e.Id, e.Type, e.Value, e.Label, e.Disposition, e.CreatedAtUtc, CaseId = c.Id, c.CaseNumber, c.Phase, c.Classification,
                        c.IsArchived, c.IsExercise
                    }).ToListAsync(ct))
                .Where(r => wanted.Contains((IocObservable.MatchFamily(r.Type), r.Value.Trim().ToLowerInvariant())))
                .ToList();
#pragma warning restore CA1304, CA1311, CA1862
            var grouped = rows
                .GroupBy(r => (IocObservable.MatchFamily(r.Type), r.Value.Trim().ToLowerInvariant()))
                .Select(g =>
                {
                    var latest = g.OrderByDescending(x => x.CreatedAtUtc).First();
                    var perCase = g.GroupBy(x => x.CaseId)
                        .Select(cg => cg.OrderByDescending(x => IndicatorService.Severity(x.Disposition)).First())
                        .OrderByDescending(x => x.CreatedAtUtc)
                        .Select(x => new FindEntityCase(x.CaseId, x.CaseNumber, x.Phase, x.Classification, x.Disposition, x.Id, x.IsArchived, x.IsExercise))
                        .ToList();
                    return new FindEntity(latest.Type, latest.Value.Trim(), g.Select(x => x.Label).FirstOrDefault(l => l is not null), perCase);
                })
                .OrderByDescending(e => e.Cases.Count)
                .ThenBy(e => e.Value, StringComparer.OrdinalIgnoreCase)
                .ToList();
            entities = grouped;
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
                var stored = IocObservable.Normalize(iocType!.Value, text).ToLower();
                var typed = IocObservable.Refang(text).ToLower();
                caseQ = caseQ.Where(c => c.Entities.Any(e => e.Value.Trim().ToLower() == stored)
                                         || c.Title.ToLower().Contains(typed) || (c.Summary != null && c.Summary.ToLower().Contains(typed))
                                         || (alsoPersonId != null && (c.IncidentCommander == alsoPersonId
                                                                      || c.Assignments.Any(a => a.UserId == alsoPersonId))));   // WF-89
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
                .Select(c => new { c.Id, c.CaseNumber, c.Title, c.Classification, c.Severity, c.Phase, c.CreatedAtUtc, c.ClosedAtUtc, c.IsExercise, c.OutcomeKey, c.IsArchived })
                .ToListAsync(ct);
            var closing = await ClosingLinesAsync(db, caseRows.Where(c => c.Phase == CasePhase.Closed).Select(c => c.Id).ToList(), ct);
            foundCases = caseRows.Select(c => new FindCase(c.Id, c.CaseNumber, c.Title, c.Classification, c.Severity, c.Phase,
                c.CreatedAtUtc, c.ClosedAtUtc, closing.GetValueOrDefault(c.Id), c.IsExercise, c.IsArchived)).ToList();
        }

        // --- Record entries (current versions), then closing briefs.
        // WF-87: owner: is about tasks, which are the only things with an owner, so it lists tasks alone.
        var entriesApply = owner is null && (readAs is FindReadAs.Indicator or FindReadAs.Words or FindReadAs.Person
                           || q.Entity is not null || by is not null || q.EntryKind is not null || q.EntryType is not null);
        List<FindEntry> entries = [];
        if (entriesApply)
        {
            var eq = db.TimelineEntries.AsNoTracking().Where(e => e.IsCurrent && caseIds.Contains(e.CaseId));
#pragma warning disable CA1304, CA1311, CA1862
            var taggedEntries = await TaggingAsync(eq, r => e => e.Description.Contains(r), e => e.Id, tagRefs, ct);
            if (readAs is FindReadAs.Indicator or FindReadAs.Words)
                foreach (var t in readAs == FindReadAs.Indicator ? [IocObservable.Refang(text).ToLower()] : terms)
                    eq = eq.Where(e => e.Description.ToLower().Contains(t) || (e.Rationale != null && e.Rationale.ToLower().Contains(t))
                                       || taggedEntries.Contains(e.Id)
                                       || (alsoPersonId != null && ((e.Version == 1 && e.CreatedBy == alsoPersonId) || alsoRecorded.Contains(e.Id))));
            // WF-09: who recorded it is the first version's author, not whoever last edited it.
            if (readAs == FindReadAs.Person)
            {
                var edited = await EditedEntriesFirstRecordedByAsync(db, caseIds, personId!, ct);
                eq = eq.Where(e => (e.Version == 1 && e.CreatedBy == personId) || edited.Contains(e.Id));
            }
            if (q.Entity is { } ent)
            {
                var v = ent.ToLower();
                eq = eq.Where(e => (e.ActorEntityId != null && entityIds.Contains(e.ActorEntityId.Value))
                                   || (e.TargetEntityId != null && entityIds.Contains(e.TargetEntityId.Value))
                                   || e.Description.ToLower().Contains(v) || taggedEntries.Contains(e.Id));
            }
#pragma warning restore CA1304, CA1311, CA1862
            if (by is not null)
            {
                var edited = await EditedEntriesFirstRecordedByAsync(db, caseIds, by, ct);
                eq = eq.Where(e => (e.Version == 1 && e.CreatedBy == by) || edited.Contains(e.Id));
            }
            if (q.EntryKind is { } k) eq = eq.Where(e => e.Kind == k);
            if (q.EntryType is { } ty) eq = eq.Where(e => e.Type == ty);
            if (from is not null) eq = eq.Where(e => e.OccurredAtUtc >= from);
            if (to is not null) eq = eq.Where(e => e.OccurredAtUtc < to);
            if (recheck)
            {
                var seen = await eq.Select(e => new { e.Id, e.Description, e.Rationale }).ToListAsync(ct);
                var shown = seen.Where(e => Shows(terms, e.Description, e.Rationale)).Select(e => e.Id).ToList();
                eq = eq.Where(e => shown.Contains(e.Id));
            }
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
                var taggedBriefs = await TaggingAsync(bq, r => b => b.WorkingAssessment!.Contains(r) || (b.Summary != null && b.Summary.Contains(r)),
                    b => b.Id, tagRefs, ct);
                foreach (var t in readAs == FindReadAs.Indicator ? [IocObservable.Refang(text).ToLower()] : terms)
                    bq = bq.Where(b => b.WorkingAssessment!.ToLower().Contains(t) || (b.Summary != null && b.Summary.ToLower().Contains(t))
                                       || taggedBriefs.Contains(b.Id));
                if (q.Entity is { } ent2) { var v = ent2.ToLower(); bq = bq.Where(b => b.WorkingAssessment!.ToLower().Contains(v) || taggedBriefs.Contains(b.Id)); }
#pragma warning restore CA1304, CA1311, CA1862
                if (recheck)
                {
                    var seen = await bq.Select(b => new { b.Id, b.WorkingAssessment, b.Summary }).ToListAsync(ct);
                    var shown = seen.Where(b => Shows(terms, b.WorkingAssessment, b.Summary)).Select(b => b.Id).ToList();
                    bq = bq.Where(b => shown.Contains(b.Id));
                }
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
            var taggedTasks = await TaggingAsync(tq, r => x => x.AboutRef == r || (x.Description != null && x.Description.Contains(r)),
                x => x.Id, tagRefs, ct);
#pragma warning disable CA1304, CA1311, CA1862
            if (readAs is FindReadAs.Indicator or FindReadAs.Words)
                foreach (var t in readAs == FindReadAs.Indicator ? [IocObservable.Refang(text).ToLower()] : terms)
                    tq = tq.Where(x => x.Title.ToLower().Contains(t) || (x.Description != null && x.Description.ToLower().Contains(t))
                                       || taggedTasks.Contains(x.Id)
                                       || (x.Owner != null && alsoOwner.Contains(x.Owner.Trim().ToLower())));   // WF-89
            if (q.Entity is { } ent3)
            {
                var v = ent3.ToLower();
                tq = tq.Where(x => x.Title.ToLower().Contains(v) || (x.Description != null && x.Description.ToLower().Contains(v))
                                   || taggedTasks.Contains(x.Id));
            }
#pragma warning restore CA1304, CA1311, CA1862
            // WF-01: a task's owner is free text, so it's theirs when it names any of their identifiers (the TaskOwner rule
            // My Work and the agenda use), compared in the query.
#pragma warning disable CA1304, CA1311
            if (readAs == FindReadAs.Person) { var ids = OwnerKeys(personId!); tq = tq.Where(x => x.Owner != null && ids.Contains(x.Owner.Trim().ToLower())); }
            if (owner is not null) { var ids = OwnerKeys(owner); tq = tq.Where(x => x.Owner != null && ids.Contains(x.Owner.Trim().ToLower())); }
#pragma warning restore CA1304, CA1311
            if (from is not null) tq = tq.Where(x => x.CreatedAtUtc >= from);
            if (to is not null) tq = tq.Where(x => x.CreatedAtUtc < to);
            if (recheck)
            {
                var seen = await tq.Select(x => new { x.Id, x.Title, x.Description }).ToListAsync(ct);
                var shown = seen.Where(x => Shows(terms, x.Title, x.Description)).Select(x => x.Id).ToList();
                tq = tq.Where(x => shown.Contains(x.Id));
            }
            counts[FindKind.Tasks] = await tq.CountAsync(ct);
            // Open first (by when they're due), then done.
            // WF-06: ordered and cut in the query (dates order on SQLite too, stored as ticks), not every match read and
            // sorted in memory on each palette keystroke.
            tasks = (await tq
                    .OrderBy(t => t.Status == ActionItemStatus.Done || t.Status == ActionItemStatus.Cancelled)
                    .ThenBy(t => t.DueAtUtc == null)
                    .ThenBy(t => t.DueAtUtc)
                    .Take(limit)
                    .Join(db.Cases, t => t.CaseId, c => c.Id, (t, c) => new { t.Id, t.CaseId, c.CaseNumber, t.Title, t.Owner, t.DueAtUtc, t.Status })
                    .ToListAsync(ct))
                .OrderBy(t => t.Status is ActionItemStatus.Done or ActionItemStatus.Cancelled)
                .ThenBy(t => t.DueAtUtc ?? DateTimeOffset.MaxValue)
                .Select(t => new FindTask(t.Id, t.CaseId, t.CaseNumber, t.Title, t.Owner, t.DueAtUtc, t.Status)).ToList();
        }

        // --- Evidence names (and a file hash matches the file's own SHA-256).
        List<FindEvidence> evidence = [];
        if (readAs is FindReadAs.Indicator or FindReadAs.Words && q.EntryKind is null && q.EntryType is null && owner is null)
        {
            var xq = db.Evidence.AsNoTracking().Where(x => caseIds.Contains(x.CaseId));
            // WF-90: only a SHA-256 can be a file's own hash; an MD5 or SHA-1 is looked for in names and descriptions.
            var hash = readAs == FindReadAs.Indicator && iocType == EntityType.FileHash && text.Trim().Length == 64
                ? text.Trim().ToLowerInvariant() : null;
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
            evidence = (await xq.OrderByDescending(x => x.CreatedAtUtc).Take(limit)   // WF-06
                    .Join(db.Cases, x => x.CaseId, c => c.Id, (x, c) => new { x.Id, x.CaseId, c.CaseNumber, x.OriginalFileName, x.Description, x.CreatedAtUtc })
                    .ToListAsync(ct))
                .OrderByDescending(x => x.CreatedAtUtc)
                .Select(x => new FindEvidence(x.Id, x.CaseId, x.CaseNumber, x.OriginalFileName, x.Description, x.CreatedAtUtc, hash is not null))
                .ToList();
        }

        // --- Working notes: only when asked for (they're working reasoning, not the record).
        List<FindNote> notes = [];
        // WF-87: and a type filter lists entries only, as owner: lists tasks only.
        if (q.Notes && owner is null && q.EntryType is null && q.EntryKind is null
            && (readAs is FindReadAs.Indicator or FindReadAs.Words or FindReadAs.Person || by is not null || q.Entity is not null))
        {
            var nq = db.Notes.AsNoTracking().Where(n => n.IsCurrent && caseIds.Contains(n.CaseId));
            var taggedNotes = await TaggingAsync(nq, r => n => n.Body.Contains(r), n => n.Id, tagRefs, ct);
#pragma warning disable CA1304, CA1311, CA1862
            if (readAs is FindReadAs.Indicator or FindReadAs.Words)
                foreach (var t in readAs == FindReadAs.Indicator ? [IocObservable.Refang(text).ToLower()] : terms)
                    nq = nq.Where(n => n.Body.ToLower().Contains(t) || taggedNotes.Contains(n.Id));
            if (q.Entity is { } ent4) { var v = ent4.ToLower(); nq = nq.Where(n => n.Body.ToLower().Contains(v) || taggedNotes.Contains(n.Id)); }
#pragma warning restore CA1304, CA1311, CA1862
            // WF-09: as for entries, the note's first author.
            foreach (var who in new[] { readAs == FindReadAs.Person ? personId : null, by }.OfType<string>())
            {
                var edited = await EditedNotesFirstWrittenByAsync(db, caseIds, who, ct);
                nq = nq.Where(n => (n.Version == 1 && n.CreatedBy == who) || edited.Contains(n.Id));
            }
            if (from is not null) nq = nq.Where(n => n.CreatedAtUtc >= from);
            if (to is not null) nq = nq.Where(n => n.CreatedAtUtc < to);
            if (recheck)
            {
                var seen = await nq.Select(n => new { n.Id, n.Body }).ToListAsync(ct);
                var shown = seen.Where(n => Shows(terms, n.Body)).Select(n => n.Id).ToList();
                nq = nq.Where(n => shown.Contains(n.Id));
            }
            counts[FindKind.Notes] = await nq.CountAsync(ct);
            var notes0 = (await nq.OrderByDescending(n => n.CreatedAtUtc).Take(limit)   // WF-06
                    .Join(db.Cases, n => n.CaseId, c => c.Id, (n, c) => new { n.Id, n.CaseId, c.CaseNumber, n.CreatedAtUtc, n.CreatedBy, n.Body, n.Version })
                    .ToListAsync(ct))
                .OrderByDescending(n => n.CreatedAtUtc)
                .ToList();
            // WF-86: listed under the note's first author, as by: and the person reading match it, not its last editor.
            var editedOn = notes0.Where(n => n.Version > 1).Select(n => n.CaseId).Distinct().ToList();
            Dictionary<Guid, string> authors = editedOn.Count == 0 ? [] : FirstAuthors(await db.Notes.AsNoTracking()
                .Where(n => editedOn.Contains(n.CaseId) && (n.Version > 1 || !n.IsCurrent))
                .Select(n => new Version(n.Id, n.SupersedesNoteId, n.CreatedBy, n.Version, n.IsCurrent)).ToListAsync(ct));
            notes = notes0
                .Select(n => new FindNote(n.Id, n.CaseId, n.CaseNumber, n.CreatedAtUtc,
                    _users.DisplayFor(authors.GetValueOrDefault(n.Id, n.CreatedBy)), Clip(Content.RichText.ToText(n.Body))))
                .ToList();
        }

        return new FindResult(q, readAs, reading, filters, counts, entities, foundCases, entries, tasks, evidence, notes);
    }

    private static readonly string[] LinkSchemes = ["entity:", "evidence:", "entry:", "note:"];

    // A word that a link target could hold: part of a scheme name, or hex digits and dashes (a GUID's).
    private static bool CouldBeHidden(string term) =>
        LinkSchemes.Any(s => s.Contains(term, StringComparison.Ordinal))
        || (term.Length >= 2 && term.All(ch => ch is (>= '0' and <= '9') or (>= 'a' and <= 'f') or '-'));

    // Whether every word is in one of the texts as the reader sees them (links shown by their names).
    private static bool Shows(IReadOnlyList<string> terms, params string?[] texts)
    {
        var shown = string.Join('\n', texts.Where(t => t is not null).Select(t => Content.RichText.ToText(t).ToLowerInvariant()));
        return terms.All(t => shown.Contains(t, StringComparison.Ordinal));
    }

    // WF-83: how many of an entity's occurrences are looked for as tags (one query per kind each; a value is on few cases).
    private const int MaxTagRefs = 25;

    // WF-83: the rows of the source whose text tags any of the refs ("entity:<id>"), one query per ref.
    private static async Task<HashSet<Guid>> TaggingAsync<T>(IQueryable<T> source, Func<string, Expression<Func<T, bool>>> tags,
        Expression<Func<T, Guid>> id, IReadOnlyList<string> refs, CancellationToken ct)
    {
        var found = new HashSet<Guid>();
        foreach (var r in refs) found.UnionWith(await source.Where(tags(r)).Select(id).ToListAsync(ct));
        return found;
    }

    // WF-09: current versions of edited entries whose first version was recorded by <who>. Edits are few, so only their
    // chains are read; an entry never edited is its own first version.
    private static async Task<List<Guid>> EditedEntriesFirstRecordedByAsync(IAppDbContext db, IQueryable<Guid> caseIds, string who,
        CancellationToken ct)
    {
        var rows = await db.TimelineEntries.AsNoTracking().Where(e => caseIds.Contains(e.CaseId) && (e.Version > 1 || !e.IsCurrent))
            .Select(e => new Version(e.Id, e.SupersedesEntryId, e.CreatedBy, e.Version, e.IsCurrent)).ToListAsync(ct);
        return FirstAuthoredBy(rows, who);
    }

    private static async Task<List<Guid>> EditedNotesFirstWrittenByAsync(IAppDbContext db, IQueryable<Guid> caseIds, string who,
        CancellationToken ct)
    {
        var rows = await db.Notes.AsNoTracking().Where(n => caseIds.Contains(n.CaseId) && (n.Version > 1 || !n.IsCurrent))
            .Select(n => new Version(n.Id, n.SupersedesNoteId, n.CreatedBy, n.Version, n.IsCurrent)).ToListAsync(ct);
        return FirstAuthoredBy(rows, who);
    }

    private sealed record Version(Guid Id, Guid? Supersedes, string CreatedBy, int Number, bool IsCurrent);

    private static List<Guid> FirstAuthoredBy(List<Version> rows, string who) =>
        FirstAuthors(rows).Where(kv => string.Equals(kv.Value, who, StringComparison.Ordinal)).Select(kv => kv.Key).ToList();

    // Each edited current version's first author, by the current version's id.
    private static Dictionary<Guid, string> FirstAuthors(List<Version> rows)
    {
        var byId = rows.ToDictionary(r => r.Id);
        var result = new Dictionary<Guid, string>();
        foreach (var r in rows.Where(r => r.IsCurrent && r.Number > 1))
        {
            var first = r;
            for (var guard = 0; first.Supersedes is { } prev && byId.TryGetValue(prev, out var p) && guard < 1000; guard++) first = p;
            result[r.Id] = first.CreatedBy;
        }
        return result;
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

    // Every identifier a task owner might name a person by, lower-cased for the query: the caller's own, or the directory's.
    private List<string> OwnerKeys(string userId)
    {
        string?[] ids = userId == _user.UserId
            ? [_user.UserId, _user.UserPrincipalName, _user.DisplayName, _user.Email]
            : _users.Resolve(userId) is { } u ? [userId, u.UserPrincipalName, u.DisplayName, u.Email] : [userId];
        return ids.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!.Trim().ToLowerInvariant()).Distinct().ToList();
    }

    // WF-89: a known person's sign-in name, email address or DOMAIN\user (which reads as an indicator by its shape).
    private UserSummary? SignInNamed(string text)
    {
        var t = text.Trim();
        var matches = _users.All().Where(u => u.UserId.Equals(t, StringComparison.OrdinalIgnoreCase)
                                              || (u.UserPrincipalName is { } upn && upn.Equals(t, StringComparison.OrdinalIgnoreCase))
                                              || (u.Email is { } em && em.Equals(t, StringComparison.OrdinalIgnoreCase))).ToList();
        return matches.Count == 1 ? matches[0] : null;
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

    private static string Article(string w) => ("aeiouAEIOU".Contains(w[0]) && !w.StartsWith("URL", StringComparison.Ordinal) ? "an " : "a ") + w;
}
