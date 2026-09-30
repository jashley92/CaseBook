using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Activity;

/// <summary>One entry in the analyst activity feed (notification center).</summary>
public sealed record ActivityItem(
    long Sequence,
    DateTimeOffset AtUtc,
    string Actor,
    string ActorDisplay,
    string Summary,
    string? CaseNumber,
    Guid? CaseId);

/// <summary>
/// Reads the most recent case activity from the (tamper-evident) audit log, scoped to the cases
/// the caller is entitled to see. Backs the notification bell / activity feed (U-17). Read-only —
/// it never writes, so it cannot disturb the hash chain.
/// </summary>
public sealed class ActivityFeedService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IUserDirectory _users;

    public ActivityFeedService(IAppDbContextFactory factory, ICurrentUser user, IUserDirectory users)
    {
        _factory = factory;
        _user = user;
        _users = users;
    }

    /// <summary>
    /// INV-04: what other people changed on one case since <paramref name="sinceUtc"/> — how many audit entries,
    /// and who. Need-to-know scoped: nothing for a case the caller can't see.
    /// </summary>
    public async Task<(int Count, IReadOnlyList<string> People)> ChangesSinceAsync(Guid caseId, DateTimeOffset sinceUtc,
        CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var number = await db.Cases.AsNoTracking().ForUser(_user).Where(c => c.Id == caseId)
            .Select(c => c.CaseNumber).FirstOrDefaultAsync(ct);
        if (number is null) return (0, []);
        var me = _user.UserId;
        var rows = await db.AuditLog.AsNoTracking()
            .Where(a => a.CaseNumber == number && a.Actor != me && a.AtUtc > sinceUtc)
            .Select(a => a.Actor)
            .ToListAsync(ct);
        return (rows.Count, rows.Distinct().Select(a => _users.DisplayFor(a)).ToList());
    }

    /// <param name="othersOnly">Leave out the caller's own actions (the notification bell: you know what you did).</param>
    public async Task<IReadOnlyList<ActivityItem>> RecentAsync(int take = 20, CancellationToken ct = default,
        bool othersOnly = false)
    {
        using var db = _factory.CreateDbContext();
        var scoped = db.Cases.AsNoTracking().ForUser(_user);

        // Join audit entries to the caller's visible cases on the denormalized case number, so the
        // feed honours need-to-know and we recover the case id for deep-linking.
        var me = _user.UserId;
        var rows = await (from a in db.AuditLog.AsNoTracking()
                          join c in scoped on a.CaseNumber equals c.CaseNumber
                          where !othersOnly || a.Actor != me
                          orderby a.Sequence descending
                          select new
                          {
                              a.Sequence,
                              a.AtUtc,
                              a.Actor,
                              a.Action,
                              a.EntityType,
                              a.Summary,
                              a.CaseNumber,
                              CaseId = c.Id
                          })
                         .Take(take * 2)
                         .ToListAsync(ct);

        // Opening a case also writes its opening phase, classification and severity: that's one act ("Added the
        // case"), so those rows are folded into it rather than listed as three changes nobody made.
        // Likewise a change record (a phase, severity, …) also touches the case row: the "Updated the case" beside
        // it says nothing more, so it's dropped when the same save wrote something more specific.
        var opened = rows.Where(r => r.EntityType == "Case" && r.Action == AuditAction.Create)
            .Select(r => (r.CaseId, r.Actor, r.AtUtc)).ToHashSet();
        var specific = rows.Where(r => r.EntityType != "Case")
            .Select(r => (r.CaseId, r.Actor, r.AtUtc)).ToHashSet();
        rows = rows.Where(r => !(OpeningValue.Contains(r.EntityType) && opened.Contains((r.CaseId, r.Actor, r.AtUtc))))
            .Where(r => !(r.EntityType == "Case" && r.Action == AuditAction.Update && specific.Contains((r.CaseId, r.Actor, r.AtUtc))))
            .Take(take).ToList();

        return rows.Select(r => new ActivityItem(
            r.Sequence, r.AtUtc, r.Actor, _users.DisplayFor(r.Actor),
            Humanize(r.Summary, r.Action, r.EntityType),
            r.CaseNumber, r.CaseId)).ToList();
    }

    private static readonly HashSet<string> OpeningValue = ["StatusChange", "ClassificationChange", "SeverityChange"];

    private static string Humanize(string? summary, AuditAction action, string entityType)
    {
        // Change records are written as new rows; say what changed rather than "Added status change".
        if (action == AuditAction.Create && entityType switch
            {
                "StatusChange" => "Changed the phase",
                "ClassificationChange" => "Changed the classification",
                "SeverityChange" => "Changed the severity",
                "MaterialityChange" => "Recorded a materiality determination",
                "CaseDataElement" => "Updated the impact assessment",
                "CaseLink" => "Linked a related case",
                "PostIncidentReview" => "Started the post-incident review",
                "ImprovementAction" => "Added an improvement action",
                _ => null,
            } is { } said)
            return said;

        // Prefer a specific verb; fall back to the stored summary, then the raw action.
        var verb = action switch
        {
            AuditAction.Create => "Added",
            AuditAction.Update => "Updated",
            AuditAction.SoftDelete => "Removed",
            AuditAction.ClassificationChanged => "Reclassified the case",
            AuditAction.StatusChanged => "Changed the case phase",
            AuditAction.EvidenceUploaded => "Uploaded evidence",
            AuditAction.EvidenceDownloaded => "Downloaded evidence",
            AuditAction.EvidenceTransferred => "Recorded an evidence transfer",
            AuditAction.ReportGenerated => "Generated a report",
            AuditAction.ReportFinalized => "Finalized a report",
            AuditAction.LegalReferral => "Referred to Legal / Privacy",
            AuditAction.Access => "Accessed",
            _ => null
        };

        if (verb is null) return summary ?? action.ToString();

        // For the generic verbs, append a friendly entity noun (e.g. "Added a timeline entry").
        return action is AuditAction.Create or AuditAction.Update or AuditAction.SoftDelete or AuditAction.Access
            ? $"{verb} {FriendlyEntity(entityType)}"
            : verb;
    }

    private static string FriendlyEntity(string entityType) => entityType switch
    {
        "Case" => "the case",
        "TimelineEntry" => "a timeline entry",
        "AnalystNote" => "a note",
        "CaseEntity" => "an entity or IOC",
        "EntityRelationship" => "a relationship",
        "CaseTechnique" => "an ATT&CK technique",
        "ActionItem" => "a task",
        "CaseAssignment" => "an assignment",
        "Evidence" => "evidence",
        "PostIncidentReview" => "the post-incident review",
        "ImprovementAction" => "an improvement action",
        _ => SpaceCamel(entityType)
    };

    private static string SpaceCamel(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        var sb = new System.Text.StringBuilder(s.Length + 4);
        for (var i = 0; i < s.Length; i++)
        {
            if (i > 0 && char.IsUpper(s[i])) sb.Append(' ');
            sb.Append(i == 0 ? s[i] : char.ToLowerInvariant(s[i]));
        }
        return sb.ToString();
    }
}
