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

    public async Task<IReadOnlyList<ActivityItem>> RecentAsync(int take = 20, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var scoped = db.Cases.AsNoTracking().ForUser(_user);

        // Join audit entries to the caller's visible cases on the denormalized case number, so the
        // feed honours need-to-know and we recover the case id for deep-linking.
        var rows = await (from a in db.AuditLog.AsNoTracking()
                          join c in scoped on a.CaseNumber equals c.CaseNumber
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
                         .Take(take)
                         .ToListAsync(ct);

        return rows.Select(r => new ActivityItem(
            r.Sequence, r.AtUtc, r.Actor, _users.DisplayFor(r.Actor),
            Humanize(r.Summary, r.Action, r.EntityType),
            r.CaseNumber, r.CaseId)).ToList();
    }

    private static string Humanize(string? summary, AuditAction action, string entityType)
    {
        // Prefer a specific verb; fall back to the stored summary, then the raw action.
        var verb = action switch
        {
            AuditAction.Create => "Added",
            AuditAction.Update => "Updated",
            AuditAction.SoftDelete => "Removed",
            AuditAction.ClassificationChanged => "Reclassified the case",
            AuditAction.StatusChanged => "Changed the case status",
            AuditAction.EvidenceUploaded => "Uploaded evidence",
            AuditAction.EvidenceDownloaded => "Downloaded evidence",
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
        "CaseEntity" => "an entity / IOC",
        "EntityRelationship" => "a relationship",
        "CaseTechnique" => "an ATT&CK technique",
        "ActionItem" => "an action item",
        "CaseAssignment" => "an assignment",
        "Evidence" => "evidence",
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
