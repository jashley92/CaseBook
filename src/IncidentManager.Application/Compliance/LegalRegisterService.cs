using System.Globalization;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using static IncidentManager.Application.Common.Csv;

namespace IncidentManager.Application.Compliance;

/// <summary>One case carrying a legal / regulatory obligation, flattened for the register.</summary>
public sealed record LegalRegisterRow(
    string CaseNumber, string Title, Classification? Classification, Severity Severity, CasePhase Phase,
    DateTimeOffset OpenedAtUtc, DateTimeOffset? ReferredAtUtc, string? ReferredBy, string? LegalContact,
    string? RelevanceNote, bool LegalHold, MaterialityStatus Materiality, string? MaterialityDecisionMaker,
    DateTimeOffset? MaterialityDecidedOnUtc, int? AffectedIndividuals, string? AffectedJurisdictions,
    DateTimeOffset? ReportedAtUtc, string? DeadlineJurisdiction, DateTimeOffset? DeadlineDueAtUtc, string? DeadlineState);

/// <summary>
/// PROD-12 (Legal/Privacy half): the obligations register as an <b>export</b> — Legal and Privacy don't use the
/// app, so their interface is a file the SOC hands over. Every visible case with a legal-facing obligation: a
/// Legal referral, a legal hold, a Breach classification, or a materiality determination in progress or made —
/// with the referral, hold, materiality, affected-population, regulator-report and notification-deadline facts
/// side by side. Need-to-know scoped; exercises excluded; read-only. The CSV is formula-injection guarded.
/// </summary>
public sealed class LegalRegisterService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly NotificationDeadlineService _deadlines;
    private readonly IUserDirectory _users;

    public LegalRegisterService(IAppDbContextFactory factory, ICurrentUser user, NotificationDeadlineService deadlines,
        IUserDirectory users)
    {
        _factory = factory;
        _user = user;
        _deadlines = deadlines;
        _users = users;
    }

    public async Task<IReadOnlyList<LegalRegisterRow>> BuildAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var cases = await db.Cases.AsNoTracking().ForUser(_user).ExcludingExercises()
            .Where(c => c.LegalReferral.IsReferred || c.LegalHold || c.Classification == Classification.Breach
                        || c.Materiality.Status != MaterialityStatus.Undetermined)
            .Select(c => new
            {
                c.Id, c.CaseNumber, c.Title, c.Classification, c.Severity, c.Phase, c.CreatedAtUtc,
                c.LegalReferral.ReferredAtUtc, c.LegalReferral.ReferredBy, c.LegalReferral.ReferredToContact,
                c.LegalReferral.RegulatoryRelevanceNote, c.LegalHold, MaterialityStatus = c.Materiality.Status,
                c.Materiality.DecisionMaker, c.Materiality.DecidedOnUtc, c.AffectedIndividualsCount, c.AffectedStates,
                c.ReportedAtUtc,
            })
            .ToListAsync(ct);

        var rows = new List<LegalRegisterRow>(cases.Count);
        foreach (var c in cases.OrderBy(x => x.CaseNumber, StringComparer.Ordinal))
        {
            // The headline (most urgent) jurisdiction, when the deadline feature is on and a clock applies.
            var d = await _deadlines.EvaluateAsync(c.Id, ct);
            var h = d.Headline;
            rows.Add(new LegalRegisterRow(
                c.CaseNumber, c.Title, c.Classification, c.Severity, c.Phase, c.CreatedAtUtc,
                c.ReferredAtUtc, c.ReferredBy is { } by ? _users.DisplayFor(by) : null, c.ReferredToContact,
                c.RegulatoryRelevanceNote, c.LegalHold, c.MaterialityStatus, c.DecisionMaker, c.DecidedOnUtc,
                c.AffectedIndividualsCount, c.AffectedStates, c.ReportedAtUtc,
                h?.JurisdictionLabel, h?.DueAtUtc, h?.State.ToString()));
        }
        return rows;
    }

    public static string ToCsv(IReadOnlyList<LegalRegisterRow> rows, DateTimeOffset generatedAtUtc)
    {
        var inv = CultureInfo.InvariantCulture;
        static string T(DateTimeOffset? t) => t?.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) ?? "";
        var sb = new StringBuilder();
        sb.Append("# CaseBook legal & regulatory obligations register, generated ")
          .Append(generatedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm", inv)).Append(" UTC. Times are UTC.\r\n");
        sb.Append("case_number,title,classification,severity,phase,opened_utc,legal_referred_utc,referred_by,legal_contact," +
                  "regulatory_relevance,legal_hold,materiality,materiality_decision_maker,materiality_decided_utc," +
                  "affected_individuals,affected_jurisdictions,reported_to_regulators_utc,deadline_jurisdiction," +
                  "deadline_due_utc,deadline_status\r\n");
        foreach (var r in rows)
        {
            string[] f =
            [
                r.CaseNumber, r.Title, r.Classification?.ToString() ?? "ComplexEvent", r.Severity.ToString(), r.Phase.ToString(),
                T(r.OpenedAtUtc), T(r.ReferredAtUtc), r.ReferredBy ?? "", r.LegalContact ?? "", r.RelevanceNote ?? "",
                r.LegalHold ? "Yes" : "No", r.Materiality.ToString(), r.MaterialityDecisionMaker ?? "", T(r.MaterialityDecidedOnUtc),
                r.AffectedIndividuals?.ToString(inv) ?? "", r.AffectedJurisdictions ?? "", T(r.ReportedAtUtc),
                r.DeadlineJurisdiction ?? "", T(r.DeadlineDueAtUtc), r.DeadlineState ?? "",
            ];
            sb.Append(string.Join(",", f.Select(Escape))).Append("\r\n");
        }
        return sb.ToString();
    }
}
