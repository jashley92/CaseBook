using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Access;

/// <summary>
/// Filter over the access log (C-05). Fields AND together; blank fields are ignored. Dates are inclusive
/// and interpreted in UTC (the stored truth).
/// </summary>
public sealed record AccessLogFilter
{
    public string? Actor { get; init; }
    public string? CaseNumber { get; init; }
    public AccessType? AccessType { get; init; }
    public bool RestrictedOnly { get; init; }
    public DateTimeOffset? FromUtc { get; init; }
    public DateTimeOffset? ToUtc { get; init; }
}

/// <summary>
/// Records and queries the out-of-chain access log (C-05). Recording is best-effort and MUST NOT throw
/// into the view/download path — a logging failure can never block opening a case or pulling a file.
/// </summary>
public interface IAccessLogService
{
    /// <summary>Record an authorized case-detail open by the current user (coalesced into a session). BUG-243:
    /// <paramref name="stillOpen"/> is a reload of a case the person already has open (after their own save, or a
    /// colleague's change arriving live): it keeps the view-session current but isn't a new open, so it sends no SIEM
    /// event (a stream of false "restricted case accessed" alerts otherwise, which could crowd out real ones).</summary>
    Task RecordCaseOpenAsync(Guid caseId, string caseNumber, bool wasRestricted, bool stillOpen = false,
        CancellationToken ct = default);

    /// <summary>
    /// Record a sensitive-artifact access (evidence/report download, or a data export) by the current
    /// user. <paramref name="caseId"/> is null for cross-case exports; the service resolves the case
    /// number and restricted flag from it when present.
    /// </summary>
    Task RecordArtifactAsync(AccessType type, Guid? caseId, string? label, Guid? targetId = null,
        CancellationToken ct = default);

    /// <summary>Cross-case query for the admin Access Log console, newest session first.</summary>
    Task<IReadOnlyList<CaseAccessEvent>> QueryAsync(AccessLogFilter filter, int take = 500, CancellationToken ct = default);

    /// <summary>
    /// CAP-32: the filtered log as CSV (<see cref="AccessLogCsv"/>), streamed to <paramref name="output"/> as it's read, in
    /// <see cref="QueryAsync"/>'s order, at most <paramref name="rowLimit"/> sessions (a cut said at the top and the end).
    /// Sessions begun after the export started aren't in it (its own access entry among them). <paramref name="started"/>
    /// is told how many rows will be written and whether it's cut, before the first byte; past <paramref name="timeLimit"/>
    /// (<c>CsvStream.TimeLimit</c> by default) it stops, says so in the file and reports it. Administrators only.
    /// </summary>
    Task<Common.CsvStreamResult> WriteCsvAsync(AccessLogFilter filter, Stream output, int rowLimit,
        Func<int, bool, Task>? started, TimeSpan? timeLimit, CancellationToken ct = default);

    /// <summary>Coalesced case-open sessions for one case (the per-case "Viewed by" panel).</summary>
    Task<IReadOnlyList<CaseAccessEvent>> ForCaseAsync(Guid caseId, int take = 200, CancellationToken ct = default);

    /// <summary>
    /// INV-04: when the current user last had this case open, before now (the end of their most recent
    /// view-session), or null if they never have. Read before the current open is recorded.
    /// </summary>
    Task<DateTimeOffset?> LastViewedAsync(Guid caseId, CancellationToken ct = default);

    /// <summary>Distinct actors present in the log, to populate the console's actor filter.</summary>
    Task<IReadOnlyList<string>> ActorsAsync(CancellationToken ct = default);
}
