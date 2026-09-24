using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Dashboards;
using IncidentManager.Application.Mitre;
using IncidentManager.Application.Security;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Notifications;

/// <summary>Remembers which quarters' executive reports have been sent (in memory, like the other trackers).</summary>
public interface IExecutiveReportTracker
{
    /// <summary>True only the first time a quarter is marked sent.</summary>
    bool TryMarkSent(ProgramPeriod period);
}

/// <inheritdoc />
public sealed class ExecutiveReportTracker : IExecutiveReportTracker
{
    private readonly object _gate = new();
    private readonly HashSet<ProgramPeriod> _sent = [];

    public bool TryMarkSent(ProgramPeriod period)
    {
        lock (_gate) return _sent.Add(period);
    }
}

/// <summary>
/// PROD-15: the scheduled executive report. In the first <see cref="SendWindowDays"/> days of each calendar
/// quarter it builds the E-31 program report for the quarter just ended and sends its headline figures to the
/// managers (via <see cref="ICaseNotifications.OnExecutiveReportAsync"/>), with a link to the full report.
/// The report is built with Manager visibility (every case, <see cref="Permission.ViewAllCases"/>), which is
/// exactly what its recipients can already see in the app, so no figure reaches someone outside their scope.
/// Read-only; exercises excluded; once per quarter via the tracker (a restart inside the window may re-send
/// once — the same trade as the other in-memory reminder trackers).
/// </summary>
public sealed class ExecutiveReportScanner(
    IAppDbContextFactory factory,
    ISlaTargetsProvider sla,
    ICaseNotifications notifications,
    IExecutiveReportTracker tracker,
    IClock clock)
{
    /// <summary>How many days into a new quarter the previous quarter's report may still go out.</summary>
    public const int SendWindowDays = 7;

    /// <summary>Sends last quarter's report if it's due and not yet sent. Returns true when sent.</summary>
    public async Task<bool> ScanAndSendAsync(CancellationToken ct = default)
    {
        var now = clock.UtcNow;
        var current = ProgramPeriod.Containing(now);
        if ((now - current.Start).TotalDays >= SendWindowDays) return false;

        var period = current.Previous;
        if (!tracker.TryMarkSent(period)) return false;

        var viewer = new ReportViewer();
        var program = new ProgramReportService(factory, viewer, clock, sla, new AttackCoverageService(factory, viewer, clock));
        var report = await program.BuildAsync(period, includeExercises: false, ct);
        await notifications.OnExecutiveReportAsync(report, ct);
        return true;
    }

    /// <summary>The system principal the report is computed as: Manager-level visibility, no write rights.</summary>
    private sealed class ReportViewer : ICurrentUser
    {
        private static readonly IReadOnlySet<Permission> Perms = RoleDefinitions.PermissionsFor([AppRole.Manager]);
        public string UserId => "system:executive-report";
        public string DisplayName => "Executive report";
        public string? UserPrincipalName => null;
        public string? Email => null;
        public bool IsAuthenticated => true;
        public IReadOnlySet<AppRole> Roles { get; } = new HashSet<AppRole> { AppRole.Manager };
        public bool IsInRole(AppRole role) => role == AppRole.Manager;
        public IReadOnlySet<Permission> Permissions => Perms;
        public bool Has(Permission permission) => Perms.Contains(permission);
    }
}
