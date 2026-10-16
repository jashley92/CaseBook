using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Dashboards;
using IncidentManager.Application.Mitre;
using IncidentManager.Application.Security;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Notifications;

/// <summary>Remembers which quarters' executive reports have been sent (BUG-95: in the database, like the other trackers).</summary>
public interface IExecutiveReportTracker
{
    /// <summary>True only the first time a quarter is marked sent.</summary>
    bool TryMarkSent(ProgramPeriod period);

    /// <summary>BUG-08: un-marks what wasn't delivered, so the next scan sends it again.</summary>
    void Forget(ProgramPeriod period);
}

/// <inheritdoc />
public sealed class ExecutiveReportTracker(INotificationMarks? marks = null) : IExecutiveReportTracker
{
    private readonly INotificationMarks _marks = marks ?? new InMemoryNotificationMarks();

    private static string Key(ProgramPeriod p) => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"executive|{p.Year}-Q{p.Quarter}");

    public bool TryMarkSent(ProgramPeriod period) => _marks.TryAdd(Key(period));

    public void Forget(ProgramPeriod period) => _marks.Remove(Key(period));
}

/// <summary>
/// PROD-15: the scheduled executive report. In the first <see cref="SendWindowDays"/> days of each calendar
/// quarter it builds the E-31 program report for the quarter just ended and sends its headline figures to the
/// managers (via <see cref="ICaseNotifications.OnExecutiveReportAsync"/>), with a link to the full report.
/// The report is built with Manager visibility (every case, <see cref="Permission.ViewAllCases"/>), which is
/// exactly what its recipients can already see in the app, so no figure reaches someone outside their scope.
/// Read-only; exercises excluded; once per quarter via the tracker, whose mark is kept in the database (BUG-95), so
/// a restart inside the window doesn't send it again.
/// </summary>
public sealed class ExecutiveReportScanner(
    IAppDbContextFactory factory,
    ISlaTargetsProvider sla,
    ICaseNotifications notifications,
    IExecutiveReportTracker tracker,
    IClock clock,
    IOrganizationTimeZone? zone = null,
    IServerSettingValues? server = null,
    Compliance.INotificationDeadlineSettingsProvider? notify = null,
    Admin.NotificationRuleService? rules = null)
{
    /// <summary>How many days into a new quarter the previous quarter's report may still go out.</summary>
    public const int SendWindowDays = 7;

    /// <summary>Sends last quarter's report if it's due and not yet sent. Returns true when sent.</summary>
    public async Task<bool> ScanAndSendAsync(CancellationToken ct = default)
    {
        var now = clock.UtcNow;
        // Quarters turn over at local midnight in the organization's reporting time zone.
        var tz = zone?.Current ?? TimeZoneInfo.Utc;
        var current = ProgramPeriod.Containing(now, tz);
        if ((now - current.StartUtc(tz)).TotalDays >= SendWindowDays) return false;

        var period = current.Previous;
        using var marks = NotificationMarkBatch.Begin();   // BUG-147: confirmed once the report has gone
        if (!tracker.TryMarkSent(period)) return false;

        // BUG-08: a quarter counts as sent only once its report is built and delivered.
        using var watch = DeliveryWatch.Begin();
        try
        {
            var viewer = new ReportViewer();
            var program = new ProgramReportService(factory, viewer, clock, sla, new AttackCoverageService(factory, viewer, clock), zone,
                notify, rules, server);   // BUG-322, BUG-585: the email's SLA and notice figures as the program report's
            var report = await program.BuildAsync(period, includeExercises: false, ct);
            await notifications.OnExecutiveReportAsync(report, ct);
        }
        catch
        {
            tracker.Forget(period);
            throw;
        }
        if (watch.Failed) { tracker.Forget(period); return false; }
        marks.Complete();
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
