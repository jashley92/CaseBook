using FluentAssertions;
using IncidentManager.Application.Dashboards;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.ValueObjects;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>The Program overview's vendor-case panel: open vendor cases, pivots into our network, and how long vendors
/// took to tell us.</summary>
public sealed class VendorCasesTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.IncidentCommander] };

    public VendorCasesTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;

    [Fact]
    public async Task Counts_open_vendor_cases_pivots_and_the_median_time_to_tell_us()
    {
        var now = _clock.UtcNow;
        await using (var db = new AppDbContext(Options()))
        {
            await db.Database.EnsureCreatedAsync();
            Case Vendor(int seq, string vendor, DateTimeOffset opened)
            {
                var c = Case.Open(2026, seq, $"V{seq}", $"Vendor {seq}", Classification.Breach, Severity.High,
                    CaseOrigin.ThirdParty, "ic1", opened);
                c.ThirdParty = new ThirdPartyDetails { VendorName = vendor };
                return c;
            }

            // Attacked at the vendor 10 days before they told us, then pivoted into our network.
            var pivot = Vendor(1, "ClaimStream", now.AddDays(-5));
            pivot.AddEventStep(now.AddDays(-15), [MitreTactic.InitialAccess], "T1078", null, null, "Admin portal", "Vendor", "ic1", now);
            pivot.AddEventStep(now.AddDays(-12), [MitreTactic.LateralMovement], "T1021", null, null, "Into our SFTP", "SIEM", "ic1", now,
                environment: StepEnvironment.Ours);
            pivot.AddEventStep(now.AddDays(-5), [], null, null, null, "They told us", "Vendor", "ic1", now, type: TimelineEntryType.Notified);
            // Attacked at the vendor 4 days before they told us; nothing in ours.
            var told = Vendor(2, "PayrollCo", now.AddDays(-3));
            told.AddEventStep(now.AddDays(-7), [MitreTactic.Exfiltration], "T1567", null, null, "Export", "Vendor", "ic1", now);
            told.AddEventStep(now.AddDays(-3), [], null, null, null, "They told us", "Vendor", "ic1", now, type: TimelineEntryType.Notified);
            // Open, opened long ago, not yet told: counts as open, not in the period.
            var old = Vendor(3, "ClaimStream", now.AddDays(-200));
            // Closed and opened long ago: neither open nor in the period.
            var closed = Vendor(4, "Other", now.AddDays(-300));
            closed.ChangePhase(CasePhase.Closed, "done", "ic1", now.AddDays(-250));
            // An internal case never counts.
            var internalCase = Case.Open(2026, 5, "I", "Internal", Classification.Incident, Severity.Low, CaseOrigin.InternalDetection, "ic1", now.AddDays(-1));
            db.Cases.AddRange(pivot, told, old, closed, internalCase);
            await db.SaveChangesAsync();
        }

        var v = await new VendorCasesService(new TestDbContextFactory(Options()), _user)
            .GetAsync(new ProgramWindow(now.AddDays(-30), now, "the last 30 days"));

        v.Open.Should().Be(3);
        v.Vendors.Should().Be(2, "ClaimStream and PayrollCo had cases opened in the period");
        v.Pivoted.Should().Be(1);
        (v.MedianDaysToTellUs, v.TellUsBasis).Should().Be((7, 2), "10 and 4 days");
        v.OpenCases[0].Should().Be(new VendorCaseRow(v.OpenCases[0].Id, v.OpenCases[0].CaseNumber, "ClaimStream", 1, 1, true),
            "a pivot is listed first");
        v.OpenCases.Should().Contain(r => r.Vendor == "ClaimStream" && !r.Notified && r.StepsAtVendor == 0);
    }

    public void Dispose() => _connection.Dispose();
}
