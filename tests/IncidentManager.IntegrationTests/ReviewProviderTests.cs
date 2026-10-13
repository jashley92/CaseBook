using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Import;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Review fixes whose queries behave differently on the two providers. Runs on SQLite always and on SQL Server when
/// <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class ReviewProviderTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 12, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "analyst1", RoleSet = [AppRole.SysAdmin] };

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private CaseService Cases(TestDatabase database) =>
        new(database.Factory(), _user, _clock, new CaseNumberGenerator(database.Factory()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_retried_submission_ending_in_spaces_is_queued_once(string provider /* REV-57 */)
    {
        using var database = Open(provider);
        var imports = new CaseImportService(database.Factory(), _user, _clock, Cases(database));
        var json = """{ "format": "casebook-case-import", "schemaVersion": 1, "title": "Spaced", "entities": [ { "value": "10.0.0.5" } ] }  """;
        var doc = CaseImportService.Parse(json).Document!;

        var first = await imports.SubmitOnceAsync(json, doc);
        var retry = await imports.SubmitOnceAsync(json, doc);

        retry.AlreadyQueued.Should().BeTrue("SQL Server's LEN ignores trailing spaces, so the length can't narrow it");
        retry.Id.Should().Be(first.Id);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Updated_and_workload_staleness_read_the_audit_trail(string provider /* REV-15 */)
    {
        using var database = Open(provider);
        var cases = Cases(database);
        var older = await cases.CreateAsync(new CreateCaseRequest { DescriptiveName = "Older", Title = "Older",
            Classification = Classification.Incident, Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection });
        _clock.UtcNow = _clock.UtcNow.AddDays(1);
        await cases.CreateAsync(new CreateCaseRequest { DescriptiveName = "Newer", Title = "Newer",
            Classification = Classification.Incident, Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection });
        _clock.UtcNow = _clock.UtcNow.AddDays(9);
        await cases.AddNoteAsync(older.Id, "Still working this.");

        (await cases.ListAsync(new CaseFilter { Sort = CaseSort.Updated })).Items.Select(i => i.Title).Should().Equal("Older", "Newer");
        var workload = await new IncidentManager.Application.Work.TeamWorkloadService(database.Factory(), _user, _clock, new TestSlaTargets()).GetAsync();
        workload.Unassigned.Stale.Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_cases_trail_includes_its_earlier_number(string provider /* REV-01 */)
    {
        using var database = Open(provider);
        var cases = Cases(database);
        var ce = await cases.CreateAsync(new CreateCaseRequest { DescriptiveName = "Beacon", Title = "Beacon",
            Classification = null, Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection });
        var intake = ce.CaseNumber;
        await cases.AddNoteAsync(ce.Id, "Before promotion.");
        await cases.ReclassifyAsync(ce.Id, Classification.AdverseEvent, "Confirmed");
        var promoted = (await cases.GetDetailAsync(ce.Id))!.CaseNumber;

        var integrity = new IncidentManager.Application.Integrity.IntegrityService(database.Factory(), _hasher,
            null!, null!, _user, _clock, new IncidentManager.Application.Integrity.IntegrityMonitor(), new NoAlerts());
        var trail = await integrity.QueryAsync(new IncidentManager.Application.Integrity.AuditQueryFilter { CaseNumber = promoted });

        trail.Select(a => a.CaseNumber).Should().Contain(intake).And.Contain(promoted);
    }

    private sealed class NoAlerts : IncidentManager.Application.Abstractions.IIntegrityAlertNotifier
    {
        public Task OnChainBrokenAsync(IncidentManager.Application.Abstractions.ChainVerificationResult result, CancellationToken ct = default) =>
            Task.CompletedTask;
    }
}
