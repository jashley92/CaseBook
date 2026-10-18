using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Web.Components.Shared;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-24: the New case form offers the vendor names on cases the user can see, and a known vendor's "Seen before" line:
/// how many earlier cases, and how the last closed one ended, with a link to the case list filtered to the vendor. Scoped
/// by need-to-know (a restricted case outside it never names its vendor) with exercises left out. Runs on SQLite always
/// and on SQL Server when <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class VendorHistoryTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic2", RoleSet = [AppRole.SysAdmin] };

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private CaseService NewService(TestDatabase database) =>
        new(database.Factory(), _user, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private Task<IncidentManager.Domain.Entities.Case> VendorCaseAsync(CaseService svc, string name, string vendor, bool exercise = false) =>
        svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = name, Title = name + " case", Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.ThirdParty, VendorName = vendor, IsExercise = exercise
        });

    private async Task CloseAsync(CaseService svc, Guid id, string conclusion)
    {
        _clock.UtcNow = _clock.UtcNow.AddHours(4);
        await svc.ChangePhaseAsync(id, CasePhase.Closed, null, closing: new(CaseOutcomeCatalog.Confirmed,
            "The vendor's portal was breached.", conclusion));
        _clock.UtcNow = _clock.UtcNow.AddDays(1);
    }

    /// <summary>Seeds as an administrator (ic2), then reads as analyst1, who isn't on any of the cases and has no clearance
    /// for restricted ones.</summary>
    private async Task<(CaseService Svc, Guid Older, Guid Newer, Guid Open)> SeedAsync(TestDatabase database)
    {
        await using (var db = database.NewContext()) await DevDataSeeder.SeedCaseOutcomesAsync(db, _clock);
        var svc = NewService(database);
        var older = (await VendorCaseAsync(svc, "Portal", "Northwind")).Id;
        await CloseAsync(svc, older, "Customer list exposed; notified.");
        var newer = (await VendorCaseAsync(svc, "Invoices", " northwind ")).Id;
        await CloseAsync(svc, newer, "Invoice fraud attempt; no payment made.");
        var open = (await VendorCaseAsync(svc, "Tokens", "Northwind")).Id;
        await VendorCaseAsync(svc, "Drill", "Northwind", exercise: true);
        await VendorCaseAsync(svc, "Drill only", "Tabletop Vendor Ltd", exercise: true);

        // A restricted case outside analyst1's need-to-know: its vendor, and its closing, must not show.
        var hidden = (await VendorCaseAsync(svc, "Secret", "Hushco")).Id;
        var hiddenNorthwind = (await VendorCaseAsync(svc, "Secret Northwind", "Northwind")).Id;
        await CloseAsync(svc, hiddenNorthwind, "This line must never reach the analyst.");
        await svc.SetRestrictedAsync(hidden, true, "Insider matter");
        await svc.SetRestrictedAsync(hiddenNorthwind, true, "Insider matter");

        _user.UserId = "analyst1";
        _user.RoleSet = [AppRole.Analyst];
        return (svc, older, newer, open);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_vendor_list_is_the_names_on_cases_the_user_can_see_without_exercises(string provider)
    {
        using var database = Open(provider);
        var (svc, _, _, _) = await SeedAsync(database);

        var names = await svc.ListVendorNamesAsync();

        names.Should().Equal(["Northwind"], "one per name ignoring case and spaces, spelled as most of its cases spell it; no restricted case's vendor, no drill's");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Seen_before_counts_the_visible_cases_and_shows_how_the_last_closed_one_ended(string provider)
    {
        using var database = Open(provider);
        var (svc, _, newer, _) = await SeedAsync(database);

        var history = await svc.FindVendorHistoryAsync("  NORTHWIND ");

        history.Should().NotBeNull();
        history!.Vendor.Should().Be("Northwind", "as the list spells it");
        history.Cases.Should().Be(3, "the two closed and the open one; not the drill or the restricted case");
        history.Open.Should().Be(1);
        var last = history.LastClosed!;
        last.CaseId.Should().Be(newer, "the restricted case closed later, but it's outside need-to-know");
        last.OutcomeKey.Should().Be(CaseOutcomeCatalog.Confirmed);
        last.ClosingLine.Should().Be("Invoice fraud attempt; no payment made.");

        (await svc.FindVendorHistoryAsync("Hushco")).Should().BeNull("a hidden case's vendor looks like an unknown one");
        (await svc.FindVendorHistoryAsync("Tabletop Vendor Ltd")).Should().BeNull();
        (await svc.FindVendorHistoryAsync("   ")).Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_seen_before_link_lists_exactly_the_cases_it_counted(string provider)
    {
        using var database = Open(provider);
        var (svc, older, newer, open) = await SeedAsync(database);

        // The link's own query, read by the page's parser (C2): ?scope=all&vendor=Northwind&closed=true.
        var query = new Dictionary<string, string> { ["scope"] = "all", ["vendor"] = "Northwind", ["closed"] = "true" };
        var filter = CaseListQuery.Parse(k => query.GetValueOrDefault(k));
        var page = await svc.ListAsync(filter);

        page.Items.Select(i => i.Id).Should().BeEquivalentTo([older, newer, open]);
        page.Total.Should().Be((await svc.FindVendorHistoryAsync("Northwind"))!.Cases);
    }
}
