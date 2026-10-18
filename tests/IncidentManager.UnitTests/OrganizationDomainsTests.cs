using System.Diagnostics;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Infrastructure.Configuration;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-28 discovery: the organization's domains found on the server's network are normalized as a saved domain is (a
/// NetBIOS name refused) and kept once each; they're in force only while the setting isn't set anywhere; and the look is
/// bounded (C10): one at a time, a time limit, a hung look not repeated, never a throw.
/// </summary>
public sealed class OrganizationDomainsTests
{
    private static readonly DateTimeOffset At = new(2026, 10, 18, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Discovered_names_are_normalized_deduplicated_and_ordered_by_source()
    {
        var found = OrganizationDomains.Normalized(
        [
            new("partner.example.", DiscoveredDomainSource.Trusted),
            new("Contoso.COM", DiscoveredDomainSource.ForestRoot),
            new("CORP.contoso.com", DiscoveredDomainSource.ThisDomain),
            new("contoso.com", DiscoveredDomainSource.Forest),        // the forest root again, as one of the forest's domains
            new("emea.contoso.com", DiscoveredDomainSource.Forest),
            new("PARTNER", DiscoveredDomainSource.Trusted),           // a downlevel trust: a NetBIOS name
            new("co.uk", DiscoveredDomainSource.Trusted),             // a public suffix
            new("", DiscoveredDomainSource.Trusted),
            new("corp.contoso.com", DiscoveredDomainSource.Trusted),  // a trust back to its own domain
        ], At);

        found.State.Should().Be(DomainDiscoveryState.Found);
        found.Domains.Should().Equal(
            new DiscoveredDomain("corp.contoso.com", DiscoveredDomainSource.ThisDomain),
            new DiscoveredDomain("contoso.com", DiscoveredDomainSource.ForestRoot),
            new DiscoveredDomain("emea.contoso.com", DiscoveredDomainSource.Forest),
            new DiscoveredDomain("partner.example", DiscoveredDomainSource.Trusted));
        found.Refused.Should().Be(3);
        found.AtUtc.Should().Be(At);
        found.NamesText.Should().Be("corp.contoso.com\ncontoso.com\nemea.contoso.com\npartner.example");
        found.Described.Should().Be(
            "corp.contoso.com (this domain), contoso.com (forest root), emea.contoso.com (same forest), partner.example (trusted)");
    }

    // --- Precedence: never set → the domains found; a saved value → it; saved blank → none --------------------------------

    private static readonly DomainDiscovery Contoso = OrganizationDomains.Normalized(
        [new("corp.contoso.com", DiscoveredDomainSource.ThisDomain), new("contoso.com", DiscoveredDomainSource.ForestRoot)], At);

    private static ConfigurationRelatedExclusions Provider(Dictionary<string, string?> values, DomainDiscovery? found = null) =>
        new(new ConfigurationBuilder().AddInMemoryCollection(values).Build(), new FakeDomains(found ?? Contoso));

    [Fact]
    public void Never_set_the_domains_found_are_in_force()
    {
        var p = Provider([]);
        p.Current.Domains.Should().Equal("corp.contoso.com", "contoso.com");
        p.DiscoveredInForce.Should().NotBeNull().And.HaveCount(2);
        p.Current.DomainOf("mail.contoso.com").Should().Be("contoso.com");
    }

    [Fact]
    public void A_saved_value_wins_over_the_domains_found()
    {
        // As DbSettingsConfiguration loads an in-app list: indexed children, the rest of the mask blank.
        var p = Provider(new() { ["RelatedIndicators:ExcludedDomains:0"] = "fabrikam.com", ["RelatedIndicators:ExcludedDomains:1"] = "" });
        p.Current.Domains.Should().Equal("fabrikam.com");
        p.DiscoveredInForce.Should().BeNull();
    }

    [Fact]
    public void A_value_saved_blank_means_none_and_the_domains_found_arent_used()
    {
        var p = Provider(new() { ["RelatedIndicators:ExcludedDomains:0"] = "", ["RelatedIndicators:ExcludedDomains:1"] = "" });
        p.Current.Domains.Should().BeEmpty();
        p.DiscoveredInForce.Should().BeNull();
    }

    [Fact]
    public void A_value_in_the_servers_settings_file_wins_over_the_domains_found()
    {
        var p = Provider(new() { ["RelatedIndicators:ExcludedDomains"] = "fabrikam.com, tailspin.example" });
        p.Current.Domains.Should().Equal("fabrikam.com", "tailspin.example");
        p.DiscoveredInForce.Should().BeNull();
    }

    [Fact]
    public void Nothing_found_means_no_domains_and_nothing_in_force()
    {
        var p = Provider([], new DomainDiscovery(DomainDiscoveryState.NotDomainJoined, [], At));
        p.Current.Domains.Should().BeEmpty();
        p.DiscoveredInForce.Should().BeNull();
        new ConfigurationRelatedExclusions(new ConfigurationBuilder().Build()).Current.Domains.Should().BeEmpty("no discovery wired");
    }

    // --- The look: bounded, single-flight, fail safe ----------------------------------------------------------------------

    [Fact]
    public async Task Not_domain_joined_finds_nothing_and_says_so()
    {
        var domains = new OrganizationDomains(new FakeSource(() => null));
        domains.Current.State.Should().Be(DomainDiscoveryState.NotYet);
        var found = await domains.DiscoverAsync();
        found.State.Should().Be(DomainDiscoveryState.NotDomainJoined);
        found.Domains.Should().BeEmpty();
        domains.Current.Should().Be(found);
    }

    [Fact]
    public async Task A_directory_failure_finds_nothing_names_the_error_type_and_never_throws()
    {
        var domains = new OrganizationDomains(new FakeSource(() => throw new InvalidOperationException("dc1.corp.contoso.com is down")));
        var found = await domains.DiscoverAsync();
        found.State.Should().Be(DomainDiscoveryState.Failed);
        found.ErrorType.Should().Be(nameof(InvalidOperationException));
        found.Domains.Should().BeEmpty();
        found.Summary(domains.TimeLimit).Should().NotContain("dc1", "only the error's type is shown");
    }

    [Fact]
    public async Task A_hung_directory_times_out_isnt_asked_again_until_it_returns_and_its_late_answer_is_kept()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var asked = 0;
        var domains = new OrganizationDomains(new FakeSource(() =>
        {
            Interlocked.Increment(ref asked);
            entered.Set();
            release.Wait(TimeSpan.FromSeconds(30));
            return [new("corp.contoso.com", DiscoveredDomainSource.ThisDomain)];
        }), timeLimit: TimeSpan.FromMilliseconds(150));
        try
        {
            var clock = Stopwatch.StartNew();
            var first = await domains.DiscoverAsync();
            first.State.Should().Be(DomainDiscoveryState.TimedOut);
            clock.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(5));
            entered.Wait(TimeSpan.FromSeconds(10)).Should().BeTrue();   // C17: the read's thread may start late

            clock.Restart();
            (await domains.DiscoverAsync()).State.Should().Be(DomainDiscoveryState.TimedOut, "the hung look's result stands");
            clock.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(1), "nothing new is started, so nothing is waited on");
            asked.Should().Be(1);
        }
        finally { release.Set(); }

        Eventually(() => domains.Current.State == DomainDiscoveryState.Found).Should().BeTrue("the late, whole answer is kept");
        domains.Current.Domains.Select(d => d.Name).Should().Equal("corp.contoso.com");
        (await domains.DiscoverAsync()).State.Should().Be(DomainDiscoveryState.Found);
        asked.Should().Be(2, "once it returned, an administrator's Look again asks again");
    }

    [Fact]
    public async Task Callers_at_once_share_one_look()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var asked = 0;
        var domains = new OrganizationDomains(new FakeSource(() =>
        {
            Interlocked.Increment(ref asked);
            entered.Set();
            release.Wait(TimeSpan.FromSeconds(30));
            return [new("corp.contoso.com", DiscoveredDomainSource.ThisDomain)];
        }), timeLimit: TimeSpan.FromSeconds(20));

        var callers = Enumerable.Range(0, 6).Select(_ => domains.DiscoverAsync()).ToList();
        entered.Wait(TimeSpan.FromSeconds(10)).Should().BeTrue();
        release.Set();

        (await Task.WhenAll(callers)).Should().AllSatisfy(r => r.State.Should().Be(DomainDiscoveryState.Found));
        asked.Should().Be(1);
    }

    [Fact]
    public async Task Start_up_doesnt_wait_on_the_directory()
    {
        using var release = new ManualResetEventSlim();
        var domains = new OrganizationDomains(new FakeSource(() =>
        {
            release.Wait(TimeSpan.FromSeconds(30));
            return null;
        }));
        try
        {
            var start = domains.StartAsync(CancellationToken.None);
            start.IsCompleted.Should().BeTrue();
            await start;
            domains.Current.State.Should().Be(DomainDiscoveryState.NotYet);
        }
        finally { release.Set(); }
        Eventually(() => domains.Current.State == DomainDiscoveryState.NotDomainJoined).Should().BeTrue("it ran in the background");
    }

    private static bool Eventually(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (condition()) return true;
            Thread.Sleep(20);
        }
        return condition();
    }

    private sealed class FakeSource(Func<IReadOnlyList<DiscoveredDomain>?> read) : IDomainDiscoverySource
    {
        public IReadOnlyList<DiscoveredDomain>? Read() => read();
    }

    private sealed class FakeDomains(DomainDiscovery current) : IOrganizationDomains
    {
        public DomainDiscovery Current => current;
        public TimeSpan TimeLimit => OrganizationDomains.DefaultTimeLimit;
        public Task<DomainDiscovery> DiscoverAsync(CancellationToken ct = default) => Task.FromResult(current);
    }
}
