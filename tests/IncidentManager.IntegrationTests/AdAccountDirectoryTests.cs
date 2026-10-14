using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Web.Security;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-419/420: which account values the AD directory asks about at all, and how it backs off a domain that failed. The
/// query and the list of trusted domains are stood in for, so no directory is needed.
/// </summary>
public sealed class AdAccountDirectoryTests
{
    private readonly List<string> _asked = [];
    private readonly ManualTime _time = new();
    private int _listings;

    private AdAccountDirectory Directory(Func<string, DirectoryLookup>? answer = null, Func<IEnumerable<string>>? trusted = null) =>
        new(query: n => { lock (_asked) _asked.Add(n); return (answer ?? (_ => DirectoryLookup.NotFound))(n); },
            trustedDomains: trusted ?? (() => { _listings++; return ["CORP", "corp.example.com", "PARTNER", "partner.example."]; }),
            time: _time);

    [Theory]
    [InlineData("attacker.example\\svc")]
    [InlineData("EVIL\\administrator")]
    [InlineData(".\\administrator")]
    [InlineData("\\administrator")]
    public async Task An_account_in_a_domain_the_server_doesnt_trust_or_a_local_one_isnt_looked_up(string value)
    {
        var result = await Directory().LookupAsync(value);

        result.Outcome.Should().Be(DirectoryLookupOutcome.NotLookedUp, "not found would claim the directory was asked");
        result.Problem.Should().NotBeNullOrEmpty();
        _asked.Should().BeEmpty("nothing is sent to the named domain");
    }

    [Fact]
    public async Task This_computers_own_accounts_arent_looked_up()
    {
        (await Directory().LookupAsync(Environment.MachineName + "\\admin")).Outcome.Should().Be(DirectoryLookupOutcome.NotLookedUp);
        _asked.Should().BeEmpty();
    }

    [Theory]
    [InlineData("CORP\\jdoe")]
    [InlineData("corp\\jdoe")]
    [InlineData("corp.example.com\\jdoe")]
    [InlineData("partner.example\\jdoe")]
    [InlineData("jdoe")]
    [InlineData("jdoe@attacker.example")]   // a UPN is searched for in the server's own domain
    public async Task The_servers_own_and_trusted_domains_are_looked_up(string value)
    {
        (await Directory().LookupAsync(value)).Outcome.Should().Be(DirectoryLookupOutcome.NotFound);
        _asked.Should().Equal(value);
    }

    [Fact]
    public async Task The_trusted_domains_are_listed_once_and_a_failed_listing_looks_nothing_up()
    {
        var directory = Directory();
        await directory.LookupAsync("CORP\\a");
        await directory.LookupAsync("PARTNER\\b");
        await directory.LookupAsync("EVIL\\c");
        _listings.Should().Be(1);

        var broken = Directory(trusted: () => throw new InvalidOperationException("no DC"));
        var result = await broken.LookupAsync("CORP\\jdoe");
        result.Outcome.Should().Be(DirectoryLookupOutcome.Unavailable, "unknown, not 'not looked up' and never 'not found'");
        _asked.Should().Equal("CORP\\a", "PARTNER\\b");
    }

    [Fact]
    public async Task A_domain_that_failed_isnt_asked_again_for_a_minute_and_others_still_are()
    {
        var down = true;
        var directory = Directory(n => n.StartsWith("CORP", StringComparison.Ordinal) && down
            ? throw new InvalidOperationException("server down") : DirectoryLookup.NotFound);

        (await directory.LookupAsync("CORP\\a")).Outcome.Should().Be(DirectoryLookupOutcome.Unavailable);
        (await directory.LookupAsync("CORP\\b")).Outcome.Should().Be(DirectoryLookupOutcome.Unavailable);
        (await directory.LookupAsync("PARTNER\\c")).Outcome.Should().Be(DirectoryLookupOutcome.NotFound);
        _asked.Should().Equal("CORP\\a", "PARTNER\\c");

        down = false;
        _time.Now += AdAccountDirectory.BackOff + TimeSpan.FromSeconds(1);
        (await directory.LookupAsync("CORP\\b")).Outcome.Should().Be(DirectoryLookupOutcome.NotFound);
        _asked.Should().Equal("CORP\\a", "PARTNER\\c", "CORP\\b");
    }

    [Fact]
    public async Task Lookups_still_blocked_after_their_callers_gave_up_are_capped()
    {
        using var release = new ManualResetEventSlim();
        var directory = Directory(_ => { release.Wait(TimeSpan.FromSeconds(30)); return DirectoryLookup.NotFound; });
        for (var i = 0; i < AdAccountDirectory.MaxInFlight; i++)
        {
            using var gaveUp = new CancellationTokenSource();
            var waiting = directory.LookupAsync($"jdoe{i}", gaveUp.Token);
            await gaveUp.CancelAsync();
            await waiting.Invoking(t => t).Should().ThrowAsync<OperationCanceledException>();
        }

        var busy = await directory.LookupAsync("jdoe");
        busy.Outcome.Should().Be(DirectoryLookupOutcome.Unavailable);
        _asked.Should().NotContain("jdoe");

        release.Set();
        var deadline = DateTime.UtcNow.AddSeconds(10);
        DirectoryLookup again;
        do { again = await directory.LookupAsync("jdoe"); await Task.Delay(20); }
        while (again.Outcome != DirectoryLookupOutcome.NotFound && DateTime.UtcNow < deadline);
        again.Outcome.Should().Be(DirectoryLookupOutcome.NotFound, "the blocked lookups finished and freed their places");
    }

    [Fact]
    public async Task A_listing_that_hangs_is_given_up_on_and_tried_again_after_the_back_off(/* BUG-457 */)
    {
        using var release = new ManualResetEventSlim();
        var time = new ManualTime { FastTimers = true };   // the 10 s timeout passes in a moment
        var listings = 0;
        var directory = new AdAccountDirectory(query: _ => DirectoryLookup.NotFound, time: time, trustedDomains: () =>
        {
            if (Interlocked.Increment(ref listings) == 1) release.Wait(TimeSpan.FromSeconds(30));   // the DC hangs
            return ["CORP"];
        });

        (await directory.LookupAsync("CORP\\a")).Outcome.Should().Be(DirectoryLookupOutcome.Unavailable);
        (await directory.LookupAsync("CORP\\b")).Outcome.Should().Be(DirectoryLookupOutcome.Unavailable, "backing off");
        listings.Should().Be(1);

        time.Now += AdAccountDirectory.BackOff + TimeSpan.FromSeconds(1);
        (await directory.LookupAsync("CORP\\c")).Outcome.Should().Be(DirectoryLookupOutcome.NotFound, "a new listing was made");
        listings.Should().Be(2);
        release.Set();
    }

    [Fact]
    public async Task A_listing_that_ran_into_the_search_time_limit_isnt_kept(/* BUG-470 */)
    {
        var directory = Directory(trusted: () =>
        {
            // The search stops at its limit with what it had so far, and no error.
            if (++_listings == 1) _time.Now += AdAccountDirectory.Timeout;
            return ["CORP"];
        });

        (await directory.LookupAsync("CORP\\a")).Outcome.Should().Be(DirectoryLookupOutcome.Unavailable,
            "a list that may be missing domains would answer 'not looked up' for them for an hour");
        (await directory.LookupAsync("CORP\\b")).Outcome.Should().Be(DirectoryLookupOutcome.Unavailable, "backing off");
        _asked.Should().BeEmpty();

        _time.Now += AdAccountDirectory.BackOff + TimeSpan.FromSeconds(1);
        (await directory.LookupAsync("CORP\\c")).Outcome.Should().Be(DirectoryLookupOutcome.NotFound);
        _listings.Should().Be(2);
    }

    [Fact]
    public async Task A_hung_domain_controller_isnt_probed_without_end_and_other_domains_are_still_asked(/* BUG-471 */)
    {
        using var release = new ManualResetEventSlim();
        var time = new ManualTime { FastTimers = true };
        var corp = 0;
        var directory = new AdAccountDirectory(time: time, trustedDomains: () => ["CORP", "PARTNER"], query: n =>
        {
            if (!n.StartsWith("CORP", StringComparison.Ordinal)) return DirectoryLookup.NotFound;
            Interlocked.Increment(ref corp);
            release.Wait(TimeSpan.FromSeconds(30));   // CORP's DC hangs
            return DirectoryLookup.NotFound;
        });

        // One probe a minute, past the old shared limit.
        for (var i = 0; i <= AdAccountDirectory.MaxInFlight; i++)
        {
            (await directory.LookupAsync($"CORP\\u{i}")).Outcome.Should().Be(DirectoryLookupOutcome.Unavailable);
            time.Now += AdAccountDirectory.BackOff + TimeSpan.FromSeconds(1);
        }
        corp.Should().Be(AdAccountDirectory.MaxHungPerDomain, "a domain whose lookups are still blocked isn't given more threads");
        (await directory.LookupAsync("PARTNER\\jdoe")).Outcome.Should().Be(DirectoryLookupOutcome.NotFound);
        (await directory.LookupAsync("jdoe")).Outcome.Should().Be(DirectoryLookupOutcome.NotFound, "nor is the server's own");

        // The blocked lookups return and free their places; CORP is asked again.
        release.Set();
        var deadline = DateTime.UtcNow.AddSeconds(10);
        DirectoryLookup again;
        do { again = await directory.LookupAsync("CORP\\later"); await Task.Delay(20); }
        while (again.Outcome != DirectoryLookupOutcome.NotFound && DateTime.UtcNow < deadline);
        again.Outcome.Should().Be(DirectoryLookupOutcome.NotFound);
    }

    [Fact]
    public async Task Listings_still_blocked_arent_started_again_and_again(/* BUG-471 sibling */)
    {
        using var release = new ManualResetEventSlim();
        var time = new ManualTime { FastTimers = true };
        var listings = 0;
        var directory = new AdAccountDirectory(query: _ => DirectoryLookup.NotFound, time: time, trustedDomains: () =>
        {
            Interlocked.Increment(ref listings);
            release.Wait(TimeSpan.FromSeconds(30));
            return ["CORP"];
        });

        for (var i = 0; i < 5; i++)
        {
            (await directory.LookupAsync($"CORP\\u{i}")).Outcome.Should().Be(DirectoryLookupOutcome.Unavailable);
            time.Now += AdAccountDirectory.BackOff + TimeSpan.FromSeconds(1);
        }
        listings.Should().Be(AdAccountDirectory.MaxHungPerDomain);
        release.Set();
    }

    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);
        public bool FastTimers { get; init; }
        public override DateTimeOffset GetUtcNow() => Now;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            base.CreateTimer(callback, state, FastTimers && dueTime > TimeSpan.Zero ? TimeSpan.FromMilliseconds(50) : dueTime, period);
    }
}
