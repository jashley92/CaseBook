using System.Diagnostics;
using FluentAssertions;
using IncidentManager.Web.Security;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-565: the display-name and group-name lookups made on every request are bounded like the token-owner check and the
/// account lookup (BUG-469/471): one per name at a time, a short wait, the bare fallback when it runs out (not kept, so
/// it's asked again), and a domain whose lookups are still blocked isn't given more threads.
/// </summary>
public sealed class BoundedDirectoryCallTests
{
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(150);

    [Fact]
    public void A_hung_lookup_gives_the_bare_username_within_the_time_limit_and_its_late_answer_is_kept()
    {
        using var release = new ManualResetEventSlim();
        var asked = 0;
        var names = new WindowsNames(query: _ =>
        {
            Interlocked.Increment(ref asked);
            release.Wait(TimeSpan.FromSeconds(30));
            return "Jordan Rivera";
        }, timeout: Short);
        try
        {
            var clock = Stopwatch.StartNew();
            names.Resolve("CORP\\jdoe").Should().Be("jdoe");
            clock.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(5));

            clock.Restart();
            names.Resolve("CORP\\jdoe").Should().Be("jdoe", "the lookup hasn't landed");
            clock.Elapsed.Should().BeLessThan(Short, "a name whose lookup is still blocked isn't waited on again");
            asked.Should().Be(1, "nor is a second lookup started");
        }
        finally { release.Set(); }

        Eventually(() => names.Resolve("CORP\\jdoe") == "Jordan Rivera").Should().BeTrue("the late answer is kept");
        names.Resolve("CORP\\jdoe").Should().Be("Jordan Rivera");
        asked.Should().Be(1, "a name found isn't looked up again");
    }

    [Fact]
    public async Task Concurrent_callers_share_one_lookup()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var asked = 0;
        var names = new WindowsNames(query: _ =>
        {
            Interlocked.Increment(ref asked);
            entered.Set();
            release.Wait(TimeSpan.FromSeconds(30));
            return "Jordan Rivera";
        }, timeout: TimeSpan.FromSeconds(20));

        var callers = Enumerable.Range(0, 8)
            .Select(i => i % 2 == 0 ? Task.Run(() => names.Resolve("CORP\\jdoe")) : names.ResolveAsync("corp\\JDOE"))
            .ToList();
        entered.Wait(TimeSpan.FromSeconds(10)).Should().BeTrue();
        await Task.Delay(100);   // let the rest join (any that come after it lands read the kept name)
        release.Set();

        (await Task.WhenAll(callers)).Should().AllBe("Jordan Rivera");
        asked.Should().Be(1);
    }

    [Fact]
    public void Past_the_hung_limit_a_domain_isnt_asked_and_other_domains_are()
    {
        using var release = new ManualResetEventSlim();
        var corp = 0;
        var names = new WindowsNames(query: n =>
        {
            if (!n.StartsWith("CORP\\", StringComparison.Ordinal)) return "Partner Person";
            Interlocked.Increment(ref corp);
            release.Wait(TimeSpan.FromSeconds(30));   // CORP's DC hangs
            return "Corp Person";
        }, timeout: Short);
        try
        {
            for (var i = 0; i < WindowsNames.MaxHung + 3; i++)
                names.Resolve($"CORP\\u{i}").Should().Be($"u{i}");
            corp.Should().Be(WindowsNames.MaxHung, "a domain whose lookups are still blocked isn't given more threads");

            var clock = Stopwatch.StartNew();
            names.Resolve("CORP\\other").Should().Be("other");
            clock.Elapsed.Should().BeLessThan(Short, "nothing is started, so nothing is waited on");
            names.Resolve("PARTNER\\p").Should().Be("Partner Person");
        }
        finally { release.Set(); }

        // The blocked lookups return; the name that got no lookup wasn't kept as unresolved, so it's asked now.
        Eventually(() => names.Resolve("CORP\\u4") == "Corp Person").Should().BeTrue();
    }

    [Fact]
    public void A_name_the_directory_cant_give_is_the_bare_username_and_asked_again_later()
    {
        var time = new ManualTime();
        var asked = 0;
        var names = new WindowsNames(query: _ =>
        {
            if (Interlocked.Increment(ref asked) == 1) throw new InvalidOperationException("no DC");
            return "Jordan Rivera";
        }, time: time);

        names.Resolve("CORP\\jdoe").Should().Be("jdoe");
        names.Resolve("CORP\\jdoe").Should().Be("jdoe", "a failure isn't retried on every request");
        asked.Should().Be(1);
        time.Now += WindowsNames.RetryUnresolved + TimeSpan.FromSeconds(1);
        names.Resolve("CORP\\jdoe").Should().Be("Jordan Rivera");
    }

    [Fact]
    public void Names_that_arent_domain_accounts_are_given_back_without_a_lookup()
    {
        var asked = 0;
        var names = new WindowsNames(query: _ => { asked++; return "X"; });
        names.Resolve(null).Should().BeNull();
        names.Resolve("").Should().Be("");
        names.Resolve("Dev Analyst").Should().Be("Dev Analyst");
        names.Resolve("jdoe@corp.example").Should().Be("jdoe@corp.example");
        names.Resolve("CORP\\").Should().Be("");
        asked.Should().Be(0);
    }

    [Fact]
    public void A_signins_unnamed_groups_are_translated_together_and_a_hung_translation_isnt_waited_on_again()
    {
        using var release = new ManualResetEventSlim();
        var batches = new List<string[]>();
        var sids = new SidNames(translate: asked =>
        {
            lock (batches) batches.Add([.. asked]);
            release.Wait(TimeSpan.FromSeconds(30));
            return asked.ToDictionary(s => s, s => "CORP\\G" + s[^1]);
        }, timeout: Short);
        try
        {
            var clock = Stopwatch.StartNew();
            sids.Resolve(["S-1-5-21-1-1", "S-1-5-21-1-2", "SOC-AppAdmins"]).Should().BeEmpty("nothing was named in time");
            clock.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(5));
            lock (batches) batches.Should().ContainSingle().Which.Should().Equal("S-1-5-21-1-1", "S-1-5-21-1-2");

            clock.Restart();
            sids.Resolve(["S-1-5-21-1-1"]).Should().BeEmpty();
            clock.Elapsed.Should().BeLessThan(Short, "a SID whose translation is still blocked isn't waited on again");

            for (var i = 0; i < SidNames.MaxHung + 2; i++) sids.Resolve([$"S-1-5-21-2-{i}"]);
            lock (batches) batches.Should().HaveCount(SidNames.MaxHung, "past the hung limit no translation starts");
        }
        finally { release.Set(); }

        Eventually(() => sids.Resolve(["S-1-5-21-1-1", "S-1-5-21-1-2"]).Count == 2).Should().BeTrue("the late names are kept");
        sids.Resolve(["S-1-5-21-1-2"]).Should().Equal(new Dictionary<string, string> { ["S-1-5-21-1-2"] = "CORP\\G2" });
    }

    [Fact]
    public async Task Concurrent_sign_ins_share_one_translation_of_a_group()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var asked = 0;
        var sids = new SidNames(translate: list =>
        {
            Interlocked.Add(ref asked, list.Count);
            entered.Set();
            release.Wait(TimeSpan.FromSeconds(30));
            return list.ToDictionary(s => s, _ => "CORP\\Analysts");
        }, timeout: TimeSpan.FromSeconds(20));

        var first = Task.Run(() => sids.Resolve(["S-1-5-21-9-1"]));
        entered.Wait(TimeSpan.FromSeconds(10)).Should().BeTrue();
        var rest = Enumerable.Range(0, 6).Select(_ => Task.Run(() => sids.Resolve(["S-1-5-21-9-1"]))).ToList();
        await Task.Delay(100);
        release.Set();

        foreach (var r in (await Task.WhenAll(rest.Prepend(first))))
            r.Should().ContainKey("S-1-5-21-9-1");
        asked.Should().Be(1);
    }

    [Fact]
    public void Every_blocking_directory_call_is_one_of_the_bounded_ones()
    {
        // BUG-565 closes the class: each file that calls the directory runs those calls on their own thread with a time
        // limit, a per-domain hung limit and one call per key. A new file calling AD must do the same and be added here.
        string[] bounded =
        [
            "AdAccountDirectory.cs",    // BUG-420/471
            "AdTokenOwnerCheck.cs",     // BUG-469
            "WindowsNames.cs",          // BUG-565
            "SidNames.cs",              // BUG-565
            "RoleClaimsTransformer.cs", // BUG-565 (the server's own domain)
        ];
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) dir = dir.Parent;
        dir.Should().NotBeNull();
        var calls = new System.Text.RegularExpressions.Regex(
            @"FindByIdentity\(|\.Translate\(|new\s+(PrincipalContext|DirectoryEntry|DirectorySearcher)\(|GetAuthorizationGroups\(",
            System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(5));

        var callers = Directory.EnumerateFiles(Path.Combine(dir!.FullName, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(f => calls.IsMatch(File.ReadAllText(f)))
            .Select(Path.GetFileName)
            .ToList();
        callers.Should().NotBeEmpty();
        callers.Should().BeSubsetOf(bounded);
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

    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
