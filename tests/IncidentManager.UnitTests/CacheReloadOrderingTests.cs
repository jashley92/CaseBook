using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C21 (BUG-623, BUG-628, BUG-225's class): an in-memory copy of stored state (the settings, the role directory, the
/// user mirror, an API token owner's last answer) is reloaded so that an older read can't land after a newer one. Two
/// reloads at once (two saves, a save and a retry timer, two token checks) each read, then store; without an order, the
/// one that read first can store last and put back what a later change removed. This reads the long-lived classes
/// (singletons and configuration providers) and finds each method that reads stored state and then stores into a field.
/// Each one stores under an order (a <c>LatestWins</c> publish, the settings load gate, a load generation) or is on the
/// reviewed list below with why it's safe.
/// </summary>
public partial class CacheReloadOrderingTests
{
    // Reload sites that store without an order, by class and method, with why that's safe. Each must still be found.
    private static readonly Dictionary<string, string> Reviewed = new(StringComparer.Ordinal)
    {
        ["EmailSender.DrainHeldAsync"] = "stores drain bookkeeping (next due, failure count, the held-since-empty flag) under _gate; the queue itself is the HeldEmails table, read fresh on each pass, so no older read of it is ever published",
        ["UserDirectory.TouchAsync"] = "stores the entry it has just saved (the caller's values) under _swap, and records it in _touched with a number on " +
            "Invalidate's order taken after the save; an Invalidate whose read began earlier puts that entry back over its older read (BUG-656)",
        // A hosted service's one loop stores when its last cycle ran: a clock time, not stored state, and one cycle at a time.
        ["DigestHostedService.RunCycleAsync"] = "stores the cycle's clock time (_lastRunUtc), one loop",
        ["DueSoonActionItemHostedService.RunCycleAsync"] = "stores the cycle's clock time (_lastRunUtc), one loop",
        ["EvidenceIntegrityHostedService.VerifyAsync"] = "stores the interval it ran in (_lastSlot), one loop; a Run now (CAP-29) never stores it",
        ["AccessLogRetentionHostedService.RunAsync"] = "PROD-52: stores the day and setting it ran with (_lastRunDay, _lastYears), one loop",
        ["AccessLogRetentionHostedService.RunPurgeAsync"] = "the removed cases' purge: stores the day it ran (_lastPurgeDay), the same one loop",
        ["AccessLogRetentionHostedService.RunImportsAsync"] = "CAP-31: stores the day and setting it ran with (_lastImportRunDay, _lastImportDays), the same one loop",
        ["RetentionReviewHostedService.RunAsync"] = "CAP-10: stores the clock time and settings it ran with (_lastRunUtc, _lastYears, _lastEmail), one loop",
        ["NotificationDeadlineHostedService.RunCycleAsync"] = "stores the cycle's clock time (_lastRunUtc), one loop",
        ["OverdueActionItemHostedService.RunCycleAsync"] = "stores the cycle's clock time (_lastRunUtc), one loop",
        ["StaleCaseHostedService.RunCycleAsync"] = "stores the cycle's clock time (_lastRunUtc), one loop",
    };

    // The classes and methods the scan must find, so a change that stops it seeing them fails here rather than passing.
    private static readonly string[] KnownHolders =
    [
        "DbSettingsConfigurationProvider.LoadCore",
        "RoleDirectory.TryLoad",
        "UserDirectory.Invalidate",
        "AdTokenOwnerCheck.CheckCoreAsync",
    ];

    [Fact]
    public void Every_reload_of_stored_state_into_memory_is_ordered_or_reviewed()
    {
        var sites = Sites();
        sites.Select(s => s.Key).Should().Contain(KnownHolders, "the scan must find the known in-memory copies of stored state");

        var offenders = sites.Where(s => !s.Ordered && !Reviewed.ContainsKey(s.Key)).Select(s => $"{s.File}: {s.Key}").ToList();
        offenders.Should().BeEmpty("a read that can finish after a newer one stores only if it's the newest (LatestWins, " +
            "the settings load gate, or a load generation), or is reviewed above with why it's safe");

        var stale = Reviewed.Keys.Where(k => !sites.Any(s => s.Key == k && !s.Ordered)).ToList();
        stale.Should().BeEmpty("a reviewed site that's gone or now ordered comes off the list");
    }

    [Fact]
    public void A_settings_save_takes_the_reload_error_from_its_own_reload(/* BUG-623 */)
    {
        // The error of the last reload was a shared static: with two reloads at once, a save could read the other's (and
        // say "saved" when its own reload failed, or the reverse). ReloadAndReport returns this call's.
        var root = ComponentSourceScanner.RepoRoot();
        var offenders = new List<string>();
        foreach (var file in Directory.EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (rel.EndsWith("/ISettingsReloader.cs", StringComparison.Ordinal) || rel.EndsWith("/ConfigurationReloader.cs", StringComparison.Ordinal)) continue;
            var code = ComponentSourceScanner.Strip(File.ReadAllText(file));
            foreach (Match m in SharedReloadError().Matches(code))
                offenders.Add($"{rel}:{code.AsSpan(0, m.Index).Count('\n') + 1} {m.Value}");
        }
        offenders.Should().BeEmpty("a save reports the error ReloadAndReport() returned for its own reload");
        File.ReadAllText(Path.Combine(root, "src", "IncidentManager.Infrastructure", "Configuration", "DbSettingsConfiguration.cs"))
            .Should().NotContain("static string? LastLoadError", "the load error is the provider's own, read under the load gate");
    }

    private sealed record Site(string File, string Key, bool Ordered);

    private static List<Site> Sites()
    {
        var root = ComponentSourceScanner.RepoRoot();
        var src = Path.Combine(root, "src");
        var files = Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}Migrations", StringComparison.Ordinal)
                && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !f.Contains($"{Path.DirectorySeparatorChar}Components{Path.DirectorySeparatorChar}", StringComparison.Ordinal))   // per circuit: LoadSequence's tests
            .Select(f => (File: Path.GetRelativePath(root, f).Replace('\\', '/'), Code: ComponentSourceScanner.Strip(File.ReadAllText(f))))
            .ToList();

        // Long-lived: registered as a singleton (one instance for every request), or a configuration provider.
        var longLived = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (_, code) in files)
        {
            foreach (Match m in SingletonGeneric().Matches(code))
                longLived.Add(m.Groups["args"].Value.Split(',')[^1].Trim().Split('.')[^1]);
            foreach (Match m in SingletonFactory().Matches(code))
                longLived.Add(m.Groups["impl"].Value.Split('.')[^1]);
        }

        var sites = new List<Site>();
        foreach (var (file, code) in files)
        {
            foreach (Match cls in ClassDeclaration().Matches(code))
            {
                var name = cls.Groups["name"].Value;
                var isProvider = cls.Groups["base"].Value.Contains("ConfigurationProvider", StringComparison.Ordinal);
                if (!isProvider && !longLived.Contains(name)) continue;
                var body = ClassBody(code, cls.Index + cls.Length);
                var methods = ComponentSourceScanner.Methods(body)
                    .Where(m => m.Name != name && !m.Name.EndsWith("<lambda>", StringComparison.Ordinal)).ToList();
                var classSites = new List<(Site Site, string Body)>();
                foreach (var method in methods)
                {
                    var read = StoredRead().Match(method.Body);
                    if (!read.Success) continue;
                    var after = method.Body[read.Index..];
                    if (!FieldStore().IsMatch(after)) continue;
                    var key = $"{name}.{method.Name}";
                    if (sites.Any(s => s.Key == key)) continue;
                    // Ordered: the method stores under an order, or every call to it is made holding a lock.
                    var site = new Site(file, key, OnlyCalledUnderLock(body, method.Name) || Order().IsMatch(method.Body));
                    sites.Add(site);
                    classSites.Add((site, method.Body));
                }

                // BUG-656: an ordered reload is only as ordered as every other writer of the fields it stores. Another method
                // of the class that stores one of them without an order (a sign-in's single entry) is an offender itself
                // unless reviewed; when reviewed, the ordered reload must take back what it recorded (name one of its other
                // fields), or an older read still overwrites it.
                foreach (var (site, siteBody) in classSites.Where(s => s.Site.Ordered && Order().IsMatch(s.Body)))
                {
                    var stored = Stores(siteBody);
                    foreach (var other in methods.Where(m => $"{name}.{m.Name}" != site.Key))
                    {
                        var otherKey = $"{name}.{other.Name}";
                        var otherStores = Stores(other.Body);
                        var shared = otherStores.Intersect(stored).ToList();
                        if (shared.Count == 0 || Order().IsMatch(other.Body) || OnlyCalledUnderLock(body, other.Name)) continue;
                        if (!Reviewed.ContainsKey(otherKey))
                            sites.Add(new Site(file, $"{otherKey} (stores {string.Join(", ", shared)} beside {site.Key}'s order)", false));
                        else if (!otherStores.Except(stored).Any(f => Regex.IsMatch(siteBody, $@"(?<![\w.]){Regex.Escape(f)}\b", RegexOptions.None, TimeSpan.FromSeconds(1))))
                            sites.Add(new Site(file, $"{site.Key} (doesn't take back what {otherKey} stores in {string.Join(", ", shared)})", false));
                    }
                }
            }
        }
        return sites;
    }

    // The fields a method stores into.
    private static HashSet<string> Stores(string methodBody) =>
        FieldStore().Matches(methodBody).Select(m => m.Groups["field"].Value).ToHashSet(StringComparer.Ordinal);

    // Every call to the method (in its class) is made holding a lock: lock (x) Name(...). Its declaration doesn't count.
    private static bool OnlyCalledUnderLock(string classBody, string name)
    {
        var calls = Regex.Matches(classBody, $@"(?<![\w.]){Regex.Escape(name)}\s*\(", RegexOptions.None, TimeSpan.FromSeconds(1))
            .Where(m => !Declared().IsMatch(classBody[..m.Index]))
            .ToList();
        return calls.Count > 0 && calls.All(m => HeldLock().IsMatch(classBody[..m.Index]));
    }

    [GeneratedRegex(@"\b(?:void|Task|bool|string|int)(?:<[^;{}]*>)?\??\s+$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Declared();

    [GeneratedRegex(@"\block\s*\(\s*\w+\s*\)\s*$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex HeldLock();

    // The class's body, from its opening brace (or the whole rest of the file when it can't tell).
    private static string ClassBody(string code, int from)
    {
        var i = code.IndexOf('{', from);
        if (i < 0) return code[from..];
        var start = i;
        var depth = 0;
        do { if (code[i] == '{') depth++; else if (code[i] == '}') depth--; i++; } while (i < code.Length && depth > 0);
        return code[start..i];
    }

    [GeneratedRegex(@"\bAdd(?:Singleton|HostedService)<(?<args>[\w.,\s]+)>\s*\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex SingletonGeneric();

    [GeneratedRegex(@"\bAddSingleton\(\s*\w+\s*=>\s*new\s+(?<impl>[\w.]+)\s*\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex SingletonFactory();

    [GeneratedRegex(@"\bclass\s+(?<name>\w+)(?:<[^>{]*>)?(?:\s*\([^){]*\))?(?<base>\s*:[^{]*)?", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex ClassDeclaration();

    // A read of stored state: a database context, a query's results, or a directory lookup.
    [GeneratedRegex(@"\bCreateScope\(\)|\bCreateDbContext\(\)|\bBuildContext\(\)|\.AsNoTracking\(\)|\b_lookup\(|\.Lookup\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex StoredRead();

    // A store into the class's own state: a field (or an entry of one), or a configuration provider's Data.
    [GeneratedRegex(@"(?<![\w.])(?:this\.)?(?<field>_\w+|Data|RejectedKeys|LastLoadError)\s*(?:\[[^\]\n]*\])?\s*=(?![=>])", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex FieldStore();

    // An order: a LatestWins publish, the settings load gate, or RoleDirectory's load generation (BUG-225).
    [GeneratedRegex(@"\.TryPublish\(|\block\s*\(\s*LoadGate\s*\)|\bgeneration\s*>\s*_applied\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Order();

    // Reading the last reload's error after the reload (a shared value), rather than the one ReloadAndReport returns.
    [GeneratedRegex(@"\b_?reloader\??\.(?:LastError|ThrowIfNotInEffect)\b|\bDbSettingsConfigurationProvider\.LastLoadError\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex SharedReloadError();
}
