using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// C17: a test that starts two or more writers while it holds a gate can't know which gets the gate next (v1.6.9's
/// release failed on one that assumed it). Such a test also runs its writers in every order through
/// <see cref="RaceOrders.ForEveryOrderAsync"/>, or says here why the order can't matter.
/// </summary>
public sealed class RaceOrderScanTests
{
    /// <summary>Tests that start several writers under a gate without <see cref="RaceOrders"/>, and why that's safe.</summary>
    private static readonly Dictionary<string, string> OrderFree = new(StringComparer.Ordinal)
    {
        ["ImportWriterGateTests.Every_import_written_admin_write_waits_for_the_import"] =
            "each probe writes its own database, and the test only checks that each waited",
    };

    private static readonly Regex Test = new(@"^    \[(Fact|Theory|SqlServerFact)\b", RegexOptions.None, TimeSpan.FromSeconds(5));
    private static readonly Regex Name = new(@"^    public\s+(async\s+)?\w+(<[^>]+>)?\s+(?<name>\w+)\(", RegexOptions.None, TimeSpan.FromSeconds(5));
    private static readonly Regex GateHeld = new(@"using\s*\(\s*(var\s+\w+\s*=\s*)?await\s+[\w.]*(GuardGate\.EnterAsync|EnterFileGateAsync)\(",
        RegexOptions.None, TimeSpan.FromSeconds(5));
    private static readonly Regex Start = new(@"\bTask\.Run\(", RegexOptions.None, TimeSpan.FromSeconds(5));

    [Fact]
    public void Every_test_racing_writers_under_a_gate_runs_them_in_every_order()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) dir = dir.Parent;
        dir.Should().NotBeNull();
        var found = new List<string>();
        var problems = new List<string>();
        foreach (var path in Directory.EnumerateFiles(Path.Combine(dir!.FullName, "tests"), "*.cs", SearchOption.AllDirectories))
        {
            if (path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)) continue;
            var cls = Path.GetFileNameWithoutExtension(path);
            foreach (var (name, body) in Tests(File.ReadAllLines(path)))
            {
                if (StartsUnderGate(body) < 2) continue;
                var key = $"{cls}.{name}";
                found.Add(key);
                var ordered = body.Any(l => l.Contains("RaceOrders.ForEveryOrderAsync", StringComparison.Ordinal));
                if (!ordered && !OrderFree.ContainsKey(key)) problems.Add(key);
            }
        }
        problems.Should().BeEmpty("these start two or more writers under a gate: run them in every order with RaceOrders.ForEveryOrderAsync");
        OrderFree.Keys.Except(found).Should().BeEmpty("the allow-list names only tests that still race writers under a gate");
        found.Should().NotBeEmpty("the scan finds the gate race tests (if this fails the patterns are stale)");
    }

    // The most Task.Run calls inside any one held-gate block of a test.
    private static int StartsUnderGate(List<string> body)
    {
        var most = 0;
        for (var i = 0; i < body.Count; i++)
        {
            if (!GateHeld.IsMatch(body[i])) continue;
            var j = i + 1;
            while (j < body.Count && GateHeld.IsMatch(body[j])) j++;   // stacked usings
            if (j >= body.Count || body[j].Trim() != "{") continue;
            int depth = 0, starts = 0;
            for (var k = j; k < body.Count; k++)
            {
                depth += body[k].Count(c => c == '{') - body[k].Count(c => c == '}');
                var here = Start.Count(body[k]);
                // One started in a loop is several writers.
                if (here > 0 && (body[k].Contains("foreach", StringComparison.Ordinal) || body[k].Contains("for (", StringComparison.Ordinal))) here++;
                starts += here;
                if (depth <= 0) break;
            }
            most = Math.Max(most, starts);
        }
        return most;
    }

    // Each test method of a file, as (name, lines from its attribute to the next test's).
    private static IEnumerable<(string Name, List<string> Body)> Tests(string[] lines)
    {
        List<string>? body = null;
        string? name = null;
        foreach (var line in lines)
        {
            if (Test.IsMatch(line))
            {
                if (body is not null && name is not null) yield return (name, body);
                body = [];
                name = null;
            }
            if (body is null) continue;
            body.Add(line);
            if (name is null && Name.Match(line) is { Success: true } m) name = m.Groups["name"].Value;
        }
        if (body is not null && name is not null) yield return (name, body);
    }
}
