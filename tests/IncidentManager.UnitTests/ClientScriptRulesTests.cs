using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// Rules kept by the client scripts, checked on their source (there's no JS test runner): each names the defect it holds
/// shut.
/// </summary>
public sealed class ClientScriptRulesTests
{
    private static string Script(string name) =>
        File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "wwwroot", "js", name));

    private static string Function(string js, string name)
    {
        var start = js.IndexOf($"function {name}(", StringComparison.Ordinal);
        start.Should().BeGreaterThan(-1, $"{name} is defined");
        var open = js.IndexOf('{', start);
        var depth = 0;
        for (var i = open; i < js.Length; i++)
        {
            if (js[i] == '{') depth++;
            else if (js[i] == '}' && --depth == 0) return js[start..(i + 1)];
        }
        throw new InvalidOperationException($"{name} doesn't close");
    }

    [Fact]
    public void Hiding_or_showing_the_tab_never_restarts_the_idle_clock(/* BUG-714 */)
    {
        var onActivity = Function(Script("idle-timeout.js"), "onActivity");
        var skip = onActivity.IndexOf("e.type === 'visibilitychange') return;", StringComparison.Ordinal);
        var reset = onActivity.IndexOf("last = Date.now();", StringComparison.Ordinal);
        skip.Should().BeGreaterThan(-1, "a visibility change is only a prompt to act on a boundary already passed");
        reset.Should().BeGreaterThan(skip, "it returns before the clock is reset");
        Regex.IsMatch(onActivity, @"tick\(\);\s*return;").Should().BeTrue("an overdue boundary is still acted on (BUG-550)");
    }
}
