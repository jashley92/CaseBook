using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// Rules kept by the client scripts, checked on their source (there's no JS test runner): each names the defect it holds
/// shut.
/// </summary>
public sealed partial class ClientScriptRulesTests
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
        TickThenReturn().IsMatch(onActivity).Should().BeTrue("an overdue boundary is still acted on (BUG-550)");
    }

    [Fact]
    public void A_tab_that_locks_itself_keeps_its_page_for_resume_and_out_of_the_lock_url()
    {
        var js = Script("idle-timeout.js");
        var lockFromClient = Function(js, "lockFromClient");
        var remember = lockFromClient.IndexOf("rememberPage();", StringComparison.Ordinal);
        remember.Should().BeGreaterThan(-1, "the browser's own lock keeps the page, as the server's does");
        lockFromClient.IndexOf("location.replace(", StringComparison.Ordinal).Should().BeGreaterThan(remember, "before leaving it");
        lockFromClient.Should().Contain("new URL('session-expired', document.baseURI)", "the lock page's URL carries no page");
        Function(js, "rememberPage").Should().Contain("sessionStorage", "kept in the tab, not the address bar");
        Function(js, "takeReturnPage").Should().Contain("sessionStorage.removeItem(", "taken once, so a later lock can't resume on it");
    }

    [Fact]
    public void The_editor_preview_renders_raw_html_and_link_schemes_as_the_server_does(/* BUG-715 */)
    {
        var js = Script("markdown-editor.js");
        js.Should().Contain("markedOptions: { sanitize: true, silent: true }", "raw HTML is shown as typed, as DisableHtml does");
        js.Should().Contain("sanitizerFunction: sanitizePreview");
        js.Should().Contain("renderingConfig: renderingConfig,", "the one editor is made with it");

        // The same scheme allow-list as MarkdownService.IsSafeUrl.
        var server = File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Application", "Content", "MarkdownService.cs"));
        static IEnumerable<string> Quoted(string list) => QuotedItem().Matches(list).Select(m => m.Groups[1].Value);
        var serverSchemes = Quoted(ServerSchemes().Match(server).Groups[1].Value).ToList();
        var clientSchemes = Quoted(ClientSchemes().Match(js).Groups[1].Value).ToList();
        serverSchemes.Should().NotBeEmpty();
        clientSchemes.Should().BeEquivalentTo(serverSchemes);
    }

    [Fact]
    public void Times_show_in_local_time_until_someone_chooses_UTC()
    {
        // Nothing saved (a new account on a new browser) reads as local; only a stored "utc" keeps UTC.
        var mode = Function(Script("time.js"), "mode");
        mode.Should().Contain("localStorage.getItem(TIME_PREF) === 'utc' ? 'utc' : 'local'");
        mode.Should().Contain("root.getAttribute('data-pref-time') === 'utc' ? 'utc' : 'local'", "private mode reads the server's copy");
    }

    [GeneratedRegex(@"tick\(\);\s*return;")]
    private static partial Regex TickThenReturn();

    [GeneratedRegex("[\"']([^\"']+)[\"']")]
    private static partial Regex QuotedItem();

    [GeneratedRegex(@"AllowedSchemes = \{([^}]*)\}")]
    private static partial Regex ServerSchemes();

    [GeneratedRegex(@"allowedSchemes = \[([^\]]*)\]")]
    private static partial Regex ClientSchemes();
}
