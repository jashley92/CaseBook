using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-566 (BUG-418's class): a component can be disposed while one of its awaits is pending (the layout's time-zone
/// @key rebuilds the page on every fresh circuit; the user leaves; an AuthorizeView re-renders). Dispose then runs before
/// the code after the await, so anything that code registers with something that outlives the component (a singleton
/// notifier, a scoped event, a timer, a palette provider, a JS-side registry) is never undone. ComponentBase also still
/// runs OnParametersSet(Async) after a disposed OnInitializedAsync. These checks read the component sources and fail
/// when such a registration has no disposed check in front of it, so a new member of the class can't come back.
/// </summary>
public partial class ComponentLifetimeTests
{
    [Fact]
    public void Nothing_long_lived_is_registered_after_an_await_without_a_disposed_check()
    {
        var offenders = new List<string>();
        foreach (var (file, code) in ComponentSources())
        {
            foreach (var m in AsyncMethods(code))
            {
                foreach (Match reg in Registration().Matches(m.Body))
                {
                    var lastAwait = m.Body.LastIndexOf("await ", reg.Index, StringComparison.Ordinal);
                    if (lastAwait < 0) continue;   // still in the synchronous part: Dispose can't have run yet
                    if (!DisposedCheck().IsMatch(m.Body[lastAwait..reg.Index]))
                        offenders.Add($"{file} {m.Name}: {reg.Value.Trim()}");
                }
            }
        }

        offenders.Should().BeEmpty("a registration made after an await needs an `if (_disposed) return;` after that await");
    }

    [Fact]
    public void A_component_that_awaits_in_OnInitializedAsync_checks_disposed_before_registering_in_OnParametersSet()
    {
        var offenders = new List<string>();
        foreach (var (file, code) in ComponentSources())
        {
            var methods = Methods(code).ToList();
            if (!methods.Any(m => m.Name == "OnInitializedAsync" && m.Body.Contains("await ", StringComparison.Ordinal))) continue;
            foreach (var m in methods.Where(m => m.Name is "OnParametersSet" or "OnParametersSetAsync"))
            {
                foreach (Match reg in Registration().Matches(m.Body))
                {
                    if (!DisposedCheck().IsMatch(m.Body[..reg.Index]))
                        offenders.Add($"{file} {m.Name}: {reg.Value.Trim()}");
                }
            }
        }

        offenders.Should().BeEmpty("ComponentBase runs OnParametersSet(Async) even when the component was disposed during OnInitializedAsync");
    }

    [Fact]
    public void Teardown_lists_are_not_added_to_after_an_await_without_a_disposed_check()
    {
        // The JS-side registrations Dispose undoes by walking a list (_mdEditors, _mediaWatches): an id added after the
        // awaited registration but after Dispose walked the list is never undone, and the markdown editor's shared
        // registry then keeps a later mount of the same editor id from attaching.
        var offenders = new List<string>();
        foreach (var (file, code) in ComponentSources())
        {
            var methods = Methods(code).ToList();
            var torn = methods.Where(m => m.Name is "Dispose" or "DisposeAsync")
                .SelectMany(m => TeardownLoop().Matches(m.Body).Select(x => x.Groups[1].Value))
                .ToHashSet(StringComparer.Ordinal);
            if (torn.Count == 0) continue;
            foreach (var m in methods.Where(m => m.IsAsync))
            {
                foreach (var list in torn)
                {
                    var add = list + ".Add(";
                    for (var i = m.Body.IndexOf(add, StringComparison.Ordinal); i >= 0; i = m.Body.IndexOf(add, i + 1, StringComparison.Ordinal))
                    {
                        var lastAwait = m.Body.LastIndexOf("await ", i, StringComparison.Ordinal);
                        if (lastAwait >= 0 && !DisposedCheck().IsMatch(m.Body[lastAwait..i]))
                            offenders.Add($"{file} {m.Name}: {list}.Add");
                    }
                }
            }
        }

        offenders.Should().BeEmpty("a teardown list filled after Dispose walked it leaks the registration");
    }

    [Fact]
    public void The_scanner_finds_the_lifecycle_methods_it_checks()
    {
        // A guard on the guard: if parsing broke, the checks above would pass by seeing nothing.
        var all = ComponentSources().SelectMany(s => Methods(s.Code).Select(m => (s.File, m.Name))).ToList();
        all.Should().Contain(("Pages/Cases.razor", "OnInitializedAsync"));
        all.Should().Contain(("Pages/CaseWorkspace.razor", "OnParametersSetAsync"));
        all.Should().Contain(("Shared/NotificationBell.razor", "OnInitializedAsync"));
        all.Should().Contain(("Pages/CaseTabs/CaseNotesTab.razor", "DisposeAsync"));
        var bell = ComponentSources().Single(s => s.File == "Shared/NotificationBell.razor").Code;
        Registration().IsMatch(Methods(bell).Single(m => m.Name == "OnInitializedAsync").Body).Should().BeTrue();
    }

    private sealed record Method(string Name, bool IsAsync, string Body);

    private static IEnumerable<(string File, string Code)> ComponentSources()
    {
        var root = Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "Components");
        return Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".razor", StringComparison.Ordinal) || f.EndsWith(".cs", StringComparison.Ordinal))
            .Select(f => (Path.GetRelativePath(root, f).Replace('\\', '/'), Strip(File.ReadAllText(f))))
            .ToList();
    }

    // Comments, Razor comments, and string and char literals out, so braces and words in them don't count.
    private static string Strip(string code)
    {
        code = RazorComment().Replace(code, " ");
        code = BlockComment().Replace(code, " ");
        code = LineComment().Replace(code, "");
        code = CharLiteral().Replace(code, "' '");
        code = StringLiteral().Replace(code, "\"\"");
        return BlankGuardedBlocks(code);
    }

    // What runs inside `if (_disposed) { ... }` is teardown, so its awaits aren't ones a registration comes after.
    private static string BlankGuardedBlocks(string code)
    {
        var chars = code.ToCharArray();
        foreach (Match g in GuardedBlock().Matches(code))
        {
            var depth = 1;
            for (var i = g.Index + g.Length; i < chars.Length; i++)
            {
                if (chars[i] == '{') depth++;
                else if (chars[i] == '}' && --depth == 0) break;
                else chars[i] = ' ';
            }
        }
        return new string(chars);
    }

    private static IEnumerable<Method> AsyncMethods(string code) => Methods(code).Where(m => m.IsAsync);

    private static IEnumerable<Method> Methods(string code)
    {
        foreach (Match sig in Signature().Matches(code))
        {
            var i = sig.Index + sig.Length;   // just past "Name("
            var depth = 1;
            while (i < code.Length && depth > 0) { if (code[i] == '(') depth++; else if (code[i] == ')') depth--; i++; }
            while (i < code.Length && char.IsWhiteSpace(code[i])) i++;
            string body;
            if (i + 1 < code.Length && code[i] == '=' && code[i + 1] == '>')
            {
                var end = code.IndexOf(';', i);
                body = end < 0 ? code[i..] : code[i..end];
            }
            else if (i < code.Length && code[i] == '{')
            {
                var start = i;
                depth = 0;
                do { if (code[i] == '{') depth++; else if (code[i] == '}') depth--; i++; } while (i < code.Length && depth > 0);
                body = code[start..i];
            }
            else continue;   // a call or a declaration without a body
            yield return new Method(sig.Groups["name"].Value, sig.Groups["async"].Success, body);
        }
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }

    // Something that outlives the component: a notifier or presence subscription, an event handler, a timer, a .NET
    // reference handed to JS, a palette provider, an options-change hook.
    [GeneratedRegex(@"\.Subscribe\w*\(|[\w.]+\s*\+=\s*(?:[A-Z]\w*\s*;|\(?[\w\s,]*\)?\s*=>)|new\s+(?:System\.Threading\.)?(?:Periodic)?Timer\s*\(|DotNetObjectReference\.Create\(|\.Set\(\s*this\b|\.OnChange\(",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Registration();

    [GeneratedRegex(@"if\s*\(\s*(?:_disposed|Disposed|_gone)\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex DisposedCheck();

    [GeneratedRegex(@"if\s*\(\s*(?:_disposed|Disposed|_gone)\b[^)]*\)\s*\{", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex GuardedBlock();

    [GeneratedRegex(@"foreach\s*\(\s*var\s+\w+\s+in\s+(_\w+)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex TeardownLoop();

    [GeneratedRegex(@"(?:private|protected|public|internal)(?:\s+(?:override|static|sealed|virtual|new))*\s+(?<async>async\s+)?(?:override\s+)?(?:void|Task|ValueTask|Task<[^>()]+>|ValueTask<[^>()]+>)\s+(?<name>\w+)\s*\(",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Signature();

    [GeneratedRegex(@"@\*.*?\*@", RegexOptions.Singleline, matchTimeoutMilliseconds: 1000)]
    private static partial Regex RazorComment();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline, matchTimeoutMilliseconds: 1000)]
    private static partial Regex BlockComment();

    [GeneratedRegex(@"(?<![:""])//[^\n]*", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex LineComment();

    [GeneratedRegex(@"'(?:\\.|[^'\\\n])'", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex CharLiteral();

    [GeneratedRegex(@"""(?:\\.|[^""\\\n])*""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex StringLiteral();
}
