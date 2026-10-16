using System.Text.RegularExpressions;

namespace IncidentManager.UnitTests;

/// <summary>
/// The shared reader behind the structural UI tests (BUG-566's ComponentLifetimeTests, and C5-C8's continuation, keyboard,
/// edit-preservation and in-flight checks). It reads the Razor components and their code-behind under
/// src/IncidentManager.Web/Components with comments taken out and string literals blanked, so braces and words in them
/// don't count; newlines are kept, so an offset still gives the right line. A string that is a bare JS function path
/// (<c>"imKeymap.registerCase"</c>) is kept, since which JS registry a call adds to is what some checks look for.
/// </summary>
internal static partial class ComponentSourceScanner
{
    /// <summary>A method (or an async lambda, named <c>Outer&lt;lambda&gt;</c>) and its body, from the opening
    /// <c>{</c> or <c>=&gt;</c>. <paramref name="Start"/> is the body's offset in the file's code.</summary>
    internal sealed record Method(string Name, bool IsAsync, string Body, int Start, string Parameters = "");

    /// <summary>One component source: its path under Components (forward slashes), its stripped code, and the same with
    /// only the comments out (<paramref name="Raw"/>: string literals and markup attribute values kept).</summary>
    internal sealed record Source(string File, string Code, string Raw)
    {
        /// <summary>The 1-based line of an offset in <see cref="Code"/>.</summary>
        public int LineOf(int offset) => Code.AsSpan(0, Math.Min(offset, Code.Length)).Count('\n') + 1;

        /// <summary>The 1-based line of an offset in <see cref="Raw"/> (or its markup).</summary>
        public int RawLineOf(int offset) => Raw.AsSpan(0, Math.Min(offset, Raw.Length)).Count('\n') + 1;

        /// <summary>The component's name: the file name up to its first dot (CaseWorkspace.Acts.cs is CaseWorkspace).</summary>
        public string Component => Path.GetFileName(File).Split('.')[0];
    }

    private static readonly Lazy<IReadOnlyList<Source>> All = new(Load);

    /// <summary>Every .razor and .cs file under src/IncidentManager.Web/Components.</summary>
    internal static IReadOnlyList<Source> Sources() => All.Value;

    /// <summary>The files of one component (a .razor and its partial .cs files) as one unit, keyed by the .razor's path.</summary>
    internal static IEnumerable<(string File, IReadOnlyList<Source> Parts)> Components() =>
        Sources().GroupBy(s => (Path.GetDirectoryName(s.File) ?? "", s.Component))
            .Select(g => (g.OrderBy(s => s.File.EndsWith(".razor", StringComparison.Ordinal) ? 0 : 1).First().File,
                (IReadOnlyList<Source>)g.ToList()));

    private static List<Source> Load()
    {
        var root = ComponentsRoot();
        return Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".razor", StringComparison.Ordinal) || f.EndsWith(".cs", StringComparison.Ordinal))
            .Select(f =>
            {
                var text = File.ReadAllText(f);
                return new Source(Path.GetRelativePath(root, f).Replace('\\', '/'), Strip(text), StripComments(text));
            })
            .ToList();
    }

    internal static string ComponentsRoot() => Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "Components");

    internal static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }

    /// <summary>Comments and Razor comments out (newlines kept).</summary>
    internal static string StripComments(string code)
    {
        code = RazorComment().Replace(code, Blank);
        code = BlockComment().Replace(code, Blank);
        return LineComment().Replace(code, "");
    }

    /// <summary>Comments, Razor comments, and string and char literals out (newlines kept).</summary>
    internal static string Strip(string code)
    {
        code = StripComments(code);
        code = CharLiteral().Replace(code, "' '");
        code = VerbatimString().Replace(code, m => "\"" + new string('\n', m.Value.Count(c => c == '\n')) + "\"");
        // A string with nothing in it that could be read as code (no braces, semicolons or escapes) is kept, so "Enter",
        // a toast's words and an empty "" stay as they are; any other becomes "s".
        code = StringLiteral().Replace(code, m => JsPath().IsMatch(m.Value) || m.Value.IndexOfAny(['{', '}', ';', '\\']) < 0 ? m.Value : "\"s\"");
        return code;
    }

    private static string Blank(Match m) => new(m.Value.Select(c => c == '\n' ? '\n' : ' ').ToArray());

    /// <summary>Every method with a body, plus every async lambda with a block body (as <c>Outer&lt;lambda&gt;</c>).</summary>
    internal static IEnumerable<Method> Methods(string code)
    {
        var found = new List<Method>();
        foreach (Match sig in Signature().Matches(code))
        {
            var i = sig.Index + sig.Length;   // just past "Name("
            var depth = 1;
            var parStart = i;
            while (i < code.Length && depth > 0) { if (code[i] == '(') depth++; else if (code[i] == ')') depth--; i++; }
            var parameters = code[parStart..Math.Max(parStart, i - 1)];
            while (i < code.Length && char.IsWhiteSpace(code[i])) i++;
            if (Body(code, i) is not { } body) continue;   // a call or a declaration without a body
            found.Add(new Method(sig.Groups["name"].Value, sig.Groups["async"].Success, body, i, parameters));
        }
        // Async lambdas (an InvokeAsync(async () => ...) in a sync handler, a callback handed to a confirm): their
        // awaits are their own, so each is checked as a method of its own.
        foreach (Match lam in AsyncLambda().Matches(code))
        {
            var i = lam.Index + lam.Length;
            while (i < code.Length && char.IsWhiteSpace(code[i])) i++;
            if (i >= code.Length || code[i] != '{' || Body(code, i) is not { } body) continue;
            var outer = found.LastOrDefault(m => m.Start <= lam.Index && lam.Index < m.Start + m.Body.Length)?.Name ?? "field";
            found.Add(new Method(outer + "<lambda>", true, body, i));
        }
        return found;
    }

    /// <summary>The body at <paramref name="i"/>: a brace block, or an expression body up to its semicolon.</summary>
    private static string? Body(string code, int i)
    {
        if (i + 1 < code.Length && code[i] == '=' && code[i + 1] == '>')
        {
            var end = code.IndexOf(';', i);
            return end < 0 ? code[i..] : code[i..end];
        }
        if (i >= code.Length || code[i] != '{') return null;
        var start = i;
        var depth = 0;
        do { if (code[i] == '{') depth++; else if (code[i] == '}') depth--; i++; } while (i < code.Length && depth > 0);
        return code[start..i];
    }

    /// <summary>What runs inside <c>if (_disposed) { ... }</c> is teardown: blanked, so its awaits don't count.</summary>
    internal static string BlankGuardedBlocks(string code)
    {
        var chars = code.ToCharArray();
        foreach (Match g in GuardedBlock().Matches(code))
        {
            var depth = 1;
            // Braces are kept (an inner block's pair stays balanced, so the method around it still ends where it does).
            for (var i = g.Index + g.Length; i < chars.Length; i++)
            {
                if (chars[i] == '{') depth++;
                else if (chars[i] == '}') { if (--depth == 0) break; }
                else if (chars[i] != '\n') chars[i] = ' ';
            }
        }
        return new string(chars);
    }

    /// <summary>The offsets of every <c>await</c> keyword in a body.</summary>
    internal static List<int> Awaits(string body) => AwaitWord().Matches(body).Select(m => m.Index).ToList();

    /// <summary>The fields a component declares, with their declared type (generic arguments and <c>?</c> kept).</summary>
    internal static Dictionary<string, string> Fields(IEnumerable<Source> parts)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in parts)
            foreach (Match f in FieldDeclaration().Matches(p.Code))
                fields.TryAdd(f.Groups["name"].Value, f.Groups["type"].Value.Trim());
        return fields;
    }

    /// <summary>The markup part of a .razor file (before its first <c>@code</c> block); "" for a .cs file.</summary>
    internal static string Markup(Source s)
    {
        if (!s.File.EndsWith(".razor", StringComparison.Ordinal)) return "";
        var code = CodeBlock().Match(s.Raw);
        return code.Success ? s.Raw[..code.Index] : s.Raw;
    }

    /// <summary>
    /// Checks what a structural test found against its allow-list (file → how many sites it may still have, each with a
    /// comment saying why and whose they are). Offenders: every site in a file over its count. Stale: a listed file with
    /// fewer sites than its count (a fixed site comes off the list, so the list only shrinks).
    /// </summary>
    internal static (List<string> Offenders, List<string> Stale) Against(
        IReadOnlyDictionary<string, int> allowed, IEnumerable<(string File, string What)> found)
    {
        var byFile = found.GroupBy(f => f.File, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Select(x => x.What).ToList(), StringComparer.Ordinal);
        var dump = Environment.GetEnvironmentVariable("CB_SCAN_DUMP");
        if (!string.IsNullOrEmpty(dump))
            File.AppendAllLines(dump, byFile.OrderBy(f => f.Key, StringComparer.Ordinal)
                .Select(f => $"[\"{f.Key}\"] = {f.Value.Count},   // {string.Join("; ", f.Value)}"));
        var offenders = byFile.Where(f => f.Value.Count > allowed.GetValueOrDefault(f.Key))
            .SelectMany(f => f.Value.Select(w => $"{f.Key}: {w}")).ToList();
        var stale = allowed.Where(a => byFile.GetValueOrDefault(a.Key)?.Count is not { } n || n < a.Value)
            .Select(a => $"{a.Key} (listed {a.Value}, found {byFile.GetValueOrDefault(a.Key)?.Count ?? 0})").ToList();
        return (offenders, stale);
    }

    /// <summary>The services a component injects (<c>@inject T Name</c>, <c>[Inject] T Name</c>), by name, less the
    /// UI plumbing (JS, navigation, toasts, logging, the clock, display and palette state).</summary>
    internal static HashSet<string> InjectedServices(IEnumerable<Source> parts)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in parts)
        {
            foreach (Match m in Inject().Matches(p.Raw))
            {
                var (type, name) = (m.Groups["type"].Value, m.Groups["name"].Value);
                if (Plumbing.Any(t => type.Contains(t, StringComparison.Ordinal))) continue;
                names.Add(name);
            }
        }
        return names;
    }

    private static readonly string[] Plumbing =
    [
        "IJSRuntime", "NavigationManager", "ILogger", "ToastService", "TimeDisplay", "IClock", "IConfiguration", "UnsavedEdits",
        "AuthenticationStateProvider", "IMarkdownService", "ISeverityLabels", "CaseListMemory", "CommandPaletteController",
        "CaseCommandRegistry", "ICurrentUser", "IUserDirectory", "IOptions", "IWebHostEnvironment", "ICaseChangeNotifier",
        "IAuthorizationService", "CaseTabsState", "IHttpClientFactory", "HttpClient", "OrgZone",
        "UserDisplayPreferenceService", "IDbContextFactory",   // how this viewer likes the page shown; a read context
    ];

    [GeneratedRegex(@"(?:@inject\s+(?<type>[\w.<>,?]+)\s+(?<name>\w+)|\[Inject\][^;{]*?\s(?<type>[\w.<>?]+)\s+(?<name>\w+)\s*\{)",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Inject();

    /// <summary>A disposed check: <c>if (_disposed</c>, <c>if (Disposed</c>, <c>if (_gone</c>.</summary>
    internal static bool HasDisposedCheck(string text) => DisposedCheck().IsMatch(text);

    [GeneratedRegex(@"if\s*\(\s*(?:_disposed|Disposed|_gone)\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex DisposedCheck();

    [GeneratedRegex(@"if\s*\(\s*(?:_disposed|Disposed|_gone)\b[^)]*\)\s*\{", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex GuardedBlock();

    // BUG-566 gaps: a tuple or nested generic return (Task<(bool, string)>, Task<IReadOnlyList<X>>) is a method too.
    [GeneratedRegex(@"(?:private|protected|public|internal)(?:\s+(?:override|static|sealed|virtual|new))*\s+(?<async>async\s+)?(?:override\s+)?(?:void|Task|ValueTask|bool|string|int)(?:<(?:[^<>;{}]|<(?:[^<>;{}]|<[^<>;{}]*>)*>)*>)?\??\s+(?<name>\w+)\s*\(",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Signature();

    [GeneratedRegex(@"\basync\s*(?:\([^()]*\)|\w+)\s*=>", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex AsyncLambda();

    [GeneratedRegex(@"\bawait\s", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex AwaitWord();

    [GeneratedRegex(@"(?m)^\s*(?:private|protected|internal|public)\s+(?:readonly\s+|static\s+)*(?<type>[\w.]+(?:<(?:[^<>;=]|<[^<>;=]*>)*>)?\??(?:\[\])?)\s+(?<name>_\w+)\s*(?:=|;)",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex FieldDeclaration();

    [GeneratedRegex(@"(?m)^@code\s*\{", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex CodeBlock();

    [GeneratedRegex(@"@\*.*?\*@", RegexOptions.Singleline, matchTimeoutMilliseconds: 1000)]
    private static partial Regex RazorComment();

    // Not inside a word: accept="image/*" in markup isn't the start of a comment (it hid the timeline's code up to the
    // next */ from every scan).
    [GeneratedRegex(@"(?<![\w""'/])/\*.*?\*/", RegexOptions.Singleline, matchTimeoutMilliseconds: 1000)]
    private static partial Regex BlockComment();

    [GeneratedRegex(@"(?<![:""])//[^\n]*", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex LineComment();

    [GeneratedRegex(@"'(?:\\.|[^'\\\n])'", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex CharLiteral();

    [GeneratedRegex(@"@""(?:""""|[^""])*""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex VerbatimString();

    [GeneratedRegex(@"""(?:\\.|[^""\\\n])*""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex StringLiteral();

    [GeneratedRegex(@"^""[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+""$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex JsPath();
}
