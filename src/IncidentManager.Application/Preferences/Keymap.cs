using System.Text.RegularExpressions;

namespace IncidentManager.Application.Preferences;

/// <summary>Where a shortcut works: anywhere, or with a case open.</summary>
public enum KeyScope { Anywhere, Case }

/// <summary>One action a key can run.</summary>
/// <param name="Command">What the dispatcher sends (the palette's or the workspace's command name).</param>
public sealed record KeyAction(string Id, string Label, KeyScope Scope, string Command, string DefaultKeys);

/// <summary>A user's keyboard settings: their own keys for some actions, and whether single-key shortcuts are on.</summary>
public sealed record KeymapSettings(bool SingleKeysOff, IReadOnlyDictionary<string, string> Keys)
{
    public static readonly KeymapSettings Default = new(false, new Dictionary<string, string>());

    /// <summary>The keys in force for an action: the user's own, else the default ("" = none).</summary>
    public string KeysFor(KeyAction a) => Keys.TryGetValue(a.Id, out var k) ? k : a.DefaultKeys;
}

/// <summary>
/// RD-24: CaseBook's one keymap. Every shortcut is listed here with its default keys; a user can change any of them,
/// clear one, or switch every single-key shortcut off (WCAG 2.1.4: shortcuts made of letters, digits or punctuation
/// alone can be turned off or remapped). The dispatcher (wwwroot/js/keymap.js) is aware of text fields: single-key
/// shortcuts never fire while typing. Three keys are fixed so the app can't be locked out: Ctrl/⌘+K (the command bar),
/// Esc (close) and Ctrl/⌘+Enter (save what you're writing).
/// <para>Keys are written as a single key (<c>/</c>, <c>n</c>, <c>1</c>), a two-key sequence starting with g
/// (<c>g d</c>), or a key with Ctrl or Alt (<c>Alt+N</c>, <c>Ctrl+Shift+F</c>). Several bindings for one action are
/// separated by commas.</para>
/// </summary>
public static partial class Keymap
{
    public static readonly IReadOnlyList<KeyAction> Actions =
    [
        new("palette", "Open the command bar", KeyScope.Anywhere, "palette", "/"),
        new("help", "Show the keyboard shortcuts", KeyScope.Anywhere, "help", "?"),
        new("go-desk", "Go to your Desk", KeyScope.Anywhere, "go:m", "g m"),
        new("go-cases", "Go to Cases", KeyScope.Anywhere, "go:c", "g c"),
        new("go-find", "Go to Find", KeyScope.Anywhere, "go:f", "g f"),
        new("go-program", "Go to Program", KeyScope.Anywhere, "go:d", "g d"),
        new("go-new", "New case", KeyScope.Anywhere, "go:n", "g n"),
        new("go-integrity", "Go to Integrity & audit", KeyScope.Anywhere, "go:i", "g i"),
        new("view-1", "In a case: Record", KeyScope.Case, "tab:1", "1"),
        new("view-2", "In a case: Things", KeyScope.Case, "tab:2", "2"),
        new("view-3", "In a case: Tasks", KeyScope.Case, "tab:3", "3"),
        new("view-4", "In a case: Briefing", KeyScope.Case, "tab:4", "4"),
        new("view-5", "In a case: Paper", KeyScope.Case, "tab:5", "5"),
        new("log", "In a case: log to the record", KeyScope.Case, "log", "l"),
        new("task", "In a case: add a task", KeyScope.Case, "task", "t"),
        new("note", "In a case: write a working note", KeyScope.Case, "note", "n"),
    ];

    public static KeyAction? Find(string id) => Actions.FirstOrDefault(a => a.Id == id);

    /// <summary>Normalizes one binding ("ctrl+shift+f" → "Ctrl+Shift+F", "G  D" → "g d"), or null if it isn't valid.</summary>
    public static string? Normalize(string? binding)
    {
        var b = (binding ?? "").Trim();
        if (b.Length == 0) return null;
        if (SequenceRx().Match(b) is { Success: true } seq) return "g " + seq.Groups[1].Value.ToLowerInvariant();
        if (SingleRx().IsMatch(b)) return b.Length == 1 && char.IsLetter(b[0]) ? b.ToLowerInvariant() : b;
        if (ChordRx().Match(b) is { Success: true } m)
        {
            var mods = m.Groups[1].Value.Split('+', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(x => char.ToUpperInvariant(x[0]) + x[1..].ToLowerInvariant()).Distinct().ToList();
            if (!mods.Contains("Ctrl") && !mods.Contains("Alt")) return null;   // Shift alone isn't a chord
            var order = new[] { "Ctrl", "Alt", "Shift" };
            var key = m.Groups[2].Value;
            return string.Join('+', order.Where(mods.Contains)) + "+" + (key.Length == 1 ? key.ToUpperInvariant() : key);
        }
        return null;
    }

    /// <summary>Whether a binding works without Ctrl or Alt (and so is off when single-key shortcuts are off).</summary>
    public static bool IsSingleKey(string binding) => !binding.Contains("Ctrl+") && !binding.Contains("Alt+");

    /// <summary>
    /// Validates and normalizes a user's keys. Returns the cleaned settings, or the problems (a binding that isn't a
    /// key, a reserved key, one key on two actions that can both fire).
    /// </summary>
    public static (KeymapSettings? Settings, IReadOnlyList<string> Problems) Validate(bool singleKeysOff, IReadOnlyDictionary<string, string> keys)
    {
        var problems = new List<string>();
        var clean = new Dictionary<string, string>();
        foreach (var (id, raw) in keys)
        {
            if (Find(id) is not { } action) { problems.Add($"There's no shortcut called \"{id}\"."); continue; }
            var parts = (raw ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var norm = new List<string>();
            foreach (var p in parts)
            {
                if (Normalize(p) is not { } n) { problems.Add($"{action.Label}: \"{p}\" isn't a key CaseBook can use. Use one key, g and a key, or Ctrl or Alt with a key."); continue; }
                if (n is "Ctrl+K" or "Ctrl+Enter" || n == "g") { problems.Add($"{action.Label}: {n} is kept for the command bar, saving or go-to keys."); continue; }
                norm.Add(n);
            }
            var value = string.Join(", ", norm.Distinct());
            if (value != action.DefaultKeys) clean[id] = value;
        }

        var settings = new KeymapSettings(singleKeysOff, clean);
        // One key may serve a case action and nothing else that can fire with a case open.
        var seen = new Dictionary<string, KeyAction>();
        foreach (var a in Actions)
            foreach (var k in settings.KeysFor(a).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (seen.TryGetValue(k, out var other)) problems.Add($"{k} is used for both \"{other.Label}\" and \"{a.Label}\".");
                else seen[k] = a;
            }
        // A single key can't also start the g sequences.
        if (seen.ContainsKey("g")) problems.Add("g starts the go-to keys, so it can't be a shortcut on its own.");

        return problems.Count == 0 ? (settings, problems) : (null, problems.Distinct().ToList());
    }

    /// <summary>Stored form: "id=keys;id=keys" (only the actions changed from their defaults).</summary>
    public static string? Serialize(IReadOnlyDictionary<string, string> keys) =>
        keys.Count == 0 ? null : string.Join(';', keys.OrderBy(k => k.Key).Select(k => $"{k.Key}={k.Value}"));

    public static Dictionary<string, string> Deserialize(string? stored)
    {
        var d = new Dictionary<string, string>();
        foreach (var part in (stored ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var i = part.IndexOf('=');
            if (i > 0 && Find(part[..i]) is not null) d[part[..i]] = part[(i + 1)..];
        }
        return d;
    }

    [GeneratedRegex(@"^g\s+([A-Za-z0-9])$", RegexOptions.IgnoreCase)]
    private static partial Regex SequenceRx();

    [GeneratedRegex(@"^[A-Za-z0-9/?.,;'\[\]\\\-=`]$")]
    private static partial Regex SingleRx();

    [GeneratedRegex(@"^((?:(?:ctrl|alt|shift)\s*\+\s*)+)([A-Za-z0-9/?.,;'\[\]\\\-=`]|F\d{1,2})$", RegexOptions.IgnoreCase)]
    private static partial Regex ChordRx();
}
