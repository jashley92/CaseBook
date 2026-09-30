using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// INV-25: what happens next on a case is its open tasks — one list, read the same way by the brief, the context
/// panel, its strip and the handoff. Overdue work comes first, then the work to finish before the next phase, then
/// by due date. A read-time view: nothing here writes.
/// </summary>
public static class CaseNext
{
    /// <summary>The phase after the case's current one, or null when it's closed.</summary>
    public static CasePhase? NextPhase(Case c)
    {
        var phases = Enum.GetValues<CasePhase>();
        var i = Array.IndexOf(phases, c.Phase);
        return i >= 0 && i < phases.Length - 1 ? phases[i + 1] : null;
    }

    /// <summary>Whether an open task is work for the phases before the next one (every open task when the next
    /// step is closing the case).</summary>
    public static bool IsBeforeNextPhase(ActionItem t, CasePhase? next) =>
        t.IsOpen && next is { } np && (np == CasePhase.Closed || (t.Kind.Phase() is { } p && p < np));

    /// <summary>The open tasks, in the order to do them.</summary>
    public static List<ActionItem> Open(Case c, DateTimeOffset nowUtc)
    {
        var next = NextPhase(c);
        return c.ActionItems.Where(t => t.IsOpen)
            .OrderByDescending(t => t.IsOverdue(nowUtc))
            .ThenByDescending(t => IsBeforeNextPhase(t, next))
            .ThenBy(t => t.DueAtUtc ?? DateTimeOffset.MaxValue)
            .ThenBy(t => t.CreatedAtUtc)
            .ToList();
    }

    /// <summary>
    /// The open tasks as Markdown bullets ("- Title (Owner)"), recorded with a brief version so its history shows
    /// what was next at the time. Null when nothing is open.
    /// </summary>
    public static string? Snapshot(Case c, DateTimeOffset nowUtc, Func<string, string> ownerName)
    {
        var lines = Open(c, nowUtc)
            .Select(t => $"- {t.Title}" + (string.IsNullOrWhiteSpace(t.Owner) ? "" : $" ({ownerName(t.Owner)})"))
            .ToList();
        return lines.Count == 0 ? null : string.Join("\n", lines);
    }

    /// <summary>
    /// The brief's open questions one per line, when the part is a plain list (so each can be followed up as a
    /// task); null when it's prose, which is shown as written.
    /// </summary>
    public static List<string>? Questions(string? openQuestions)
    {
        if (string.IsNullOrWhiteSpace(openQuestions)) return null;
        var lines = openQuestions.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        var items = new List<string>();
        foreach (var line in lines)
        {
            var text = ListItemText(line);
            if (text is null) return null;
            items.Add(text);
        }
        return items;
    }

    private static string? ListItemText(string line)
    {
        if (line.Length > 1 && line[0] is '-' or '*' or '+' && line[1] == ' ') return line[2..].Trim();
        var dot = line.IndexOfAny(['.', ')']);
        return dot > 0 && dot < line.Length - 1 && line[..dot].All(char.IsDigit) && line[dot + 1] == ' '
            ? line[(dot + 2)..].Trim()
            : null;
    }
}
