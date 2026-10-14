using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>A task saved with an entry (RD-09).</summary>
public sealed record FollowUpTask(string Title, string? Owner = null, TaskKind Kind = TaskKind.General, DateTimeOffset? DueAtUtc = null);

/// <summary>
/// RD-09: what the composer saves with a timeline entry, in the same save: tasks about the entry, a question for the
/// brief (optionally followed up as a task), a line for the brief's Known, and a link to another case.
/// </summary>
public sealed record EntryFollowUps(
    IReadOnlyList<FollowUpTask>? Tasks = null,
    string? Question = null,
    bool QuestionTask = false,
    string? KnownLine = null,
    Guid? LinkCaseId = null,
    CaseLinkType LinkType = CaseLinkType.RelatedTo)
{
    /// <summary>Whether anything is asked for at all.</summary>
    public bool Any => (Tasks?.Count ?? 0) > 0 || Clean(Question) is not null || Clean(KnownLine) is not null || LinkCaseId is not null;

    /// <summary>Checks the parts before anything is written, so a bad follow-up stops the whole save.</summary>
    public void Validate()
    {
        foreach (var t in Tasks ?? [])
        {
            if (string.IsNullOrWhiteSpace(t.Title)) throw new ArgumentException("Say what each task needs to do.");
            if (t.Title.Trim().Length > ActionItem.MaxTitleLength)
                throw new ArgumentException($"Keep each task to {ActionItem.MaxTitleLength} characters or fewer.");
        }
        if (Clean(Question) is { } q && TypedLength(q) > ActionItem.MaxTitleLength)
            throw new ArgumentException($"Keep the question to {ActionItem.MaxTitleLength} characters or fewer.");
        if (Clean(KnownLine) is { } k && TypedLength(k) > 2000)
            throw new ArgumentException("Keep the line for Known to 2,000 characters or fewer.");
    }

    /// <summary>
    /// BUG-481: a line's length as the box counts it: its plain text (the task title a question gets), not the Markdown
    /// its [[tags]] expand to, about 43 characters more each. The stored part is still held to its 8,000 by the brief.
    /// </summary>
    public static int TypedLength(string line) => Content.MarkdownService.PlainLine(line).Length;

    /// <summary>One line, without a leading list marker; null when empty.</summary>
    public static string? Clean(string? text)
    {
        var line = string.Join(' ', (text ?? "").Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
        if (line.StartsWith("- ", StringComparison.Ordinal)) line = line[2..].Trim();
        return line.Length == 0 ? null : line;
    }
}
