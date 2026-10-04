using IncidentManager.Domain.Entities;

namespace IncidentManager.Application.Cases;

/// <summary>HR-02: what a completed task found or did, as recorded when it was marked done.</summary>
/// <param name="Text">The result, without the "Result: " prefix it's stored with.</param>
/// <param name="RecordedAtUtc">When the result was recorded.</param>
/// <param name="RecordedBy">Who recorded it (a user id).</param>
public sealed record TaskResult(string Text, DateTimeOffset RecordedAtUtc, string RecordedBy);

/// <summary>
/// HR-02: a task's result is stored as an append-only task comment starting "Result: " (INV-08), so the record keeps
/// every answer a task was given, including one from before it was reopened. These helpers read the latest one.
/// </summary>
public static class TaskResults
{
    public const string Prefix = "Result: ";

    /// <summary>The comment body that records <paramref name="text"/> as a task's result.</summary>
    public static string Body(string text) => Prefix + text;

    /// <summary>The result text in a comment body, or null when the comment isn't a result.</summary>
    public static string? Parse(string? body) =>
        body is not null && body.StartsWith(Prefix, StringComparison.Ordinal) && body.Length > Prefix.Length
            ? body[Prefix.Length..].Trim()
            : null;

    /// <summary>The latest result for each task among <paramref name="comments"/>.</summary>
    public static IReadOnlyDictionary<Guid, TaskResult> Latest(IEnumerable<ActionItemComment> comments) =>
        comments
            .Select(c => (c, text: Parse(c.Body)))
            .Where(x => x.text is { Length: > 0 })
            .GroupBy(x => x.c.ActionItemId)
            .ToDictionary(g => g.Key, g =>
            {
                var last = g.OrderBy(x => x.c.CreatedAtUtc).Last();
                return new TaskResult(last.text!, last.c.CreatedAtUtc, last.c.CreatedBy);
            });

    /// <summary>A one-line excerpt of a result, for chips and lists.</summary>
    public static string Excerpt(string text, int max = 140)
    {
        var line = string.Join(' ', text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)).Trim();
        return line.Length <= max ? line : line[..(max - 1)].TrimEnd() + "…";
    }
}
