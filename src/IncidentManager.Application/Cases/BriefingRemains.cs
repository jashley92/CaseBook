namespace IncidentManager.Application.Cases;

/// <summary>
/// BUG-533: the briefing's "What remains" open questions, one source for the page and its copied text: prose (before a
/// list, or all of it) as written, then the list's questions.
/// </summary>
public static class BriefingRemains
{
    /// <summary>The brief's open questions as the briefing shows them: the prose, if any, then the list's questions.</summary>
    public static (string? Prose, List<string> Items) Parts(string? openQuestions)
    {
        var parts = CaseNext.QuestionParts(openQuestions);
        var prose = parts is { } qp ? qp.Prose : string.IsNullOrWhiteSpace(openQuestions) ? null : openQuestions;
        return (prose, parts?.Items ?? []);
    }

    /// <summary>The same as lines for the copied text briefing: the prose made plain, then "? question" for each.</summary>
    public static IEnumerable<string> Lines(string? openQuestions, Func<string, string> plain)
    {
        var (prose, items) = Parts(openQuestions);
        if (prose is not null) yield return plain(prose);
        foreach (var q in items) yield return "? " + plain(q);
    }
}
