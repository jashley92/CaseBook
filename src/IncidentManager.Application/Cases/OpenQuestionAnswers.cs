using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// CAP-23: which of the brief's open questions a finding can answer. The composer's picker lists these, and the save
/// checks a pick with no task against the same reading, so what was offered and what is accepted can't differ (C2). A
/// question is paired with its tasks as the brief and Briefing pair them (<see cref="Case.TasksFollowingUp"/>, BUG-298);
/// one whose task is already done is answered (or was closed without an answer: reopen the task to answer it) and isn't
/// offered.
/// </summary>
public static class OpenQuestionAnswers
{
    /// <summary>
    /// The current brief's listed questions not yet answered, in the brief's order, each once, with the open task that
    /// follows each up (null when none does yet).
    /// </summary>
    public static IReadOnlyList<QuestionAnswer> Answerable(Case c)
    {
        var brief = c.Briefs.FirstOrDefault(b => b.IsCurrent);
        var list = new List<QuestionAnswer>();
        foreach (var q in (CaseNext.Questions(brief?.OpenQuestions) ?? []).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var tasks = c.TasksFollowingUp(Content.MarkdownService.PlainLine(q)).ToList();
            if (tasks.Any(t => t.Status == ActionItemStatus.Done)) continue;
            var open = tasks.Where(t => t.IsOpen).OrderByDescending(t => t.CreatedAtUtc).FirstOrDefault();
            list.Add(new QuestionAnswer(q, open?.Id));
        }
        return list;
    }
}
