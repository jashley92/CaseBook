using IncidentManager.Application.Admin;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>CAP-11: a playbook for the case's rung, and its steps not yet on the case (in the playbook's order).</summary>
public sealed record PlaybookSuggestion(TemplateView Template, IReadOnlyList<TemplateStepView> Missing);

/// <summary>CAP-11: what the notice's "Add them…" does to the apply card (<see cref="PlaybookOffer.Take"/>).</summary>
public enum OfferTake
{
    /// <summary>Open the card on the offered playbook with its missing steps ticked.</summary>
    Open,
    /// <summary>The card is already open on it, as offered: leave it, and the default owner chosen there, alone.</summary>
    Keep,
    /// <summary>The card is open on another playbook, or other steps are ticked: don't replace that work (C7).</summary>
    Refuse
}

/// <summary>
/// CAP-11: after a case is escalated, or filed straight at a rung, the playbooks whose default classification is that
/// rung are offered with the steps the case doesn't have yet. A suggestion only (ADR 0004, A4): the notice opens the
/// apply-playbook flow with those steps ticked, and nothing is written until the person applies them.
/// <para>
/// A step is "already on the case" when a task of any status (open, done or canceled) has its title, compared trimmed
/// and ignoring case: a canceled task was a decision that the work isn't needed, and a done one was the work. Two steps
/// of one playbook with the same title count once (the first), so applying the offer never adds the same task twice.
/// </para>
/// </summary>
public static class PlaybookOffer
{
    /// <summary>The template's steps whose titles aren't among <paramref name="taskTitles"/>, in step order, each title once.</summary>
    public static IReadOnlyList<TemplateStepView> MissingSteps(TemplateView template, IEnumerable<string> taskTitles)
    {
        var have = new HashSet<string>(taskTitles.Select(t => (t ?? "").Trim()), StringComparer.OrdinalIgnoreCase);
        return template.Steps.OrderBy(s => s.Order).Where(s => have.Add(s.Title.Trim())).ToList();
    }

    /// <summary>
    /// Whether the case reached the rung it's on by going up it: filed at it, promoted onto it, or escalated to it (the
    /// latest recorded classification change). Not after a de-escalation: the lower rung's playbook isn't what's needed.
    /// </summary>
    public static bool ReachedByEscalation(Case c)
    {
        if (c.Classification is not { } now) return false;
        var last = c.ClassificationChanges.OrderBy(x => x.ChangedAtUtc).LastOrDefault();
        return last is null || (last.To == now && (last.From is not { } from || now > from));
    }

    /// <summary>
    /// The playbooks to offer on <paramref name="c"/>: active ones for its rung with at least one step missing, in the
    /// pickers' order. None for a Complex Event, a closed or archived case, or one de-escalated to where it is.
    /// </summary>
    public static IReadOnlyList<PlaybookSuggestion> For(Case c, IEnumerable<TemplateView> templates)
    {
        if (c.Phase == CasePhase.Closed || c.IsArchived || !ReachedByEscalation(c)) return [];
        var titles = c.ActionItems.Select(t => t.Title).ToList();
        return templates.Where(t => t.IsActive && t.DefaultClassification == c.Classification)
            .OrderBy(t => t.SortOrder).ThenBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
            .Select(t => new PlaybookSuggestion(t, MissingSteps(t, titles)))
            .Where(s => s.Missing.Count > 0)
            .ToList();
    }

    /// <summary>
    /// CAP-11 review (C7): what "Add them…" does when the apply card may already be open. A card showing another playbook,
    /// or other steps ticked, is someone's work in progress and isn't replaced; one already showing this offer is kept as
    /// it is, so a second click doesn't reset the default owner chosen in it.
    /// </summary>
    public static OfferTake Take(Guid? openTemplateId, IReadOnlySet<Guid> ticked, Guid offeredTemplateId, IReadOnlySet<Guid> missing) =>
        openTemplateId is not { } open ? OfferTake.Open
        : open == offeredTemplateId && ticked.SetEquals(missing) ? OfferTake.Keep
        : OfferTake.Refuse;
}
