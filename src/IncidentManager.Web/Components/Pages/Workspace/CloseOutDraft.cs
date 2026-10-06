using IncidentManager.Application.Admin;
using IncidentManager.Application.Content;
using IncidentManager.Domain.Entities;

namespace IncidentManager.Web.Components.Pages.Workspace;

/// <summary>
/// RD-14 (RD-27: lifted out of CaseWorkspace): a close-out in progress. The workspace owns it, so the draft survives
/// looking at the rest of the case (the Close-out view is rebuilt on every visit); it belongs to one case and is
/// dropped when another case opens, when the case closes, or when the analyst discards it.
/// </summary>
public sealed class CloseOutDraft
{
    /// <summary>A draft exists (the Close-out tab stays in the bar until it's closed or discarded).</summary>
    public bool Open { get; set; }

    public string? Outcome { get; set; }
    /// <summary>What happened: the case summary, printed in the report.</summary>
    public string? Summary { get; set; }
    /// <summary>What the team concluded, and on what basis (the working assessment's closing version).</summary>
    public string? Conclusion { get; set; }
    /// <summary>HR-18: the reply pasted back from the analyst's own AI tool.</summary>
    public string? AiReply { get; set; }
    public string? Error { get; set; }

    public List<CaseOutcomeView> Outcomes { get; set; } = [];
    public TransitionDraft Transition { get; } = new();

    // Entity tags and evidence citations show as [[name]] in the plain boxes, and turn back into links on save.
    private readonly Dictionary<string, string> _refs = new(StringComparer.Ordinal);
    private Guid? _prefilledFor;

    /// <summary>Starts a draft at "now" (an existing one keeps its time, ticks and text).</summary>
    public void Begin(DateTime nowWall)
    {
        if (Open) return;
        Transition.Reset(nowWall);
        Open = true;
    }

    /// <summary>Starts the text from the current brief, once per case, so the analyst edits rather than retypes it.</summary>
    public void Prefill(Case c)
    {
        if (_prefilledFor == c.Id) return;
        var brief = c.Briefs.FirstOrDefault(b => b.IsCurrent);
        _refs.Clear();
        Summary = TagText.ToEditable(brief?.Summary ?? c.Summary, _refs);
        Conclusion = TagText.ToEditable(brief?.WorkingAssessment, _refs);
        Outcome = null;
        _prefilledFor = c.Id;
    }

    /// <summary>The draft is spent (closed) or thrown away.</summary>
    public void Discard()
    {
        Open = false;
        _prefilledFor = null;
        AiReply = null;
        Error = null;
    }

    /// <summary>The text with its [[name]] tags turned back into entity links and citations.</summary>
    public string? Linked(Case c, string? text) =>
        TagText.FromEditable(text, _refs, c.Entities.Select(e => (e.Id, e.Label, e.Value)));

    /// <summary>Close is refused until the outcome, the text and the gate are in order.</summary>
    public bool CloseDisabled =>
        (Transition.NeedsOverride && string.IsNullOrWhiteSpace(Transition.Override))
        || Transition.RationaleError(Conclusion) is not null
        || Transition.When is null
        || string.IsNullOrWhiteSpace(Outcome) || string.IsNullOrWhiteSpace(Summary) || string.IsNullOrWhiteSpace(Conclusion);
}
