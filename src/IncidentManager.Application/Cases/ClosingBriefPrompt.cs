using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using IncidentManager.Application.Content;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>An outcome the AI may suggest: its stable key, label and what it means.</summary>
public sealed record ClosingOutcomeOption(string Key, string Label, string? Description);

/// <summary>The parts of a pasted closing-brief draft that were found; null when a part wasn't.</summary>
public sealed record ClosingBriefDraft(string? WhatHappened, string? Conclusion, string? OutcomeKey);

/// <summary>
/// HR-18: bring-your-own-AI help with the closing brief. Builds a copy-paste prompt holding the case's own record
/// (the drafted account, the brief, the investigation timeline, verdicts and task results) for the analyst to run
/// in their organisation's approved AI tool, and reads the reply back into the close dialog's fields for the analyst
/// to edit. CaseBook never calls an AI: this only produces and parses text. Nothing is saved until the analyst closes
/// the case. Pure, so it's unit-tested.
/// </summary>
public static partial class ClosingBriefPrompt
{
    public const string WhatHappenedHeading = "WHAT HAPPENED:";
    public const string ConclusionHeading = "CONCLUSION:";
    public const string OutcomeHeading = "OUTCOME:";

    /// <summary>The most timeline entries the prompt carries (the newest are dropped past it, with a note).</summary>
    public const int MaxEntries = 80;

    private const int MaxEntryLength = 600;

    /// <param name="narrative">The deterministic account of the case (<see cref="Lessons.CaseNarrative.Draft"/>).</param>
    /// <param name="results">Each task's latest result (<see cref="TaskResults.Latest"/>).</param>
    /// <param name="userName">Resolves a user id to a display name.</param>
    public static string Build(Case c, string narrative, IReadOnlyList<ClosingOutcomeOption> outcomes,
        IReadOnlyDictionary<Guid, TaskResult> results, Func<string?, string> userName)
    {
        var sb = new StringBuilder();
        sb.AppendLine("You are helping a security analyst write the closing brief for a case in CaseBook, a case-management");
        sb.AppendLine("system that is a book of record. The analyst will read and edit what you write before anything is saved.");
        sb.AppendLine();
        sb.AppendLine("Write three parts, using only the CASE RECORD below:");
        sb.AppendLine(CultureInfo.InvariantCulture, $"1. {WhatHappenedHeading} what happened, in two to five plain sentences, in the order it happened.");
        sb.AppendLine(CultureInfo.InvariantCulture, $"2. {ConclusionHeading} what the team concluded and on what basis (the facts that support it), in two to four");
        sb.AppendLine("   sentences. Say what is still unknown, if anything.");
        sb.AppendLine(CultureInfo.InvariantCulture, $"3. {OutcomeHeading} the one key from OUTCOMES that best fits, or \"none\" if none fits.");
        sb.AppendLine();
        sb.AppendLine("RULES");
        sb.AppendLine("- Use only facts in the case record. Do not invent times, names, indicators, causes or impact.");
        sb.AppendLine("- Neutral, factual wording: this record can be read by examiners and in litigation. No blame, no speculation,");
        sb.AppendLine("  and no legal conclusions (for example \"breach\", \"negligent\", \"compliant\") unless the record states them.");
        sb.AppendLine("- Where the record is uncertain or an open question has no answer, say so rather than resolving it.");
        sb.AppendLine("- Plain text only: no Markdown, no bullet lists, no headings other than the three below.");
        sb.AppendLine("- Reply in exactly this form:");
        sb.AppendLine();
        sb.AppendLine(WhatHappenedHeading);
        sb.AppendLine("<text>");
        sb.AppendLine();
        sb.AppendLine(ConclusionHeading);
        sb.AppendLine("<text>");
        sb.AppendLine();
        sb.AppendLine(CultureInfo.InvariantCulture, $"{OutcomeHeading} <key>");
        sb.AppendLine();

        sb.AppendLine("OUTCOMES");
        foreach (var o in outcomes)
            sb.AppendLine(CultureInfo.InvariantCulture, $"- {o.Key}: {o.Label}{(string.IsNullOrWhiteSpace(o.Description) ? "" : " (" + o.Description.Trim() + ")")}");
        sb.AppendLine();

        sb.AppendLine("CASE RECORD");
        sb.AppendLine(CultureInfo.InvariantCulture, $"Case {c.CaseNumber}: {c.Title}");
        sb.AppendLine();
        sb.AppendLine("Account drafted from the record:");
        // The draft's "review and edit before saving" preamble is for the review editor, not the AI.
        sb.AppendLine(string.Join(Environment.NewLine, RichText.ToText(narrative).Trim().Split('\n')
            .Select(l => l.TrimEnd('\r')).SkipWhile(l => l.StartsWith("Drafted from the case record", StringComparison.Ordinal))).Trim());
        sb.AppendLine();

        if (c.Briefs.FirstOrDefault(b => b.IsCurrent) is { } brief)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"Current brief (version {brief.Version}):");
            Part(sb, "Summary", brief.Summary);
            Part(sb, "Working assessment", brief.WorkingAssessment);
            Part(sb, "Known", brief.Known);
            Part(sb, "Open questions", brief.OpenQuestions);
            // HR-02: the answers to the brief's questions, from the tasks that followed them up.
            var answers = c.ActionItems.Where(t => t.FollowsUpQuestion).ToList();
            if (answers.Count > 0)
            {
                sb.AppendLine("Answers to the open questions:");
                foreach (var t in answers)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"- {t.Title} {(results.TryGetValue(t.Id, out var a) ? "Answer: " + One(a.Text) : "No answer recorded.")}");
            }
            sb.AppendLine();
        }

        var entries = c.TimelineEntries.Where(e => e.Kind == TimelineKind.Investigation && e.IsCurrent)
            .OrderBy(e => e.OccurredAtUtc).ThenBy(e => e.CreatedAtUtc).ToList();
        if (entries.Count > 0)
        {
            sb.AppendLine("Investigation timeline (oldest first, UTC):");
            foreach (var e in entries.Take(MaxEntries))
            {
                var text = One(RichText.ToText(e.Description));
                if (e.Type == TimelineEntryType.Decision && !string.IsNullOrWhiteSpace(e.Rationale))
                    text += " Why: " + One(e.Rationale);
                sb.AppendLine(CultureInfo.InvariantCulture, $"- {Stamp(e.OccurredAtUtc)} [{e.Type}] {Clip(text)}");
            }
            if (entries.Count > MaxEntries)
                sb.AppendLine(CultureInfo.InvariantCulture, $"({entries.Count - MaxEntries} later entries not included.)");
            sb.AppendLine();
        }

        var assessed = c.Entities.Where(e => e.Disposition is EntityDisposition.Malicious or EntityDisposition.Compromised
            or EntityDisposition.Suspicious or EntityDisposition.Benign).OrderBy(e => e.Disposition).ToList();
        if (assessed.Count > 0)
        {
            sb.AppendLine("Entities and indicators with a verdict:");
            foreach (var e in assessed)
                sb.AppendLine(CultureInfo.InvariantCulture, $"- {e.Type} {(string.IsNullOrWhiteSpace(e.Label) ? e.Value : $"{e.Label} ({e.Value})")}: {e.Disposition}");
            sb.AppendLine();
        }

        var done = c.ActionItems.Where(t => t.Status == ActionItemStatus.Done && !t.FollowsUpQuestion && results.ContainsKey(t.Id))
            .OrderBy(t => t.CompletedAtUtc).ToList();
        if (done.Count > 0)
        {
            sb.AppendLine("Completed tasks and their results:");
            foreach (var t in done)
                sb.AppendLine(CultureInfo.InvariantCulture,
                    $"- {t.Title}{(t.CompletedAtUtc is { } at ? $" (done {Stamp(at)}{(t.CompletedBy is { } by ? " by " + userName(by) : "")})" : "")}: {Clip(One(results[t.Id].Text))}");
            sb.AppendLine();
        }
        return sb.ToString().TrimEnd() + Environment.NewLine;
    }

    /// <summary>
    /// Reads an AI reply back: the text after "WHAT HAPPENED:" and "CONCLUSION:" (tolerating Markdown bold, a
    /// leading number, and text on the heading's own line), and the suggested outcome key when it's one of
    /// <paramref name="outcomeKeys"/>. Parts longer than a brief allows are cut to fit.
    /// </summary>
    public static ClosingBriefDraft Parse(string? reply, IEnumerable<string> outcomeKeys)
    {
        if (string.IsNullOrWhiteSpace(reply)) return new(null, null, null);
        var text = reply.Replace("\r\n", "\n").Replace("**", "").Replace("__", "");
        var heads = Heading().Matches(text).Cast<Match>().ToList();
        string? Section(string name)
        {
            var i = heads.FindIndex(m => m.Groups["name"].Value.Replace(" ", "").Equals(name, StringComparison.OrdinalIgnoreCase));
            if (i < 0) return null;
            var start = heads[i].Index + heads[i].Length;
            var end = i + 1 < heads.Count ? heads[i + 1].Index : text.Length;
            var body = text[start..end].Trim();
            return body.Length == 0 ? null : body.Length <= CaseBrief.MaxPartLength ? body : body[..CaseBrief.MaxPartLength];
        }
        var outcome = Section("OUTCOME")?.Split(['\n', ' ', '.', ','], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        var key = outcome is null ? null : outcomeKeys.FirstOrDefault(k => k.Equals(outcome.Trim('"', '\'', '`'), StringComparison.OrdinalIgnoreCase));
        return new(Section("WHATHAPPENED"), Section("CONCLUSION"), key);
    }

    [GeneratedRegex(@"^[\s>#*\-\d.)]*(?<name>what\s+happened|conclusion|outcome)\s*:", RegexOptions.IgnoreCase | RegexOptions.Multiline)]
    private static partial Regex Heading();

    private static void Part(StringBuilder sb, string label, string? markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown)) return;
        sb.AppendLine(CultureInfo.InvariantCulture, $"{label}:");
        sb.AppendLine(RichText.ToText(markdown).Trim());
    }

    private static string One(string text) => string.Join(' ', text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)).Trim();

    private static string Clip(string text) => text.Length <= MaxEntryLength ? text : text[..(MaxEntryLength - 1)].TrimEnd() + "…";

    private static string Stamp(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
}
