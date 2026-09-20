using System.Globalization;
using System.Text;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Import;

/// <summary>Options that tune the generated AI prompt (PROD-32).</summary>
/// <param name="TargetIsExisting">True when the import will land in an already-chosen case, so the AI must
/// NOT emit a target block (the analyst selects the case in CaseBook).</param>
/// <param name="Classification">An optional classification hint for a new case; null lists the choices.</param>
/// <param name="ToolName">The analyst's AI tool, used only to phrase the <c>origin</c> provenance value.</param>
public sealed record CaseImportPromptOptions(
    bool TargetIsExisting = false, Classification? Classification = null, string? ToolName = null);

/// <summary>
/// PROD-32: builds a copy-paste prompt that instructs an analyst's <b>own</b> AI (e.g. Microsoft Copilot) to
/// turn raw incident material — emails, chat logs, notes — into a <see cref="CaseImportDocument"/> that
/// PROD-31 imports. CaseBook never calls an LLM; this only produces text for the analyst to run elsewhere.
/// The schema, allowed enum values and example are derived from the real types, so the prompt cannot drift
/// from what the importer accepts. Pure — unit-tested.
/// </summary>
public static class CaseImportPrompt
{
    public static string Build(CaseImportPromptOptions? options = null)
    {
        var o = options ?? new CaseImportPromptOptions();
        var tool = string.IsNullOrWhiteSpace(o.ToolName) ? "your AI tool" : o.ToolName.Trim();
        var originExample = string.IsNullOrWhiteSpace(o.ToolName) ? "AI-assisted" : $"AI-assisted ({o.ToolName.Trim()})";

        var kinds = Names<TimelineKind>();
        var timelineTypes = Names<TimelineEntryType>();
        var entityTypes = Names<EntityType>();
        var dispositions = Names<EntityDisposition>();
        // null classification = Complex Event, so offer it alongside the ladder values.
        var classifications = "ComplexEvent, " + Names<Classification>();
        var severities = Names<Severity>();
        var origins = Names<CaseOrigin>();

        var sb = new StringBuilder();
        sb.AppendLine("You are turning raw incident material (emails, chat logs, and notes) into a single structured");
        sb.AppendLine("JSON document that will be imported into CaseBook, a security case-management system. A human");
        sb.AppendLine("analyst reviews and edits every field before anything is saved, so accuracy matters more than");
        sb.AppendLine("completeness.");
        sb.AppendLine();
        sb.AppendLine("Read the SOURCE MATERIAL at the end and produce ONE JSON object matching the SCHEMA below.");
        sb.AppendLine("(A machine-readable JSON Schema for this format is published at /api/import/cases/schema.)");
        sb.AppendLine();
        sb.AppendLine("OUTPUT RULES");
        sb.AppendLine("- Output ONLY the JSON object — no prose, no explanation, no Markdown code fences.");
        sb.AppendLine("- Use only facts present in the source material. Do NOT invent indicators, times, names, or");
        sb.AppendLine("  events. If a field is unknown, omit it.");
        sb.AppendLine("- All timestamps must be ISO-8601 in UTC, e.g. \"2026-09-19T13:05:00Z\".");
        sb.AppendLine("- Create one timeline entry per distinct event, in the order events happened.");
        sb.AppendLine("- Leave indicators exactly as written, including any \"defanged\" form (hxxp://, 1.1.1[.]1,");
        sb.AppendLine("  user[at]example.com) — CaseBook normalizes them. Do not add or remove indicators.");
        sb.AppendLine("- Use only the values listed under ALLOWED VALUES for each enum field; if unsure, omit it.");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- Set \"origin\" to how this was produced: \"{originExample}\".");
        sb.AppendLine();
        sb.AppendLine("SCHEMA");
        sb.AppendLine("{");
        sb.AppendLine(CultureInfo.InvariantCulture, $"  \"format\": \"{CaseImportJson.FormatTag}\",        // required, exactly this string");
        sb.AppendLine(CultureInfo.InvariantCulture, $"  \"schemaVersion\": {CaseImportJson.CurrentSchemaVersion},                      // required");
        sb.AppendLine(CultureInfo.InvariantCulture, $"  \"origin\": \"{originExample}\",");
        if (o.TargetIsExisting)
        {
            sb.AppendLine("  // Do NOT include a \"target\" — the case is already selected in CaseBook.");
        }
        else
        {
            var clsField = o.Classification is { } c
                ? $"\"{c}\""
                : $"\"<one of: {classifications}>\"";
            sb.AppendLine("  \"target\": {");
            sb.AppendLine("    \"newCase\": {");
            sb.AppendLine("      \"title\": \"<a short, specific case title>\",");
            sb.AppendLine(CultureInfo.InvariantCulture, $"      \"classification\": {clsField},");
            sb.AppendLine("      \"severity\": \"<one of the severities below>\"");
            sb.AppendLine("    }");
            sb.AppendLine("  },");
        }
        sb.AppendLine("  \"summary\": \"<a concise narrative summary of the matter>\",");
        sb.AppendLine("  \"timeline\": [");
        sb.AppendLine("    { \"occurredAtUtc\": \"<ISO-8601 UTC>\", \"kind\": \"<kind>\", \"type\": \"<type>\",");
        sb.AppendLine("      \"description\": \"<what happened>\", \"source\": \"<optional: where this came from>\" }");
        sb.AppendLine("  ],");
        sb.AppendLine("  \"entities\": [");
        sb.AppendLine("    { \"type\": \"<optional — auto-detected if omitted>\", \"value\": \"<the indicator>\",");
        sb.AppendLine("      \"label\": \"<optional>\", \"disposition\": \"<optional>\", \"source\": \"<optional>\" }");
        sb.AppendLine("  ],");
        sb.AppendLine("  \"actionItems\": [");
        sb.AppendLine("    { \"title\": \"<follow-up task>\", \"owner\": \"<optional>\", \"dueAtUtc\": \"<optional ISO-8601 UTC>\" }");
        sb.AppendLine("  ]");
        sb.AppendLine("}");
        sb.AppendLine();
        sb.AppendLine("ALLOWED VALUES");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- timeline.kind: {kinds}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- timeline.type: {timelineTypes}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- entities.type: {entityTypes}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- entities.disposition: {dispositions}");
        if (!o.TargetIsExisting)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"- target.newCase.classification: {classifications}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- target.newCase.severity: {severities}");
            sb.AppendLine(CultureInfo.InvariantCulture, $"- target.newCase.origin (optional): {origins}");
        }
        sb.AppendLine();
        sb.AppendLine("SOURCE MATERIAL");
        sb.AppendLine(CultureInfo.InvariantCulture, $"<< Paste the emails, chat logs, and notes here, then give this whole prompt to {tool}. >>");

        return sb.ToString();
    }

    private static string Names<TEnum>() where TEnum : struct, Enum => string.Join(", ", Enum.GetNames<TEnum>());
}
