using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Import;

/// <summary>Options that tune the generated AI prompt (PROD-32).</summary>
/// <param name="TargetIsExisting">True when the import will land in an already-chosen case, so the AI must
/// NOT emit a target block (the analyst selects the case in CaseBook).</param>
/// <param name="Classification">An optional classification hint for a new case; null lists the choices.</param>
/// <param name="ToolName">The analyst's AI tool, used only to phrase the <c>origin</c> provenance value.</param>
/// <param name="TimeZone">BUG-636: the zone local times in the material are in when it doesn't say (an IANA id, such as
/// the organization's America/New_York). The AI keeps such times as written and names the zone, rather than converting
/// them to UTC itself.</param>
/// <param name="Exercise">BUG-635: the new case is a tabletop / exercise case.</param>
/// <param name="Origin">Who found the new case: internal detection, or a vendor (third-party); null lets the AI tell from
/// the material.</param>
public sealed record CaseImportPromptOptions(
    bool TargetIsExisting = false, Classification? Classification = null, string? ToolName = null,
    string? TimeZone = null, bool Exercise = false, CaseOrigin? Origin = null);

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

        // null classification = Complex Event, so offer it alongside the ladder values.
        var classifications = "ComplexEvent, " + Names<Classification>();

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
        // BUG-636: converting local times to UTC is where an AI slips (daylight saving), so times are kept as stated.
        sb.AppendLine("- Write every timestamp as ISO-8601. Keep each time as the material states it: with its UTC offset when");
        sb.AppendLine("  the material gives one (e.g. \"2026-09-19T09:05:00-04:00\"), or with Z when it's in UTC. Don't convert times.");
        if (!string.IsNullOrWhiteSpace(o.TimeZone))
            sb.AppendLine(CultureInfo.InvariantCulture,
                $"- Times the material gives without a time zone are in {o.TimeZone.Trim()}: write them without an offset and set \"timeZone\": \"{o.TimeZone.Trim()}\".");
        else
            sb.AppendLine("- Times the material gives without a time zone: write them without an offset, and set \"timeZone\" to the zone they're in (an IANA id such as America/New_York).");
        sb.AppendLine("- Create one timeline entry per distinct event, in the order events happened.");
        sb.AppendLine("- Leave indicators exactly as written, including any \"defanged\" form (hxxp://, 1.1.1[.]1,");
        sb.AppendLine("  user[at]example.com) — CaseBook normalizes them. Do not add or remove indicators.");
        sb.AppendLine("- Use only the values listed under ALLOWED VALUES for each enum field; if unsure, omit it.");
        sb.AppendLine(CultureInfo.InvariantCulture, $"- Set the top-level \"origin\" to how this document was produced: \"{originExample}\". It is NOT who found the");
        sb.AppendLine("  incident; that is the case's own origin" + (o.TargetIsExisting ? ", which is already set." : ", in the target block."));
        if (!o.TargetIsExisting)
        {
            if (o.Origin == CaseOrigin.ThirdParty)
                sb.AppendLine("- This incident was disclosed to us by a vendor (a third party): the case's origin is ThirdParty, and vendorName is the vendor's name.");
            else if (o.Origin == CaseOrigin.InternalDetection)
                sb.AppendLine("- This incident was found by our own monitoring or staff: the case's origin is InternalDetection.");
            else
                sb.AppendLine("- The case's origin: ThirdParty when a vendor or other third party told us about an incident on their side (then set vendorName to them), InternalDetection when our own monitoring or staff found it.");
        }
        // A third-party case's event steps are two kinds; what tells them apart is the attack detail.
        sb.AppendLine("- Event steps (kind Event) record what happened in the incident. When a vendor disclosed it, they are of two kinds:");
        sb.AppendLine("  * the attacker's steps: give each its ATT&CK \"tactics\" (and \"techniqueId\" when the material makes it clear), and");
        sb.AppendLine("    \"environment\": Vendor when it happened in the vendor's systems, Ours when the attacker reached our systems;");
        sb.AppendLine("  * the disclosure milestones (what the vendor told us and what we confirmed): no tactics, technique or environment,");
        sb.AppendLine("    and type Notified, ScopeConfirmed, DataConfirmed, Remediation or RegulatoryNotification.");
        sb.AppendLine("  When we found it ourselves, every event step is the attacker's: give its tactics (and technique when clear), no environment.");
        sb.AppendLine("  Use ATT&CK only as the material supports it; never guess a technique.");
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
            sb.AppendLine("      \"severity\": \"<one of the severities in FIELDS>\",");
            sb.AppendLine(o.Origin is { } fixedOrigin
                ? $"      \"origin\": \"{fixedOrigin}\","
                : "      \"origin\": \"<InternalDetection or ThirdParty>\",");
            sb.AppendLine(o.Exercise
                ? "      \"vendorName\": \"<for ThirdParty: the vendor that disclosed it; omit otherwise>\","
                : "      \"vendorName\": \"<for ThirdParty: the vendor that disclosed it; omit otherwise>\"");
            if (o.Exercise) sb.AppendLine("      \"exercise\": true");   // BUG-635: a tabletop case
            sb.AppendLine("    }");
            sb.AppendLine("  },");
        }
        sb.AppendLine("  \"timeZone\": \"<the zone of times written without an offset, e.g. America/New_York; omit if none>\",");
        sb.AppendLine("  \"summary\": \"<a concise narrative summary of the matter>\",");
        sb.AppendLine("  \"timeline\": [");
        sb.AppendLine("    { \"occurredAt\": \"<ISO-8601 date-time>\", \"timePrecision\": \"<optional, Event only>\", \"occurredUntil\": \"<Window only>\",");
        sb.AppendLine("      \"kind\": \"<kind>\", \"type\": \"<type>\",");
        sb.AppendLine("      \"tactics\": [\"<Event only, attacker's steps: ATT&CK tactics>\"], \"techniqueId\": \"<optional, e.g. T1566.001>\",");
        sb.AppendLine("      \"environment\": \"<vendor-disclosed attacker's steps only: Vendor or Ours>\",");
        sb.AppendLine("      \"description\": \"<what happened>\", \"source\": \"<optional: where this came from>\" }");
        sb.AppendLine("  ],");
        sb.AppendLine("  \"entities\": [");
        sb.AppendLine("    { \"type\": \"<optional — auto-detected if omitted>\", \"value\": \"<the indicator>\",");
        sb.AppendLine("      \"label\": \"<optional>\", \"disposition\": \"<optional>\", \"source\": \"<optional>\" }");
        sb.AppendLine("  ],");
        sb.AppendLine("  \"actionItems\": [");
        sb.AppendLine("    { \"title\": \"<follow-up task>\", \"owner\": \"<optional>\", \"dueAt\": \"<optional ISO-8601 date-time>\" }");
        sb.AppendLine("  ]");
        sb.AppendLine("}");
        sb.AppendLine();
        sb.AppendLine("GUIDANCE");
        sb.AppendLine("- timePrecision (kind Event only): never invent a time the material doesn't give. A date without a time is Day; \"between March 2 and 5\" is Window with occurredUntil; \"on or before\" is OnOrBefore; a step the material puts in order but gives no date for is NotStated, listed right after the step it follows. List event steps in the order the material gives them.");
        sb.AppendLine("- A timeline entry of type Decision records something the team decided: put the decision in description, why in rationale (required), and optionally optionsConsidered and decidedBy.");
        sb.AppendLine();
        // Generated from the import schema itself, so a field added to the importer is in the prompt without anyone
        // remembering to add it here.
        sb.AppendLine("FIELDS (every field the importer reads, with its allowed values)");
        AppendFields(sb, o.TargetIsExisting);
        sb.AppendLine();
        sb.AppendLine("SOURCE MATERIAL");
        sb.AppendLine(CultureInfo.InvariantCulture, $"<< Paste the emails, chat logs, and notes here, then give this whole prompt to {tool}. >>");

        return sb.ToString();
    }

    private static string Names<TEnum>() where TEnum : struct, Enum => string.Join(", ", Enum.GetNames<TEnum>());

    /// <summary>
    /// One line per field of <see cref="CaseImportSchema"/>: its path (arrays as <c>timeline[]</c>), whether it's required,
    /// its description and its allowed values. Deprecated names are left out, and so is the target when the case is
    /// already chosen.
    /// </summary>
    internal static void AppendFields(StringBuilder sb, bool targetIsExisting)
    {
        var root = JsonNode.Parse(CaseImportSchema.Build())!.AsObject();
        var defs = root["$defs"]!.AsObject();
        Walk(sb, "", root, defs, targetIsExisting);
    }

    /// <summary>The field paths <see cref="AppendFields"/> writes, for a test to hold the prompt to the schema.</summary>
    internal static IReadOnlyList<string> FieldPaths(bool targetIsExisting)
    {
        var sb = new StringBuilder();
        AppendFields(sb, targetIsExisting);
        return sb.ToString().Split(Environment.NewLine.ToCharArray(), StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.TrimStart('-', ' ').Split(' ', ':')[0]).ToList();
    }

    private static void Walk(StringBuilder sb, string path, JsonObject obj, JsonObject defs, bool targetIsExisting)
    {
        if (obj["properties"] is not JsonObject props) return;
        var required = (obj["required"] as JsonArray)?.Select(r => r?.GetValue<string>()).ToHashSet() ?? [];
        foreach (var (name, node) in props)
        {
            if (node is not JsonObject p || p["deprecated"]?.GetValue<bool>() == true) continue;
            if (path.Length == 0 && name == "target" && targetIsExisting) continue;
            var full = path.Length == 0 ? name : $"{path}.{name}";
            var isArray = p["type"]?.GetValue<string>() == "array";
            var shape = isArray ? p["items"] as JsonObject : p;
            if (shape?["$ref"]?.GetValue<string>() is { } reference)
            {
                var def = defs[reference.Split('/')[^1]]!.AsObject();
                if (!string.IsNullOrWhiteSpace(p["description"]?.GetValue<string>()))
                    sb.AppendLine(CultureInfo.InvariantCulture, $"- {full}{(isArray ? "[]" : "")}: {p["description"]!.GetValue<string>()}");
                Walk(sb, full + (isArray ? "[]" : ""), def, defs, targetIsExisting);
                continue;
            }
            var line = new StringBuilder("- ").Append(full).Append(isArray ? "[]" : "");
            if (required.Contains(name)) line.Append(" (required)");
            line.Append(':');
            if (p["description"]?.GetValue<string>() is { Length: > 0 } description) line.Append(' ').Append(description);
            if (shape?["enum"] is JsonArray values)
                line.Append(" One of: ").Append(string.Join(", ", values.Select(v => v?.ToString()))).Append('.');
            if (shape?["const"] is { } constant) line.Append(" Exactly ").Append(constant.ToJsonString()).Append('.');
            sb.AppendLine(line.ToString());
        }
    }
}
