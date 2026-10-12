using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using IncidentManager.Domain.Enums;
using IncidentManager.Application.Common;

namespace IncidentManager.Application.Import;

/// <summary>What a pasted/uploaded import turned out to be.</summary>
public enum ImportSourceFormat
{
    /// <summary>CaseBook's own case-import document (PROD-31) — passed through untouched.</summary>
    CaseImport,
    /// <summary>A STIX 2.1 bundle (a partner share, a TIP export, or CaseBook's own E-07 export).</summary>
    StixBundle,
    /// <summary>A CSV of indicators (a vendor list, a blocklist, or CaseBook's own IOC feed export).</summary>
    IocCsv,
}

/// <summary>The outcome of converting an import: the document to preview (or an error), and conversion notes.</summary>
public sealed record IocImportConversion(ImportSourceFormat Format, CaseImportDocument? Document, string? Error,
    IReadOnlyList<string> Notes)
{
    public bool Ok => Document is not null;
}

/// <summary>
/// PROD-06: the inverse of <see cref="Export.StixExportService"/> and the IOC feed CSV. Converts a STIX 2.1
/// bundle or an indicator CSV into a <see cref="CaseImportDocument"/> carrying only entities, so it flows
/// through the existing PROD-31 path: an editable preview, then a human-confirmed apply through the guarded,
/// audited case writes. Pure and side-effect free; the input is untrusted, so anything unrecognised is skipped
/// and counted in <see cref="IocImportConversion.Notes"/> rather than failing the whole file. Imports land in a
/// case a person chose; nothing here ingests a stream or opens cases on its own.
/// </summary>
public static partial class IocImportConverter
{
    /// <summary>Hard cap on indicators from one file — a partner share, not a feed.</summary>
    public const int MaxIndicators = 2000;

    /// <summary>Says where the parser gave up, so a truncated or hand-edited document can be fixed rather than guessed at.</summary>
    internal static string InvalidJson(JsonException ex) =>
        ex.LineNumber is { } line
            ? $"This isn't valid JSON. The problem is around line {line + 1}, character {(ex.BytePositionInLine ?? 0) + 1}. A document cut short or with text around it is the usual cause."
            : "This isn't valid JSON. Check the document and try again.";

    /// <summary>Sniffs the text and converts it. A CaseBook case-import document is returned as-is (via <see cref="CaseImportService.Parse"/>).</summary>
    /// <param name="nowUtc">BUG-169: to tell an expired indicator (<c>valid_until</c> passed); the current time when omitted.</param>
    public static IocImportConversion Convert(string? text, string? fileName = null, DateTimeOffset? nowUtc = null)
    {
        if (string.IsNullOrWhiteSpace(text))
            return new(ImportSourceFormat.CaseImport, null, "Paste or upload a document first.", []);

        var trimmed = text.TrimStart('﻿', ' ', '\t', '\r', '\n');
        if (trimmed.StartsWith('{'))
        {
            JsonDocument json;
            try { json = JsonDocument.Parse(trimmed, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip }); }
            catch (JsonException ex) { return new(ImportSourceFormat.CaseImport, null, InvalidJson(ex), []); }

            using (json)
            {
                var root = json.RootElement;
                if (root.ValueKind == JsonValueKind.Object && Str(root, "type") == "bundle")
                    return FromStix(root, nowUtc ?? DateTimeOffset.UtcNow);
            }
            var parsed = CaseImportService.Parse(trimmed);
            return new(ImportSourceFormat.CaseImport, parsed.Document, parsed.Error, []);
        }

        return FromCsv(trimmed, fileName);
    }

    // ------------------------------------------------------------------ STIX 2.1

    private static IocImportConversion FromStix(JsonElement bundle, DateTimeOffset nowUtc)
    {
        if (!bundle.TryGetProperty("objects", out var objects) || objects.ValueKind != JsonValueKind.Array)
            return new(ImportSourceFormat.StixBundle, null, "This STIX bundle has no objects.", []);

        var entities = new List<CaseImportEntity>();
        var skipped = new SortedDictionary<string, int>(StringComparer.Ordinal);
        var unparsedPatterns = 0;
        var withdrawn = 0;   // BUG-169
        string? producer = null;
        var markings = TlpMarkings(objects);   // BUG-152

        foreach (var o in objects.EnumerateArray())
        {
            if (o.ValueKind != JsonValueKind.Object) continue;
            var type = Str(o, "type") ?? "";
            switch (type)
            {
                case "identity":
                    producer ??= Str(o, "name");
                    break;
                case "indicator":
                    // BUG-169: an indicator its producer revoked (a false positive withdrawn) or that is past valid_until no
                    // longer asserts anything, and imported as Malicious it would reach the blocking feed.
                    if ((o.TryGetProperty("revoked", out var rv) && rv.ValueKind == JsonValueKind.True)
                        || (Str(o, "valid_until") is { } until && DateTimeOffset.TryParse(until, System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.AssumeUniversal, out var u) && u <= nowUtc))
                    {
                        withdrawn++;
                        break;
                    }
                    var found = PatternObservables(Str(o, "pattern"));
                    if (found.Count == 0) { unparsedPatterns++; break; }
                    // An indicator SDO is a producer's assertion about what it matches; carry its name/description,
                    // and its verdict from indicator_types (BUG-123: an allow-list "benign" entry isn't malicious).
                    var verdict = IndicatorVerdict(o);
                    foreach (var (t, v) in found)
                        entities.Add(new CaseImportEntity
                        {
                            Type = t.ToString(), Value = v, Disposition = verdict.ToString(),
                            Label = Str(o, "name"), Description = Str(o, "description"), Tlp = MarkingOf(o, markings),
                        });
                    break;
                case "relationship" or "report" or "marking-definition" or "extension-definition" or "language-content":
                    skipped[type] = skipped.GetValueOrDefault(type) + 1;
                    break;
                default:
                    if (FromSco(type, o) is { } e) { e.Tlp = MarkingOf(o, markings); entities.Add(e); }
                    else skipped[type] = skipped.GetValueOrDefault(type) + 1;
                    break;
            }
        }

        var notes = new List<string>();
        if (withdrawn > 0)
            notes.Add($"{Plural.Of(withdrawn, "STIX indicator")} {(withdrawn == 1 ? "was" : "were")} revoked or past {(withdrawn == 1 ? "its" : "their")} valid_until, " +
                      $"so {(withdrawn == 1 ? "it wasn't" : "they weren't")} imported.");
        if (unparsedPatterns > 0)
            notes.Add($"{Plural.Of(unparsedPatterns, "STIX indicator pattern")} {(unparsedPatterns == 1 ? "was" : "were")} too complex to read (only simple \"[type:property = 'value']\" comparisons are imported).");
        if (skipped.Count > 0)
            notes.Add("Not imported (no matching CaseBook entity): " +
                      string.Join(", ", skipped.Select(kv => $"{kv.Value} × {kv.Key}")) + ".");

        return Finish(ImportSourceFormat.StixBundle, entities, notes,
            producer is null ? "STIX 2.1 bundle" : $"STIX 2.1 bundle ({producer})", "This STIX bundle has no indicators CaseBook can import.");
    }

    // BUG-152: the TLP marking-definitions STIX 2.1 defines (TLP 2.0, then TLP 1.0, whose WHITE is CLEAR).
    private static readonly Dictionary<string, TlpLevel> WellKnownTlp = new(StringComparer.OrdinalIgnoreCase)
    {
        ["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"] = TlpLevel.Clear,
        ["marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb"] = TlpLevel.Green,
        ["marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421"] = TlpLevel.Amber,
        ["marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003"] = TlpLevel.AmberStrict,
        ["marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1"] = TlpLevel.Red,
        ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"] = TlpLevel.Clear,
        ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"] = TlpLevel.Green,
        ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"] = TlpLevel.Amber,
        ["marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"] = TlpLevel.Red,
    };

    /// <summary>
    /// BUG-152: the TLP marking-definitions a bundle can refer to: the well-known ones, plus any it carries itself (a TLP
    /// 1.0 <c>definition.tlp</c>, or a name like "TLP:AMBER+STRICT").
    /// </summary>
    private static Dictionary<string, TlpLevel> TlpMarkings(JsonElement objects)
    {
        var map = new Dictionary<string, TlpLevel>(WellKnownTlp, StringComparer.OrdinalIgnoreCase);
        foreach (var o in objects.EnumerateArray())
        {
            if (o.ValueKind != JsonValueKind.Object || Str(o, "type") != "marking-definition" || Str(o, "id") is not { } id
                || map.ContainsKey(id)) continue;
            var named = o.TryGetProperty("definition", out var d) && Str(d, "tlp") is { } tlp ? tlp : Str(o, "name");
            if ((named is not null && named.Trim().StartsWith("TLP", StringComparison.OrdinalIgnoreCase)) || Str(o, "definition_type") == "tlp")
                if (CaseImportService.ParseTlp(named, []) is { } level) map[id] = level;
        }
        return map;
    }

    /// <summary>BUG-152: the most restrictive TLP an object's <c>object_marking_refs</c> name, as a TLP level name.</summary>
    private static string? MarkingOf(JsonElement o, Dictionary<string, TlpLevel> markings)
    {
        if (!o.TryGetProperty("object_marking_refs", out var refs) || refs.ValueKind != JsonValueKind.Array) return null;
        TlpLevel? most = null;
        foreach (var r in refs.EnumerateArray())
            if (r.ValueKind == JsonValueKind.String && markings.TryGetValue(r.GetString()!, out var level) && (most is null || level > most))
                most = level;
        return most?.ToString();
    }

    /// <summary>Maps a STIX cyber-observable (or CaseBook's custom artifact SCO) to an entity, keeping the x_casebook_* round-trip fields.</summary>
    private static CaseImportEntity? FromSco(string stixType, JsonElement o)
    {
        (EntityType Type, string? Value)? mapped = stixType switch
        {
            "ipv4-addr" or "ipv6-addr" => (EntityType.IpAddress, Str(o, "value")),
            "domain-name" => (EntityType.Domain, Str(o, "value")),
            "url" => (EntityType.Url, Str(o, "value")),
            "email-addr" => (EntityType.EmailAddress, Str(o, "value")),
            "file" => FileObservable(o),
            "windows-registry-key" => (EntityType.RegistryKey, Str(o, "key")),
            "user-account" => (EntityType.Account, Str(o, "account_login") ?? Str(o, "user_id")),
            "process" => (EntityType.Process, Str(o, "command_line") ?? Str(o, "name")),
            "x-casebook-artifact" => (EntityType.Other, Str(o, "value")),
            _ => null,
        };
        if (mapped is not { Value: { Length: > 0 } value } m) return null;

        // Our own export carries the precise entity type (e.g. Host behind x-casebook-artifact) and the verdict.
        var type = ImportEnums.TryName<EntityType>(Str(o, "x_casebook_entity_type"), out var t) ? t : m.Type;
        return new CaseImportEntity
        {
            Type = type.ToString(), Value = value,
            Disposition = Str(o, "x_casebook_disposition"),
            Label = Str(o, "x_casebook_label"),
            Description = Str(o, "x_casebook_description"),
            Source = Str(o, "x_casebook_source"),
        };
    }

    private static (EntityType, string?) FileObservable(JsonElement o)
    {
        if (o.TryGetProperty("hashes", out var hashes) && hashes.ValueKind == JsonValueKind.Object)
        {
            // Prefer the strongest digest present.
            foreach (var alg in new[] { "SHA-256", "SHA256", "SHA-1", "SHA1", "MD5" })
                if (Str(hashes, alg) is { Length: > 0 } h) return (EntityType.FileHash, h);
            foreach (var p in hashes.EnumerateObject())
                if (p.Value.ValueKind == JsonValueKind.String) return (EntityType.FileHash, p.Value.GetString());
        }
        return (EntityType.FileName, Str(o, "name"));
    }

    [GeneratedRegex(@"\[\s*(?<obj>[a-z0-9-]+)\s*:\s*(?<prop>[a-z0-9_.'\-]+)\s*=\s*'(?<val>(?:[^'\\]|\\.)*)'\s*\]", RegexOptions.IgnoreCase)]
    private static partial Regex SimpleComparison();

    /// <summary>The observables in a STIX pattern made of simple equality comparisons (joined by OR/AND).</summary>
    public static List<(EntityType Type, string Value)> PatternObservables(string? pattern)
    {
        var result = new List<(EntityType, string)>();
        if (string.IsNullOrWhiteSpace(pattern)) return result;
        foreach (Match m in SimpleComparison().Matches(pattern))
        {
            var obj = m.Groups["obj"].Value.ToLowerInvariant();
            var prop = m.Groups["prop"].Value.ToLowerInvariant();
            var val = m.Groups["val"].Value.Replace("\\'", "'").Replace("\\\\", "\\");
            EntityType? t = obj switch
            {
                "ipv4-addr" or "ipv6-addr" when prop == "value" => EntityType.IpAddress,
                "domain-name" when prop == "value" => EntityType.Domain,
                "url" when prop == "value" => EntityType.Url,
                "email-addr" when prop == "value" => EntityType.EmailAddress,
                "file" when prop.StartsWith("hashes.", StringComparison.Ordinal) => EntityType.FileHash,
                "file" when prop == "name" => EntityType.FileName,
                "windows-registry-key" when prop == "key" => EntityType.RegistryKey,
                "user-account" when prop is "account_login" or "user_id" => EntityType.Account,
                _ => null,
            };
            if (t is { } type && val.Length > 0) result.Add((type, val));
        }
        return result;
    }

    // ------------------------------------------------------------------ CSV

    private static IocImportConversion FromCsv(string text, string? fileName)
    {
        var rows = ParseCsv(text)
            .Where(r => r.Count > 0 && !(r.Count == 1 && r[0].Length == 0))
            .Where(r => !r[0].TrimStart().StartsWith('#'))   // comment lines (our feed's provenance line)
            .ToList();
        if (rows.Count == 0)
            return new(ImportSourceFormat.IocCsv, null, "This file has no rows to import.", []);

        // A header row names the columns; without one, the first column is the indicator.
        var header = rows[0].Select(h => h.Trim().ToLowerInvariant()).ToList();
        int Col(params string[] names) => header.FindIndex(h => names.Contains(h));
        var valueCol = Col("value", "indicator", "ioc", "observable", "indicator_value");
        var hasHeader = valueCol >= 0;
        var typeCol = hasHeader ? Col("type", "indicator_type", "ioc_type", "kind") : -1;
        var dispCol = hasHeader ? Col("disposition", "verdict", "status") : -1;
        var labelCol = hasHeader ? Col("label", "name", "title") : -1;
        var descCol = hasHeader ? Col("description", "comment", "notes", "context") : -1;
        var sourceCol = hasHeader ? Col("source", "sources", "feed", "provider") : -1;
        if (!hasHeader) valueCol = 0;

        var entities = new List<CaseImportEntity>();
        var unknownTypes = 0;
        foreach (var r in rows.Skip(hasHeader ? 1 : 0))
        {
            string? Cell(int i) => i >= 0 && i < r.Count && Clean(r[i]) is { Length: > 0 } v ? v : null;
            if (Cell(valueCol) is not { } value) continue;

            string? type = null;
            if (Cell(typeCol) is { } rawType)
            {
                type = CsvType(rawType);
                if (type is null) unknownTypes++;          // falls back to auto-detection in the preview
            }
            entities.Add(new CaseImportEntity
            {
                Type = type, Value = value,
                Disposition = Cell(dispCol) is { } d ? CsvDisposition(d) : null,
                Label = Cell(labelCol), Description = Cell(descCol), Source = Cell(sourceCol),
            });
        }

        var notes = new List<string>();
        if (unknownTypes > 0)
            notes.Add($"{Plural.Of(unknownTypes, "row")} had a type CaseBook doesn't recognize, so the type was detected from the value.");
        if (!hasHeader)
            notes.Add("No header row found, so the first column was read as the indicator.");
        var origin = string.IsNullOrWhiteSpace(fileName) ? "IOC CSV" : $"IOC CSV ({Path.GetFileName(fileName)})";
        return Finish(ImportSourceFormat.IocCsv, entities, notes, origin, "This file has no indicators to import.");
    }

    /// <summary>Feed-style type words (ours and common vendor ones) → entity type names; null if unknown.</summary>
    private static string? CsvType(string raw) => raw.Trim().ToLowerInvariant().Replace("_", "").Replace("-", "").Replace(" ", "") switch
    {
        "ip" or "ipv4" or "ipv6" or "ipaddress" or "ipv4addr" or "ipv6addr" or "ipaddr" => nameof(EntityType.IpAddress),
        "domain" or "domainname" or "fqdn" or "hostname" => nameof(EntityType.Domain),
        "url" or "uri" or "link" => nameof(EntityType.Url),
        "hash" or "filehash" or "md5" or "sha1" or "sha256" => nameof(EntityType.FileHash),
        "email" or "emailaddress" or "emailaddr" or "sender" => nameof(EntityType.EmailAddress),
        "filename" or "file" => nameof(EntityType.FileName),
        "account" or "user" or "username" or "useraccount" => nameof(EntityType.Account),
        "host" or "device" or "endpoint" => nameof(EntityType.Host),
        "process" or "commandline" => nameof(EntityType.Process),
        "registrykey" or "registry" or "regkey" => nameof(EntityType.RegistryKey),
        var other => ImportEnums.TryName<EntityType>(other, out var t) ? t.ToString() : null,
    };

    private static string? CsvDisposition(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "malicious" or "bad" or "block" or "blocked" or "confirmed" => nameof(EntityDisposition.Malicious),
        "suspicious" or "suspect" => nameof(EntityDisposition.Suspicious),
        "benign" or "clean" or "good" or "allow" or "allowed" => nameof(EntityDisposition.Benign),
        "compromised" => nameof(EntityDisposition.Compromised),
        _ => raw.Trim(),   // passes through; the preview flags an unknown value and defaults it
    };

    /// <summary>Trims a cell and undoes the formula-injection guard our own CSV exports add (a leading ').</summary>
    private static string Clean(string cell)
    {
        var v = cell.Trim();
        return v.Length > 1 && v[0] == '\'' && "=+-@\t\r".Contains(v[1]) ? v[1..] : v;
    }

    /// <summary>RFC-4180 reader: quoted fields, doubled quotes, embedded commas/newlines, CRLF or LF.</summary>
    public static List<List<string>> ParseCsv(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < text.Length; i++)
        {
            var ch = text[i];
            if (quoted)
            {
                if (ch == '"')
                {
                    if (i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                    else quoted = false;
                }
                else field.Append(ch);
                continue;
            }
            switch (ch)
            {
                case '"' when field.Length == 0: quoted = true; break;
                case ',': row.Add(field.ToString()); field.Clear(); break;
                case '\r': break;
                case '\n': row.Add(field.ToString()); field.Clear(); rows.Add(row); row = []; break;
                default: field.Append(ch); break;
            }
        }
        if (field.Length > 0 || row.Count > 0) { row.Add(field.ToString()); rows.Add(row); }
        return rows;
    }

    // ------------------------------------------------------------------ shared

    private static IocImportConversion Finish(ImportSourceFormat format, List<CaseImportEntity> entities,
        List<string> notes, string origin, string emptyError)
    {
        if (entities.Count == 0) return new(format, null, emptyError, notes);
        if (entities.Count > MaxIndicators)
        {
            notes.Add($"Only the first {MaxIndicators} of {entities.Count} indicators were read. Split the file to import the rest.");
            entities = entities.Take(MaxIndicators).ToList();
        }
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            SchemaVersion = CaseImportJson.CurrentSchemaVersion,
            Origin = origin,
            Entities = entities,
        };
        return new(format, doc, null, notes);
    }

    private static string? Str(JsonElement o, string name) =>
        o.ValueKind == JsonValueKind.Object && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()?.Trim() is { Length: > 0 } s ? s : null
            : null;

    // STIX 2.1 indicator-type-ov: "benign" and "compromised" say so; "anomalous-activity" and "unknown" are suspicions;
    // the rest ("malicious-activity", "attribution", "anonymization", or none given) mean malicious.
    private static EntityDisposition IndicatorVerdict(JsonElement o)
    {
        if (!o.TryGetProperty("indicator_types", out var types) || types.ValueKind != JsonValueKind.Array) return EntityDisposition.Malicious;
        var set = types.EnumerateArray().Where(t => t.ValueKind == JsonValueKind.String).Select(t => t.GetString()!.ToLowerInvariant()).ToHashSet();
        if (set.Contains("malicious-activity")) return EntityDisposition.Malicious;
        if (set.Contains("compromised")) return EntityDisposition.Compromised;
        if (set.Contains("benign")) return EntityDisposition.Benign;
        if (set.Contains("anomalous-activity") || set.Contains("unknown")) return EntityDisposition.Suspicious;
        return EntityDisposition.Malicious;
    }
}
