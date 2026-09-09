using System.Globalization;

namespace IncidentManager.Application.Common;

/// <summary>
/// Shared CSV field encoding for every export. Combines RFC-4180 quoting with spreadsheet
/// formula-injection (CSV / DDE) neutralisation: a field that a spreadsheet would evaluate as a formula
/// when the file is opened in Excel / Google Sheets is prefixed with an apostrophe so it renders as
/// text instead. The regulatory / IOC exports carry outsider-influenced values (indicator strings,
/// evidence file names, case numbers, free-text reasons); those are exactly the fields an attacker
/// would seed with <c>=…</c>/<c>@…</c>/<c>+…</c> payloads, so every exporter routes fields through
/// here rather than quoting alone. (S-01)
/// </summary>
public static class Csv
{
    private static readonly char[] QuoteTriggers = ['"', ',', '\r', '\n'];

    /// <summary>
    /// Encodes one value for a CSV cell. First neutralises a leading formula trigger (<c>=</c>,
    /// <c>+</c>, <c>-</c>, <c>@</c>, or a leading tab/CR), then applies RFC-4180 quoting (quote when the
    /// field contains a comma, quote, CR or LF; double embedded quotes). A genuinely numeric field —
    /// including a signed number such as <c>-5</c> — is left numeric, so real data is not turned into text.
    /// </summary>
    public static string Escape(string? field)
    {
        var value = field ?? "";

        if (NeedsFormulaGuard(value))
            value = "'" + value; // the apostrophe forces text and is not shown as part of the cell value

        if (value.IndexOfAny(QuoteTriggers) < 0) return value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    private static bool NeedsFormulaGuard(string v)
    {
        if (v.Length == 0) return false;
        var c = v[0];
        if (c is '\t' or '\r') return true;   // a control-char leader never introduces a legitimate data field
        if (c is '=' or '@') return true;     // never a plain number — always a formula/DDE trigger
        if (c is not ('+' or '-')) return false;
        // '+'/'-' can lead a real signed number; only guard when the whole field is not one, so a genuine
        // negative value stays numeric rather than becoming apostrophe-prefixed text.
        return !double.TryParse(v, NumberStyles.Number, CultureInfo.InvariantCulture, out _);
    }
}
