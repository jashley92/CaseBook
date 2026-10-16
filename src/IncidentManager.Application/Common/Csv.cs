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
    /// field contains a comma, quote, CR or LF; double embedded quotes). BUG-579: the same guard is applied after
    /// each <c>;</c>, where a ';'-separator Excel starts a new cell. A genuinely numeric field —
    /// including a signed number such as <c>-5</c> — is left numeric, so real data is not turned into text.
    /// </summary>
    public static string Escape(string? field)
    {
        var value = field ?? "";

        if (NeedsFormulaGuard(value))
            value = "'" + value; // the apostrophe forces text and is not shown as part of the cell value
        if (value.Contains(';')) value = GuardAfterSemicolons(value);

        if (value.IndexOfAny(QuoteTriggers) < 0) return value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    /// <summary>
    /// Undoes <see cref="Escape"/>'s guards on a cell read back from one of our own exports (an IOC re-import): the
    /// apostrophe before the value and the one after each <c>;</c>. Plain values are returned unchanged.
    /// </summary>
    public static string Unguard(string cell)
    {
        var v = cell.Length > 1 && cell[0] == '\'' && IsTrigger(cell[1]) ? cell[1..] : cell;
        if (!v.Contains(";'", StringComparison.Ordinal)) return v;
        var sb = new System.Text.StringBuilder(v.Length);
        var i = 0;
        while (i < v.Length)
        {
            sb.Append(v[i]);
            var guarded = v[i] == ';' && i + 2 < v.Length && v[i + 1] == '\'' && (IsTrigger(v[i + 2]) || v[i + 2] == '"');
            i += guarded ? 2 : 1;   // skip the apostrophe Escape put after the ';'
        }
        return sb.ToString();
    }

    private static bool IsTrigger(char c) => c is '=' or '+' or '-' or '@' or '\t' or '\r';

    // BUG-579: Excel in a locale whose list separator is ';' (most of Europe) splits an unquoted line at every ';', and
    // honours quotes only at the start of a cell, so "x;=1+1" opened there puts =1+1 in a cell of its own and evaluates
    // it. Each piece after a ';' gets the same guard as the start of the field (a quote opening the piece is looked
    // past, since Excel would read the quoted text as the cell). Pieces that are plain text or numbers are unchanged.
    private static string GuardAfterSemicolons(string value)
    {
        var sb = new System.Text.StringBuilder(value.Length + 4);
        var start = 0;
        while (true)
        {
            var semi = value.IndexOf(';', start);
            if (semi < 0) { sb.Append(value, start, value.Length - start); break; }
            sb.Append(value, start, semi + 1 - start);
            var end = value.IndexOf(';', semi + 1);
            var piece = value[(semi + 1)..(end < 0 ? value.Length : end)];
            if (NeedsFormulaGuard(piece.StartsWith('"') ? piece[1..] : piece)) sb.Append('\'');
            start = semi + 1;
        }
        return sb.ToString();
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
