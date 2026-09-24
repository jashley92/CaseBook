namespace IncidentManager.Domain.Enums;

/// <summary>
/// PROD-45: Traffic Light Protocol 2.0 (FIRST) — how widely information may be shared. Printed on reports and, per
/// indicator, alongside IOCs. CLEAR = no limit; GREEN = the community; AMBER = recipients' organisations on a
/// need-to-know basis; AMBER+STRICT = the recipient's organisation only; RED = named recipients only.
/// </summary>
public enum TlpLevel
{
    Clear = 0,
    Green = 1,
    Amber = 2,
    AmberStrict = 3,
    Red = 4
}

public static class Tlp
{
    /// <summary>The standard marking text, e.g. "TLP:AMBER+STRICT".</summary>
    public static string Label(TlpLevel level) => level switch
    {
        TlpLevel.Clear => "TLP:CLEAR",
        TlpLevel.Green => "TLP:GREEN",
        TlpLevel.Amber => "TLP:AMBER",
        TlpLevel.AmberStrict => "TLP:AMBER+STRICT",
        TlpLevel.Red => "TLP:RED",
        _ => "TLP:AMBER"
    };

    /// <summary>What the marking means for the reader, in one line.</summary>
    public static string Meaning(TlpLevel level) => level switch
    {
        TlpLevel.Clear => "Disclosure is not limited.",
        TlpLevel.Green => "Limited disclosure: may be shared within the community, not publicly.",
        TlpLevel.Amber => "Limited disclosure: recipients may share with their organisation and its clients on a need-to-know basis.",
        TlpLevel.AmberStrict => "Limited disclosure: recipients may share only within their own organisation, on a need-to-know basis.",
        TlpLevel.Red => "For the eyes and ears of individual recipients only; no further disclosure.",
        _ => ""
    };

    /// <summary>
    /// The marking's standard colour on a black background (TLP 2.0 guidance), as an RGB hex string without '#'.
    /// </summary>
    public static string Color(TlpLevel level) => level switch
    {
        TlpLevel.Clear => "FFFFFF",
        TlpLevel.Green => "33FF00",
        TlpLevel.Red => "FF2B2B",
        _ => "FFC000"   // AMBER and AMBER+STRICT
    };

    /// <summary>
    /// Parses "AMBER", "tlp:amber+strict", "AmberStrict", "WHITE" (the TLP 1.0 name for CLEAR) and the like; null when
    /// blank or unrecognised.
    /// </summary>
    public static TlpLevel? Parse(string? value)
    {
        var v = (value ?? "").Trim().ToUpperInvariant();
        if (v.StartsWith("TLP:", StringComparison.Ordinal)) v = v[4..];
        v = v.Replace(" ", "").Replace("_", "").Replace("-", "");
        return v switch
        {
            "CLEAR" or "WHITE" => TlpLevel.Clear,
            "GREEN" => TlpLevel.Green,
            "AMBER" => TlpLevel.Amber,
            "AMBER+STRICT" or "AMBERSTRICT" => TlpLevel.AmberStrict,
            "RED" => TlpLevel.Red,
            _ => null
        };
    }
}
