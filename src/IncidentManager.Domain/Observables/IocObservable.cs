using System.Text.RegularExpressions;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Observables;

/// <summary>
/// Normalizes "defanged" indicator notation that analysts paste — <c>hxxp://evil[.]com</c>,
/// <c>1.1.1[.]1</c>, <c>user[at]evil(dot)com</c> — back to its canonical, live form so that
/// exact-match correlation (E-08), entity deep-links (E-05), and the pushed IOC feed (E-13)
/// all operate on real values instead of verbatim defanged strings. It also produces the
/// inverse <see cref="Defang"/> form for safe on-screen copy/paste (E-19).
/// </summary>
/// <remarks>
/// Refanging is applied only to network/address indicators (<see cref="IsRefangable"/>). Hashes,
/// file names, accounts, processes and registry keys are left byte-for-byte as entered — they can
/// legitimately contain brackets or the literal text "dot"/"at", and re-writing them would corrupt
/// the observable.
/// </remarks>
public static partial class IocObservable
{
    /// <summary>Indicator types that carry defang notation and are safe to refang.</summary>
    public static bool IsRefangable(EntityType type) => type is
        EntityType.IpAddress or EntityType.Domain or EntityType.Url or EntityType.EmailAddress;

    /// <summary>
    /// Best-effort classification of a pasted indicator into an <see cref="EntityType"/> — used to
    /// auto-type IOCs captured at case creation (E-23) so the analyst doesn't pick a type per line.
    /// Only the unambiguous network/hash/email shapes are detected; anything else falls back to
    /// <see cref="EntityType.Other"/> and can be re-typed on the Entities tab. The value is refanged
    /// first, so a defanged paste (<c>1.1.1[.]1</c>, <c>hxxp://evil[.]com</c>) classifies correctly.
    /// </summary>
    public static EntityType DetectType(string? value)
    {
        var v = Refang(value);
        if (v.Length == 0) return EntityType.Other;

        if (UrlRx().IsMatch(v)) return EntityType.Url;
        if (EmailRx().IsMatch(v)) return EntityType.EmailAddress;
        // IPAddress.TryParse is lenient (it accepts partials like "1.2.3" as 1.2.0.3), so require a real
        // dotted-quad for IPv4; IPv6 is unambiguous (it always carries ':').
        if (System.Net.IPAddress.TryParse(v, out var ip) &&
            (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ||
             (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && CountDots(v) == 3)))
            return EntityType.IpAddress;
        // MD5 / SHA-1 / SHA-256 are fixed-length hex strings.
        if (v.Length is 32 or 40 or 64 && HexRx().IsMatch(v)) return EntityType.FileHash;
        if (DomainRx().IsMatch(v)) return EntityType.Domain;
        return EntityType.Other;
    }

    private static int CountDots(string s)
    {
        var n = 0;
        foreach (var c in s) if (c == '.') n++;
        return n;
    }

    /// <summary>
    /// Trims and, for a refangable <paramref name="type"/>, refangs the value into its canonical
    /// form for storage and matching. The single choke point used by the case aggregate on add/edit.
    /// </summary>
    public static string Normalize(EntityType type, string? value)
    {
        var v = (value ?? string.Empty).Trim();
        return IsRefangable(type) ? Refang(v) : v;
    }

    /// <summary>
    /// Converts a defanged indicator back to its live form. Idempotent — a value that is already
    /// live (or only partially defanged) passes through unchanged apart from a trim.
    /// </summary>
    public static string Refang(string? value)
    {
        var s = (value ?? string.Empty).Trim();
        if (s.Length == 0) return s;

        // Protocol scheme: hxxp/hxxps → http/https, fxp → ftp (case-insensitive; canonical lowercase).
        s = HxxpsRx().Replace(s, "https");
        s = HxxpRx().Replace(s, "http");
        s = FxpRx().Replace(s, "ftp");

        // Bracketed / parenthesized / braced separators, with or without the spelled-out word and
        // any padding whitespace: [.] (.) {.} [dot] (dot) → "." ; [:] → ":" ; [/] → "/" ; [@]/[at] → "@".
        s = DotRx().Replace(s, ".");
        s = ColonRx().Replace(s, ":");
        s = SlashRx().Replace(s, "/");
        s = AtRx().Replace(s, "@");

        return s.Trim();
    }

    /// <summary>
    /// Produces a defanged rendering of a live indicator for safe display and copy/paste — neutralizes
    /// the scheme and dots (and <c>@</c> in email addresses) so a value can't be clicked or auto-linked.
    /// </summary>
    public static string Defang(string? value)
    {
        var s = (value ?? string.Empty).Trim();
        if (s.Length == 0) return s;

        s = HttpSchemeRx().Replace(s, m => m.Value.Length == 5 ? "hxxps" : "hxxp");
        s = s.Replace(".", "[.]");
        s = s.Replace("@", "[at]");
        return s;
    }

    // Refang patterns. \b avoids rewriting the middle of an unrelated token.
    [GeneratedRegex(@"\bhxxps\b", RegexOptions.IgnoreCase)] private static partial Regex HxxpsRx();
    [GeneratedRegex(@"\bhxxp\b", RegexOptions.IgnoreCase)] private static partial Regex HxxpRx();
    [GeneratedRegex(@"\bfxp(?=:)", RegexOptions.IgnoreCase)] private static partial Regex FxpRx();
    [GeneratedRegex(@"[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]", RegexOptions.IgnoreCase)] private static partial Regex DotRx();
    [GeneratedRegex(@"[\[\(\{]\s*:\s*[\]\)\}]")] private static partial Regex ColonRx();
    [GeneratedRegex(@"[\[\(\{]\s*/\s*[\]\)\}]")] private static partial Regex SlashRx();
    [GeneratedRegex(@"[\[\(\{]\s*(?:@|at)\s*[\]\)\}]", RegexOptions.IgnoreCase)] private static partial Regex AtRx();

    // Defang: match an http/https scheme (with its ://) so we can neuter it in one pass.
    [GeneratedRegex(@"\bhttps?(?=://)", RegexOptions.IgnoreCase)] private static partial Regex HttpSchemeRx();

    // Classification patterns (DetectType).
    [GeneratedRegex(@"^[a-z][a-z0-9+.\-]*://\S+$", RegexOptions.IgnoreCase)] private static partial Regex UrlRx();
    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$")] private static partial Regex EmailRx();
    [GeneratedRegex(@"^[0-9a-f]+$", RegexOptions.IgnoreCase)] private static partial Regex HexRx();
    [GeneratedRegex(@"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$", RegexOptions.IgnoreCase)] private static partial Regex DomainRx();
}
