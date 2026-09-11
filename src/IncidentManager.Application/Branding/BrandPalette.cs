using System.Globalization;
using System.Text;

namespace IncidentManager.Application.Branding;

/// <summary>
/// Derives the brand/accent CSS-variable override block for a white-label instance (X-08) from one or two
/// admin-chosen colours. Pure and deterministic so the <b>AA-contrast guarantee</b> on the link/emphasis
/// shade can be unit-tested. Only <b>brand/accent</b> tokens are produced — the semantic status palette
/// (severity / phase / danger / warn / ok) is deliberately never emitted, so red keeps reading as danger
/// regardless of brand. Returns <c>null</c> when no valid colour is set, so the compile-time defaults stand.
/// </summary>
public static class BrandPalette
{
    private readonly record struct Rgb(int R, int G, int B)
    {
        public string Hex => $"#{R:x2}{G:x2}{B:x2}";
        public string Rgba(double a) => $"rgba({R}, {G}, {B}, {a.ToString(CultureInfo.InvariantCulture)})";
    }

    // Surfaces the brand text sits on, used as the contrast reference per theme.
    private static readonly Rgb White = new(255, 255, 255);
    private static readonly Rgb DarkSurface = new(0x1a, 0x21, 0x2a);
    private const double AaText = 4.5; // WCAG 2.1 AA for normal text

    /// <summary>
    /// Builds the CSS overriding the brand tokens for both themes, or <c>null</c> when neither colour is a
    /// valid hex. <paramref name="accentHex"/> drives the gold/accent roles (links, active states, focus);
    /// <paramref name="inkHex"/> (optional) drives the charcoal primary-action roles.
    /// </summary>
    public static string? BuildCss(string? accentHex, string? inkHex)
    {
        var accent = TryParse(accentHex);
        var ink = TryParse(inkHex);
        if (accent is null && ink is null) return null;

        var light = new List<string>();
        var dark = new List<string>();

        if (accent is { } a)
        {
            var lightText = ContrastOn(a, White, AaText, darken: true);   // legible on light surfaces
            var darkText = ContrastOn(a, DarkSurface, AaText, darken: false); // legible on dark surfaces

            light.Add($"--im-gold:{a.Hex}");
            light.Add($"--im-accent:{a.Hex}");
            light.Add($"--im-gold-strong:{Darken(a, .12).Hex}");
            light.Add($"--im-accent-strong:{Darken(a, .12).Hex}");
            light.Add($"--im-accent-text:{lightText.Hex}");
            light.Add($"--im-accent-bg:{a.Rgba(.12)}");
            light.Add($"--im-focus:{a.Rgba(.45)}");
            light.Add($"--bs-link-hover-color:{Darken(lightText, .2).Hex}");

            dark.Add($"--im-accent:{a.Hex}");
            dark.Add($"--im-accent-strong:{Lighten(a, .12).Hex}");
            dark.Add($"--im-accent-text:{darkText.Hex}");
            dark.Add($"--im-accent-bg:{a.Rgba(.14)}");
            dark.Add($"--im-focus:{a.Rgba(.5)}");
            dark.Add($"--bs-link-hover-color:{Lighten(a, .18).Hex}");
        }

        if (ink is { } k)
        {
            // Charcoal primary-action colour; the hover is a touch lighter. Applies to both themes.
            var inkLines = new[]
            {
                $"--im-ink:{k.Hex}",
                $"--im-ink-hover:{Lighten(k, .10).Hex}",
                $"--bs-primary:{k.Hex}",
                $"--bs-primary-rgb:{k.R}, {k.G}, {k.B}",
            };
            light.AddRange(inkLines);
            dark.Add($"--im-ink:{k.Hex}");
            dark.Add($"--im-ink-hover:{Lighten(k, .10).Hex}");
        }

        var sb = new StringBuilder();
        if (light.Count > 0) sb.Append(":root{").Append(string.Join(";", light)).Append(";}");
        if (dark.Count > 0) sb.Append("[data-bs-theme=\"dark\"]{").Append(string.Join(";", dark)).Append(";}");
        return sb.ToString();
    }

    /// <summary>Parses <c>#rgb</c> / <c>#rrggbb</c> (with or without the hash); null for anything else.</summary>
    public static bool IsValidHex(string? hex) => TryParse(hex) is not null;

    private static Rgb? TryParse(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex)) return null;
        var h = hex.Trim().TrimStart('#');
        if (h.Length == 3) h = string.Concat(h[0], h[0], h[1], h[1], h[2], h[2]);
        if (h.Length != 6) return null;
        if (!int.TryParse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out _)) return null;
        return new Rgb(
            Convert.ToInt32(h[..2], 16),
            Convert.ToInt32(h.Substring(2, 2), 16),
            Convert.ToInt32(h.Substring(4, 2), 16));
    }

    /// <summary>
    /// Concrete colours for the HTML email shell (E-03b branded email). Emails can't use CSS variables, so
    /// unlike <see cref="BuildCss"/> this resolves the console theme to literal hex values, applying the same
    /// compile-time defaults (gold accent, charcoal ink) when a colour is unset, and the same AA-contrast
    /// nudge for the link colour. Pure/deterministic so it can be unit-tested.
    /// </summary>
    public sealed record EmailPalette(
        string PageBg, string CardBg, string HeaderBg, string HeaderText,
        string Accent, string Link, string Text, string Muted, string Border,
        string ButtonBg, string ButtonText);

    private static readonly Rgb DefaultAccent = new(0xff, 0xcf, 0x31); // gold
    private static readonly Rgb DefaultInk = new(0x23, 0x2a, 0x33);    // charcoal

    public static EmailPalette EmailColors(string? accentHex, string? inkHex)
    {
        var accent = TryParse(accentHex) ?? DefaultAccent;
        var ink = TryParse(inkHex) ?? DefaultInk;
        var link = ContrastOn(accent, White, AaText, darken: true); // brand link, legible on the white card
        var buttonText = Contrast(White, ink) >= 3.0 ? White : new Rgb(0x1f, 0x29, 0x33);
        return new EmailPalette(
            PageBg: "#f4f5f7",
            CardBg: White.Hex,
            HeaderBg: ink.Hex,
            HeaderText: Contrast(White, ink) >= 3.0 ? White.Hex : "#1f2933",
            Accent: accent.Hex,
            Link: link.Hex,
            Text: "#1f2933",
            Muted: "#6b7280",
            Border: "#e5e7eb",
            ButtonBg: ink.Hex,
            ButtonText: buttonText.Hex);
    }

    private static Rgb Darken(Rgb c, double f) => new(
        (int)Math.Round(c.R * (1 - f)), (int)Math.Round(c.G * (1 - f)), (int)Math.Round(c.B * (1 - f)));

    private static Rgb Lighten(Rgb c, double f) => new(
        (int)Math.Round(c.R + (255 - c.R) * f), (int)Math.Round(c.G + (255 - c.G) * f), (int)Math.Round(c.B + (255 - c.B) * f));

    private static double Lin(int v)
    {
        var s = v / 255.0;
        return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
    }

    private static double Luminance(Rgb c) => 0.2126 * Lin(c.R) + 0.7152 * Lin(c.G) + 0.0722 * Lin(c.B);

    private static double Contrast(Rgb x, Rgb y)
    {
        double lx = Luminance(x), ly = Luminance(y);
        var (hi, lo) = lx > ly ? (lx, ly) : (ly, lx);
        return (hi + 0.05) / (lo + 0.05);
    }

    /// <summary>
    /// Nudges a colour darker (light theme) or lighter (dark theme) in small steps until it meets the target
    /// contrast against the surface it sits on — so a brand link/emphasis is always AA-legible, whatever
    /// brand colour an admin picks. Falls back to pure black/white if the ramp is exhausted.
    /// </summary>
    private static Rgb ContrastOn(Rgb colour, Rgb surface, double target, bool darken)
    {
        var c = colour;
        for (var i = 0; i < 24 && Contrast(c, surface) < target; i++)
            c = darken ? Darken(c, .06) : Lighten(c, .06);
        return c;
    }
}
