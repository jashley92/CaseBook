using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;

namespace IncidentManager.Domain.Observables;

/// <summary>
/// CAP-28 review (F3): an IP address as an analyst or an administrator writes one. <see cref="IPAddress.TryParse(string?, out IPAddress?)"/>
/// reads IPv4 the way inet_aton does: a leading zero makes a part octal and <c>0x</c> hex, so <c>010.0.0.1</c> is 8.0.0.1
/// and <c>192.168.010.000</c> is 192.168.8.0, and <c>1.2.3</c> is 1.2.0.3. Logs and firewalls zero-pad addresses to line
/// them up, and nobody means octal, so here IPv4 is four decimal parts of one to three digits, 0 to 255 each, a leading
/// zero read as decimal (<c>010</c> is 10); hex, octal-only digits and short forms aren't an address. The same holds for
/// the IPv4 part at the end of an IPv6 address (<c>::ffff:010.0.0.1</c>). IPv6 is otherwise read as the framework does.
/// </summary>
public static class IpText
{
    public static bool TryParse(string? text, [NotNullWhen(true)] out IPAddress? address)
    {
        address = null;
        var t = text ?? "";
        if (t.Contains(':'))
        {
            // CAP-28 review: the IPv4 part ends the address, before a zone ID (fe80::1%eth0.5, ::ffff:1.2.3.4%3) or the
            // bracket of [addr]:port, which go to the framework as written, as they did before IpText.
            var end = t.IndexOfAny(['%', ']']);
            if (end < 0) end = t.Length;
            var colon = t.LastIndexOf(':', Math.Max(end - 1, 0));
            if (colon >= 0 && colon < end)
            {
                var tail = t[(colon + 1)..end];
                if (tail.Contains('.'))
                {
                    if (DottedDecimal(tail) is not { } v4) return false;
                    t = t[..(colon + 1)] + v4 + t[end..];
                }
            }
            return IPAddress.TryParse(t, out address);
        }
        return DottedDecimal(t) is { } dotted && IPAddress.TryParse(dotted, out address);
    }

    /// <summary>Whether <paramref name="text"/> is IPv4 the framework reads but not as decimal (<c>0x0A.0.0.1</c>).</summary>
    public static bool IsNonDecimalIpv4(string? text) =>
        !string.IsNullOrEmpty(text) && !text.Contains(':') && DottedDecimal(text) is null
        && IPAddress.TryParse(text, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;

    // "010.0.0.1" as "10.0.0.1"; null unless it's four decimal parts of 1 to 3 digits, each 0 to 255.
    private static string? DottedDecimal(string s)
    {
        var parts = s.Split('.');
        if (parts.Length != 4) return null;
        var values = new int[4];
        for (var i = 0; i < 4; i++)
        {
            var p = parts[i];
            if (p.Length is 0 or > 3 || !p.All(char.IsAsciiDigit)) return null;
            values[i] = int.Parse(p, NumberStyles.None, CultureInfo.InvariantCulture);
            if (values[i] > 255) return null;
        }
        return string.Join('.', values.Select(v => v.ToString(CultureInfo.InvariantCulture)));
    }
}
