using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace IncidentManager.Domain.Observables;

/// <summary>
/// CAP-28 exclusions: what the organization says is its own, so it's never used to suggest "possibly related" indicators
/// and nothing is suggested because of it. CaseBook can't tell an internal account or a private /24 from an attacker's,
/// so without these every case with the company's own domain or a 10.x address was suggested beside every other.
/// </summary>
/// <remarks>
/// <para>A domain matches itself and every name under it (<c>contoso.com</c> covers <c>mail.contoso.com</c> and an
/// address <c>a@corp.contoso.com</c>, never <c>notcontoso.com</c>). It's checked against the indicator's whole host, so a
/// listed <c>corp.contoso.com</c> leaves out <c>x.corp.contoso.com</c> but not <c>www.contoso.com</c>.</para>
/// <para>A range matches the addresses inside it, an IPv4-mapped IPv6 address (<c>::ffff:10.1.2.3</c>) as its IPv4
/// address, and an address in a URL's host as the address.</para>
/// </remarks>
public sealed class RelatedExclusions
{
    /// <summary>
    /// The address ranges left out by default: the RFC 1918 private ranges, IPv4 loopback and link-local, IPv6 loopback,
    /// link-local and unique local (ULA). Every organization uses them, so a /24 in one says nothing about another case.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultRanges =
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7"];

    /// <summary>Nothing left out (the rules' shape alone).</summary>
    public static readonly RelatedExclusions None = new([], [], freeMail: false);

    /// <summary>The shipped defaults: no domains, <see cref="DefaultRanges"/>, free mail left out.</summary>
    public static readonly RelatedExclusions Default = new([], DefaultRanges.Select(r => ParseRange(r)!.Value), freeMail: true);

    private readonly string[] _domains;
    private readonly IPNetwork[] _ranges;

    public RelatedExclusions(IEnumerable<string> domains, IEnumerable<IPNetwork> ranges, bool freeMail)
    {
        _domains = domains.Distinct(StringComparer.Ordinal).ToArray();
        _ranges = ranges.Distinct().ToArray();
        FreeMail = freeMail;
    }

    /// <summary>
    /// The exclusions from settings as stored: entries that aren't a domain or a range (one written into a settings file
    /// by hand; the admin page refuses them) are skipped, and Diagnostics lists them as invalid settings.
    /// </summary>
    public static RelatedExclusions From(IEnumerable<string?> domains, IEnumerable<string?> ranges, bool freeMail) => new(
        domains.Select(d => NormalizeDomain(d, out _)).OfType<string>(),
        ranges.Select(r => ParseRange(r)).Where(r => r is not null).Select(r => r!.Value),
        freeMail);

    /// <summary>The organization's domains, lowercased, without a trailing dot.</summary>
    public IReadOnlyList<string> Domains => _domains;

    /// <summary>The organization's address ranges.</summary>
    public IReadOnlyList<IPNetwork> Ranges => _ranges;

    /// <summary>Whether an email address at a big free mail provider is left out (on by default).</summary>
    public bool FreeMail { get; }

    /// <summary>The listed domain <paramref name="host"/> is or is under (lowercased, no trailing dot), or null.</summary>
    public string? DomainOf(string? host)
    {
        var h = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Length == 0) return null;
        foreach (var d in _domains)
            if (h == d || (h.Length > d.Length && h.EndsWith(d, StringComparison.Ordinal) && h[^(d.Length + 1)] == '.'))
                return d;
        return null;
    }

    /// <summary>The listed range <paramref name="address"/> is in (an IPv4-mapped address as its IPv4 address), or null.</summary>
    public IPNetwork? RangeOf(IPAddress address)
    {
        var v4 = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : null;
        foreach (var r in _ranges)
            if (r.Contains(address) || (v4 is not null && r.Contains(v4)))
                return r;
        return null;
    }

    /// <summary>
    /// A domain entry as stored (lowercased, a trailing dot and a leading "*." dropped), or null with <paramref name="problem"/>
    /// saying why it isn't one, worded to follow the entry ("isn't a domain name. ...").
    /// </summary>
    public static string? NormalizeDomain(string? entry, out string? problem)
    {
        var d = (entry ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (d.StartsWith("*.", StringComparison.Ordinal)) d = d[2..];
        d = d.TrimStart('.');
        problem = null;
        if (d.Contains('@')) problem = "is an email address. Enter its domain only, like contoso.com.";
        else if (d.Contains('/') || d.Contains(':') || IPAddress.TryParse(d, out _))
            problem = "isn't a domain name. Enter a name like contoso.com; put addresses in the excluded address ranges.";
        else if (d.Any(c => c > 127))
            problem = "has characters outside A-Z, 0-9 and hyphens. Enter an international name in its xn-- form.";
        else
        {
            var labels = d.Split('.');
            if (d.Length is 0 or > 253 || labels.Any(l => l.Length is 0 or > 63 || l[0] == '-' || l[^1] == '-'
                    || !l.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')))
                problem = "isn't a domain name. Enter a name like contoso.com or corp.contoso.local.";
            else if (labels.Length < 2)
                problem = "is a single label. Enter the full domain, like contoso.com or corp.contoso.local.";
            else if (labels[^1].All(char.IsAsciiDigit))
                problem = "isn't a domain name. Enter a name like contoso.com; put addresses in the excluded address ranges.";
            else if (RelatedObservables.RegistrableDomain(d) is null)
                problem = "is a public suffix that many organizations share. Enter your own domain under it, like contoso.co.uk.";
        }
        return problem is null ? d : null;
    }

    /// <summary>
    /// A range entry as stored ("10.0.0.0/8", "fc00::/7"; a bare address is /32 or /128), or null with
    /// <paramref name="problem"/> saying why it isn't one, worded to follow the entry.
    /// </summary>
    public static string? NormalizeRange(string? entry, out string? problem)
    {
        var r = ParseRange(entry, out problem);
        return r?.ToString();
    }

    private static IPNetwork? ParseRange(string? entry) => ParseRange(entry, out _);

    private static IPNetwork? ParseRange(string? entry, out string? problem)
    {
        var e = (entry ?? "").Trim();
        var slash = e.IndexOf('/');
        var addressPart = slash < 0 ? e : e[..slash];
        // IPAddress.TryParse takes "10.1" as 10.0.0.1; only a dotted quad or an IPv6 address is a range's address here.
        if (!IPAddress.TryParse(addressPart, out var address) || addressPart.Contains('%')
            || (address.AddressFamily == AddressFamily.InterNetwork && addressPart.Count(c => c == '.') != 3))
        {
            problem = "isn't an address range. Write it as CIDR, like 10.0.0.0/8 or fd00::/8.";
            return null;
        }
        var max = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = max;
        if (slash >= 0 && !(int.TryParse(e[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) && prefix <= max))
        {
            problem = $"has a prefix length that isn't 0 to {max}. Write it as CIDR, like {(max == 32 ? "10.0.0.0/8" : "fd00::/8")}.";
            return null;
        }
        var network = Masked(address, prefix);
        if (!network.Equals(address))
        {
            problem = $"has bits set past its /{prefix}. Did you mean {network}/{prefix}?";
            return null;
        }
        problem = null;
        return new IPNetwork(network, prefix);
    }

    private static IPAddress Masked(IPAddress address, int prefix)
    {
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var keep = Math.Clamp(prefix - (i * 8), 0, 8);
            bytes[i] &= (byte)(0xFF << (8 - keep));
        }
        return new IPAddress(bytes);
    }
}
