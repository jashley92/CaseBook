using System.Net;
using System.Net.Sockets;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Observables;

/// <summary>CAP-28: why two indicators are possibly related.</summary>
public enum RelatedRule
{
    /// <summary>A domain, or a URL's host, under the same registrable domain (itself, a parent or a child).</summary>
    RegistrableDomain,
    /// <summary>IPv4 addresses (or URLs on them) in the same /24.</summary>
    Ipv4Slash24,
    /// <summary>IPv6 addresses (or URLs on them) in the same /48.</summary>
    Ipv6Slash48,
    /// <summary>Email addresses (or accounts written as one) at the same domain.</summary>
    EmailDomain,
}

/// <summary>CAP-28: what an indicator shares with others it's possibly related to: the rule and the shared part
/// ("evil.example", "203.0.113", "2001:db8:1"), compared ordinally (it's lowercased).</summary>
public readonly record struct RelatedKey(RelatedRule Rule, string Shared)
{
    /// <summary>How the shared part reads: "same registrable domain evil.example", "same /24 (203.0.113.0/24)".</summary>
    public string Describe() => Rule switch
    {
        RelatedRule.RegistrableDomain => $"same registrable domain {Shared}",
        RelatedRule.Ipv4Slash24 => $"same /24 ({Shared}.0/24)",
        RelatedRule.Ipv6Slash48 => $"same /48 ({Shared}::/48)",
        _ => $"same email domain {Shared}",
    };
}

/// <summary>
/// CAP-28: the fixed rules for "possibly related" indicators, beside the exact match of <see cref="IocObservable.MatchFamily"/>:
/// the same registrable domain (a parent, a child or a sibling), the same IPv4 /24 or IPv6 /48, and the same email domain.
/// Suggestions only: nothing links, and nothing counts toward a gate or the Desk (A4).
/// </summary>
/// <remarks>
/// <para>The registrable domain is a built-in approximation of the Public Suffix List, which CaseBook doesn't ship or fetch
/// (no outbound calls). It takes the last two labels, or three when the last two are a public suffix: a known two-label
/// suffix (<c>co.uk</c>, <c>com.au</c>, …), any two-letter country code under a generic second level (<c>com.xx</c>,
/// <c>co.xx</c>, <c>gov.xx</c>, …), or a shared host where anyone can have a name (<c>azurewebsites.net</c>,
/// <c>github.io</c>, <c>s3.amazonaws.com</c>, …). Its limits: a country's own second levels outside that list
/// (<c>kawasaki.jp</c>'s city names, <c>pvt.k12.ma.us</c>) read as registrable, so two unrelated names under one can be
/// suggested; and a shared host it doesn't know relates everyone hosted there. A single-label name, an IP or a public
/// suffix itself has no registrable domain.</para>
/// <para>Email domains match exactly (<c>mail.evil.example</c> isn't <c>evil.example</c>).</para>
/// <para>CAP-28 exclusions: what the organization says is its own (<see cref="RelatedExclusions"/>: its domains, its
/// address ranges, and by default the big free mail providers) is never used to suggest relations, and nothing is
/// suggested because of it. Every public rule here takes the exclusions in force, so no caller can leave them out.</para>
/// </remarks>
public static class RelatedObservables
{
    // Generic second levels under a two-letter country code: com.au, co.uk, gov.in, ac.jp, gob.mx, ...
    private static readonly HashSet<string> GenericSecondLevels = new(StringComparer.Ordinal)
    {
        "com", "co", "net", "org", "gov", "govt", "edu", "ac", "or", "ne", "go", "gob", "mil", "nic", "sch", "ltd", "plc",
        "nhs", "nom", "int", "me", "biz", "info", "res", "web", "firm", "gen", "police", "mod", "lg", "ed", "gv", "in",
    };

    // Two-label public suffixes not covered by the rule above (a three-letter top level, or a country with its own).
    private static readonly HashSet<string> KnownSuffixes = new(StringComparer.Ordinal)
    {
        // Shared hosting where anyone can register a name: everyone on them would read as related.
        "github.io", "gitlab.io", "blogspot.com", "appspot.com", "herokuapp.com", "azurewebsites.net", "cloudapp.net",
        "cloudfront.net", "trafficmanager.net", "azureedge.net", "azurefd.net", "web.core.windows.net", "blob.core.windows.net",
        "file.core.windows.net", "sharepoint.com", "onmicrosoft.com", "s3.amazonaws.com", "elasticbeanstalk.com",
        "amazonaws.com", "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "ngrok.io",
        "ngrok-free.app", "ngrok.app", "trycloudflare.com", "duckdns.org", "ddns.net", "no-ip.org", "no-ip.com",
        "hopto.org", "zapto.org", "servebeer.com", "onrender.com", "glitch.me", "repl.co", "fly.dev", "googleusercontent.com",
        "myshopify.com", "wordpress.com", "wixsite.com", "weebly.com", "000webhostapp.com", "000webhost.com", "godaddysites.com",
        "dynv6.net", "freedns.afraid.org", "r2.dev", "surge.sh", "translate.goog", "ipfs.io", "dweb.link",
        "framer.app", "webflow.io", "notion.site", "carrd.co",
    };

    // Free mail: an address there says nothing about who sent it. Left out while RelatedExclusions.FreeMail is on.
    private static readonly HashSet<string> FreeMail = new(StringComparer.Ordinal)
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com", "yahoo.com",
        "yahoo.co.uk", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "pm.me",
        "gmx.com", "gmx.de", "gmx.net", "mail.com", "yandex.ru", "yandex.com", "zoho.com", "qq.com", "163.com", "126.com",
        "web.de", "mail.ru", "tutanota.com", "tuta.io", "fastmail.com",
    };

    /// <summary>
    /// What <paramref name="value"/> (as stored, of <paramref name="type"/>) shares with possibly related indicators, or
    /// null when no rule applies to it (a hash, a host name, a file, a single-label name) or <paramref name="exclusions"/>
    /// leave it out (one of the organization's domains or ranges, a free mail address).
    /// </summary>
    public static RelatedKey? KeyOf(EntityType type, string? value, RelatedExclusions exclusions) =>
        KeyOf(type, value) is { } key && ExcludedBecause(type, value, key, exclusions) is null ? key : null;

    /// <summary>Whether any rule applies to <paramref name="value"/>'s type and shape, before exclusions: whether the
    /// entity panel has anything to say about it.</summary>
    public static bool HasRule(EntityType type, string? value) => KeyOf(type, value) is not null;

    /// <summary>
    /// CAP-28 exclusions: why <paramref name="value"/> isn't used to suggest relations, worded for the entity panel
    /// ("contoso.com is one of your organization's domains, so it isn't used to suggest relations."), or null when it is
    /// used, or when no rule applies to it at all.
    /// </summary>
    public static string? ExcludedBecause(EntityType type, string? value, RelatedExclusions exclusions) =>
        KeyOf(type, value) is { } key ? ExcludedBecause(type, value, key, exclusions) : null;

    private static string? ExcludedBecause(EntityType type, string? value, RelatedKey key, RelatedExclusions exclusions)
    {
        var v = (value ?? "").Trim();
        switch (key.Rule)
        {
            case RelatedRule.Ipv4Slash24:
            case RelatedRule.Ipv6Slash48:
            {
                var address = type == EntityType.Url && Uri.TryCreate(v, UriKind.Absolute, out var u) ? UrlHost(v, u) : v;   // R1
                if (!IpText.TryParse(address, out var ip) || exclusions.RangeOf(ip) is not { } range) return null;   // F3: decimal parts
                return $"{address.ToLowerInvariant()} is in {range}, one of your organization's excluded address ranges, so it isn't used to suggest relations.";
            }
            case RelatedRule.RegistrableDomain:
            {
                var host = (type == EntityType.Url && Uri.TryCreate(v, UriKind.Absolute, out var u) ? UrlHost(v, u) : v).TrimEnd('.').ToLowerInvariant();
                return OwnDomain(host, exclusions);
            }
            default:
            {
                // The email domain is the key's shared part, already lowercased.
                if (OwnDomain(key.Shared, exclusions) is { } own) return own;
                return exclusions.FreeMail && FreeMail.Contains(key.Shared)
                    ? $"{key.Shared} is a free mail provider, so an address there isn't used to suggest relations."
                    : null;
            }
        }
    }

    private static string? OwnDomain(string host, RelatedExclusions exclusions) => exclusions.DomainOf(host) switch
    {
        null => null,
        var d when d == host => $"{d} is one of your organization's domains, so it isn't used to suggest relations.",
        var d => $"{host} is under {d}, one of your organization's domains, so it isn't used to suggest relations.",
    };

    // The rule's key, nothing excluded but what can never relate (loopback, unspecified, IPv6 link-local).
    private static RelatedKey? KeyOf(EntityType type, string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length == 0) return null;
        switch (type)
        {
            case EntityType.IpAddress:
                return IpKey(v);
            case EntityType.Domain:
                return RegistrableDomain(v) is { } d ? new RelatedKey(RelatedRule.RegistrableDomain, d) : null;
            case EntityType.Url:
                if (!Uri.TryCreate(v, UriKind.Absolute, out var uri) || uri.Host.Length == 0) return null;
                var host = UrlHost(v, uri);
                return IpKey(host) ?? (RegistrableDomain(host) is { } h ? new RelatedKey(RelatedRule.RegistrableDomain, h) : null);
            case EntityType.EmailAddress:
            case EntityType.Account:
                return EmailDomain(v) is { } m ? new RelatedKey(RelatedRule.EmailDomain, m) : null;
            default:
                return null;
        }
    }

    /// <summary>
    /// The host of <paramref name="url"/> as the rules read it: an IPv6 one without its brackets, a name as <see cref="Uri"/>
    /// reads it, and (CAP-28 review, R1) an IPv4 one as written. System.Uri reads an IPv4 host the way inet_aton does, so
    /// <c>http://010.0.0.5/</c> has host 8.0.0.5 and <c>http://0x0a.0.0.5/</c> 10.0.0.5; read as written, by
    /// <see cref="IpText"/>, the first is 10.0.0.5, as the address 010.0.0.5 is, and the second isn't an address at all.
    /// </summary>
    private static string UrlHost(string url, Uri uri)
    {
        if (uri.HostNameType is UriHostNameType.IPv6) return uri.Host.Trim('[', ']');
        if (uri.HostNameType is not UriHostNameType.IPv4) return uri.Host;
        // The authority follows the scheme's "//" and ends at the path, query or fragment; the host follows any userinfo
        // "@" and ends at the port.
        var slashes = url.IndexOf("//", StringComparison.Ordinal);
        if (slashes < 0) return uri.Host;
        var start = slashes + 2;
        var stop = url.IndexOfAny(['/', '\\', '?', '#'], start);
        var authority = stop < 0 ? url[start..] : url[start..stop];
        var hostPort = authority[(authority.LastIndexOf('@') + 1)..];
        var colon = hostPort.IndexOf(':');
        return colon < 0 ? hostPort : hostPort[..colon];
    }

    /// <summary>
    /// Whether two indicators are possibly related: they share a key, and they aren't the same observable (an exact
    /// match is "Seen before", not a suggestion).
    /// </summary>
    public static bool AreRelated(EntityType aType, string a, EntityType bType, string b, RelatedExclusions exclusions)
    {
        if (IocObservable.MatchFamily(aType) == IocObservable.MatchFamily(bType)
            && string.Equals(a.Trim(), b.Trim(), StringComparison.OrdinalIgnoreCase)) return false;
        return KeyOf(aType, a, exclusions) is { } ka && KeyOf(bType, b, exclusions) is { } kb && ka == kb;
    }

    /// <summary>The types a key can be shared with (the types whose values can carry it).</summary>
    public static IReadOnlyList<EntityType> TypesFor(RelatedRule rule) => rule switch
    {
        RelatedRule.RegistrableDomain => [EntityType.Domain, EntityType.Url],
        RelatedRule.Ipv4Slash24 or RelatedRule.Ipv6Slash48 => [EntityType.IpAddress, EntityType.Url],
        _ => [EntityType.EmailAddress, EntityType.Account],
    };

    /// <summary>
    /// The registrable domain of <paramref name="host"/> (lowercased, without a trailing dot), by the approximation in the
    /// remarks; null for a single label, an IP address, a public suffix itself, or anything that isn't a DNS name.
    /// </summary>
    public static string? RegistrableDomain(string? host)
    {
        var h = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Length == 0 || h.Length > 253 || IPAddress.TryParse(h, out _)) return null;
        var labels = h.Split('.');
        if (labels.Length < 2 || labels.Any(l => l.Length is 0 or > 63 || !l.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            return null;
        if (labels[^1].All(char.IsAsciiDigit)) return null;   // not a name: a partial address
        var suffix = SuffixLabels(labels);
        return labels.Length > suffix ? string.Join('.', labels[^(suffix + 1)..]) : null;
    }

    // How many trailing labels are the public suffix: 1 (a top level), 2 (co.uk, github.io) or 3 (blob.core.windows.net).
    private static int SuffixLabels(string[] labels)
    {
        if (labels.Length >= 4 && KnownSuffixes.Contains(string.Join('.', labels[^4..]))) return 4;
        if (labels.Length >= 3 && KnownSuffixes.Contains(string.Join('.', labels[^3..]))) return 3;
        if (labels.Length >= 2)
        {
            var two = string.Join('.', labels[^2..]);
            if (KnownSuffixes.Contains(two)) return 2;
            if (labels[^1].Length == 2 && GenericSecondLevels.Contains(labels[^2])) return 2;
        }
        return 1;
    }

    private static RelatedKey? IpKey(string v)
    {
        // CAP-28 review (F3): each IPv4 part decimal; IPAddress.TryParse read 010.0.0.1 as 8.0.0.1, so its /24 was 8.0.0.
        if (!IpText.TryParse(v, out var ip)) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.None)) return null;
        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            // IPAddress.TryParse takes "1.2.3" as 1.2.0.3; only a dotted quad is an address here.
            if (v.Count(c => c == '.') != 3) return null;
            return new RelatedKey(RelatedRule.Ipv4Slash24, $"{bytes[0]}.{bytes[1]}.{bytes[2]}");
        }
        if (ip.AddressFamily != AddressFamily.InterNetworkV6 || ip.IsIPv6LinkLocal) return null;
        var hextets = Enumerable.Range(0, 3).Select(i => ((bytes[2 * i] << 8) | bytes[2 * i + 1]).ToString("x", System.Globalization.CultureInfo.InvariantCulture));
        return new RelatedKey(RelatedRule.Ipv6Slash48, string.Join(':', hextets));
    }

    private static string? EmailDomain(string v)
    {
        var at = v.LastIndexOf('@');
        if (at <= 0 || at == v.Length - 1) return null;
        var domain = v[(at + 1)..].Trim().TrimEnd('.').ToLowerInvariant();
        if (domain.IndexOf('.') < 0 || RegistrableDomain(domain) is null) return null;
        return domain;
    }
}
