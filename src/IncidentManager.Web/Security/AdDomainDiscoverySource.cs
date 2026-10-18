using System.DirectoryServices.ActiveDirectory;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using IncidentManager.Application.Abstractions;
using AdDomain = System.DirectoryServices.ActiveDirectory.Domain;

namespace IncidentManager.Web.Security;

/// <summary>
/// CAP-28 discovery: the organization's domains from Active Directory, as the app pool's identity (read-only): the domain
/// the computer is joined to, its forest's root and other domains, and the domains the domain and the forest trust.
/// Blocking: <see cref="Application.Admin.OrganizationDomains"/> runs it once on its own thread with a time limit (C10).
/// Not Windows, or not joined to a domain, is null; a domain controller that can't be read throws, so a partial list is
/// never taken for a whole one.
/// </summary>
public sealed class AdDomainDiscoverySource : IDomainDiscoverySource
{
    public IReadOnlyList<DiscoveredDomain>? Read() => OperatingSystem.IsWindows() ? ReadOnWindows() : null;

    [SupportedOSPlatform("windows")]
    private static List<DiscoveredDomain>? ReadOnWindows()
    {
        AdDomain domain;
        try { domain = AdDomain.GetComputerDomain(); }
        catch (ActiveDirectoryObjectNotFoundException) when (!Joined())
        {
            return null;   // a workgroup computer; joined but no domain controller found throws on
        }
        using (domain)
        {
            var found = new List<DiscoveredDomain> { new(domain.Name, DiscoveredDomainSource.ThisDomain) };
            using var forest = domain.Forest;
            found.Add(new(forest.Name, DiscoveredDomainSource.ForestRoot));   // a forest is named for its root domain
            foreach (AdDomain d in forest.Domains)
                using (d) found.Add(new(d.Name, DiscoveredDomainSource.Forest));
            // A downlevel trust's partner is a NetBIOS name, which the normalizer refuses.
            foreach (TrustRelationshipInformation t in domain.GetAllTrustRelationships())
                found.Add(new(t.TargetName ?? "", DiscoveredDomainSource.Trusted));
            foreach (TrustRelationshipInformation t in forest.GetAllTrustRelationships())
                found.Add(new(t.TargetName ?? "", DiscoveredDomainSource.Trusted));
            return found;
        }
    }

    // As RoleClaimsTransformer tells: a joined computer has a DNS domain; can't tell, so assume joined (the failure stands).
    private static bool Joined()
    {
        try { return !string.IsNullOrEmpty(IPGlobalProperties.GetIPGlobalProperties().DomainName); }
        catch (NetworkInformationException) { return true; }
    }
}
