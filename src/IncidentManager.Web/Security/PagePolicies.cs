using System.Reflection;
using IncidentManager.Domain.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;

namespace IncidentManager.Web.Security;

/// <summary>
/// S-22: which permission a page needs, read from the pages' own <c>@page</c> + <c>[Authorize(Policy)]</c>
/// attributes, so the access-denied page can say "that page needs Administer" instead of a generic refusal — and can
/// never drift from what the page actually enforces. Policy names are the permission names (see <c>Policies</c>).
/// </summary>
public static class PagePolicies
{
    private sealed record PageRoute(string[] Segments, Permission? Required);

    private static readonly IReadOnlyList<PageRoute> Routes = typeof(PagePolicies).Assembly.GetTypes()
        .Where(t => typeof(IComponent).IsAssignableFrom(t))
        .SelectMany(t => t.GetCustomAttributes<RouteAttribute>().Select(r => new PageRoute(
            Split(r.Template),
            Enum.TryParse<Permission>(t.GetCustomAttribute<AuthorizeAttribute>()?.Policy, out var p) ? p : null)))
        .ToList();

    /// <summary>The permission the page at <paramref name="path"/> requires, or null if unknown / none.</summary>
    public static Permission? RequiredFor(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var clean = path.Split('?', '#')[0];
        var segments = Split(clean);
        // Like the router, a literal segment beats a parameter ("/cases/new" isn't "/cases/{Id:guid}").
        return Routes.Where(r => Matches(r.Segments, segments))
            .OrderByDescending(r => r.Segments.Count(seg => !seg.StartsWith('{')))
            .FirstOrDefault()?.Required;
    }

    private static bool Matches(string[] template, string[] path) =>
        template.Length == path.Length && template.Zip(path).All(p => SegmentMatches(p.First, p.Second));

    private static bool SegmentMatches(string template, string value) =>
        !template.StartsWith('{')
            ? string.Equals(template, value, StringComparison.OrdinalIgnoreCase)
            : !template.Contains(":guid", StringComparison.OrdinalIgnoreCase) || Guid.TryParse(value, out _);

    private static string[] Split(string s) => s.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
}
