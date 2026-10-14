namespace IncidentManager.Web.Services;

/// <summary>
/// Circuit-scoped memory of the case list's last query string (filters, scope, page), so the case workspace's
/// "Cases" breadcrumb goes back to the list as it was left instead of the unfiltered queue. Nothing is stored
/// outside the circuit.
/// </summary>
public sealed class CaseListMemory
{
    private bool _remembered;

    /// <summary>The list's query string, including the leading "?", or empty.</summary>
    public string Query { get; private set; } = "";

    public void Remember(string uri)
    {
        var i = uri.IndexOf('?');
        var path = (i < 0 ? uri : uri[..i]).Split('#')[0].TrimEnd('/');
        Query = i < 0 ? "" : uri[i..].Split('#')[0];
        // BUG-474: the legacy /cases/mine route carries its scope in the path, which BackHref doesn't keep.
        // The page reads that route as Mine whatever ?scope says, so any scope parameter is replaced.
        if (path.EndsWith("/cases/mine", StringComparison.OrdinalIgnoreCase))
        {
            var rest = Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Where(p => !p.Split('=')[0].Equals("scope", StringComparison.OrdinalIgnoreCase));
            Query = "?" + string.Join('&', rest.Prepend("scope=mine"));
        }
        _remembered = true;
    }

    /// <summary>The list URL to go back to.</summary>
    // BUG-474: a list left at All with no filters goes back there, not to a bare "cases" (the PROD-24 default-view
    // redirect). Only a workspace reached without visiting the list keeps the bare, fresh-landing link.
    public string BackHref => !_remembered ? "cases" : Query.Length > 1 ? "cases" + Query : "cases?scope=all";
}
