namespace IncidentManager.Web.Services;

/// <summary>
/// Circuit-scoped memory of the case list's last query string (filters, scope, page), so the case workspace's
/// "Cases" breadcrumb goes back to the list as it was left instead of the unfiltered queue. Nothing is stored
/// outside the circuit.
/// </summary>
public sealed class CaseListMemory
{
    /// <summary>The list's query string, including the leading "?", or empty.</summary>
    public string Query { get; private set; } = "";

    public void Remember(string uri)
    {
        var i = uri.IndexOf('?');
        Query = i < 0 ? "" : uri[i..];
    }

    /// <summary>The list URL to go back to.</summary>
    public string BackHref => "cases" + Query;
}
