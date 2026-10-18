namespace IncidentManager.Infrastructure.Siem;

/// <summary>One SIEM row on the Diagnostics delivery card: the transport's name, and why it stopped (null when it's sending).</summary>
public sealed record SiemTransportRow(string Name, string? StoppedReason);

/// <summary>
/// CAP-04 review: which SIEM transports the delivery card shows. A row is chosen by whether the transport is switched on
/// in its options (<see cref="ISecurityEventTransport.Configured"/>), not by whether it's delivering right now, so one
/// that has stopped (an Event Log source that's missing) shows as failing with its reason instead of dropping off the
/// card and leaving "no transport is on". Kept out of the .razor file so the decision is testable.
/// </summary>
public static class SiemTransportRows
{
    public static IReadOnlyList<SiemTransportRow> Pick(IEnumerable<ISecurityEventTransport> transports)
    {
        var rows = new List<SiemTransportRow>();
        foreach (var t in transports)
        {
            bool configured;
            try { configured = t.Configured; }   // BUG-262: options can throw
            catch (Exception ex) when (ex is not OutOfMemoryException) { continue; }
            if (!configured) continue;

            string? stopped;
            try { stopped = t.StoppedReason ?? (t.Enabled ? null : "not sending"); }
            catch (Exception ex) when (ex is not OutOfMemoryException) { stopped = "not sending: its settings couldn't be read"; }
            rows.Add(new SiemTransportRow(t.Name, stopped));
        }
        return rows;
    }
}
