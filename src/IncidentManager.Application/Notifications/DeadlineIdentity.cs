using System.Globalization;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Sla;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// BUG-619: the one way to name a regulatory deadline in a sent mark: the case, the jurisdiction, the band and the due
/// time. Without the jurisdiction, a second regulator on the same clock (the default window gives every unruled one the
/// same due time) was taken as already reminded and never got its at-risk or breached reminder.
/// </summary>
public static class DeadlineIdentity
{
    /// <summary>The mark for one jurisdiction's deadline in one band.</summary>
    public static string Key(Guid caseId, string jurisdictionCode, SlaState band, DateTimeOffset? dueAtUtc) =>
        string.Create(CultureInfo.InvariantCulture, $"{JurisdictionPrefix(caseId, jurisdictionCode)}{band}|{Ticks(dueAtUtc)}");

    /// <summary>A mark from before v1.6.13, which named no jurisdiction. Read only to convert it (<see cref="MarkNew"/>).</summary>
    public static string LegacyKey(Guid caseId, SlaState band, DateTimeOffset? dueAtUtc) =>
        string.Create(CultureInfo.InvariantCulture, $"{CasePrefix(caseId)}{band}|{Ticks(dueAtUtc)}");

    /// <summary>The start of every mark for the case, legacy ones included.</summary>
    public static string CasePrefix(Guid caseId) => string.Create(CultureInfo.InvariantCulture, $"deadline|{caseId:N}|");

    /// <summary>The start of every mark for one of the case's jurisdictions.</summary>
    public static string JurisdictionPrefix(Guid caseId, string jurisdictionCode) => CasePrefix(caseId) + Code(jurisdictionCode) + "|";

    /// <summary>The start of the case's legacy marks, one per band. A code is upper case, so it can't read as a band.</summary>
    public static IEnumerable<string> LegacyPrefixes(Guid caseId) =>
        Enum.GetValues<SlaState>().Select(band => string.Create(CultureInfo.InvariantCulture, $"{CasePrefix(caseId)}{band}|"));

    /// <summary>
    /// Marks each of <paramref name="codes"/> in <paramref name="marks"/> (under <paramref name="key"/>) and returns those
    /// marked now, not before. Owner decision: a clock reminded before marks named the jurisdiction (its
    /// <paramref name="legacyKey"/> is held) counts as reminded for every code on it now, so nobody gets a repeat. Those
    /// codes are marked as sent, kept whether or not the scan's sends finish, and the legacy mark is removed, so a code that
    /// comes onto the clock later is reminded.
    /// </summary>
    public static List<string> MarkNew(INotificationMarks marks, IEnumerable<string> codes, Func<string, string> key, string legacyKey)
    {
        var fresh = codes.Distinct(StringComparer.OrdinalIgnoreCase).Where(code => marks.TryAdd(key(code))).ToList();
        if (fresh.Count == 0 || !Holds(marks, legacyKey)) return fresh;
        foreach (var code in fresh) marks.Remove(key(code));   // out of the scan's batch, and kept in one of their own
        using (var converted = NotificationMarkBatch.Begin())
        {
            foreach (var code in fresh) marks.TryAdd(key(code));
            marks.Remove(legacyKey);
            converted.Complete();
        }
        return [];
    }

    // The stores have no lookup; a mark that can't be added is held (one added is taken back).
    private static bool Holds(INotificationMarks marks, string key)
    {
        if (!marks.TryAdd(key)) return true;
        marks.Remove(key);
        return false;
    }

    private static string Code(string code) => code.Trim().ToUpperInvariant().Replace("|", "%7C", StringComparison.Ordinal);

    private static long Ticks(DateTimeOffset? due) => (due ?? DateTimeOffset.MinValue).UtcTicks;
}
