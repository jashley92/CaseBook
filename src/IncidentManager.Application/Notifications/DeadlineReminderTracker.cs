using IncidentManager.Application.Sla;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// Remembers which cases have already had a regulatory-deadline reminder sent for a given <em>band</em>
/// (PROD-37), so the periodic scan alerts <em>once</em> as a case crosses into "at risk" and again if it
/// crosses into "breached" — rather than on every cycle while it sits there. BUG-95: kept in the database, outside
/// the tamper-evident chain, so a restart doesn't resend. The key is (case, jurisdiction, band, deadline instant)
/// (<see cref="DeadlineIdentity"/>, BUG-619): a case whose clock is re-based (e.g. the materiality decision date is
/// corrected) has a new deadline and so is treated as a fresh reminder, and each regulator on a clock is reminded.
/// </summary>
public interface IDeadlineReminderTracker
{
    /// <summary>BUG-619: records the case as reminded for this (band, deadline) for each of <paramref name="jurisdictionCodes"/>;
    /// returns the codes seen for the first time.</summary>
    IReadOnlyList<string> MarkNotified(Guid caseId, IReadOnlyCollection<string> jurisdictionCodes, SlaState band, DateTimeOffset? dueAtUtc);

    /// <summary>BUG-08: un-marks what wasn't delivered, so the next scan sends it again.</summary>
    void Forget(Guid caseId, IReadOnlyCollection<string> jurisdictionCodes, SlaState band, DateTimeOffset? dueAtUtc);

    /// <summary>BUG-156: un-marks every reminder sent for the case, when its clock runs again (a notice was cleared).</summary>
    void ForgetCase(Guid caseId);

    /// <summary>BUG-619: un-marks the reminders sent for one of the case's jurisdictions, when its notice is removed.</summary>
    void ForgetJurisdiction(Guid caseId, string jurisdictionCode);
}

/// <inheritdoc />
public sealed class DeadlineReminderTracker(Abstractions.INotificationMarks? marks = null) : IDeadlineReminderTracker
{
    private readonly Abstractions.INotificationMarks _marks = marks ?? new Abstractions.InMemoryNotificationMarks();

    public IReadOnlyList<string> MarkNotified(Guid caseId, IReadOnlyCollection<string> jurisdictionCodes, SlaState band, DateTimeOffset? dueAtUtc)
    {
        var legacy = DeadlineIdentity.LegacyKey(caseId, band, dueAtUtc);
        // BUG-649: the codes on the clock now are converted here, so who each was sent to (BUG-148) goes with the legacy mark.
        return DeadlineIdentity.MarkNew(_marks, jurisdictionCodes, code => DeadlineIdentity.Key(caseId, code, band, dueAtUtc), legacy,
            DeadlineIdentity.LegacyRecipientPrefix(legacy));
    }

    public void Forget(Guid caseId, IReadOnlyCollection<string> jurisdictionCodes, SlaState band, DateTimeOffset? dueAtUtc)
    {
        foreach (var code in jurisdictionCodes) _marks.Remove(DeadlineIdentity.Key(caseId, code, band, dueAtUtc));
    }

    public void ForgetCase(Guid caseId)
    {
        var prefix = DeadlineIdentity.CasePrefix(caseId);
        _marks.RemovePrefix(prefix);
        _marks.RemovePrefix("to|" + prefix);   // and who each was sent to (BUG-148)
    }

    public void ForgetJurisdiction(Guid caseId, string jurisdictionCode)
    {
        // A legacy mark covered every code on its clock, so it would hold this one back: it goes too.
        foreach (var prefix in DeadlineIdentity.LegacyPrefixes(caseId).Append(DeadlineIdentity.JurisdictionPrefix(caseId, jurisdictionCode)))
        {
            _marks.RemovePrefix(prefix);
            _marks.RemovePrefix("to|" + prefix);
        }
    }
}
