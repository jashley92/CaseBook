using System.Globalization;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// BUG-09: when one regulator was notified about a case (a jurisdiction code such as "NY"). Each jurisdiction's
/// notification clock stops on its own notice; the case's <see cref="Case.ReportedAtUtc"/> is the time the last one
/// in play was notified. Hash-chained and audited like the rest of the record. A correction updates it in place.
/// CAP-07: it can also say how the regulator was notified (<see cref="Method"/>, <see cref="Reference"/>,
/// <see cref="NotifiedBy"/>, <see cref="EvidenceId"/>), each optional and editable later without moving the time.
/// </summary>
public class JurisdictionNotice : AuditableEntity, IHashableEntity
{
    public const int MaxJurisdictionLength = 50;
    public const int MaxReferenceLength = 200;
    public const int MaxNotifiedByLength = 200;

    public Guid CaseId { get; set; }

    /// <summary>The jurisdiction code, upper case, as the data elements name it.</summary>
    public string Jurisdiction { get; set; } = string.Empty;

    public DateTimeOffset NotifiedAtUtc { get; set; }

    /// <summary>
    /// WF-77: the regulator's deadline as it stood when the notice was recorded (the rule's window from the clock's start
    /// then), so whether the notice was on time doesn't change when a rule's window or the materiality decision changes
    /// later. Null where no clock ran, or for a notice recorded before it was kept (filled at start-up). BUG-630: it decides
    /// whether the notice was on time, so it's in the canonical from format 4 (when set), and the start-up fill is an
    /// audited change.
    /// </summary>
    public DateTimeOffset? DueAtUtc { get; set; }

    /// <summary>CAP-07: how the notice was given (portal, letter, email, phone or other).</summary>
    public NoticeMethod? Method { get; set; }

    /// <summary>CAP-07: the regulator's reference or confirmation number, as typed.</summary>
    public string? Reference { get; set; }

    /// <summary>CAP-07: who gave the notice, as typed (a person, or counsel).</summary>
    public string? NotifiedBy { get; set; }

    /// <summary>CAP-07: the evidence file on the same case that holds the notice (the service checks it's there).</summary>
    public Guid? EvidenceId { get; set; }

    public string? RowHash { get; set; }

    /// <summary>CAP-07: whether any of how it was notified is recorded.</summary>
    public bool HasDetails => Method is not null || Reference is not null || NotifiedBy is not null || EvidenceId is not null;

    /// <summary>CAP-07: how it was notified, as recorded.</summary>
    public NoticeDetails GetDetails() => new(Method, Reference, NotifiedBy, EvidenceId);

    /// <summary>
    /// CAP-07: records how the regulator was notified, replacing what was recorded (a blank clears its part). The caller
    /// checks the evidence file is on the case. False when nothing changed.
    /// </summary>
    public bool SetDetails(NoticeDetails details)
    {
        var d = details.Normalized();
        if (d == GetDetails()) return false;
        (Method, Reference, NotifiedBy, EvidenceId) = (d.Method, d.Reference, d.NotifiedBy, d.EvidenceId);
        return true;
    }

    /// <summary>CAP-07: signature of the details editor's fields (FR-06 / REL-02), so a stale edit is refused.</summary>
    public string DetailsConcurrencyStamp() => string.Join('\u001f',
        Method is { } m ? ((int)m).ToString(CultureInfo.InvariantCulture) : "", Reference, NotifiedBy, EvidenceId?.ToString());

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, Jurisdiction, NotifiedAtUtc.ToString("o"), CreatedBy, CreatedAtUtc.ToString("o"))
        + Canonical.Since(4, DueAtUtc is not null, () => "|due|" + Canonical.Time(DueAtUtc))
        // CAP-07: from format 5, how it was notified, only when any of it is recorded (a notice without keeps its hash).
        + Canonical.Since(5, HasDetails, () => "|how|" + Canonical.Num(Method) + "|" + Canonical.Text(Reference)
                                               + "|" + Canonical.Text(NotifiedBy) + "|" + EvidenceId);
}

/// <summary>
/// CAP-07: how a regulator was notified, each part optional: the method, the regulator's reference or confirmation number,
/// who gave the notice and the evidence file holding it.
/// </summary>
public sealed record NoticeDetails(NoticeMethod? Method = null, string? Reference = null, string? NotifiedBy = null, Guid? EvidenceId = null)
{
    public static readonly NoticeDetails None = new();

    /// <summary>Whether any part is given.</summary>
    public bool IsEmpty => Method is null && string.IsNullOrWhiteSpace(Reference) && string.IsNullOrWhiteSpace(NotifiedBy) && EvidenceId is null;

    /// <summary>Trimmed, a blank as none, and checked: a method that isn't one, or text too long, is refused.</summary>
    public NoticeDetails Normalized()
    {
        if (Method is { } m && !Enum.IsDefined(m)) throw new ArgumentException("Choose how the regulator was notified from the list.");
        var reference = Blank(Reference);
        var by = Blank(NotifiedBy);
        if (reference?.Length > JurisdictionNotice.MaxReferenceLength)
            throw new ArgumentException($"The reference can be at most {JurisdictionNotice.MaxReferenceLength} characters.");
        if (by?.Length > JurisdictionNotice.MaxNotifiedByLength)
            throw new ArgumentException($"Who notified can be at most {JurisdictionNotice.MaxNotifiedByLength} characters.");
        return new NoticeDetails(Method, reference, by, EvidenceId == Guid.Empty ? null : EvidenceId);
    }

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
