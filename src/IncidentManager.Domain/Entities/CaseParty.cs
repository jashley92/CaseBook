using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// CAP-34: an outside party on a case (outside counsel, a forensics firm, the insurer, law enforcement, a regulator's
/// contact), with the reference it gave the matter (a claim, report or matter number) and when it was engaged. Facts
/// only (ADR 0012): who, how to reach them, their reference and when; no rating of how they did. Audited and
/// hash-chained like the rest of the case; seen by whoever can see the case. A new table, so every field is in its row
/// hash from its first row (no format brought any of them in later).
/// </summary>
public class CaseParty : AuditableEntity, IHashableEntity
{
    public const int MaxNameLength = 300;
    public const int MaxContactLength = 300;
    public const int MaxReferenceLength = 200;
    public const int MaxNotesLength = 2000;

    public Guid CaseId { get; set; }

    public PartyRole Role { get; set; }

    /// <summary>The firm, agency or person, as typed.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>How to reach them (a person, a phone number, an address), as typed.</summary>
    public string? Contact { get; set; }

    /// <summary>The party's own reference for the matter: a claim number, a police report number, a matter number.</summary>
    public string? Reference { get; set; }

    /// <summary>When they were engaged on (or told of) this matter.</summary>
    public DateTimeOffset? EngagedAtUtc { get; set; }

    /// <summary>Facts about the engagement (its scope, when to call), as typed.</summary>
    public string? Notes { get; set; }

    public string? RowHash { get; set; }

    /// <summary>The party as recorded.</summary>
    public PartyDetails GetDetails() => new(Role, Name, Contact, Reference, EngagedAtUtc, Notes);

    /// <summary>Replaces what's recorded with <paramref name="d"/> (already normalized). False when nothing changed.</summary>
    internal bool Set(PartyDetails d)
    {
        if (d == GetDetails()) return false;
        (Role, Name, Contact, Reference, EngagedAtUtc, Notes) = (d.Role, d.Name, d.Contact, d.Reference, d.EngagedAtUtc, d.Notes);
        return true;
    }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, Canonical.Num(Role), Canonical.Text(Name), Canonical.Text(Contact), Canonical.Text(Reference),
        Canonical.Time(EngagedAtUtc), Canonical.Text(Notes), CreatedBy, Canonical.Time(CreatedAtUtc));
}

/// <summary>CAP-34: what's recorded about an outside party. <see cref="Name"/> is required; the rest is optional.</summary>
public sealed record PartyDetails(PartyRole Role, string Name, string? Contact = null, string? Reference = null,
    DateTimeOffset? EngagedAtUtc = null, string? Notes = null)
{
    /// <summary>Trimmed, a blank as none, and checked: a role that isn't one, a missing name, text over its column or an
    /// engagement in the future is refused.</summary>
    public PartyDetails Normalized(DateTimeOffset nowUtc)
    {
        if (!Enum.IsDefined(Role)) throw new ArgumentException("Choose the party's role from the list.");
        var name = Blank(Name) ?? throw new ArgumentException("Name the party: the firm, agency or person.");
        Check(name, CaseParty.MaxNameLength, "The name");
        var contact = Blank(Contact);
        Check(contact, CaseParty.MaxContactLength, "The contact");
        var reference = Blank(Reference);
        Check(reference, CaseParty.MaxReferenceLength, "The reference");
        var notes = Blank(Notes);
        Check(notes, CaseParty.MaxNotesLength, "The notes");
        if (EngagedAtUtc is { } at && Case.ToMinute(at) > Case.ToMinute(nowUtc))
            throw new ArgumentException("When they were engaged can't be in the future.");
        return new PartyDetails(Role, name, contact, reference, EngagedAtUtc, notes);
    }

    private static void Check(string? s, int max, string what)
    {
        if (s?.Length > max) throw new ArgumentException($"{what} can be at most {max} characters.");
    }

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
