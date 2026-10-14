using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// BUG-416: what Active Directory said about an account entity at one moment: taken when the account is added to the
/// case, and again whenever an analyst asks for a fresh lookup and chooses to keep it. Append-only and hashed, so the
/// record shows the account's state (enabled, locked, last logon) as the team saw it then, even after it changes in AD.
/// No foreign key to the entity: like a verdict change, the row outlives it.
/// </summary>
public class AccountDirectorySnapshot : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public Guid EntityId { get; set; }

    /// <summary>The account as it was looked up (the entity's value then).</summary>
    public string LookedUp { get; set; } = string.Empty;

    public DirectorySnapshotTrigger Trigger { get; set; }

    /// <summary>False when the directory answered and had no such account; the other fields are then empty.</summary>
    public bool Found { get; set; }

    public string? SamAccountName { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? DisplayName { get; set; }
    public string? Title { get; set; }
    public string? Department { get; set; }
    public string? Manager { get; set; }
    public string? Email { get; set; }
    public string? DistinguishedName { get; set; }
    public bool? Enabled { get; set; }
    public bool? LockedOut { get; set; }
    public DateTimeOffset? AccountExpiresUtc { get; set; }
    public DateTimeOffset? LastLogonUtc { get; set; }
    public DateTimeOffset? PasswordLastSetUtc { get; set; }
    public DateTimeOffset? WhenCreatedUtc { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, EntityId, Canonical.Text(LookedUp), (int)Trigger, Found ? 1 : 0,
        Canonical.Text(SamAccountName), Canonical.Text(UserPrincipalName), Canonical.Text(DisplayName), Canonical.Text(Title),
        Canonical.Text(Department), Canonical.Text(Manager), Canonical.Text(Email), Canonical.Text(DistinguishedName),
        Flag(Enabled), Flag(LockedOut), Canonical.Time(AccountExpiresUtc), Canonical.Time(LastLogonUtc),
        Canonical.Time(PasswordLastSetUtc), Canonical.Time(WhenCreatedUtc), CreatedBy, Canonical.Time(CreatedAtUtc));

    private static string Flag(bool? b) => b is null ? "" : b.Value ? "1" : "0";
}
