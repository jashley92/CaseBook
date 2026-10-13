using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// PROD-34: a bearer token for the API. A <see cref="ApiTokenKind.Personal"/> token belongs to a user, so
/// API actions attribute to them; a <see cref="ApiTokenKind.System"/> token is a named machine identity an
/// admin created and granted roles (for XSIAM/SOAR/scripts). Only a **SHA-256 hash** of the token is stored —
/// the plaintext is shown once at creation and never persisted. Permissions derive from the token's granted
/// role names at call time.
///
/// REV-05: hash-chained like other records, so a token row written or edited in the database (an admin identity minted
/// with a chosen secret) is caught by the record check. Its hash covers everything that decides what the token can do;
/// the per-call <see cref="LastUsedAtUtc"/> is left out, and an update that only moves it isn't audited.
/// </summary>
public class ApiToken : Entity, IHashableEntity
{
    /// <summary>A label; for a system token it also identifies the integration in the audit trail.</summary>
    public string Name { get; set; } = "";

    public ApiTokenKind Kind { get; set; }

    /// <summary>The identity API actions attribute to (the audit actor): a user id for a personal token, or
    /// <c>apitoken:&lt;slug&gt;</c> for a system token.</summary>
    public string OwnerUserId { get; set; } = "";

    /// <summary>The display name for that identity (the user's name, or the token name).</summary>
    public string OwnerDisplayName { get; set; } = "";

    /// <summary>The granted role names (comma-separated); permissions are resolved from these.</summary>
    public string RolesCsv { get; set; } = "";

    /// <summary>SHA-256 (hex) of the plaintext token — the lookup key. The plaintext is never stored.</summary>
    public string TokenHash { get; set; } = "";

    /// <summary>A short, non-secret leading fragment of the token, shown in lists to identify it.</summary>
    public string Prefix { get; set; } = "";

    public string CreatedBy { get; set; } = "";
    public DateTimeOffset CreatedAtUtc { get; set; }

    /// <summary>Required expiry — the token stops working after this instant (PROD-34 owner decision).</summary>
    public DateTimeOffset ExpiresAtUtc { get; set; }

    public DateTimeOffset? RevokedAtUtc { get; set; }
    public string? RevokedBy { get; set; }

    public DateTimeOffset? LastUsedAtUtc { get; set; }

    public string? RowHash { get; set; }   // REV-05

    public string BuildCanonicalContent() => string.Join('|',
        Canonical.Text(Name), Canonical.Num(Kind), Canonical.Text(OwnerUserId), Canonical.Text(OwnerDisplayName),
        Canonical.Text(RolesCsv), TokenHash, Prefix, Canonical.Text(CreatedBy), Canonical.Time(CreatedAtUtc),
        Canonical.Time(ExpiresAtUtc), Canonical.Time(RevokedAtUtc), Canonical.Text(RevokedBy));

    /// <summary>Usable right now: not revoked and not past its expiry.</summary>
    public bool IsActive(DateTimeOffset now) => RevokedAtUtc is null && ExpiresAtUtc > now;

    public IReadOnlyList<string> GetRoles() =>
        RolesCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
