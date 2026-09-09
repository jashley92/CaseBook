namespace IncidentManager.Application.Abstractions;

/// <summary>A directory entry mirrored from Active Directory — for display and assignment pickers.</summary>
/// <param name="UserId">Stable identifier (AD SID, or UPN as a fallback) — the same value stored as an actor/assignee.</param>
public sealed record UserSummary(
    string UserId,
    string DisplayName,
    string? UserPrincipalName,
    string? Email,
    string RolesCsv);

/// <summary>
/// A cached directory of known users (the <c>AppUser</c> mirror). Populated as users sign in
/// (self-service) and seeded with the team in dev. Resolves stable ids to human names and emails for
/// display, the assignment picker, and notification lookups — without a per-request database hit.
/// Rebuilt on startup and whenever the mirror changes (<see cref="Invalidate"/>).
/// </summary>
public interface IUserDirectory
{
    /// <summary>
    /// Records or refreshes a user from their authenticated identity. Idempotent (keyed on
    /// <paramref name="userId"/>) and throttled, so calling it per request is cheap.
    /// </summary>
    Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv,
        CancellationToken ct = default);

    /// <summary>All known users, ordered by display name — backs the assignment picker.</summary>
    IReadOnlyList<UserSummary> All();

    /// <summary>Resolves a stable id to its directory entry, or <c>null</c> when unknown.</summary>
    UserSummary? Resolve(string userId);

    /// <summary>Display name for an id — "System" for background work, the id itself when unknown,
    /// "—" when the id is null/empty (e.g. an unedited entry's ModifiedBy).</summary>
    string DisplayFor(string? userId);

    /// <summary>
    /// Email for an id, or <c>null</c> when unknown — the seam that unblocks assignment / overdue
    /// after-action notifications (E-03b).
    /// </summary>
    string? EmailFor(string userId);

    /// <summary>Rebuilds the cached snapshot from the database (call after seeding / a mirror change).</summary>
    void Invalidate();
}
