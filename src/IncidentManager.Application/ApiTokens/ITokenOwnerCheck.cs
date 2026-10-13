namespace IncidentManager.Application.ApiTokens;

/// <summary>An owner's access as the directory of record (Active Directory) reports it now.</summary>
/// <param name="Active">False when the account is gone or disabled: the owner's tokens stop working.</param>
/// <param name="Roles">The CaseBook roles the owner's current groups map to.</param>
public sealed record OwnerAccess(bool Active, IReadOnlySet<string> Roles);

/// <summary>
/// BUG-20: a personal API token acts as its owner, so it should carry only the access the owner holds now. The user
/// mirror updates only when the owner signs in, so a leaver who never signs in again kept their roles on their tokens
/// until expiry. This asks the directory instead (cached briefly). Null means it can't say (not using Windows sign-in),
/// and the mirror is used as before.
/// </summary>
public interface ITokenOwnerCheck
{
    Task<OwnerAccess?> CheckAsync(string ownerUserId, CancellationToken ct = default);

    /// <summary>
    /// WF-57: the same question when choosing who gets an email. When the directory can't be reached the answer is null
    /// (the mirror stands), not "inactive": a token stays fail-closed, but a manager isn't left off a report or an
    /// escalation because the domain controller was briefly out of reach (owner's decision).
    /// </summary>
    Task<OwnerAccess?> CheckRecipientAsync(string userId, CancellationToken ct = default) => CheckAsync(userId, ct);
}
