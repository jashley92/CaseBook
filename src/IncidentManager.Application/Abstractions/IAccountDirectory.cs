namespace IncidentManager.Application.Abstractions;

/// <summary>BUG-416: what the directory holds for one account. Every field is as AD returned it (times in UTC).</summary>
public sealed record DirectoryAccount(
    string SamAccountName,
    string? Domain,
    string? UserPrincipalName,
    string? DisplayName,
    string? Title,
    string? Department,
    string? Manager,
    string? Email,
    string? DistinguishedName,
    bool? Enabled,
    bool? LockedOut,
    DateTimeOffset? AccountExpiresUtc,
    DateTimeOffset? LastLogonUtc,
    DateTimeOffset? PasswordLastSetUtc,
    DateTimeOffset? WhenCreatedUtc);

/// <summary>
/// The answer to a lookup: found, not found, the directory couldn't be asked, or the account wasn't looked up at all
/// (BUG-419: it names a domain CaseBook doesn't ask, or one computer's local accounts).
/// </summary>
public sealed record DirectoryLookup(DirectoryLookupOutcome Outcome, DirectoryAccount? Account, string? Problem = null)
{
    public static DirectoryLookup NotFound { get; } = new(DirectoryLookupOutcome.NotFound, null);
    public static DirectoryLookup Unavailable(string problem) => new(DirectoryLookupOutcome.Unavailable, null, problem);
    public static DirectoryLookup NotLookedUp(string reason) => new(DirectoryLookupOutcome.NotLookedUp, null, reason);
    public static DirectoryLookup Of(DirectoryAccount account) => new(DirectoryLookupOutcome.Found, account);

    /// <summary>BUG-432: the account value this answers for, as the case had it when it was looked up.</summary>
    public string? LookedUp { get; init; }
}

/// <summary>BUG-419: NotLookedUp is neither "not found" nor a failure: nothing was asked.</summary>
public enum DirectoryLookupOutcome { Found, NotFound, Unavailable, NotLookedUp }

/// <summary>
/// BUG-416: looks an account up in the organisation's directory (Active Directory under Windows sign-in). Read-only; the
/// app never changes the directory. <see cref="IsAvailable"/> is false where there's no directory to ask (development
/// off Windows, or sign-in that isn't Windows), and the UI then doesn't offer a lookup.
/// </summary>
public interface IAccountDirectory
{
    bool IsAvailable { get; }

    /// <summary>
    /// Finds the account written as <c>DOMAIN\sam</c>, a bare sAMAccountName or a UPN. BUG-419: a domain the server
    /// doesn't belong to or trust, and a local account (<c>.\sam</c>, <c>COMPUTER\sam</c>), answer NotLookedUp.
    /// </summary>
    Task<DirectoryLookup> LookupAsync(string account, CancellationToken ct = default);
}
