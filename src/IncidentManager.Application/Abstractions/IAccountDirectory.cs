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

/// <summary>The answer to a lookup: found, not found, or the directory couldn't be asked.</summary>
public sealed record DirectoryLookup(DirectoryLookupOutcome Outcome, DirectoryAccount? Account, string? Problem = null)
{
    public static DirectoryLookup NotFound { get; } = new(DirectoryLookupOutcome.NotFound, null);
    public static DirectoryLookup Unavailable(string problem) => new(DirectoryLookupOutcome.Unavailable, null, problem);
    public static DirectoryLookup Of(DirectoryAccount account) => new(DirectoryLookupOutcome.Found, account);
}

public enum DirectoryLookupOutcome { Found, NotFound, Unavailable }

/// <summary>
/// BUG-416: looks an account up in the organisation's directory (Active Directory under Windows sign-in). Read-only; the
/// app never changes the directory. <see cref="IsAvailable"/> is false where there's no directory to ask (development
/// off Windows, or sign-in that isn't Windows), and the UI then doesn't offer a lookup.
/// </summary>
public interface IAccountDirectory
{
    bool IsAvailable { get; }

    /// <summary>Finds the account written as <c>DOMAIN\sam</c>, <c>.\sam</c>, a bare sAMAccountName or a UPN.</summary>
    Task<DirectoryLookup> LookupAsync(string account, CancellationToken ct = default);
}
