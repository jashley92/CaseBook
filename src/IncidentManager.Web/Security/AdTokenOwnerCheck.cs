using System.Collections.Concurrent;
using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.ApiTokens;

namespace IncidentManager.Web.Security;

/// <summary>
/// BUG-20: a personal API token's owner, checked in Active Directory. The account must still exist and be enabled,
/// and the token keeps only the roles the owner's current groups map to (resolved the same way as at sign-in). Each
/// answer is reused for <see cref="Fresh"/>. If AD can't be reached, the last answer is used for up to
/// <see cref="LastKnownLimit"/>, then the token is refused rather than trusted.
/// </summary>
public sealed class AdTokenOwnerCheck : ITokenOwnerCheck
{
    public static readonly TimeSpan Fresh = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan LastKnownLimit = TimeSpan.FromHours(24);

    /// <summary>What the directory says about an account: enabled, and the SIDs of its groups; null if it doesn't exist.</summary>
    public sealed record AccountGroups(bool Enabled, IReadOnlyList<string> GroupSids);

    private static readonly IReadOnlySet<string> NoRoles = new HashSet<string>();

    private readonly IRoleDirectory _roles;
    private readonly IClock _clock;
    private readonly ILogger<AdTokenOwnerCheck>? _log;
    private readonly Func<string, AccountGroups?> _lookup;
    private readonly ConcurrentDictionary<string, (OwnerAccess Access, DateTimeOffset At)> _answers = new(StringComparer.OrdinalIgnoreCase);

    public AdTokenOwnerCheck(IRoleDirectory roles, IClock clock, ILogger<AdTokenOwnerCheck>? log = null,
        Func<string, AccountGroups?>? lookup = null)
    {
        _roles = roles;
        _clock = clock;
        _log = log;
        _lookup = lookup ?? (OperatingSystem.IsWindows() ? QueryDirectory : _ => throw new PlatformNotSupportedException());
    }

    public async Task<OwnerAccess?> CheckAsync(string ownerUserId, CancellationToken ct = default)
    {
        var now = _clock.UtcNow;
        var known = _answers.TryGetValue(ownerUserId, out var last);
        if (known && now - last.At < Fresh) return last.Access;
        try
        {
            var account = await Task.Run(() => _lookup(ownerUserId), ct);
            var access = account is null
                ? new OwnerAccess(false, NoRoles)
                : new OwnerAccess(account.Enabled, _roles.RolesForGroups(Candidates(account.GroupSids)));
            _answers[ownerUserId] = (access, now);
            return access;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "Couldn't check an API token's owner in Active Directory.");
            return known && now - last.At < LastKnownLimit ? last.Access : new OwnerAccess(false, NoRoles);
        }
    }

    // The same names a sign-in matches mappings against: the SID, and "DOMAIN\Group" and "Group".
    private static IEnumerable<string> Candidates(IEnumerable<string> groupSids) =>
        groupSids.SelectMany(sid => RoleClaimsTransformer.NamesForSid(sid).Prepend(sid));

    // BUG-127: an owner id is however the user signed in: DOMAIN\sam under Windows sign-in (WindowsIdentity carries no
    // name-identifier or UPN claim), a UPN or a SID otherwise. FindByIdentity without a type tries each of those forms.
    [SupportedOSPlatform("windows")]
    private static AccountGroups? QueryDirectory(string ownerUserId)
    {
        using var ctx = new PrincipalContext(ContextType.Domain);
        using var user = UserPrincipal.FindByIdentity(ctx, ownerUserId);
        if (user is null) return null;
        using var groups = user.GetAuthorizationGroups();
        var sids = groups.Select(g => g.Sid?.Value).Where(s => s is not null).Select(s => s!).ToList();
        // REV-68: an account past its expiry date can't sign in either (a common way to end a contractor's access, without
        // disabling the account), so its tokens and calendar feed stop with it.
        var expired = user.AccountExpirationDate is { } expires
            && (expires.Kind == DateTimeKind.Local ? expires.ToUniversalTime() : expires) <= DateTime.UtcNow;
        return new AccountGroups(user.Enabled != false && !expired, sids);
    }
}
