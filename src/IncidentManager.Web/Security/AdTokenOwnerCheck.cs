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
/// <para>
/// BUG-469: a lookup taking longer than <see cref="Timeout"/> counts as AD being unreachable. It runs on its own thread,
/// one at a time per account (later callers join it), and an account whose lookup timed out and is still blocked isn't
/// asked about again until it returns.
/// </para>
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
    // BUG-266: what the directory said (enabled, the names its groups match mappings by), not the roles: the roles are
    // resolved from the groups on each call, so a mapping removed in Administration applies at once, as it does to
    // signed-in sessions. BUG-575: kept only when every group was named.
    private readonly ConcurrentDictionary<string, (Known Account, DateTimeOffset At)> _answers = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>An account as last answered: whether it exists, is enabled, and its groups' names.</summary>
    private sealed record Known(bool Exists, bool Enabled, IReadOnlySet<string> Groups);

    private readonly SidNames? _sids;
    // BUG-292: when the directory last failed for an account; it isn't asked again for a minute, so every call during an
    // outage doesn't wait out its own timeout.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _failedAt = new(StringComparer.OrdinalIgnoreCase);
    public static readonly TimeSpan RetryAfterFailure = TimeSpan.FromMinutes(1);

    /// <summary>BUG-469: how long a caller waits on the directory before taking it to be unreachable.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    /// <summary>BUG-469: lookups still blocked after timing out in one domain, past which no further account in that domain
    /// is asked about (a hung trusted domain doesn't stop lookups in the others, as in AdAccountDirectory, BUG-471).</summary>
    public const int MaxHung = 8;

    private readonly TimeProvider _time;
    private readonly object _gate = new();
    // BUG-469: the lookup running for an account, which later callers join rather than starting another.
    private readonly Dictionary<string, Pending> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _hung = new(StringComparer.OrdinalIgnoreCase);   // per domain

    public AdTokenOwnerCheck(IRoleDirectory roles, IClock clock, ILogger<AdTokenOwnerCheck>? log = null,
        Func<string, AccountGroups?>? lookup = null, TimeProvider? time = null, SidNames? sids = null)
    {
        _sids = sids;
        _roles = roles;
        _clock = clock;
        _log = log;
        _time = time ?? TimeProvider.System;
        _lookup = lookup ?? (OperatingSystem.IsWindows() ? QueryDirectory : _ => throw new PlatformNotSupportedException());
    }

    public Task<OwnerAccess?> CheckAsync(string ownerUserId, CancellationToken ct = default) => CheckCoreAsync(ownerUserId, failOpen: false, ct);

    public Task<OwnerAccess?> CheckRecipientAsync(string userId, CancellationToken ct = default) => CheckCoreAsync(userId, failOpen: true, ct);

    private async Task<OwnerAccess?> CheckCoreAsync(string ownerUserId, bool failOpen, CancellationToken ct)
    {
        var now = _clock.UtcNow;
        var known = _answers.TryGetValue(ownerUserId, out var last);
        if (known && now - last.At < Fresh) return Access(last.Account);
        if (_failedAt.TryGetValue(ownerUserId, out var failed) && now - failed < RetryAfterFailure)
            return Unreachable(known, last, now, failOpen);
        Pending pending;
        lock (_gate)
        {
            if (_pending.TryGetValue(ownerUserId, out var running))
            {
                // BUG-469: one for this account timed out and is still blocked: no second one, and no wait on it.
                if (running.Hung)
                {
                    _failedAt[ownerUserId] = now;
                    return Unreachable(known, last, now, failOpen);
                }
                pending = running;
            }
            else
            {
                // BUG-469: with MaxHung blocked in its domain, that domain is taken to be down rather than given another thread.
                if (_hung.GetValueOrDefault(DomainOf(ownerUserId)) >= MaxHung) return Unreachable(known, last, now, failOpen);
                pending = Start(ownerUserId);
            }
        }
        try
        {
            var account = await pending.Lookup.WaitAsync(Timeout, _time, ct);
            if (await NamedAsync(account) is not { } named)
            {
                // BUG-575: some of its groups weren't named in time (or the directory failed naming them). Read as the
                // whole answer, a Manager mapped by group name lost the role: dropped from escalations and the executive
                // report, a reminder rerouted and marked sent, a token refused. It's AD being unreachable instead.
                _log?.LogWarning("Active Directory didn't name all of an account's groups in time when checking an API token's owner.");
                _failedAt[ownerUserId] = now;
                return Unreachable(known, last, now, failOpen);
            }
            _answers[ownerUserId] = (named, now);
            _failedAt.TryRemove(ownerUserId, out _);
            return Access(named);
        }
        catch (TimeoutException)
        {
            _log?.LogWarning("Active Directory didn't answer in time when checking an API token's owner.");
            lock (_gate)
            {
                if (!pending.Done && !pending.Hung)
                {
                    pending.Hung = true;
                    _hung[pending.Domain] = _hung.GetValueOrDefault(pending.Domain) + 1;
                }
            }
            _failedAt[ownerUserId] = now;
            return Unreachable(known, last, now, failOpen);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "Couldn't check an API token's owner in Active Directory.");
            _failedAt[ownerUserId] = now;
            return Unreachable(known, last, now, failOpen);
        }
    }

    // BUG-469: on its own thread (a blocked directory call doesn't hold a pool thread); called under _gate. One that
    // finishes after its callers stopped waiting only frees its place; its answer isn't kept.
    private Pending Start(string ownerUserId)
    {
        var pending = new Pending { Domain = DomainOf(ownerUserId) };
        pending.Lookup = Task.Factory.StartNew(() =>
        {
            try { return _lookup(ownerUserId); }
            finally
            {
                lock (_gate)
                {
                    pending.Done = true;
                    if (pending.Hung && _hung.TryGetValue(pending.Domain, out var n))
                    {
                        if (n <= 1) _hung.Remove(pending.Domain);
                        else _hung[pending.Domain] = n - 1;
                    }
                    _pending.Remove(ownerUserId);
                }
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        _pending[ownerUserId] = pending;
        return pending;
    }

    private sealed class Pending
    {
        public Task<AccountGroups?> Lookup = null!;
        public bool Done;
        public bool Hung;   // timed out, still blocked
        public string Domain = "";
    }

    // The domain QueryDirectory asks: DOMAIN of DOMAIN\sam, else "" (a UPN or SID goes to the server's own domain).
    private static string DomainOf(string ownerUserId)
    {
        var slash = ownerUserId.IndexOf('\\');
        return slash > 0 ? ownerUserId[..slash] : "";
    }

    private OwnerAccess Access(Known account) => account.Exists
        ? new OwnerAccess(account.Enabled, _roles.RolesForGroups(account.Groups))
        : new OwnerAccess(false, NoRoles);

    // The directory can't be asked: the last answer for up to a day, then refused (or, for a feed recipient, not known).
    private OwnerAccess? Unreachable(bool known, (Known Account, DateTimeOffset At) last, DateTimeOffset now, bool failOpen) =>
        known && now - last.At < LastKnownLimit ? Access(last.Account) : failOpen ? null : new OwnerAccess(false, NoRoles);

    // The same names a sign-in matches mappings against: the SID, and "DOMAIN\Group" and "Group" (BUG-565: translated
    // together, bounded). Null when some weren't named (BUG-575).
    private async Task<Known?> NamedAsync(AccountGroups? account)
    {
        if (account is null) return new Known(false, false, NoRoles);
        var groups = await RoleClaimsTransformer.CandidatesForAsync(account.GroupSids, _sids);
        return groups.Complete ? new Known(true, account.Enabled, groups.Names) : null;
    }

    // BUG-127: an owner id is however the user signed in: DOMAIN\sam under Windows sign-in (WindowsIdentity carries no
    // name-identifier or UPN claim), a UPN or a SID otherwise. FindByIdentity without a type tries each of those forms.
    [SupportedOSPlatform("windows")]
    private static AccountGroups? QueryDirectory(string ownerUserId)
    {
        // BUG-400 sibling: a trusted domain's DOMAIN\sam is looked up in that domain, not the server's, where a namesake
        // would answer with someone else's groups and enabled state.
        var slash = ownerUserId.IndexOf('\\');
        var domain = slash > 0 ? ownerUserId[..slash] : null;
        using var ctx = domain is not null && string.Equals(domain, Environment.MachineName, StringComparison.OrdinalIgnoreCase)
            ? new PrincipalContext(ContextType.Machine)
            : new PrincipalContext(ContextType.Domain, domain);
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
