using System.Security.Cryptography;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.ApiTokens;

/// <summary>Resolved identity + permissions for a validated API token (what the auth handler needs).</summary>
/// <param name="TokenId">CAP-09 review: the token's row id (never the secret), for a limit kept per token.</param>
public sealed record ApiTokenAuth(string OwnerUserId, string DisplayName, IReadOnlySet<Permission> Permissions, Guid TokenId = default);

/// <summary>A token row for the management lists (never carries the secret).</summary>
public sealed record ApiTokenView(
    Guid Id, string Name, ApiTokenKind Kind, string OwnerDisplayName, IReadOnlyList<string> Roles, string Prefix,
    string CreatedBy, DateTimeOffset CreatedAtUtc, DateTimeOffset ExpiresAtUtc,
    DateTimeOffset? RevokedAtUtc, DateTimeOffset? LastUsedAtUtc, bool IsActive);

/// <summary>The result of creating a token: the row plus the plaintext, shown to the caller exactly once.</summary>
public sealed record ApiTokenCreated(ApiTokenView Token, string Plaintext);

/// <summary>
/// PROD-34: issues, lists, revokes and validates API tokens. Personal tokens attribute to their owning user;
/// system tokens are named machine identities an admin grants roles. Only a SHA-256 hash is stored; the
/// plaintext is returned once at creation. Permissions derive from the token's roles via <see cref="IRoleDirectory"/>.
/// Create/revoke go to the SIEM stream; the token row is hash-chained (REV-05), so the interceptor records them in the
/// audit trail in the same save. The per-call last-used stamp is left out of the chain.
/// </summary>
public sealed class ApiTokenService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IRoleDirectory _directory;
    private readonly ISecurityEventSink? _siem;
    private readonly IUserDirectory? _users;
    private readonly ITokenOwnerCheck? _owners;

    /// <summary>S-11: the longest a personal token may live — it acts as a person, whose access can change.</summary>
    public static readonly TimeSpan MaxPersonalLifetime = TimeSpan.FromDays(90);

    /// <summary>S-11: the longest a system (integration) token may live before it must be re-issued.</summary>
    public static readonly TimeSpan MaxSystemLifetime = TimeSpan.FromDays(365);

    public ApiTokenService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        IRoleDirectory directory, ISecurityEventSink? siem = null, IUserDirectory? users = null,
        ITokenOwnerCheck? owners = null)
    {
        _owners = owners;
        _factory = factory;
        _user = user;
        _clock = clock;
        _directory = directory;
        _siem = siem;
        _users = users;
    }

    // ── Validation of a presented token (called by the auth handler) ──────────────────────────────

    /// <summary>Validates a presented token: hash → lookup → active? Returns the attribution + permissions, or
    /// null if unknown/expired/revoked. Stamps last-used.</summary>
    public async Task<ApiTokenAuth?> AuthenticateAsync(string? rawToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawToken)) return null;
        var hash = HashToken(rawToken.Trim());

        using var db = _factory.CreateDbContext();
        var row = await db.ApiTokens.FirstOrDefaultAsync(t => t.TokenHash == hash, ct);
        if (row is null || !row.IsActive(_clock.UtcNow)) return null;

        // S-11: a personal token acts as its owner, so it carries only the roles the owner still holds (as of their
        // latest sign-in, per the user mirror). An owner who has lost a role loses it on their tokens too; an owner
        // the directory no longer knows can't authenticate by token at all.
        var roles = row.GetRoles(_directory.IsRole);   // BUG-591: a legacy role name with a comma is one role
        // BUG-20: ask the directory of record when it can answer, since the mirror only moves when the owner signs in.
        if (row.Kind == ApiTokenKind.Personal && _owners is not null
            && await _owners.CheckAsync(row.OwnerUserId, ct) is { } access)
        {
            if (!access.Active) return null;
            roles = roles.Where(access.Roles.Contains).ToList();
            if (roles.Count == 0) return null;
        }
        else if (row.Kind == ApiTokenKind.Personal && _users is not null)
        {
            var owner = _users.Resolve(row.OwnerUserId);
            if (owner is null) return null;
            var current = IncidentManager.Domain.Common.RoleList.Split(owner.RolesCsv, _directory.IsRole)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            roles = roles.Where(current.Contains).ToList();
            if (roles.Count == 0) return null;
        }

        row.LastUsedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);

        var perms = _directory.PermissionsForRoles(roles);
        if (perms.Count == 0) perms = RoleDefinitions.PermissionsForRoleNames(roles);
        return new ApiTokenAuth(row.OwnerUserId, row.OwnerDisplayName, perms, row.Id);
    }

    // ── Creation ─────────────────────────────────────────────────────────────────────────────────

    /// <summary>Admin-only: create a named system token granted a set of roles.</summary>
    public async Task<ApiTokenCreated> CreateSystemAsync(string name, IEnumerable<string> roleNames,
        DateOnly expiresOn, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ApiTokenService>(_user, _siem);
        var n = Clean(name);
        var roles = CleanRoles(roleNames);
        var expiresAtUtc = ValidateExpiry(expiresOn, MaxSystemLifetime);
        if (roles.Count == 0) throw new ArgumentException("Grant the token at least one role.");
        // BUG-567: the role check with the save, under the gate a role delete (which refuses while a token holds the role)
        // and an import hold, so a token can't be left holding a deleted role that a later role of that name would fill.
        using var guard = await Admin.GuardGate.EnterAsync(ct);
        await EnsureRolesExistAsync(roles, ct);
        await EnsureSystemNameFreeAsync(n, ct);
        return await CreateAsync(n, ApiTokenKind.System, "apitoken:" + Slug(n), n, roles, expiresAtUtc, ct);
    }

    /// <summary>Any user: create a personal token. Roles must be a subset of the caller's own roles, so the
    /// token can never grant more than the user has; API actions attribute to the user.</summary>
    public async Task<ApiTokenCreated> CreatePersonalAsync(string name, IEnumerable<string> roleNames,
        DateOnly expiresOn, CancellationToken ct = default)
    {
        if (!_user.IsAuthenticated)
            throw new ForbiddenException(Permission.ViewCases, nameof(CreatePersonalAsync));
        var n = Clean(name);
        var roles = CleanRoles(roleNames);
        var expiresAtUtc = ValidateExpiry(expiresOn, MaxPersonalLifetime);
        if (roles.Count == 0) throw new ArgumentException("Select at least one of your roles for the token.");

        var mine = _user.RoleNames.ToHashSet(StringComparer.OrdinalIgnoreCase);   // S-14: custom roles count too
        var extra = roles.Where(r => !mine.Contains(r)).ToList();
        if (extra.Count > 0)
            throw new ArgumentException($"A personal token can't grant roles you don't have: {string.Join(", ", extra)}.");

        var display = string.IsNullOrWhiteSpace(_user.DisplayName) ? _user.UserId : _user.DisplayName;
        return await CreateAsync(n, ApiTokenKind.Personal, _user.UserId, display, roles, expiresAtUtc, ct);
    }

    private async Task<ApiTokenCreated> CreateAsync(string name, ApiTokenKind kind, string ownerUserId,
        string ownerDisplay, IReadOnlyList<string> roles, DateTimeOffset expiresAtUtc, CancellationToken ct)
    {
        var (plaintext, prefix, hash) = NewToken();
        var row = new ApiToken
        {
            Name = name, Kind = kind, OwnerUserId = ownerUserId, OwnerDisplayName = ownerDisplay,
            RolesCsv = IncidentManager.Domain.Common.RoleList.Join(roles), TokenHash = hash, Prefix = prefix,
            CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow, ExpiresAtUtc = expiresAtUtc
        };

        // REV-05: the token is chained like any record, so its Create entry (with its roles, expiry and row hash) is written
        // in the same save: there's no live credential without its audit line (REV-06).
        using var db = _factory.CreateDbContext();
        db.ApiTokens.Add(row);
        await db.SaveChangesAsync(ct);
        _siem?.Emit(SecurityEvents.ApiTokenChanged("ApiTokenCreated", _user.UserId, _user.UserPrincipalName,
            $"{name} ({kind})"));

        return new ApiTokenCreated(ToView(row), plaintext);
    }

    // ── Listing & revocation ─────────────────────────────────────────────────────────────────────

    /// <summary>The current user's own tokens (for the account page).</summary>
    public async Task<IReadOnlyList<ApiTokenView>> ListMineAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var rows = await db.ApiTokens.AsNoTracking()
            .Where(t => t.Kind == ApiTokenKind.Personal && t.OwnerUserId == _user.UserId)   // REV-06: not system tokens they made
            .OrderByDescending(t => t.CreatedAtUtc).ToListAsync(ct);
        return rows.Select(ToView).ToList();
    }

    /// <summary>Every token (admin oversight).</summary>
    public async Task<IReadOnlyList<ApiTokenView>> ListAllAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<ApiTokenService>(_user, _siem);
        using var db = _factory.CreateDbContext();
        var rows = await db.ApiTokens.AsNoTracking()
            .OrderByDescending(t => t.CreatedAtUtc).ToListAsync(ct);
        return rows.Select(ToView).ToList();
    }

    /// <summary>Revokes a token. The owner may revoke their own; an admin may revoke any.</summary>
    public async Task RevokeAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var row = await db.ApiTokens.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (row is null || row.RevokedAtUtc is not null) return;

        // REV-06: the owner path is for personal tokens. A system token is the admins' to revoke, not whoever created it.
        var owns = row.Kind == ApiTokenKind.Personal && string.Equals(row.OwnerUserId, _user.UserId, StringComparison.Ordinal);
        if (!_user.Has(Permission.Administer) && !owns)
            throw new ForbiddenException(Permission.Administer, nameof(RevokeAsync));

        row.RevokedAtUtc = _clock.UtcNow;
        row.RevokedBy = _user.UserId;
        await db.SaveChangesAsync(ct);   // REV-05: chained, with the revocation in the same save
        _siem?.Emit(SecurityEvents.ApiTokenChanged("ApiTokenRevoked", _user.UserId, _user.UserPrincipalName,
            $"{row.Name} ({row.Kind})"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static ApiTokenView ToView(ApiToken t) => new(
        t.Id, t.Name, t.Kind, t.OwnerDisplayName, t.GetRoles(), t.Prefix, t.CreatedBy, t.CreatedAtUtc,
        t.ExpiresAtUtc, t.RevokedAtUtc, t.LastUsedAtUtc, t.RevokedAtUtc is null && t.ExpiresAtUtc > DateTimeOffset.UtcNow);

    /// <summary>Generates a token: an opaque, high-entropy secret; returns (plaintext, display prefix, hash).</summary>
    public static (string Plaintext, string Prefix, string Hash) NewToken()
    {
        var body = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var plaintext = "cbk_" + body;
        return (plaintext, plaintext[..12], HashToken(plaintext));
    }

    /// <summary>SHA-256 (hex) of a token — the stored lookup key.</summary>
    public static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <summary>BUG-717: a token picked to expire on day D works through the end of D (23:59:59.9999999 UTC), not until
    /// its start; the lifetime cap counts whole days from today (UTC). Returns the instant it stops working.</summary>
    private DateTimeOffset ValidateExpiry(DateOnly expiresOn, TimeSpan maxLifetime)
    {
        var expiresAtUtc = EndOfUtcDay(expiresOn);
        if (expiresAtUtc <= _clock.UtcNow)
            throw new ArgumentException("The expiry date must be in the future.");
        if (expiresOn > DateOnly.FromDateTime(_clock.UtcNow.UtcDateTime).AddDays((int)maxLifetime.TotalDays))
            throw new ArgumentException($"A token can last at most {maxLifetime.TotalDays:0} days. Re-issue it before it lapses.");
        return expiresAtUtc;
    }

    /// <summary>The last instant of a UTC calendar day.</summary>
    public static DateTimeOffset EndOfUtcDay(DateOnly day) => new(day.ToDateTime(TimeOnly.MaxValue), TimeSpan.Zero);

    private static string Clean(string name)
    {
        var n = (name ?? "").Trim();
        if (n.Length == 0) throw new ArgumentException("A token name is required.");
        if (n.Length > 100) throw new ArgumentException("A token name must be 100 characters or fewer.");
        return n;
    }

    private static List<string> CleanRoles(IEnumerable<string> roleNames) =>
        (roleNames ?? [])
        .Select(r => r?.Trim() ?? "")
        .Where(r => r.Length > 0)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    private async Task EnsureRolesExistAsync(IReadOnlyList<string> roles, CancellationToken ct)
    {
        using var db = _factory.CreateDbContext();
        var known = (await db.Roles.AsNoTracking().Select(r => r.Name).ToListAsync(ct))
            .Concat(Enum.GetNames<AppRole>())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unknown = roles.Where(r => !known.Contains(r)).ToList();
        if (unknown.Count > 0)
            throw new ArgumentException($"Unknown role(s): {string.Join(", ", unknown)}.");
    }

    private async Task EnsureSystemNameFreeAsync(string name, CancellationToken ct)
    {
        using var db = _factory.CreateDbContext();
        // WF-47: a system token acts as apitoken:<slug>, so two active tokens whose names slug alike ("Splunk SOAR" and
        // "Splunk-SOAR", or "Splunk" and "splunk") would share one identity in the audit trail, the import review and the
        // retry dedupe. Compared by the identity, not the exact name (which SQLite compares case-sensitively).
        var owner = "apitoken:" + Slug(name);
        var clash = await db.ApiTokens.AsNoTracking()
            .Where(t => t.Kind == ApiTokenKind.System && t.RevokedAtUtc == null && t.OwnerUserId == owner)
            .Select(t => t.Name).FirstOrDefaultAsync(ct);
        if (clash is not null)
            throw new ArgumentException(string.Equals(clash, name, StringComparison.Ordinal)
                ? $"An active system token named '{name}' already exists."
                : $"An active system token named '{clash}' already acts as {owner}. Choose a name that differs by more than case or punctuation.");
    }

    private static string Slug(string s)
    {
        var sb = new StringBuilder();
        foreach (var c in s.Trim().ToLowerInvariant())
        {
            if (char.IsLetterOrDigit(c)) sb.Append(c);
            else if (sb.Length > 0 && sb[^1] != '-') sb.Append('-');
        }
        var slug = sb.ToString().Trim('-');
        return slug.Length == 0 ? "token" : slug;
    }
}
