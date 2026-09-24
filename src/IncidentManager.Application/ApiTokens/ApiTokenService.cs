using System.Security.Cryptography;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.ApiTokens;

/// <summary>Resolved identity + permissions for a validated API token (what the auth handler needs).</summary>
public sealed record ApiTokenAuth(string OwnerUserId, string DisplayName, IReadOnlySet<Permission> Permissions);

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
/// Create/revoke are recorded to the audit trail and the SIEM stream (the token entity itself is NotAudited so
/// per-call last-used updates don't spam the hash chain).
/// </summary>
public sealed class ApiTokenService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IRoleDirectory _directory;
    private readonly IAuditWriter _audit;
    private readonly ISecurityEventSink? _siem;
    private readonly IUserDirectory? _users;

    /// <summary>S-11: the longest a personal token may live — it acts as a person, whose access can change.</summary>
    public static readonly TimeSpan MaxPersonalLifetime = TimeSpan.FromDays(90);

    /// <summary>S-11: the longest a system (integration) token may live before it must be re-issued.</summary>
    public static readonly TimeSpan MaxSystemLifetime = TimeSpan.FromDays(365);

    public ApiTokenService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        IRoleDirectory directory, IAuditWriter audit, ISecurityEventSink? siem = null, IUserDirectory? users = null)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _directory = directory;
        _audit = audit;
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
        var roles = row.GetRoles();
        if (row.Kind == ApiTokenKind.Personal && _users is not null)
        {
            var owner = _users.Resolve(row.OwnerUserId);
            if (owner is null) return null;
            var current = owner.RolesCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            roles = roles.Where(current.Contains).ToList();
            if (roles.Count == 0) return null;
        }

        row.LastUsedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);

        var perms = _directory.PermissionsForRoles(roles);
        if (perms.Count == 0) perms = RoleDefinitions.PermissionsForRoleNames(roles);
        return new ApiTokenAuth(row.OwnerUserId, row.OwnerDisplayName, perms);
    }

    // ── Creation ─────────────────────────────────────────────────────────────────────────────────

    /// <summary>Admin-only: create a named system token granted a set of roles.</summary>
    public async Task<ApiTokenCreated> CreateSystemAsync(string name, IEnumerable<string> roleNames,
        DateTimeOffset expiresAtUtc, CancellationToken ct = default)
    {
        if (!_user.Has(Permission.Administer))
            throw new ForbiddenException(Permission.Administer, nameof(CreateSystemAsync));
        var n = Clean(name);
        var roles = CleanRoles(roleNames);
        ValidateExpiry(expiresAtUtc, MaxSystemLifetime);
        if (roles.Count == 0) throw new ArgumentException("Grant the token at least one role.");
        await EnsureRolesExistAsync(roles, ct);
        await EnsureSystemNameFreeAsync(n, ct);
        return await CreateAsync(n, ApiTokenKind.System, "apitoken:" + Slug(n), n, roles, expiresAtUtc, ct);
    }

    /// <summary>Any user: create a personal token. Roles must be a subset of the caller's own roles, so the
    /// token can never grant more than the user has; API actions attribute to the user.</summary>
    public async Task<ApiTokenCreated> CreatePersonalAsync(string name, IEnumerable<string> roleNames,
        DateTimeOffset expiresAtUtc, CancellationToken ct = default)
    {
        if (!_user.IsAuthenticated)
            throw new ForbiddenException(Permission.ViewCases, nameof(CreatePersonalAsync));
        var n = Clean(name);
        var roles = CleanRoles(roleNames);
        ValidateExpiry(expiresAtUtc, MaxPersonalLifetime);
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
            RolesCsv = string.Join(",", roles), TokenHash = hash, Prefix = prefix,
            CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow, ExpiresAtUtc = expiresAtUtc
        };

        using var db = _factory.CreateDbContext();
        db.ApiTokens.Add(row);
        await db.SaveChangesAsync(ct);

        await _audit.RecordAsync(AuditAction.Create, nameof(ApiToken), row.Id.ToString(), null,
            $"Created {kind} API token '{name}' (roles: {row.RolesCsv}; expires {expiresAtUtc:u})", ct);
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
            .Where(t => t.CreatedBy == _user.UserId)
            .OrderByDescending(t => t.CreatedAtUtc).ToListAsync(ct);
        return rows.Select(ToView).ToList();
    }

    /// <summary>Every token (admin oversight).</summary>
    public async Task<IReadOnlyList<ApiTokenView>> ListAllAsync(CancellationToken ct = default)
    {
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

        if (!_user.Has(Permission.Administer) && !string.Equals(row.CreatedBy, _user.UserId, StringComparison.Ordinal))
            throw new ForbiddenException(Permission.Administer, nameof(RevokeAsync));

        row.RevokedAtUtc = _clock.UtcNow;
        row.RevokedBy = _user.UserId;
        await db.SaveChangesAsync(ct);

        await _audit.RecordAsync(AuditAction.Update, nameof(ApiToken), row.Id.ToString(), null,
            $"Revoked {row.Kind} API token '{row.Name}'", ct);
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

    private void ValidateExpiry(DateTimeOffset expiresAtUtc, TimeSpan maxLifetime)
    {
        if (expiresAtUtc <= _clock.UtcNow)
            throw new ArgumentException("The expiry date must be in the future.");
        // S-11: a day's grace so picking the last allowed date in the form (midnight UTC) is never refused.
        if (expiresAtUtc > _clock.UtcNow + maxLifetime + TimeSpan.FromDays(1))
            throw new ArgumentException($"A token can last at most {maxLifetime.TotalDays:0} days. Re-issue it before it lapses.");
    }

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
        var taken = await db.ApiTokens.AsNoTracking().AnyAsync(
            t => t.Kind == ApiTokenKind.System && t.RevokedAtUtc == null && t.Name == name, ct);
        if (taken) throw new ArgumentException($"An active system token named '{name}' already exists.");
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
