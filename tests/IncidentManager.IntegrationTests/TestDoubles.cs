using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.IntegrationTests;

/// <summary>Captures emitted security events (F-18) so tests can assert what was streamed.</summary>
public sealed class CapturingSecurityEventSink : ISecurityEventSink
{
    public List<SecurityEvent> Events { get; } = new();
    public void Emit(SecurityEvent e) => Events.Add(e);
}

/// <summary>
/// A test <see cref="IAppDbContextFactory"/> (H-08): creates a new <see cref="AppDbContext"/> from the
/// same <see cref="DbContextOptions{TContext}"/> — and therefore the same shared SQLite connection and
/// the same interceptor wiring — on every call, mirroring how services now get a fresh per-operation
/// context while every context created in a test still sees the same data.
/// </summary>
public sealed class TestDbContextFactory : IAppDbContextFactory
{
    private readonly DbContextOptions<AppDbContext> _options;

    public TestDbContextFactory(DbContextOptions<AppDbContext> options) => _options = options;

    public IAppDbContext CreateDbContext() => new AppDbContext(_options);

    /// <summary>Same context, typed concretely for test collaborators (e.g. <c>CaseNumberGenerator</c>,
    /// <c>AuditWriter</c>) that still take <see cref="AppDbContext"/> directly.</summary>
    public AppDbContext CreateAppDbContext() => new(_options);
}

/// <summary>A deterministic clock for tests.</summary>
public sealed class FixedClock(DateTimeOffset now) : IClock
{
    public DateTimeOffset UtcNow { get; set; } = now;
}

/// <summary>A stub authenticated user for tests.</summary>
public sealed class TestCurrentUser : ICurrentUser
{
    public string UserId { get; set; } = "analyst1";
    public string DisplayName { get; set; } = "Analyst One";
    public string? UserPrincipalName { get; set; } = "analyst1@contoso.example";
    public string? Email { get; set; } = "analyst1@contoso.example";
    public bool IsAuthenticated { get; set; } = true;
    public HashSet<AppRole> RoleSet { get; set; } = [AppRole.Analyst];
    public IReadOnlySet<AppRole> Roles => RoleSet;
    public bool IsInRole(AppRole role) => RoleSet.Contains(role);

    // Effective permissions derive from the role set, mirroring production claim expansion.
    public IReadOnlySet<Permission> Permissions => RoleDefinitions.PermissionsFor(RoleSet);
    public bool Has(Permission permission) => Permissions.Contains(permission);
}
