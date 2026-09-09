using System.Security.Claims;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using Microsoft.AspNetCore.Components.Authorization;

namespace IncidentManager.Web.Security;

/// <summary>
/// Resolves the current user for both plain HTTP requests and interactive Blazor circuits.
/// Prefers the request principal; falls back to the circuit's authentication state.
/// </summary>
public sealed class CurrentUser : ICurrentUser
{
    private readonly IHttpContextAccessor _http;
    private readonly AuthenticationStateProvider _authState;
    private ClaimsPrincipal? _cached;

    public CurrentUser(IHttpContextAccessor http, AuthenticationStateProvider authState)
    {
        _http = http;
        _authState = authState;
    }

    private ClaimsPrincipal Principal
    {
        get
        {
            var fromHttp = _http.HttpContext?.User;
            if (fromHttp?.Identity?.IsAuthenticated == true) return fromHttp;
            if (_cached is not null) return _cached;

            try
            {
                // Works inside a Razor component circuit.
                _cached = _authState.GetAuthenticationStateAsync().GetAwaiter().GetResult().User;
            }
            catch
            {
                // Outside any auth scope (e.g. startup seeding): treat as anonymous → "system".
                _cached = new ClaimsPrincipal(new ClaimsIdentity());
            }
            return _cached;
        }
    }

    public bool IsAuthenticated => Principal.Identity?.IsAuthenticated == true;

    public string UserId =>
        Principal.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? Principal.FindFirstValue(ClaimTypes.Upn)
        ?? Principal.Identity?.Name
        ?? "system";

    // Windows auth only exposes DOMAIN\sam as the name; resolve the real AD display name (cached),
    // degrading to the bare username so the UI never shows the domain. Dev auth already sets a real name.
    public string DisplayName => WindowsNames.Friendly(Principal.Identity?.Name) ?? UserId;

    public string? UserPrincipalName => Principal.FindFirstValue(ClaimTypes.Upn);

    public string? Email => Principal.FindFirstValue(ClaimTypes.Email);

    public IReadOnlySet<AppRole> Roles =>
        Principal.FindAll(ClaimTypes.Role)
            .Select(c => Enum.TryParse<AppRole>(c.Value, out var r) ? (AppRole?)r : null)
            .Where(r => r is not null)
            .Select(r => r!.Value)
            .ToHashSet();

    public bool IsInRole(AppRole role) => Principal.IsInRole(role.ToString());

    public IReadOnlySet<Permission> Permissions =>
        Principal.FindAll(AppClaimTypes.Permission)
            .Select(c => Enum.TryParse<Permission>(c.Value, out var p) ? (Permission?)p : null)
            .Where(p => p is not null)
            .Select(p => p!.Value)
            .ToHashSet();

    public bool Has(Permission permission) =>
        Principal.HasClaim(AppClaimTypes.Permission, permission.ToString());
}
