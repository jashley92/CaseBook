using System.Security.Claims;
using System.Text.Encodings.Web;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Security;

public sealed class DevAuthOptions
{
    public string UserId { get; set; } = "S-1-5-21-DEV-1001";
    public string DisplayName { get; set; } = "Dev Analyst";
    public string Upn { get; set; } = "dev.analyst@contoso-insurance.example";
    public string Email { get; set; } = "dev.analyst@contoso-insurance.example";

    /// <summary>Roles granted to the dev user (AppRole names). Defaults to full access for local testing.</summary>
    public string[] Roles { get; set; } = ["Analyst", "IncidentCommander", "Manager", "LegalPrivacy", "SysAdmin"];
}

/// <summary>
/// Development-only authentication: signs every request in as a fixed user so the app is usable
/// without a domain controller. NEVER enabled in production (guarded by Auth:Mode = "Windows").
/// </summary>
public sealed class DevAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "Dev";
    private readonly DevAuthOptions _dev;

    public DevAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IOptions<DevAuthOptions> dev)
        : base(options, logger, encoder)
    {
        _dev = dev.Value;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Dev-only convenience: `?as=<name>` on the initial page load signs in as a distinct throwaway
        // identity (same roles) so collaborative features — presence (U-01b), assignment, need-to-know
        // — can be exercised with several users on one box. Only ever reached under Auth:Mode!=Windows;
        // Production forbids this handler entirely (see Program.cs), so it can never leak to prod.
        var userId = _dev.UserId;
        var displayName = _dev.DisplayName;
        var upn = _dev.Upn;
        var email = _dev.Email;

        // `?as=<name>` on the initial page GET pins the identity for this browser via a cookie, so the
        // Blazor circuit's websocket (which carries no query string) resolves to the same person.
        const string cookieName = "dev_as";
        var asName = Context.Request.Query["as"].ToString();
        if (!string.IsNullOrWhiteSpace(asName))
            // Secure=true is safe even though dev runs over http://localhost: browsers treat localhost as
            // a secure context and still send the cookie. This handler is dev-only (Production forbids it),
            // so it never sees a non-localhost HTTP origin.
            Context.Response.Cookies.Append(cookieName, asName.Trim(),
                new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, IsEssential = true });
        else
            asName = Context.Request.Cookies[cookieName] ?? "";

        if (!string.IsNullOrWhiteSpace(asName))
        {
            displayName = asName.Trim();
            userId = "dev:" + displayName.ToLowerInvariant();
            upn = email = displayName.Replace(" ", ".").ToLowerInvariant() + "@contoso-insurance.example";
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Name, displayName),
            new(ClaimTypes.Upn, upn),
            new(ClaimTypes.Email, email),
        };
        claims.AddRange(_dev.Roles.Select(r => new Claim(ClaimTypes.Role, r)));

        // Expand the dev user's roles to permissions from the database directory (so custom roles apply
        // in dev too); fall back to the code definitions so local dev can never lock itself out.
        var directory = Context.RequestServices.GetService<IRoleDirectory>();
        var perms = directory?.PermissionsForRoles(_dev.Roles) ?? new HashSet<Permission>();
        if (perms.Count == 0) perms = RoleDefinitions.PermissionsForRoleNames(_dev.Roles);
        foreach (var perm in perms)
            claims.Add(new Claim(AppClaimTypes.Permission, perm.ToString()));

        var identity = new ClaimsIdentity(claims, SchemeName, ClaimTypes.Name, ClaimTypes.Role);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
