using System.Security.Claims;
using System.Text.Encodings.Web;
using IncidentManager.Application.ApiTokens;
using IncidentManager.Application.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Security;

/// <summary>
/// PROD-34: authenticates a request presenting an API token as <c>Authorization: Bearer &lt;token&gt;</c>.
/// It validates the token (hash lookup, active, not expired) and builds a <see cref="ClaimsPrincipal"/> that
/// carries the token's attribution id (<see cref="ClaimTypes.NameIdentifier"/> → <c>ICurrentUser.UserId</c> +
/// audit actor + rate-limit partition), a display name, and one <c>perm</c> claim per granted permission.
/// It deliberately emits <b>no</b> <see cref="ClaimTypes.Role"/> claims, so the Windows-mode
/// <c>RoleClaimsTransformer</c> early-returns and never tries to AD-resolve them. When no bearer token is
/// present it returns <see cref="AuthenticateResult.NoResult"/> so it never interferes with other schemes.
/// </summary>
public sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "ApiKey";
    private const string Prefix = "Bearer ";

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder) { }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header) || !header.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.NoResult();

        var token = header[Prefix.Length..].Trim();
        if (token.Length == 0) return AuthenticateResult.NoResult();

        var svc = Context.RequestServices.GetRequiredService<ApiTokenService>();
        var auth = await svc.AuthenticateAsync(token);
        if (auth is null) return AuthenticateResult.Fail("Invalid, expired, or revoked API token.");

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, auth.OwnerUserId),
            new(ClaimTypes.Name, auth.DisplayName),
        };
        foreach (var perm in auth.Permissions)
            claims.Add(new Claim(AppClaimTypes.Permission, perm.ToString()));

        var identity = new ClaimsIdentity(claims, SchemeName, ClaimTypes.Name, ClaimTypes.Role);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return AuthenticateResult.Success(ticket);
    }
}
