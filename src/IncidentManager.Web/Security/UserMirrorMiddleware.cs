using System.Security.Claims;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Security;

/// <summary>
/// After authentication, records the signed-in user into the directory mirror (<c>AppUser</c>) so their
/// stable id resolves to a display name / email for the activity feed, audit view, and assignment picker.
/// The directory throttles writes, so this is cheap on every request.
/// </summary>
public sealed class UserMirrorMiddleware
{
    private readonly RequestDelegate _next;

    public UserMirrorMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, IUserDirectory directory)
    {
        var principal = context.User;
        if (principal.Identity?.IsAuthenticated == true)
        {
            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier)
                         ?? principal.FindFirstValue(ClaimTypes.Upn)
                         ?? principal.Identity.Name;

            if (!string.IsNullOrWhiteSpace(userId))
            {
                // Store the real display name (AD lookup for DOMAIN\sam), not the domain-qualified logon.
                var display = WindowsNames.Friendly(principal.Identity.Name) ?? userId;
                var upn = principal.FindFirstValue(ClaimTypes.Upn);
                var email = principal.FindFirstValue(ClaimTypes.Email);

                // Keep only resolved application-role names (Windows group SIDs won't parse), de-duped
                // since a principal can carry the same role claim more than once.
                var roles = string.Join(',', principal.FindAll(ClaimTypes.Role)
                    .Select(c => c.Value)
                    .Where(v => Enum.TryParse<AppRole>(v, out _))
                    .Distinct(StringComparer.OrdinalIgnoreCase));

                await directory.TouchAsync(userId, display, upn, email, roles);
            }
        }

        await _next(context);
    }
}
