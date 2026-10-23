using System.Security.Claims;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
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

    public async Task InvokeAsync(HttpContext context, IUserDirectory directory, IRoleDirectory roleDirectory)
    {
        var principal = context.User;
        if (principal.Identity?.IsAuthenticated == true)
        {
            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier)
                         ?? principal.FindFirstValue(ClaimTypes.Upn)
                         ?? principal.Identity.Name;

            // BUG-708: not from a request whose groups weren't all named in time. Its roles are short (fail closed for the
            // request), and stored they'd stand for the person's roles until the next touch, 30 minutes on: the calendar feed
            // and the recipient fallback read them. Skipped, the next whole answer writes the row.
            if (!string.IsNullOrWhiteSpace(userId) && !RoleClaimsTransformer.GroupsIncomplete(principal))
            {
                // Store the real display name (AD lookup for DOMAIN\sam), not the domain-qualified logon.
                // BUG-565: bounded, and awaited so a slow domain controller doesn't hold the request's thread.
                var display = await WindowsNames.FriendlyAsync(principal.Identity.Name) ?? userId;
                var upn = principal.FindFirstValue(ClaimTypes.Upn);
                var email = principal.FindFirstValue(ClaimTypes.Email);

                // Keep only CaseBook role names — built-in or custom (S-14); Windows group SIDs are dropped.
                // De-duped since a principal can carry the same role claim more than once.
                // BUG-591: written as every role list is, so a legacy name with a comma reads back as one role.
                var roles = IncidentManager.Domain.Common.RoleList.Join(principal.FindAll(ClaimTypes.Role)
                    .Select(c => c.Value)
                    .Where(v => RoleDefinitions.TryParseRole(v, out _) || roleDirectory.IsRole(v))
                    .Distinct(StringComparer.OrdinalIgnoreCase));

                // S8949: flow the request's cancellation token — the mirror is a best-effort, throttled
                // convenience write, so abandon it if the client disconnects rather than doing dead work.
                await directory.TouchAsync(userId, display, upn, email, roles, context.RequestAborted);
            }
        }

        await _next(context);
    }
}
