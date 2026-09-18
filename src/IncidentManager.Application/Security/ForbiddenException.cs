using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Security;

/// <summary>
/// Thrown when the current user lacks the <see cref="Permission"/> a use case requires (F-21). This is the
/// write-authorization backstop asserted at the service boundary, behind the Blazor UI gates: an endpoint
/// boundary maps it to HTTP 403, the UI to a friendly "you don't have permission" toast. It is distinct
/// from need-to-know <em>data</em> scoping, which silently omits out-of-scope cases in the query layer
/// rather than throwing — this signals a user who can see the case but may not perform the action.
/// </summary>
public sealed class ForbiddenException : Exception
{
    /// <summary>The permission that was required and not held.</summary>
    public Permission Required { get; }

    /// <summary>The service action that was refused (the calling method name), for logging.</summary>
    public string? Action { get; }

    public ForbiddenException(Permission required, string? action = null)
        : base($"This action requires the '{required}' permission.")
    {
        Required = required;
        Action = action;
    }
}
