using FluentValidation;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Application.StageGates;

namespace IncidentManager.Web.Services;

/// <summary>
/// REL-06: turns an exception into something safe to show a user. Domain/validation/authorization
/// exceptions carry messages that are deliberately authored for the person doing the work (a case-number
/// collision, a stale-edit conflict, an unmet stage gate, a bad argument) — those pass through verbatim.
/// Anything else — EF/SQLite, IO, timeouts, other framework internals — is cryptic and can leak internal
/// detail (table names, SQL, file paths), so it is replaced with a plain generic line and the real
/// exception is logged for an operator to diagnose.
/// </summary>
public static class UserFacingError
{
    /// <summary>The fallback shown for an unexpected (non-domain) failure when the caller gives no override.</summary>
    public const string GenericSave = "Something went wrong and your change couldn't be saved. Please try again.";

    /// <param name="action">A short phrase for the log, e.g. "creating a case" or "uploading evidence".</param>
    /// <param name="generic">Context-specific fallback for unexpected failures; defaults to <see cref="GenericSave"/>.</param>
    public static string Describe(Exception ex, ILogger logger, string action, string? generic = null)
    {
        switch (ex)
        {
            // FluentValidation carries one message per broken rule — join them into one line.
            case ValidationException v:
                return string.Join(" ", v.Errors.Select(e => e.ErrorMessage));

            // Exceptions whose Message is written for the end user. ArgumentException / InvalidOperationException
            // are included because the domain uses them to signal business-rule violations (e.g. "Case number
            // 'X' is already in use", "The detected time cannot be in the future").
            case ForbiddenException:
            case StaleEditException:
            case GateNotSatisfiedException:
            case ArgumentException:
            case InvalidOperationException:
                return ex.Message;

            default:
                logger.LogError(ex, "Unexpected error while {Action}", action);
                return generic ?? GenericSave;
        }
    }
}
