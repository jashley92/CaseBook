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
    public const string GenericSave = "Couldn't save your change. Try again, and if it keeps failing, contact your CaseBook administrator.";

    /// <param name="action">A short phrase for the log, e.g. "creating a case" or "uploading evidence".</param>
    /// <param name="generic">Context-specific fallback for unexpected failures; defaults to <see cref="GenericSave"/>.</param>
    // REV-66: whether CaseBook threw it, read from the frame that raised it rather than TargetSite, which is best-effort
    // and names the BCL for a guard like ArgumentException.ThrowIfNullOrEmpty. An exception type's own throw helpers are
    // stepped over, so the guard counts as thrown by whoever called it; any other framework frame (EF, SqlClient,
    // System.Linq) is not ours. With no frames to read, it isn't ours, and the generic line is shown.
    private static bool Ours(Exception ex)
    {
        foreach (var frame in new System.Diagnostics.StackTrace(ex, false).GetFrames())
        {
            var type = frame.GetMethod()?.DeclaringType;
            if (type is null) continue;
            if (typeof(Exception).IsAssignableFrom(type) && type.Namespace == "System") continue;
            return type.FullName?.StartsWith("IncidentManager.", StringComparison.Ordinal) == true;
        }
        return false;
    }

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
                return ex.Message;
            // REV-66: only when CaseBook threw it. EF Core and SqlClient raise these too (a query that won't translate,
            // quoting the expression and entity names; a second operation on a context; an exhausted connection pool),
            // and those messages are internals for the log, not for the person.
            case ArgumentException or InvalidOperationException when Ours(ex):
                return ex.Message;

            // PROD-57: written for the person (the administrators have already been alerted).
            case IncidentManager.Application.Abstractions.EvidenceKeyUnavailableException:
                return ex.Message;
            // PROD-56: the store's folder is gone (a share down or remapped); its message names the path, for the log.
            case IncidentManager.Application.Abstractions.EvidenceStoreUnreachableException:
                logger.LogWarning(ex, "The evidence store couldn't be reached while {Action}", action);
                return "The evidence store can't be reached just now, so nothing was stored. Try again later; an administrator " +
                       "can see why under Administration › Diagnostics.";

            default:
                logger.LogError(ex, "Unexpected error while {Action}", action);
                return generic ?? GenericSave;
        }
    }
}
