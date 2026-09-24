namespace IncidentManager.Application.Cases;

/// <summary>
/// F-12: two-person control for releasing a legal hold, bound from <c>Governance:LegalHoldRelease</c> and
/// administered in-app. Off by default. When on, releasing a hold is a request (with a reason) that a different
/// person holding Manage Legal must approve; the direct release is refused.
/// </summary>
public sealed class LegalHoldOptions
{
    public bool RequireSecondApprover { get; set; }
}
