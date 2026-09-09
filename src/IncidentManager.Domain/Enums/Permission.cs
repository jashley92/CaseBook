namespace IncidentManager.Domain.Enums;

/// <summary>
/// A fine-grained, code-enforced capability. Permissions are the stable security atoms: a permission
/// only means anything because code checks for it, so they are defined here — never administered.
/// Roles (system or custom) are bundles of these; a user's effective permissions are the union across
/// the roles granted by their AD group memberships.
/// </summary>
public enum Permission
{
    /// <summary>See cases within need-to-know scope.</summary>
    ViewCases,

    /// <summary>See every case regardless of restriction/need-to-know scoping (leadership/oversight).</summary>
    ViewAllCases,

    /// <summary>Create and edit case content.</summary>
    EditCases,

    /// <summary>Change a case's classification (Adverse Event / Incident / Breach).</summary>
    ChangeClassification,

    /// <summary>Approve and finalize reports.</summary>
    ApproveReports,

    /// <summary>Open the content of restricted (need-to-know) cases.</summary>
    ViewRestricted,

    /// <summary>Manage Legal/Privacy referral workflow.</summary>
    ManageLegal,

    /// <summary>Administer the application (settings, roles, integrity operations).</summary>
    Administer
}
