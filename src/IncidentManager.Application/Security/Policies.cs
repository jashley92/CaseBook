using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Security;

/// <summary>Authorization policy names and their role composition, in one place.</summary>
public static class Policies
{
    public const string ViewCases = nameof(ViewCases);
    public const string ViewAllCases = nameof(ViewAllCases);
    public const string EditCases = nameof(EditCases);
    public const string ChangeClassification = nameof(ChangeClassification);
    public const string ApproveReports = nameof(ApproveReports);
    public const string ViewRestricted = nameof(ViewRestricted);
    public const string ManageLegal = nameof(ManageLegal);
    public const string Administer = nameof(Administer);

    /// <summary>
    /// The permission each policy requires. Authorization is permission-based: the Web layer registers
    /// one policy per entry requiring the matching permission claim, so roles (system or custom) only
    /// need to grant the right permissions — no policy is tied to a specific role.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, Permission> Required = new Dictionary<string, Permission>
    {
        [ViewCases] = Permission.ViewCases,
        [ViewAllCases] = Permission.ViewAllCases,
        [EditCases] = Permission.EditCases,
        [ChangeClassification] = Permission.ChangeClassification,
        [ApproveReports] = Permission.ApproveReports,
        [ViewRestricted] = Permission.ViewRestricted,
        [ManageLegal] = Permission.ManageLegal,
        [Administer] = Permission.Administer,
    };
}
