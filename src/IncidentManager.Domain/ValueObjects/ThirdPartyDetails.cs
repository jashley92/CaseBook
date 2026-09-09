namespace IncidentManager.Domain.ValueObjects;

/// <summary>
/// Details of a third-party/vendor event we are managing on their behalf.
/// Only populated when <see cref="Enums.CaseOrigin.ThirdParty"/>.
/// </summary>
public class ThirdPartyDetails
{
    public string VendorName { get; set; } = string.Empty;
    public string? VendorContact { get; set; }

    /// <summary>The vendor's own reference/ticket number for the event, if provided.</summary>
    public string? VendorReference { get; set; }

    public string ToCanonical() => $"{VendorName}|{VendorContact}|{VendorReference}";
}
