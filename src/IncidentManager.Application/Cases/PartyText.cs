using System.Globalization;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// CAP-34: an outside party in words, the same on the Connections list, in the report and in the legal register. Facts
/// only (ADR 0012): the role, the name, how to reach them, their reference and when they were engaged.
/// </summary>
public static class PartyText
{
    /// <summary>The role's label.</summary>
    public static string Label(PartyRole role) => role switch
    {
        PartyRole.Counsel => "Outside counsel",
        PartyRole.Forensics => "Forensics firm",
        PartyRole.Insurer => "Insurer",
        PartyRole.LawEnforcement => "Law enforcement",
        PartyRole.RegulatorContact => "Regulator contact",
        _ => "Other party",
    };

    /// <summary>"Outside counsel: Lee &amp; Park LLP (contact Dana Lee), reference MAT-114, engaged 2026-10-02 14:00 UTC."</summary>
    public static string Line(PartyRole role, string name, string? contact, string? reference, DateTimeOffset? engagedAtUtc)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(reference)) parts.Add($"reference {reference}");
        if (engagedAtUtc is { } at) parts.Add(string.Create(CultureInfo.InvariantCulture, $"engaged {at.UtcDateTime:yyyy-MM-dd HH:mm} UTC"));
        return $"{Label(role)}: {name}{(string.IsNullOrWhiteSpace(contact) ? "" : $" (contact {contact})")}"
               + (parts.Count == 0 ? "." : $", {string.Join(", ", parts)}.");
    }
}
