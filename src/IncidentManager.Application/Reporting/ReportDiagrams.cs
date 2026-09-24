using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Reporting;

/// <summary>PROD-46: one attack-chain step as the diagram needs it (values already defanged when reports defang).</summary>
public sealed record DiagramStep(int Order, DateTimeOffset OccurredAtUtc, IReadOnlyList<MitreTactic> Tactics,
    string? TechniqueId, string Actor, string Target);

/// <summary>PROD-46: one entity in the relationship picture; X/Y are the analyst's saved graph layout, if any.</summary>
public sealed record DiagramNode(Guid Id, string Label, EntityType Type, EntityDisposition Disposition, double? X, double? Y);

/// <summary>PROD-46: one directed relationship between two entities.</summary>
public sealed record DiagramEdge(Guid From, Guid To, string Label);

/// <summary>
/// PROD-46: draws the report's pictures server-side — the attack chain (steps in time order across ATT&amp;CK tactic
/// lanes) and the entity relationship graph — as PNG images the Word and PDF renderers embed. No browser at
/// generation time. Returns null when there's nothing worth drawing. The tables stay as the searchable record.
/// </summary>
public interface IReportDiagrams
{
    /// <summary>The attack chain as one or more images (long chains wrap into several).</summary>
    IReadOnlyList<byte[]> AttackChain(IReadOnlyList<DiagramStep> steps);

    /// <summary>The entity relationship graph, or null when there are no relationships.</summary>
    byte[]? EntityGraph(IReadOnlyList<DiagramNode> nodes, IReadOnlyList<DiagramEdge> edges);
}

/// <summary>
/// Colours and names shared by the app's screens and the report pictures, so a tactic or verdict looks the same
/// everywhere. The web UI's <c>Ui</c> helpers delegate here.
/// </summary>
public static class DiagramPalette
{
    /// <summary>Hex accent for a tactic, laid out along the kill-chain (warm early → red at impact).</summary>
    public static string TacticColor(MitreTactic t) => t switch
    {
        // Slate for a tactic-less event — intentional and distinct, not the dull fallback grey.
        MitreTactic.Unspecified => "#64748b",
        MitreTactic.Reconnaissance => "#6c757d",
        MitreTactic.ResourceDevelopment => "#6f42c1",
        MitreTactic.InitialAccess => "#0d6efd",
        MitreTactic.Execution => "#0dcaf0",
        MitreTactic.Persistence => "#20c997",
        MitreTactic.PrivilegeEscalation => "#198754",
        MitreTactic.Stealth => "#84cc16",
        MitreTactic.DefenseImpairment => "#65a30d",
        MitreTactic.CredentialAccess => "#ffc107",
        MitreTactic.Discovery => "#fd7e14",
        MitreTactic.LateralMovement => "#f97316",
        MitreTactic.Collection => "#e8590c",
        MitreTactic.CommandAndControl => "#d63384",
        MitreTactic.Exfiltration => "#dc3545",
        MitreTactic.Impact => "#b02a37",
        _ => "#6c757d"
    };

    public static string TacticLabel(MitreTactic t) => t switch
    {
        MitreTactic.Unspecified => "Unmapped",
        MitreTactic.ResourceDevelopment => "Resource Development",
        MitreTactic.InitialAccess => "Initial Access",
        MitreTactic.PrivilegeEscalation => "Privilege Escalation",
        MitreTactic.DefenseImpairment => "Defense Impairment",
        MitreTactic.CredentialAccess => "Credential Access",
        MitreTactic.LateralMovement => "Lateral Movement",
        MitreTactic.CommandAndControl => "Command and Control",
        // Stealth (TA0005, formerly "Defense Evasion") and the rest print their member name.
        _ => t.ToString()
    };

    /// <summary>ATT&amp;CK matrix position (1-based) — display order, since enum values are frozen for storage.</summary>
    public static int TacticRank(MitreTactic t) => t switch
    {
        MitreTactic.Reconnaissance => 1,
        MitreTactic.ResourceDevelopment => 2,
        MitreTactic.InitialAccess => 3,
        MitreTactic.Execution => 4,
        MitreTactic.Persistence => 5,
        MitreTactic.PrivilegeEscalation => 6,
        MitreTactic.Stealth => 7,
        MitreTactic.DefenseImpairment => 8,
        MitreTactic.CredentialAccess => 9,
        MitreTactic.Discovery => 10,
        MitreTactic.LateralMovement => 11,
        MitreTactic.Collection => 12,
        MitreTactic.CommandAndControl => 13,
        MitreTactic.Exfiltration => 14,
        MitreTactic.Impact => 15,
        _ => 99 // Unspecified / unknown sort last.
    };

    public static string DispositionColor(EntityDisposition d) => d switch
    {
        EntityDisposition.Malicious => "#dc3545",
        EntityDisposition.Compromised => "#9333ea",   // purple: a taken-over legit asset (E-35)
        EntityDisposition.Suspicious => "#fd7e14",
        EntityDisposition.Benign => "#198754",
        _ => "#6c757d"
    };
}
