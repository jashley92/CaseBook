using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Web.Components.Shared;

/// <summary>Presentation helpers for consistent badges and labels across the UI.</summary>
public static class Ui
{
    // X-02: admin-set taxonomy display labels. Wired once at startup (Program.cs) to the singleton provider.
    // Taxonomy overrides are GLOBAL (same for every user), so a process-wide static reference is safe — it is
    // not per-circuit state. Every existing Ui.Label(...) call site then picks up a rename with no per-site
    // change. Null-safe: before configuration, or for an un-overridden member, the built-in default stands.
    private static ITaxonomyDisplay? _taxonomy;

    /// <summary>Wires the taxonomy label provider (called once at application startup).</summary>
    public static void UseTaxonomy(ITaxonomyDisplay taxonomy) => _taxonomy = taxonomy;

    private static string Tax(string kind, string member, string fallback) =>
        _taxonomy?.Label(kind, member, fallback) ?? fallback;

    /// <summary>
    /// The pick-list options for an enum taxonomy (X-02 slice 3): the enum values with any admin-hidden
    /// members removed, in the admin-configured order (falling back to the enum's own order). Use this in a
    /// selection <c>&lt;select&gt;</c> instead of <c>Enum.GetValues</c>; display of already-stored values is
    /// unaffected, so a value hidden here still renders through <see cref="Label(Domain.Enums.EntityType)"/>
    /// and friends. Before the taxonomy provider is wired, this is just the enum's values.
    /// </summary>
    public static IReadOnlyList<TEnum> Options<TEnum>(string kind) where TEnum : struct, Enum
    {
        var names = Enum.GetNames<TEnum>();
        if (_taxonomy is null) return Enum.GetValues<TEnum>();

        var order = _taxonomy.Order(kind);
        int Rank(string name)
        {
            for (var i = 0; i < order.Count; i++)
                if (order[i] == name) return i;
            return order.Count + Array.IndexOf(names, name); // unlisted members keep their natural order, after listed ones
        }

        return names
            .Where(n => !_taxonomy.IsHidden(kind, n))
            .OrderBy(Rank)
            .Select(Enum.Parse<TEnum>)
            .ToList();
    }

    // Status badges use the U-18 design tokens (soft tint + AA-legible same-hue text) via .im-badge.
    // A null classification is a Complex Event (pre-triage intake) — a neutral badge, off the ladder.
    public static string ClassificationBadge(Classification? c) => c switch
    {
        Classification.Breach => "im-badge im-cls-breach",
        Classification.Incident => "im-badge im-cls-incident",
        Classification.AdverseEvent => "im-badge im-cls-adverse",
        _ => "im-badge im-cls-intake"
    };

    public static string SeverityBadge(Severity s) => s switch
    {
        Severity.Critical => "im-badge im-sev-critical",
        Severity.High => "im-badge im-sev-high",
        Severity.Medium => "im-badge im-sev-medium",
        Severity.Low => "im-badge im-sev-low",
        _ => "im-badge im-sev-informational"
    };

    /// <summary>Saturated hex per severity, for solid fills like the team-workload distribution bar (E-25).</summary>
    public static string SeverityColor(Severity s) => s switch
    {
        Severity.Critical => "#dc3545",
        Severity.High => "#fd7e14",
        Severity.Medium => "#e6a700",
        Severity.Low => "#3b82f6",
        _ => "#94a3b8"
    };

    // Lifecycle arc, cooling toward done: intake (blue) → active response (amber) → recovery (teal) → closed (green).
    public static string PhaseBadge(CasePhase p) => p switch
    {
        CasePhase.Closed => "im-badge im-phase-closed",
        CasePhase.New or CasePhase.Triage => "im-badge im-phase-open",
        CasePhase.Containment or CasePhase.Eradication => "im-badge im-phase-response",
        _ => "im-badge im-phase-recovery"   // Recovery, Post-Incident
    };

    public static string Label(CasePhase p)
    {
        var def = p switch { CasePhase.PostIncident => "Post-Incident", _ => p.ToString() };
        return Tax("CasePhase", p.ToString(), def);
    }

    public static string Label(Classification? c)
    {
        var def = c switch { null => "Complex Event", Classification.AdverseEvent => "Adverse Event", _ => c.ToString()! };
        return Tax("Classification", c?.ToString() ?? "ComplexEvent", def);
    }

    public static string Label(AppRole r) => r switch
    {
        AppRole.IncidentCommander => "Incident Commander",
        AppRole.LegalPrivacy => "Legal / Privacy",
        AppRole.SysAdmin => "System Admin",
        _ => r.ToString()
    };

    public static string Label(EntityType t)
    {
        var def = t switch
        {
            EntityType.IpAddress => "IP Address",
            EntityType.FileHash => "File Hash",
            EntityType.FileName => "File Name",
            EntityType.EmailAddress => "Email Address",
            EntityType.RegistryKey => "Registry Key",
            _ => t.ToString()
        };
        return Tax("EntityType", t.ToString(), def);
    }

    public static string Label(EntityDisposition d) => Tax("EntityDisposition", d.ToString(), d.ToString());

    public static string Label(TimelineEntryType t) => Tax("TimelineEntryType", t.ToString(), t.ToString());

    public static string Label(EntityRelationshipType t)
    {
        var def = t switch
        {
            EntityRelationshipType.RelatedTo => "related to",
            EntityRelationshipType.CommunicatedWith => "communicated with",
            EntityRelationshipType.ConnectedTo => "connected to",
            EntityRelationshipType.ResolvedTo => "resolved to",
            EntityRelationshipType.LoggedInTo => "logged in to",
            EntityRelationshipType.Executed => "executed",
            EntityRelationshipType.Downloaded => "downloaded",
            EntityRelationshipType.Dropped => "dropped",
            EntityRelationshipType.Contacted => "contacted",
            EntityRelationshipType.Contains => "contains",
            EntityRelationshipType.Redirected => "redirected to",
            EntityRelationshipType.ChildOf => "child of",
            EntityRelationshipType.Accessed => "accessed",
            EntityRelationshipType.Impersonated => "impersonated",
            _ => t.ToString()
        };
        return Tax("EntityRelationshipType", t.ToString(), def);
    }

    public static string Label(MitreTactic t) => t switch
    {
        MitreTactic.ResourceDevelopment => "Resource Development",
        MitreTactic.InitialAccess => "Initial Access",
        MitreTactic.PrivilegeEscalation => "Privilege Escalation",
        MitreTactic.DefenseImpairment => "Defense Impairment",
        MitreTactic.CredentialAccess => "Credential Access",
        MitreTactic.LateralMovement => "Lateral Movement",
        MitreTactic.CommandAndControl => "Command and Control",
        // Stealth (TA0005, formerly "Defense Evasion") and the rest fall through to their member name.
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

    /// <summary>The official MITRE ATT&amp;CK Enterprise tactic ID (TA00xx) for cross-reference.</summary>
    public static string TacticId(MitreTactic t) => t switch
    {
        MitreTactic.Reconnaissance => "TA0043",
        MitreTactic.ResourceDevelopment => "TA0042",
        MitreTactic.InitialAccess => "TA0001",
        MitreTactic.Execution => "TA0002",
        MitreTactic.Persistence => "TA0003",
        MitreTactic.PrivilegeEscalation => "TA0004",
        MitreTactic.Stealth => "TA0005",
        MitreTactic.DefenseImpairment => "TA0112",
        MitreTactic.CredentialAccess => "TA0006",
        MitreTactic.Discovery => "TA0007",
        MitreTactic.LateralMovement => "TA0008",
        MitreTactic.Collection => "TA0009",
        MitreTactic.CommandAndControl => "TA0011",
        MitreTactic.Exfiltration => "TA0010",
        MitreTactic.Impact => "TA0040",
        _ => ""
    };

    /// <summary>Bootstrap-icon class for a MITRE ATT&amp;CK tactic, so attack steps read at a glance.</summary>
    public static string TacticGlyph(MitreTactic t) => t switch
    {
        // An event step with no tactic assigned still reads as an adversary action, not a broken "?".
        MitreTactic.Unspecified => "bi-lightning-charge",
        MitreTactic.Reconnaissance => "bi-binoculars",
        MitreTactic.ResourceDevelopment => "bi-tools",
        MitreTactic.InitialAccess => "bi-door-open",
        MitreTactic.Execution => "bi-terminal",
        MitreTactic.Persistence => "bi-pin-angle",
        MitreTactic.PrivilegeEscalation => "bi-arrow-up-circle",
        MitreTactic.Stealth => "bi-incognito",
        MitreTactic.DefenseImpairment => "bi-shield-slash",
        MitreTactic.CredentialAccess => "bi-key",
        MitreTactic.Discovery => "bi-search",
        MitreTactic.LateralMovement => "bi-arrows-move",
        MitreTactic.Collection => "bi-collection",
        MitreTactic.CommandAndControl => "bi-broadcast-pin",
        MitreTactic.Exfiltration => "bi-box-arrow-up",
        MitreTactic.Impact => "bi-exclamation-octagon",
        _ => "bi-question-circle"
    };

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

    /// <summary>One-line description of a tactic — reference text shown in the ATT&amp;CK picker.</summary>
    public static string TacticDescription(MitreTactic t) => t switch
    {
        MitreTactic.Reconnaissance => "Gathering information to plan the operation.",
        MitreTactic.ResourceDevelopment => "Establishing resources to support operations.",
        MitreTactic.InitialAccess => "Getting into the network.",
        MitreTactic.Execution => "Running malicious code.",
        MitreTactic.Persistence => "Maintaining a foothold across restarts.",
        MitreTactic.PrivilegeEscalation => "Gaining higher-level permissions.",
        MitreTactic.Stealth => "Avoiding detection.",
        MitreTactic.DefenseImpairment => "Disabling or degrading defenses.",
        MitreTactic.CredentialAccess => "Stealing account names and passwords.",
        MitreTactic.Discovery => "Learning the environment.",
        MitreTactic.LateralMovement => "Moving through the environment.",
        MitreTactic.Collection => "Gathering data of interest.",
        MitreTactic.CommandAndControl => "Communicating with compromised systems.",
        MitreTactic.Exfiltration => "Stealing data out of the network.",
        MitreTactic.Impact => "Manipulate, interrupt, or destroy systems and data.",
        _ => "Tactic not specified."
    };

    /// <summary>
    /// Up-to-two-letter initials for an avatar, e.g. "Analyst One" → "AO"; a single name → its first
    /// letter; empty → "?". Used by the profile menu and the case-presence avatars (U-01b).
    /// </summary>
    public static string Initials(string? name)
    {
        // Split on '\' and '/' too so a raw DOMAIN\user never yields the domain's initial.
        var parts = (name ?? "").Split(new[] { ' ', '.', ',', '_', '@', '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return "?";
        var first = parts[0].FirstOrDefault(char.IsLetterOrDigit);
        if (parts.Length == 1) return first == default ? "?" : char.ToUpperInvariant(first).ToString();
        var second = parts[1].FirstOrDefault(char.IsLetterOrDigit);
        var a = first == default ? "" : char.ToUpperInvariant(first).ToString();
        var b = second == default ? "" : char.ToUpperInvariant(second).ToString();
        return (a + b) is { Length: > 0 } s ? s : "?";
    }

    /// <summary>A stable hue (0–359) derived from a seed, so presence avatars are distinguishable per person.</summary>
    public static int AvatarHue(string? seed)
    {
        if (string.IsNullOrEmpty(seed)) return 210;
        unchecked
        {
            var h = 17;
            foreach (var ch in seed) h = h * 31 + ch;
            return ((h % 360) + 360) % 360;
        }
    }

    /// <summary>A short glyph/abbreviation for an entity type, used in the graph nodes.</summary>
    public static string EntityGlyph(EntityType t) => t switch
    {
        EntityType.Account => "👤",
        EntityType.Host => "🖥",
        EntityType.IpAddress => "🌐",
        EntityType.Domain => "🌐",
        EntityType.Url => "🔗",
        EntityType.FileHash => "#",
        EntityType.FileName => "📄",
        EntityType.EmailAddress => "✉",
        EntityType.Process => "⚙",
        EntityType.RegistryKey => "🗝",
        _ => "•"
    };

    /// <summary>Whether an entity type is a network/file observable (IOC) worth pivoting to threat-intel lookups, as opposed to an asset like an account or host.</summary>
    public static bool IsIocLike(EntityType t) => t switch
    {
        EntityType.IpAddress => true,
        EntityType.Domain => true,
        EntityType.Url => true,
        EntityType.FileHash => true,
        _ => false
    };

    /// <summary>How a case link reads from one side (E-14). Only <c>DuplicateOf</c> differs by direction.</summary>
    public static string CaseLinkLabel(CaseLinkType type, bool outgoing) => type switch
    {
        CaseLinkType.DuplicateOf => outgoing ? "Duplicate of" : "Duplicated by",
        CaseLinkType.PartOfCampaign => "Same campaign as",
        _ => "Related to"
    };

    /// <summary>Badge style for a case-link type.</summary>
    public static string CaseLinkBadge(CaseLinkType type) => type switch
    {
        CaseLinkType.DuplicateOf => "im-badge im-b-neutral",
        CaseLinkType.PartOfCampaign => "im-badge im-b-danger",
        _ => "im-badge im-b-info"
    };

    public static string DispositionBadge(EntityDisposition d) => d switch
    {
        EntityDisposition.Malicious => "im-badge im-b-danger",
        EntityDisposition.Suspicious => "im-badge im-b-warn",
        EntityDisposition.Benign => "im-badge im-b-ok",
        _ => "im-badge im-b-neutral"
    };

    /// <summary>Hex fill for a graph node, keyed to the entity's disposition.</summary>
    public static string DispositionColor(EntityDisposition d) => d switch
    {
        EntityDisposition.Malicious => "#dc3545",
        EntityDisposition.Suspicious => "#fd7e14",
        EntityDisposition.Benign => "#198754",
        _ => "#6c757d"
    };

    /// <summary>Short human label for an SLA state (E-16).</summary>
    public static string SlaLabel(SlaState s) => s switch
    {
        SlaState.OnTrack => "On track",
        SlaState.AtRisk => "At risk",
        SlaState.Breached => "Overdue",
        SlaState.Met => "Met",
        SlaState.Missed => "Missed",
        _ => "—"
    };

    /// <summary>Badge classes for an SLA state, reusing the U-18 severity/phase tint tokens.</summary>
    public static string SlaBadge(SlaState s) => s switch
    {
        SlaState.OnTrack => "im-badge im-sla-ontrack",
        SlaState.AtRisk => "im-badge im-sla-atrisk",
        SlaState.Breached => "im-badge im-sla-breached",
        SlaState.Met => "im-badge im-sla-met",
        SlaState.Missed => "im-badge im-sla-missed",
        _ => "im-badge im-sla-none"
    };

    /// <summary>Bootstrap-icon class for an SLA state, so the flag reads at a glance.</summary>
    public static string SlaGlyph(SlaState s) => s switch
    {
        SlaState.OnTrack => "bi-clock",
        SlaState.AtRisk => "bi-clock-history",
        SlaState.Breached => "bi-exclamation-triangle-fill",
        SlaState.Met => "bi-check-circle",
        SlaState.Missed => "bi-x-circle",
        _ => "bi-dash-circle"
    };

    /// <summary>Which milestone an SLA clock measures, phrased as an action so it can't be misread as the
    /// same-named lifecycle <see cref="CasePhase"/> (U-44) — e.g. "Time to contain", not "Containment".</summary>
    public static string SlaClockLabel(SlaClock c) => c switch
    {
        SlaClock.Containment => "Time to contain",
        SlaClock.Resolution => "Time to resolve",
        _ => c.ToString()
    };

    /// <summary>
    /// Time-left / overshoot phrasing for a status. Active clocks read "3h left" / "2h over"; historical
    /// outcomes read the elapsed time to the milestone (e.g. "in 3h"). Empty when no SLA applies.
    /// </summary>
    public static string SlaTiming(SlaStatus st) => st.State switch
    {
        SlaState.OnTrack or SlaState.AtRisk when st.Remaining is { } r => $"{HoursText(r.TotalHours)} left",
        SlaState.Breached when st.Remaining is { } r => $"{HoursText(-r.TotalHours)} over",
        SlaState.Met or SlaState.Missed when st.ElapsedHours is { } h => $"in {HoursText(h)}",
        _ => ""
    };

    // Compact hours/days phrasing for SLA deltas (e.g. 30 → "1d 6h", 5 → "5h", 0.5 → "<1h").
    private static string HoursText(double hours)
    {
        if (hours < 1) return "<1h";
        var whole = (int)Math.Round(hours);
        if (whole < 48) return $"{whole}h";
        var days = whole / 24;
        var rem = whole % 24;
        return rem == 0 ? $"{days}d" : $"{days}d {rem}h";
    }

    public static string Age(DateTimeOffset from, DateTimeOffset now)
    {
        var span = now - from;
        if (span.TotalDays >= 1) return $"{(int)span.TotalDays}d ago";
        if (span.TotalHours >= 1) return $"{(int)span.TotalHours}h ago";
        if (span.TotalMinutes >= 1) return $"{(int)span.TotalMinutes}m ago";
        return "just now";
    }

    /// <summary>Relative time that also reads forward (e.g. an event dated in the future), for timeline entries.</summary>
    public static string RelativeTime(DateTimeOffset when, DateTimeOffset now)
    {
        if (when > now)
        {
            var ahead = when - now;
            if (ahead.TotalMinutes < 1) return "just now";
            if (ahead.TotalHours < 1) return $"in {(int)ahead.TotalMinutes}m";
            if (ahead.TotalDays < 1) return $"in {(int)ahead.TotalHours}h";
            return $"in {(int)ahead.TotalDays}d";
        }
        return Age(when, now);
    }

    /// <summary>Bootstrap-icon class for a timeline entry type, so the chronological rail reads at a glance.</summary>
    public static string TimelineGlyph(TimelineEntryType t) => t switch
    {
        TimelineEntryType.Detection => "bi-radar",
        TimelineEntryType.Analysis => "bi-search",
        TimelineEntryType.Containment => "bi-shield-lock",
        TimelineEntryType.Eradication => "bi-x-octagon",
        TimelineEntryType.Recovery => "bi-heart-pulse",
        TimelineEntryType.Communication => "bi-megaphone",
        TimelineEntryType.Evidence => "bi-paperclip",
        TimelineEntryType.Escalation => "bi-arrow-up-circle",
        TimelineEntryType.Note => "bi-journal-text",
        _ => "bi-record-circle"
    };

    /// <summary>Hex accent for a timeline entry type's rail dot (theme-independent; sits on a tinted ring).</summary>
    public static string TimelineColor(TimelineEntryType t) => t switch
    {
        TimelineEntryType.Detection => "#0d6efd",       // blue
        TimelineEntryType.Analysis => "#6f42c1",        // indigo
        TimelineEntryType.Containment => "#fd7e14",     // orange
        TimelineEntryType.Eradication => "#dc3545",     // red
        TimelineEntryType.Recovery => "#198754",        // green
        TimelineEntryType.Communication => "#0dcaf0",   // cyan
        TimelineEntryType.Evidence => "#20c997",        // teal
        TimelineEntryType.Escalation => "#d63384",      // pink
        TimelineEntryType.Note => "#6c757d",            // gray
        _ => "#6c757d"
    };

    /// <summary>Friendly label for an access-log entry's type (C-05).</summary>
    public static string AccessTypeLabel(AccessType t) => t switch
    {
        AccessType.CaseOpen => "Case open",
        AccessType.EvidenceDownload => "Evidence download",
        AccessType.ReportDownload => "Report download",
        AccessType.Export => "Export",
        _ => t.ToString()
    };

    /// <summary>Bootstrap-icon glyph for an access-log entry's type (C-05).</summary>
    public static string AccessTypeGlyph(AccessType t) => t switch
    {
        AccessType.CaseOpen => "bi-folder2-open",
        AccessType.EvidenceDownload => "bi-paperclip",
        AccessType.ReportDownload => "bi-file-earmark-text",
        AccessType.Export => "bi-download",
        _ => "bi-eye"
    };
}
