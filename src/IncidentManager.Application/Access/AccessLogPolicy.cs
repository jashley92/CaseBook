using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Access;

/// <summary>How much read/access activity the access log captures (C-05). Admin-configurable.</summary>
public enum AccessLogScope
{
    /// <summary>Log nothing — the machinery is dormant.</summary>
    Off = 0,
    /// <summary>Log restricted-case opens, plus all artifact/export access (inherently sensitive).</summary>
    RestrictedOnly = 1,
    /// <summary>Log every authenticated case open and artifact/export access.</summary>
    All = 2
}

/// <summary>
/// Pure decision for whether an access should be recorded, given the configured scope. Kept separate
/// from the config-reading provider so the matrix is unit-testable without configuration or a DB.
/// </summary>
public static class AccessLogRules
{
    public static bool ShouldLog(AccessLogScope scope, AccessType type, bool wasRestricted) => scope switch
    {
        AccessLogScope.Off => false,
        // A case open is logged only when the case is restricted; artifacts/exports are always sensitive.
        AccessLogScope.RestrictedOnly => type != AccessType.CaseOpen || wasRestricted,
        _ => true // All
    };
}

/// <summary>Live source of the access-log scope and coalescing window (reads config on demand).</summary>
public interface IAccessLogPolicy
{
    AccessLogScope Scope { get; }

    /// <summary>Accesses of the same (actor, case, type, target) within this window fold into one row.</summary>
    TimeSpan CoalesceWindow { get; }

    bool ShouldLog(AccessType type, bool wasRestricted);
}

/// <summary>
/// Pure coalescing decision (C-05): whether a fresh access folds into the most recent matching session.
/// Deterministic and DB-free so the window boundary is unit-testable.
/// </summary>
public static class AccessCoalescer
{
    public static bool ShouldCoalesce(DateTimeOffset lastSeenUtc, DateTimeOffset now, TimeSpan window)
        => now >= lastSeenUtc && now - lastSeenUtc <= window;
}
