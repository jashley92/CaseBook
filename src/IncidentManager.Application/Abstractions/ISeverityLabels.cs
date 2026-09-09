using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Resolves the administrator-configurable display label for a <see cref="Severity"/>. The severity set,
/// ordering, colours and SLA targets stay fixed; only the shown name varies per organisation (e.g. an org
/// that calls Critical "SEV-1"). Backed by live configuration (appsettings default + DB override), so a
/// rename takes effect without a restart. The stored value on a case is always the canonical enum.
/// </summary>
public interface ISeverityLabels
{
    /// <summary>The configured display name for <paramref name="severity"/>, or the canonical enum name if unset.</summary>
    string For(Severity severity);
}
