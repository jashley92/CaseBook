using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Search;

/// <summary>
/// CAP-22: Diagnostics' search row and its "Create full-text indexes" action, for a server that got Full-Text Search after
/// CaseBook's migration ran (the migration creates them only where the feature is installed then). The action is
/// <c>Administer</c>'s, recorded in the audit trail before it runs, and creates only what's missing; it needs a database
/// account that may create them (db_owner, as the default AppMigrates install grants). Where a DBA applies the schema, the
/// DBA runs deploy/sql/03-Enable-FullText.sql instead, and the row shows the result at its next check.
/// </summary>
public sealed class FullTextAdminService(IFullTextSearch fullText, ICurrentUser user, IAuditWriter audit, ISecurityEventSink? siem = null)
{
    /// <summary>The audit trail's entity type for the action.</summary>
    public const string AuditEntity = "FullTextSearch";

    /// <summary>The status, checked now (Diagnostics opening).</summary>
    public Task<FullTextStatus> StatusAsync(CancellationToken ct = default) => fullText.RefreshAsync(ct);

    /// <summary>
    /// Creates whatever of CaseBook's full-text catalog and indexes is missing, and returns the status after. Refused, with
    /// words, on SQLite and on a server without Full-Text Search; a no-op when they're all there.
    /// </summary>
    public async Task<FullTextStatus> CreateIndexesAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<FullTextAdminService>(user, siem);
        var before = await fullText.RefreshAsync(ct);
        switch (before.Mode)
        {
            case FullTextMode.NotSqlServer:
                throw new InvalidOperationException("Full-text search is a SQL Server feature; this database always searches by substring.");
            case FullTextMode.NotInstalled:
                throw new InvalidOperationException(
                    "This SQL Server doesn't have Full-Text Search. Add the feature with SQL Server setup (Full-Text and Semantic "
                    + "Extractions for Search), then try again.");
            case FullTextMode.Ready:
                return before;
        }
        await audit.RecordAsync(AuditAction.Update, AuditEntity, null, null,
            "Full-text indexes: creating whatever was missing, from Diagnostics.", ct);
        return await fullText.CreateIndexesAsync(ct);
    }
}
