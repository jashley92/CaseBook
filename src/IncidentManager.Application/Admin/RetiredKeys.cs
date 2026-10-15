using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>
/// BUG-569: a deleted outcome's or data element's key is never given to a new one. A case save that started using it
/// while it was deleted (case saves don't wait for admin edits) keeps the key with no row, and a later item with the same
/// label would otherwise get the same key and so that case's meaning. The audit trail records every delete with the row as
/// it was, so the key is read from there (no schema change).
/// </summary>
internal static class RetiredKeys
{
    /// <summary>The keys of every deleted <paramref name="entityType"/> row the audit trail records.</summary>
    public static async Task<IReadOnlyList<string>> DeletedAsync(IAppDbContext db, string entityType, CancellationToken ct)
    {
        var before = await db.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == entityType && a.Action == AuditAction.Delete && a.BeforeJson != null)
            .Select(a => a.BeforeJson!)
            .ToListAsync(ct);
        return before.Select(KeyOf).OfType<string>().ToList();
    }

    private static string? KeyOf(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                   && doc.RootElement.TryGetProperty("Key", out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString()
                : null;
        }
        catch (JsonException) { return null; }
    }
}
