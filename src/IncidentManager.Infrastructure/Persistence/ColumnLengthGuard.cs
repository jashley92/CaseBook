using System.Globalization;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// BUG-105: refuses a save whose text is longer than its column, before it reaches the database. SQL Server enforces
/// column lengths and SQLite doesn't, so a value a form or an import let through used to fail only in production, as
/// an unhandled database error that lost what was typed. This raises the same <see cref="ArgumentException"/> the
/// services use for user errors, on both providers, naming the field and its limit. Services still check the fields
/// people type into, with their own wording; this is the backstop for any they don't.
/// </summary>
public static class ColumnLengthGuard
{
    public static void Check(ChangeTracker tracker)
    {
        foreach (var entry in tracker.Entries())
        {
            if (entry.State is not (EntityState.Added or EntityState.Modified)) continue;
            foreach (var p in entry.Properties)
            {
                if (p.Metadata.ClrType != typeof(string) || p.CurrentValue is not string value) continue;
                if (entry.State == EntityState.Modified && !p.IsModified) continue;
                if (p.Metadata.GetMaxLength() is not { } max || value.Length <= max) continue;
                throw new ArgumentException(
                    $"Keep the {Words(entry.Metadata.ClrType.Name)} {Words(p.Metadata.Name)} to {max.ToString("N0", CultureInfo.InvariantCulture)} characters or fewer " +
                    $"(it's {value.Length.ToString("N0", CultureInfo.InvariantCulture)}). Nothing was saved.");
            }
        }
    }

    // "ImpactedAssets" -> "impacted assets", "DetectionCaseId" -> "detection case id".
    private static string Words(string name)
    {
        var sb = new StringBuilder(name.Length + 8);
        for (var i = 0; i < name.Length; i++)
        {
            if (i > 0 && char.IsUpper(name[i]) && !char.IsUpper(name[i - 1])) sb.Append(' ');
            sb.Append(char.ToLowerInvariant(name[i]));
        }
        return sb.ToString();
    }
}
