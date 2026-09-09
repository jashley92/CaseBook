using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// Seeds the built-in ("system") roles from <see cref="RoleDefinitions"/> and, on first run, migrates
/// the file-based AD-group→role mapping into the database. System roles are kept canonical to code on
/// every startup; custom roles and mapping edits made in the console are preserved.
/// </summary>
public static class RoleSeeder
{
    public static async Task SeedAsync(AppDbContext db, IClock clock, RoleMappingOptions mapping, CancellationToken ct = default)
    {
        var now = clock.UtcNow;

        // 1) System roles: create if missing, and keep their permissions in lockstep with code.
        var existing = await db.Roles.ToListAsync(ct);
        foreach (var (appRole, perms) in RoleDefinitions.SystemRoles)
        {
            var name = appRole.ToString();
            var csv = string.Join(',', perms
                .Distinct()
                .OrderBy(p => p.ToString(), StringComparer.Ordinal)
                .Select(p => p.ToString()));

            var row = existing.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
            if (row is null)
            {
                db.Roles.Add(new Role
                {
                    Name = name,
                    Description = Describe(appRole),
                    IsSystem = true,
                    PermissionsCsv = csv,
                    UpdatedAtUtc = now,
                    UpdatedBy = "system"
                });
            }
            else
            {
                row.IsSystem = true;
                if (!string.Equals(row.PermissionsCsv, csv, StringComparison.Ordinal))
                {
                    row.PermissionsCsv = csv;
                    row.UpdatedAtUtc = now;
                    row.UpdatedBy = "system";
                }
            }
        }
        await db.SaveChangesAsync(ct);

        // 2) AD-group → role mappings: seed from file config only when none exist yet.
        if (!await db.RoleMappings.AnyAsync(ct))
        {
            foreach (var (roleName, groups) in mapping.Groups)
                foreach (var group in groups.Distinct())
                    db.RoleMappings.Add(new AdGroupRoleMapping
                    {
                        AdGroup = group,
                        RoleName = roleName,
                        UpdatedAtUtc = now,
                        UpdatedBy = "system"
                    });

            await db.SaveChangesAsync(ct);
        }
    }

    private static string Describe(AppRole role) => role switch
    {
        AppRole.Analyst => "SOC analyst — investigate and edit assigned cases.",
        AppRole.IncidentCommander => "Owns incidents; changes classification and approves reports.",
        AppRole.Manager => "Leadership — read and report across all cases.",
        AppRole.LegalPrivacy => "Legal/Privacy — breach oversight and referral workflow.",
        AppRole.SysAdmin => "Full administrative access.",
        _ => ""
    };
}
