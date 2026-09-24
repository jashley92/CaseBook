using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Application.Compliance;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>A notification-rule reference row for the admin editor (PROD-07).</summary>
public sealed record NotificationRuleView(
    Guid Id, string Code, string Label, int WindowHours, bool IsActive, bool IsSystem)
{
    /// <summary>Built-in rules are archived, never deleted, so a stable baseline always exists.</summary>
    public bool IsDeletable => !IsSystem;
}

/// <summary>
/// Administers the per-jurisdiction notification-deadline rules (PROD-07): the timers the compliance clock
/// uses, e.g. NY = 72h. Admin-managed reference data — add, relabel, retime, archive/restore, and (for a
/// genuine mistake on a non-built-in rule) delete; each change is audited and hash-chained by the save
/// interceptor. The <b>Code</b> is the rule's identity — matched against
/// <see cref="DataElement.NotificationJurisdictions"/> — assigned once and never changed.
/// </summary>
public sealed class NotificationRuleService
{
    private const int MaxLabelLength = 200;
    private const int MaxCodeLength = 16;
    private const int MaxWindowHours = 24 * 365; // a year — a sane ceiling, well above any real deadline

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public NotificationRuleService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    /// <summary>Every rule, active and archived, in code order — for administration.</summary>
    public async Task<List<NotificationRuleView>> ListAllAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return (await db.NotificationRules.AsNoTracking()
            .OrderBy(r => r.Code).ToListAsync(ct))
            .Select(Project).ToList();
    }

    /// <summary>The active rules as a <see cref="NotificationRuleSet"/> for the deadline policy, with the
    /// supplied default window covering any jurisdiction without an explicit rule.</summary>
    public async Task<NotificationRuleSet> LoadRuleSetAsync(int defaultWindowHours, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var active = await db.NotificationRules.AsNoTracking()
            .Where(r => r.IsActive)
            .Select(r => new { r.Code, r.Label, r.WindowHours })
            .ToListAsync(ct);

        var map = active.ToDictionary(
            r => r.Code, r => (r.Label, r.WindowHours), StringComparer.OrdinalIgnoreCase);
        return new NotificationRuleSet(map, defaultWindowHours);
    }

    /// <summary>Creates a rule (Id null) or updates an existing one's label/window (Code is immutable). The code
    /// is uppercased and must be unique. Audited.</summary>
    public async Task SaveAsync(Guid? id, string code, string label, int windowHours, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<NotificationRuleService>(_user);
        code = (code ?? "").Trim().ToUpperInvariant();
        label = (label ?? "").Trim();
        if (string.IsNullOrWhiteSpace(code)) throw new ArgumentException("A jurisdiction code is required.");
        if (code.Length > MaxCodeLength) throw new ArgumentException($"A code must be {MaxCodeLength} characters or fewer.");
        if (string.IsNullOrWhiteSpace(label)) throw new ArgumentException("A label is required.");
        if (label.Length > MaxLabelLength) throw new ArgumentException($"A label must be {MaxLabelLength} characters or fewer.");
        if (windowHours is <= 0 or > MaxWindowHours)
            throw new ArgumentException($"The window must be between 1 and {MaxWindowHours} hours.");

        using var db = _factory.CreateDbContext();
        var now = _clock.UtcNow;

        if (id is { } ruleId)
        {
            var rule = await db.NotificationRules.FirstOrDefaultAsync(r => r.Id == ruleId, ct)
                ?? throw new InvalidOperationException("Notification rule not found.");
            rule.Label = label;
            rule.WindowHours = windowHours;
            rule.ModifiedBy = _user.UserId;
            rule.ModifiedAtUtc = now;
        }
        else
        {
            if (await db.NotificationRules.AnyAsync(r => r.Code == code, ct))
                throw new InvalidOperationException($"A rule for '{code}' already exists.");
            db.NotificationRules.Add(new NotificationRule
            {
                Code = code, Label = label, WindowHours = windowHours,
                IsActive = true, IsSystem = false, CreatedBy = _user.UserId, CreatedAtUtc = now
            });
        }

        await db.SaveChangesAsync(ct);
    }

    /// <summary>Archives or restores a rule (built-in ones included). Archiving drops it from the clock; the
    /// default window then covers its jurisdiction. Audited.</summary>
    public async Task SetArchivedAsync(Guid id, bool archived, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<NotificationRuleService>(_user);
        using var db = _factory.CreateDbContext();
        var rule = await db.NotificationRules.FirstOrDefaultAsync(r => r.Id == id, ct)
            ?? throw new InvalidOperationException("Notification rule not found.");
        if (rule.IsActive != archived) return;
        rule.IsActive = !archived;
        rule.ModifiedBy = _user.UserId;
        rule.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Permanently deletes a non-built-in rule; built-in ones must be archived. Audited.</summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<NotificationRuleService>(_user);
        using var db = _factory.CreateDbContext();
        var rule = await db.NotificationRules.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (rule is null) return;
        if (rule.IsSystem)
            throw new InvalidOperationException("Built-in rules can't be deleted — archive it instead.");
        db.NotificationRules.Remove(rule);
        await db.SaveChangesAsync(ct);
    }

    private static NotificationRuleView Project(NotificationRule r) =>
        new(r.Id, r.Code, r.Label, r.WindowHours, r.IsActive, r.IsSystem);
}
