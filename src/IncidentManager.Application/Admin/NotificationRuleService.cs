using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Application.Compliance;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>A notification-rule reference row for the admin editor (PROD-07).</summary>
public sealed record NotificationRuleView(
    Guid Id, string Code, string Label, int WindowHours, bool IsActive, bool IsSystem, string Stamp = "")
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
    public const int MaxLabelLength = 200;
    public const int MaxCodeLength = 16;
    public const int MaxWindowHours = 24 * 365; // a year — a sane ceiling, well above any real deadline

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ISecurityEventSink? _siem;   // CAP-06

    public NotificationRuleService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, ISecurityEventSink? siem = null)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _siem = siem;
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
    /// is uppercased and must be unique. Audited. REV-27 / BUG-396: <paramref name="expectedStamp"/> is the rule's
    /// <see cref="NotificationRuleView.Stamp"/> when the editor opened; the edit writes the label and window back, so a
    /// rule someone changed since is refused. Null skips the check.</summary>
    public async Task SaveAsync(Guid? id, string code, string label, int windowHours, string? expectedStamp = null,
        CancellationToken ct = default)
    {
        AdminActionPermissions.Require<NotificationRuleService>(_user);
        using var guard = await GuardGate.EnterAsync(ct);   // BUG-567: the stamp and code checks with the save, and not inside an import
        code = (code ?? "").Trim().ToUpperInvariant();
        label = (label ?? "").Trim();
        if (string.IsNullOrWhiteSpace(code)) throw new ArgumentException("A jurisdiction code is required.");
        if (code.Length > MaxCodeLength) throw new ArgumentException($"A code must be {MaxCodeLength} characters or fewer.");
        // BUG-558: a new code only (it's immutable, so a rule saved before this can still be relabelled, retimed or deleted).
        if (id is null && HasSeparator(code)) throw new ArgumentException(SeparatorMessage(code));
        if (string.IsNullOrWhiteSpace(label)) throw new ArgumentException("A label is required.");
        if (label.Length > MaxLabelLength) throw new ArgumentException($"A label must be {MaxLabelLength} characters or fewer.");
        if (windowHours is <= 0 or > MaxWindowHours)
            throw new ArgumentException($"The window must be between 1 and {MaxWindowHours} hours.");

        using var db = _factory.CreateDbContext();
        var now = _clock.UtcNow;
        Guid savedId;

        if (id is { } ruleId)
        {
            var rule = await db.NotificationRules.FirstOrDefaultAsync(r => r.Id == ruleId, ct)
                ?? throw new InvalidOperationException("That rule no longer exists. Reload the page and try again.");
            if (expectedStamp is not null && !string.Equals(StampOf(rule), expectedStamp, StringComparison.Ordinal))
                throw new InvalidOperationException($"Someone changed the deadline rule \"{rule.Code}\" since you opened it, so nothing was saved: " +
                    "it would have undone that. Reload the page, then make your change again.");
            rule.Label = label;
            rule.WindowHours = windowHours;
            rule.ModifiedBy = _user.UserId;
            rule.ModifiedAtUtc = now;
            savedId = rule.Id;
        }
        else
        {
            // Codes match ignoring case, as the rule set does (LoadRuleSetAsync): a lower-case "ny" saved before REV-49 is NY,
            // and SQLite's "=" let an "NY" in beside it, which then made the rule set throw on the duplicate.
#pragma warning disable CA1304, CA1311, CA1862 // EF translates ToUpper() to SQL UPPER(); the culture overloads don't translate.
            if (await db.NotificationRules.AnyAsync(r => r.Code.ToUpper() == code, ct))
#pragma warning restore CA1304, CA1311, CA1862
                throw new InvalidOperationException($"A rule for '{code}' already exists. Edit that rule instead.");
            savedId = db.NotificationRules.Add(new NotificationRule
            {
                Code = code, Label = label, WindowHours = windowHours,
                IsActive = true, IsSystem = false, CreatedBy = _user.UserId, CreatedAtUtc = now
            }).Entity.Id;
        }

        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException ex) when (id is null)
        {
            // BUG-339: a rule for the same code was added between the check above and this insert.
            using var check = _factory.CreateDbContext();
#pragma warning disable CA1304, CA1311, CA1862 // as above: translated to SQL UPPER()
            if (await check.NotificationRules.AnyAsync(r => r.Code.ToUpper() == code, ct))
#pragma warning restore CA1304, CA1311, CA1862
                throw new InvalidOperationException($"A rule for '{code}' already exists. Edit that rule instead.", ex);
            throw;
        }
        // CAP-06: the code and window, which is what a SOC rule cares about (a window lengthened lets a deadline pass later).
        _siem.ReferenceDataChanged(_user, ReferenceDataKinds.DeadlineRule, RuleName(code, windowHours),
            id is null ? ReferenceDataAction.Created : ReferenceDataAction.Changed, savedId);
    }

    private static string RuleName(string code, int windowHours) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{code} ({windowHours} h)");

    /// <summary>Archives or restores a rule (built-in ones included). Archiving drops it from the clock; the
    /// default window then covers its jurisdiction. Audited.</summary>
    public async Task SetArchivedAsync(Guid id, bool archived, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<NotificationRuleService>(_user);
        using var guard = await GuardGate.EnterAsync(ct);   // BUG-567: not between a save's (or an import's) load and its save
        using var db = _factory.CreateDbContext();
        var rule = await db.NotificationRules.FirstOrDefaultAsync(r => r.Id == id, ct)
            ?? throw new InvalidOperationException("That rule no longer exists. Reload the page and try again.");
        if (rule.IsActive != archived) return;
        rule.IsActive = !archived;
        rule.ModifiedBy = _user.UserId;
        rule.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
        _siem.ReferenceDataChanged(_user, ReferenceDataKinds.DeadlineRule,
            $"{RuleName(rule.Code, rule.WindowHours)} ({(archived ? "archived" : "restored")})", ReferenceDataAction.Changed, rule.Id);   // CAP-06
    }

    /// <summary>Permanently deletes a non-built-in rule; built-in ones must be archived. Audited.</summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<NotificationRuleService>(_user);
        using var guard = await GuardGate.EnterAsync(ct);   // BUG-567: as SetArchivedAsync
        using var db = _factory.CreateDbContext();
        var rule = await db.NotificationRules.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (rule is null) return;
        if (rule.IsSystem)
            throw new InvalidOperationException("A built-in rule can't be deleted. Archive it instead.");
        db.NotificationRules.Remove(rule);
        await db.SaveChangesAsync(ct);
        _siem.ReferenceDataChanged(_user, ReferenceDataKinds.DeadlineRule, RuleName(rule.Code, rule.WindowHours),
            ReferenceDataAction.Deleted, rule.Id);   // CAP-06
    }

    /// <summary>
    /// BUG-558: a data element's jurisdictions are split on "," and ";" (BUG-404), so a rule whose code holds either never
    /// matches a jurisdiction and its cases silently get the default window. Rules saved before this are kept as they are
    /// (shown by the config import) rather than rewritten.
    /// </summary>
    public static bool HasSeparator(string? code) => code is not null && code.AsSpan().IndexOfAny(',', ';') >= 0;

    public static string SeparatorMessage(string code) =>
        $"A rule's code is one jurisdiction, so it can't contain \",\" or \";\" (\"{code}\"). Add a rule for each jurisdiction.";

    private static NotificationRuleView Project(NotificationRule r) =>
        new(r.Id, r.Code, r.Label, r.WindowHours, r.IsActive, r.IsSystem, StampOf(r));

    // BUG-396: what the editor holds and writes back (the label and the window).
    private static string StampOf(NotificationRule r) =>
        string.Join('|', r.Label, r.WindowHours.ToString(System.Globalization.CultureInfo.InvariantCulture));
}
