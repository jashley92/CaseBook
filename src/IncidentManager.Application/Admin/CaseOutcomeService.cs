using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Common;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>An outcome for the admin editor and the close dialog. <see cref="UseCount"/> counts closes that recorded it.</summary>
public sealed record CaseOutcomeView(Guid Id, string Key, string Label, string? Description, int SortOrder,
    bool IsActive, bool IsSystem, int UseCount)
{
    /// <summary>Only an added outcome that no close has recorded can be deleted; anything else is archived.</summary>
    public bool IsDeletable => !IsSystem && UseCount == 0;
}

/// <summary>One active row from the admin editor: an existing outcome (Id set) or a new one. Order is list position.</summary>
public sealed record CaseOutcomeRow(Guid? Id, string Label, string? Description);

/// <summary>
/// HR-01: administers the case outcomes offered when a case is closed. Admins add, relabel, describe, reorder,
/// archive and restore outcomes, and delete one added by mistake. Each change is audited and hash-chained like other
/// reference data. An outcome's stable Key is what cases store, so it's generated once and never changed; built-in
/// outcomes and outcomes a close recorded are archived, never deleted.
/// </summary>
public sealed class CaseOutcomeService
{
    private const int MaxLabelLength = 200;
    private const int MaxDescriptionLength = 500;

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public CaseOutcomeService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    /// <summary>Every outcome, active and archived, in display order, with how many closes recorded each.</summary>
    public async Task<List<CaseOutcomeView>> ListAllAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var outcomes = await Ordered(db).ToListAsync(ct);
        var uses = await db.StatusChanges.AsNoTracking()
            .Where(s => s.OutcomeKey != null)
            .GroupBy(s => s.OutcomeKey!)
            .Select(g => new { Key = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, StringComparer.Ordinal, ct);
        return outcomes.Select(o => Project(o, uses.GetValueOrDefault(o.Key))).ToList();
    }

    /// <summary>Active outcomes in display order: what the close dialog offers.</summary>
    public async Task<List<CaseOutcomeView>> ListActiveAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return (await Ordered(db).Where(o => o.IsActive).ToListAsync(ct)).Select(o => Project(o, 0)).ToList();
    }

    /// <summary>Every outcome's label by key, archived ones included, for showing what a case recorded.</summary>
    public async Task<IReadOnlyDictionary<string, string>> LabelsAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.CaseOutcomes.AsNoTracking().ToDictionaryAsync(o => o.Key, o => o.Label, StringComparer.Ordinal, ct);
    }

    /// <summary>
    /// Applies the editor's active rows in one audited save: existing rows are relabelled, described and reordered;
    /// rows without an id are created with a generated key. Archived outcomes aren't in the submission and are
    /// untouched. Labels are required, at most 200 characters, and unique.
    /// </summary>
    public async Task SaveAsync(IReadOnlyList<CaseOutcomeRow> rows, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<CaseOutcomeService>(_user);
        if (rows.Count == 0) throw new ArgumentException("Keep at least one outcome active, or a case can't be closed.");
        var labels = new List<string>(rows.Count);
        foreach (var r in rows)
        {
            var label = (r.Label ?? "").Trim();
            if (label.Length == 0) throw new ArgumentException("Every outcome needs a label.");
            if (label.Length > MaxLabelLength) throw new ArgumentException($"A label must be {MaxLabelLength} characters or fewer.");
            if ((r.Description ?? "").Trim().Length > MaxDescriptionLength)
                throw new ArgumentException($"A description must be {MaxDescriptionLength} characters or fewer.");
            labels.Add(label);
        }
        if (labels.Select(l => l.ToLowerInvariant()).Distinct().Count() != labels.Count)
            throw new InvalidOperationException("Each outcome needs a unique label.");

        using var db = _factory.CreateDbContext();
        var existing = await db.CaseOutcomes.ToListAsync(ct);
        var byId = existing.ToDictionary(o => o.Id);
        var usedKeys = existing.Select(o => o.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var now = _clock.UtcNow;

        for (var i = 0; i < rows.Count; i++)
        {
            var description = string.IsNullOrWhiteSpace(rows[i].Description) ? null : rows[i].Description!.Trim();
            if (rows[i].Id is { } id)
            {
                if (!byId.TryGetValue(id, out var o))
                    throw new InvalidOperationException("An outcome you were editing was deleted. Reload the page and try again.");
                o.Label = labels[i];
                o.Description = description;
                o.SortOrder = i + 1;
                o.IsActive = true;   // the editor submits only the active set
                o.ModifiedBy = _user.UserId;
                o.ModifiedAtUtc = now;
            }
            else
            {
                var key = UniqueKey(labels[i], usedKeys);
                usedKeys.Add(key);
                db.CaseOutcomes.Add(new CaseOutcome
                {
                    Key = key, Label = labels[i], Description = description, SortOrder = i + 1,
                    IsActive = true, IsSystem = false, CreatedBy = _user.UserId, CreatedAtUtc = now
                });
            }
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Archives or restores an outcome (built-in ones too). Archived outcomes aren't offered when closing
    /// but stay on the cases that recorded them. The last active outcome can't be archived.</summary>
    public async Task SetArchivedAsync(Guid id, bool archived, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<CaseOutcomeService>(_user);
        using var db = _factory.CreateDbContext();
        var o = await db.CaseOutcomes.FirstOrDefaultAsync(x => x.Id == id, ct)
            ?? throw new InvalidOperationException("That outcome no longer exists. Reload the page and try again.");
        if (o.IsActive != archived) return;
        if (archived && !await db.CaseOutcomes.AnyAsync(x => x.IsActive && x.Id != id, ct))
            throw new InvalidOperationException("Keep at least one outcome active, or a case can't be closed.");
        o.IsActive = !archived;
        o.ModifiedBy = _user.UserId;
        o.ModifiedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Deletes an added outcome that no close has recorded. Built-in or recorded outcomes are archived instead.</summary>
    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<CaseOutcomeService>(_user);
        using var db = _factory.CreateDbContext();
        var o = await db.CaseOutcomes.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (o is null) return;
        if (o.IsSystem) throw new InvalidOperationException("A built-in outcome can't be deleted. Archive it instead.");
        var uses = await db.StatusChanges.CountAsync(s => s.OutcomeKey == o.Key, ct);
        if (uses > 0)
            throw new InvalidOperationException(
                $"'{o.Label}' was recorded when closing {Plural.Of(uses, "case")} and can't be deleted. Archive it instead.");
        if (o.IsActive && !await db.CaseOutcomes.AnyAsync(x => x.IsActive && x.Id != id, ct))
            throw new InvalidOperationException("Keep at least one outcome active, or a case can't be closed.");
        db.CaseOutcomes.Remove(o);
        await db.SaveChangesAsync(ct);
    }

    private static IQueryable<CaseOutcome> Ordered(IAppDbContext db) =>
        db.CaseOutcomes.AsNoTracking().OrderBy(o => o.SortOrder).ThenBy(o => o.Label);

    private static CaseOutcomeView Project(CaseOutcome o, int uses) =>
        new(o.Id, o.Key, o.Label, o.Description, o.SortOrder, o.IsActive, o.IsSystem, uses);

    // A stable PascalCase key from the label ("Insider misuse" → "InsiderMisuse"), made unique with a number.
    private static string UniqueKey(string label, ISet<string> used)
    {
        var sb = new StringBuilder(label.Length);
        var capNext = true;
        foreach (var ch in label)
        {
            if (char.IsLetterOrDigit(ch)) { sb.Append(capNext ? char.ToUpperInvariant(ch) : ch); capNext = false; }
            else capNext = true;
        }
        var baseKey = sb.Length == 0 ? "Outcome" : sb.ToString();
        if (char.IsDigit(baseKey[0])) baseKey = "O" + baseKey;
        if (baseKey.Length > 60) baseKey = baseKey[..60];
        var key = baseKey;
        var n = 2;
        while (used.Contains(key)) key = $"{baseKey}{n++}";
        return key;
    }
}
