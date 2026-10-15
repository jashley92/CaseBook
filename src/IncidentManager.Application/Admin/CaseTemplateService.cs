using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>One playbook step in a template edit/view (E-06).</summary>
public sealed record TemplateStepInput(string Title, string? Description, string? OwnerHint, int? DueOffsetHours,
    TaskKind Kind = TaskKind.General);

/// <summary>A step as shown in the apply/preview UIs, carrying its stable id for selection.</summary>
public sealed record TemplateStepView(Guid Id, int Order, string Title, string? Description, string? OwnerHint, int? DueOffsetHours,
    TaskKind Kind = TaskKind.General);

/// <summary>A template resolved for the pickers and the New Case / Apply flows.</summary>
public sealed record TemplateView(
    Guid Id, string Name, string? Description, bool IsActive, int SortOrder,
    Classification? DefaultClassification, Severity? DefaultSeverity,
    string? DefaultDataTypes, string? SummaryBoilerplate,
    IReadOnlyList<TemplateStepView> Steps, string Stamp = "");

/// <summary>The field defaults + steps to create a template with, or replace an existing one's content.</summary>
public sealed record TemplateInput(
    string Name, string? Description, bool IsActive, int SortOrder,
    Classification? DefaultClassification, Severity? DefaultSeverity,
    string? DefaultDataTypes, string? SummaryBoilerplate,
    IReadOnlyList<TemplateStepInput> Steps);

/// <summary>
/// Administers case templates / playbooks (E-06): the curated field defaults + ordered steps a case can
/// be started from or an open case can have applied. Reads are open to case editors (they drive the New
/// Case picker and the Apply-playbook dialog); writes are admin-only and gated at the web layer. Every
/// change is audited and hash-chained by the save interceptor like other reference data.
/// </summary>
public sealed class CaseTemplateService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public CaseTemplateService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    /// <summary>Active templates for the pickers, ordered for display.</summary>
    public async Task<List<TemplateView>> ListActiveAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return Project(await Load(db).Where(t => t.IsActive).ToListAsync(ct));
    }

    /// <summary>Every template, active or not, for administration.</summary>
    public async Task<List<TemplateView>> ListAllAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return Project(await Load(db).ToListAsync(ct));
    }

    public async Task<TemplateView?> GetAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var t = await Load(db).FirstOrDefaultAsync(t => t.Id == id, ct);
        return t is null ? null : Project(t);
    }

    public async Task<Guid> CreateAsync(TemplateInput input, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<CaseTemplateService>(_user);
        using var guard = await GuardGate.EnterAsync(ct);   // BUG-557: the name check with the save, and not inside an import
        using var db = _factory.CreateDbContext();
        var name = (input.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A template name is required.");
#pragma warning disable CA1304, CA1311, CA1862 // BUG-269: LOWER() on both sides, so SQLite matches as SQL Server does
        if (await db.CaseTemplates.AnyAsync(t => t.Name.ToLower() == name.ToLower(), ct))
#pragma warning restore CA1304, CA1311, CA1862
            throw new InvalidOperationException($"A template named '{name}' already exists. Choose a different name.");

        var template = new CaseTemplate { Name = name, CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow };
        ApplyContent(template, input);
        db.CaseTemplates.Add(template);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException ex)
        {
            // BUG-339: the same name was saved between the check above and this insert (the unique index refused it).
            using var check = _factory.CreateDbContext();
            if (await check.CaseTemplates.AnyAsync(t => t.Name == name, ct))
                throw new InvalidOperationException($"A template named '{name}' already exists. Choose a different name.", ex);
            throw;
        }
        return template.Id;
    }

    /// <summary>REV-27: <paramref name="expectedStamp"/> is the template's <see cref="TemplateView.Stamp"/> when the editor
    /// opened; the edit replaces the whole template, so one someone changed since is refused. Null skips the check.</summary>
    public async Task UpdateAsync(Guid id, TemplateInput input, string? expectedStamp = null, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<CaseTemplateService>(_user);
        using var guard = await GuardGate.EnterAsync(ct);   // BUG-557: the stamp and name checks with the save
        using var db = _factory.CreateDbContext();
        var template = await db.CaseTemplates.Include(t => t.Steps).FirstOrDefaultAsync(t => t.Id == id, ct)
                       ?? throw new InvalidOperationException("That template no longer exists. Reload the page and try again.");
        if (expectedStamp is not null && !string.Equals(StampOf(template), expectedStamp, StringComparison.Ordinal))
            throw new InvalidOperationException(ChangedSinceOpened(template.Name));

        var name = (input.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A template name is required.");
#pragma warning disable CA1304, CA1311, CA1862 // BUG-269: LOWER() on both sides, so SQLite matches as SQL Server does
        if (await db.CaseTemplates.AnyAsync(t => t.Name.ToLower() == name.ToLower() && t.Id != id, ct))
#pragma warning restore CA1304, CA1311, CA1862
            throw new InvalidOperationException($"A template named '{name}' already exists. Choose a different name.");

        template.Name = name;
        template.ModifiedBy = _user.UserId;
        template.ModifiedAtUtc = _clock.UtcNow;

        // Replace the step set wholesale (like roles replace permissions) — simplest, and every add/remove
        // is captured by the audit chain.
        db.CaseTemplateSteps.RemoveRange(template.Steps);
        template.Steps.Clear();
        ApplyContent(template, input);
        try { await db.SaveChangesAsync(ct); }
        // BUG-557: a writer outside the gate changed or removed it meanwhile (the context's message is about cases).
        catch (ConcurrentEditException ex) { throw new InvalidOperationException(ChangedSinceOpened(template.Name), ex); }
        catch (DbUpdateException ex)
        {
            // BUG-557: as on create, a rename onto a name saved meanwhile by a writer outside the gate (the unique index refused it).
            using var check = _factory.CreateDbContext();
            if (await check.CaseTemplates.AnyAsync(t => t.Name == name && t.Id != id, ct))
                throw new InvalidOperationException($"A template named '{name}' already exists. Choose a different name.", ex);
            throw;
        }
    }

    private static string ChangedSinceOpened(string name) =>
        $"Someone changed the template \"{name}\" since you opened it, so nothing was saved: " +
        "it would have undone that. Reload the page, then make your change again.";

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<CaseTemplateService>(_user);
        using var guard = await GuardGate.EnterAsync(ct);   // BUG-557: not between an edit's (or an import's) load and its save
        using var db = _factory.CreateDbContext();
        var template = await db.CaseTemplates.Include(t => t.Steps).FirstOrDefaultAsync(t => t.Id == id, ct);
        if (template is null) return;
        db.CaseTemplateSteps.RemoveRange(template.Steps);
        db.CaseTemplates.Remove(template);
        try { await db.SaveChangesAsync(ct); }
        // BUG-557: it or its steps changed meanwhile (a writer outside the gate); the context's message is about cases.
        catch (ConcurrentEditException ex)
        {
            using var check = _factory.CreateDbContext();
            if (!await check.CaseTemplates.AnyAsync(t => t.Id == id, ct)) return;   // already gone
            throw new InvalidOperationException($"Someone changed the template \"{template.Name}\" while you deleted it, so it " +
                "wasn't deleted. Reload the page and try again.", ex);
        }
    }

    private static void ApplyContent(CaseTemplate t, TemplateInput input)
    {
        t.Description = Trim(input.Description);
        t.IsActive = input.IsActive;
        t.SortOrder = input.SortOrder;
        t.DefaultClassification = input.DefaultClassification;
        t.DefaultSeverity = input.DefaultSeverity;
        t.DefaultDataTypes = Trim(input.DefaultDataTypes);
        t.SummaryBoilerplate = Trim(input.SummaryBoilerplate);

        var order = 0;
        foreach (var s in input.Steps ?? [])
        {
            var title = (s.Title ?? "").Trim();
            if (string.IsNullOrWhiteSpace(title)) continue; // drop blank rows the editor may leave behind
            if (s.DueOffsetHours > CaseTemplateStep.MaxDueOffsetHours)   // BUG-267
                throw new ArgumentException($"Step \"{title}\": the due time can be at most {CaseTemplateStep.MaxDueOffsetHours:N0} hours (a year) after the playbook is applied.");
            t.Steps.Add(new CaseTemplateStep
            {
                TemplateId = t.Id,
                Order = order++,
                Title = title,
                Description = Trim(s.Description),
                OwnerHint = Trim(s.OwnerHint),
                DueOffsetHours = s.DueOffsetHours is { } h && h > 0 ? h : null,
                Kind = s.Kind
            });
        }
    }

    private static IQueryable<CaseTemplate> Load(IAppDbContext db) =>
        db.CaseTemplates.AsNoTracking()
            .Include(t => t.Steps)
            .OrderBy(t => t.SortOrder).ThenBy(t => t.Name);

    private static List<TemplateView> Project(IEnumerable<CaseTemplate> templates) =>
        templates.Select(Project).ToList();

    private static TemplateView Project(CaseTemplate t) => new(
        t.Id, t.Name, t.Description, t.IsActive, t.SortOrder,
        t.DefaultClassification, t.DefaultSeverity, t.DefaultDataTypes, t.SummaryBoilerplate,
        t.Steps.OrderBy(s => s.Order)
            .Select(s => new TemplateStepView(s.Id, s.Order, s.Title, s.Description, s.OwnerHint, s.DueOffsetHours, s.Kind))
            .ToList(), StampOf(t));

    // The template's row and each step's, in order: what the editor holds and writes back.
    private static string StampOf(CaseTemplate t) =>
        string.Join(',', t.Steps.OrderBy(s => s.Order).Select(s => s.RowHash ?? "").Prepend(t.RowHash ?? ""));

    private static string? Trim(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
