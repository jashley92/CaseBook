using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>One playbook step in a template edit/view (E-06).</summary>
public sealed record TemplateStepInput(string Title, string? Description, string? OwnerHint, int? DueOffsetHours);

/// <summary>A step as shown in the apply/preview UIs, carrying its stable id for selection.</summary>
public sealed record TemplateStepView(Guid Id, int Order, string Title, string? Description, string? OwnerHint, int? DueOffsetHours);

/// <summary>A template resolved for the pickers and the New Case / Apply flows.</summary>
public sealed record TemplateView(
    Guid Id, string Name, string? Description, bool IsActive, int SortOrder,
    Classification? DefaultClassification, Severity? DefaultSeverity,
    string? DefaultDataTypes, string? SummaryBoilerplate,
    IReadOnlyList<TemplateStepView> Steps);

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
        using var db = _factory.CreateDbContext();
        var name = (input.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A template name is required.");
        if (await db.CaseTemplates.AnyAsync(t => t.Name == name, ct))
            throw new InvalidOperationException($"A template named '{name}' already exists.");

        var template = new CaseTemplate { Name = name, CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow };
        ApplyContent(template, input);
        db.CaseTemplates.Add(template);
        await db.SaveChangesAsync(ct);
        return template.Id;
    }

    public async Task UpdateAsync(Guid id, TemplateInput input, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var template = await db.CaseTemplates.Include(t => t.Steps).FirstOrDefaultAsync(t => t.Id == id, ct)
                       ?? throw new InvalidOperationException("Template not found.");

        var name = (input.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A template name is required.");
        if (await db.CaseTemplates.AnyAsync(t => t.Name == name && t.Id != id, ct))
            throw new InvalidOperationException($"A template named '{name}' already exists.");

        template.Name = name;
        template.ModifiedBy = _user.UserId;
        template.ModifiedAtUtc = _clock.UtcNow;

        // Replace the step set wholesale (like roles replace permissions) — simplest, and every add/remove
        // is captured by the audit chain.
        db.CaseTemplateSteps.RemoveRange(template.Steps);
        template.Steps.Clear();
        ApplyContent(template, input);
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var template = await db.CaseTemplates.Include(t => t.Steps).FirstOrDefaultAsync(t => t.Id == id, ct);
        if (template is null) return;
        db.CaseTemplateSteps.RemoveRange(template.Steps);
        db.CaseTemplates.Remove(template);
        await db.SaveChangesAsync(ct);
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
            t.Steps.Add(new CaseTemplateStep
            {
                TemplateId = t.Id,
                Order = order++,
                Title = title,
                Description = Trim(s.Description),
                OwnerHint = Trim(s.OwnerHint),
                DueOffsetHours = s.DueOffsetHours is { } h && h > 0 ? h : null
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
            .Select(s => new TemplateStepView(s.Id, s.Order, s.Title, s.Description, s.OwnerHint, s.DueOffsetHours))
            .ToList());

    private static string? Trim(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
