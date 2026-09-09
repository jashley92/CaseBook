using IncidentManager.Application.Abstractions;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>One requirement in a gate edit. <paramref name="CheckKey"/> is a machine-check registry key
/// (set only for a MachineCheck); null for an attestation. <paramref name="CheckParam"/> is the threshold
/// for a parameterized check (ignored otherwise).</summary>
public sealed record GateRequirementInput(GateRequirementKind Kind, string? CheckKey, int? CheckParam, string Label, bool IsBlocking);

/// <summary>A requirement as shown in the authoring UI, carrying its stable id.</summary>
public sealed record GateRequirementView(Guid Id, int Order, GateRequirementKind Kind, string? CheckKey, int? CheckParam, string Label, bool IsBlocking);

/// <summary>A stage gate resolved for administration.</summary>
public sealed record StageGateView(
    Guid Id, StageGateTrigger Trigger, string Name, string? Description, bool IsActive,
    IReadOnlyList<GateRequirementView> Requirements, int CommentaryMinLength);

/// <summary>The content to create a gate with, or replace an existing one's content.</summary>
public sealed record StageGateInput(
    StageGateTrigger Trigger, string Name, string? Description, bool IsActive,
    IReadOnlyList<GateRequirementInput> Requirements, int CommentaryMinLength = 0);

/// <summary>
/// Administers stage gates (C-08): the admin-authored completeness requirements enforced on ladder
/// escalations and case closure (C-07). Writes are admin-only and gated at the web layer; every change
/// is audited and hash-chained by the save interceptor like other reference data. At most one gate may
/// be active per transition — the evaluator only ever consults the active one.
/// </summary>
public sealed class StageGateService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public StageGateService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    /// <summary>Every gate, active or not, for administration.</summary>
    public async Task<List<StageGateView>> ListAllAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return Project(await Load(db).ToListAsync(ct));
    }

    public async Task<StageGateView?> GetAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var g = await Load(db).FirstOrDefaultAsync(g => g.Id == id, ct);
        return g is null ? null : Project(g);
    }

    public async Task<Guid> CreateAsync(StageGateInput input, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var name = (input.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A gate name is required.");
        await GuardSingleActiveAsync(db, input.Trigger, input.IsActive, excludeId: null, ct);

        var gate = new StageGate { Trigger = input.Trigger, Name = name, CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow };
        ApplyContent(gate, input);
        db.StageGates.Add(gate);
        await db.SaveChangesAsync(ct);
        return gate.Id;
    }

    public async Task UpdateAsync(Guid id, StageGateInput input, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var gate = await db.StageGates.Include(g => g.Requirements).FirstOrDefaultAsync(g => g.Id == id, ct)
                   ?? throw new InvalidOperationException("Gate not found.");

        var name = (input.Name ?? "").Trim();
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A gate name is required.");
        await GuardSingleActiveAsync(db, input.Trigger, input.IsActive, excludeId: id, ct);

        gate.Trigger = input.Trigger;
        gate.Name = name;
        gate.ModifiedBy = _user.UserId;
        gate.ModifiedAtUtc = _clock.UtcNow;

        // Replace the requirement set wholesale (like templates replace steps) — every add/remove is
        // captured by the audit chain.
        db.StageGateRequirements.RemoveRange(gate.Requirements);
        gate.Requirements.Clear();
        ApplyContent(gate, input);
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var gate = await db.StageGates.Include(g => g.Requirements).FirstOrDefaultAsync(g => g.Id == id, ct);
        if (gate is null) return;
        db.StageGateRequirements.RemoveRange(gate.Requirements);
        db.StageGates.Remove(gate);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>At most one active gate per transition, so the evaluator's choice is never ambiguous.</summary>
    private static async Task GuardSingleActiveAsync(IAppDbContext db, StageGateTrigger trigger, bool isActive,
        Guid? excludeId, CancellationToken ct)
    {
        if (!isActive) return;
        var clash = await db.StageGates
            .AnyAsync(g => g.IsActive && g.Trigger == trigger && (excludeId == null || g.Id != excludeId), ct);
        if (clash)
            throw new InvalidOperationException(
                $"Another active gate already governs '{StageGateTriggers.Label(trigger)}'. Deactivate it first.");
    }

    private static void ApplyContent(StageGate g, StageGateInput input)
    {
        g.Description = Trim(input.Description);
        g.IsActive = input.IsActive;
        g.CommentaryMinLength = Math.Max(0, input.CommentaryMinLength);

        var order = 0;
        foreach (var r in input.Requirements ?? [])
        {
            if (r.Kind == GateRequirementKind.MachineCheck)
            {
                // A machine check without a selected check is a blank row; an unrecognised key is refused
                // (the registry is the whitelist — an admin can only pick a code-defined predicate).
                if (string.IsNullOrWhiteSpace(r.CheckKey)) continue;
                if (!GateCheckRegistry.IsKnown(r.CheckKey))
                    throw new ArgumentException($"Unknown machine check '{r.CheckKey}'.");
                // A parameterized check stores a threshold clamped to its floor (defaulted when absent);
                // a parameterless check ignores any supplied value.
                var spec = GateCheckRegistry.Param(r.CheckKey);
                int? param = spec is null ? null : Math.Max(spec.Min, r.CheckParam ?? spec.Default);
                g.Requirements.Add(new StageGateRequirement
                {
                    GateId = g.Id, Order = order++, Kind = GateRequirementKind.MachineCheck,
                    CheckKey = r.CheckKey, CheckParam = param,
                    Label = string.IsNullOrWhiteSpace(r.Label) ? GateCheckRegistry.Label(r.CheckKey, param) : r.Label.Trim(),
                    IsBlocking = r.IsBlocking
                });
            }
            else
            {
                var label = (r.Label ?? "").Trim();
                if (string.IsNullOrWhiteSpace(label)) continue; // drop blank attestation rows
                g.Requirements.Add(new StageGateRequirement
                {
                    GateId = g.Id, Order = order++, Kind = GateRequirementKind.Attestation,
                    CheckKey = null, Label = label, IsBlocking = r.IsBlocking
                });
            }
        }
    }

    private static IQueryable<StageGate> Load(IAppDbContext db) =>
        db.StageGates.AsNoTracking()
            .Include(g => g.Requirements)
            .OrderBy(g => g.Trigger).ThenBy(g => g.Name);

    private static List<StageGateView> Project(IEnumerable<StageGate> gates) =>
        gates.Select(Project).ToList();

    private static StageGateView Project(StageGate g) => new(
        g.Id, g.Trigger, g.Name, g.Description, g.IsActive,
        g.Requirements.OrderBy(r => r.Order)
            .Select(r => new GateRequirementView(r.Id, r.Order, r.Kind, r.CheckKey, r.CheckParam, r.Label, r.IsBlocking))
            .ToList(),
        g.CommentaryMinLength);

    private static string? Trim(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
