using FluentAssertions;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// HR-12: upgrading turns the shipped "Post-incident review complete" attestation on a close gate into the
/// LessonsCaptured check in place, and adds the advisory EntitiesAssessed check; an admin's own wording, other
/// gates and a gate that already has the checks are left alone.
/// </summary>
public sealed class ClosureGateHonestChecksMigrationTests : IDisposable
{
    private const string Before = "20261004094435_AddEntityVerdictChanges";
    private readonly SqliteConnection _connection = new("Data Source=:memory:");

    public ClosureGateHonestChecksMigrationTests() => _connection.Open();

    private AppDbContext NewContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);

    private static StageGate Gate(StageGateTrigger trigger, params (GateRequirementKind Kind, string? Key, string Label)[] reqs)
    {
        var gate = new StageGate { Trigger = trigger, Name = trigger.ToString(), IsActive = true, CreatedBy = "admin", CreatedAtUtc = DateTimeOffset.UtcNow };
        var order = 0;
        foreach (var (kind, key, label) in reqs)
            gate.Requirements.Add(new StageGateRequirement { Kind = kind, CheckKey = key, Label = label, IsBlocking = true, Order = order++ });
        return gate;
    }

    private static (GateRequirementKind, string?, string) Check(string key) => (GateRequirementKind.MachineCheck, key, GateCheckRegistry.Label(key));
    private static (GateRequirementKind, string?, string) Attest(string label) => (GateRequirementKind.Attestation, null, label);

    private async Task<List<StageGate>> UpgradeAsync(params StageGate[] gates)
    {
        await using (var db = NewContext())
        {
            await db.GetService<IMigrator>().MigrateAsync(Before);
            db.StageGates.AddRange(gates);
            await db.SaveChangesAsync();
        }
        await using (var db = NewContext())
            await db.Database.MigrateAsync();
        await using (var read = NewContext())
            return await read.StageGates.Include(g => g.Requirements).AsNoTracking().ToListAsync();
    }

    [Fact]
    public async Task The_shipped_review_attestation_becomes_the_review_check_in_place()
    {
        var gates = await UpgradeAsync(
            Gate(StageGateTrigger.CloseCase, Check(GateCheckKeys.SummaryPresent), Attest("Post-incident review complete"),
                Attest("Evidence preserved and chain of custody complete")),
            Gate(StageGateTrigger.EscalateToBreach, Attest("Post-incident review complete")));

        var close = gates.Single(g => g.Trigger == StageGateTrigger.CloseCase).Requirements.OrderBy(r => r.Order).ToList();
        close[1].Kind.Should().Be(GateRequirementKind.MachineCheck);
        close[1].CheckKey.Should().Be(GateCheckKeys.LessonsCaptured);
        close[1].IsBlocking.Should().BeTrue();
        close[1].Label.Should().Be(GateCheckRegistry.Label(GateCheckKeys.LessonsCaptured));
        close[2].Label.Should().Be("Evidence preserved and chain of custody complete", "the evidence attestation stays");
        var added = close.Should().ContainSingle(r => r.CheckKey == GateCheckKeys.EntitiesAssessed).Subject;
        added.IsBlocking.Should().BeFalse();
        added.Order.Should().Be(3);
        added.Label.Should().Be(GateCheckRegistry.Label(GateCheckKeys.EntitiesAssessed));

        gates.Single(g => g.Trigger == StageGateTrigger.EscalateToBreach).Requirements
            .Should().ContainSingle(r => r.Kind == GateRequirementKind.Attestation, "only close gates change");
    }

    [Fact]
    public async Task An_admins_own_wording_and_existing_checks_are_left_alone()
    {
        var gates = await UpgradeAsync(Gate(StageGateTrigger.CloseCase,
            Attest("Review held with the CISO"), Check(GateCheckKeys.EntitiesAssessed)));

        var close = gates.Single().Requirements;
        close.Should().ContainSingle(r => r.Label == "Review held with the CISO" && r.Kind == GateRequirementKind.Attestation);
        close.Should().ContainSingle(r => r.CheckKey == GateCheckKeys.EntitiesAssessed);
        close.Should().NotContain(r => r.CheckKey == GateCheckKeys.LessonsCaptured);
    }

    public void Dispose() => _connection.Dispose();
}
