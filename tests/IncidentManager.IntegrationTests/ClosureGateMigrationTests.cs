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
/// INV-43: upgrading an install whose close gate predates the NotificationsRecorded check adds it once, as a
/// blocking machine check after the gate's other requirements; other gates are untouched, and a gate that
/// already has it gets no second copy.
/// </summary>
public sealed class ClosureGateMigrationTests : IDisposable
{
    private const string Before = "20260930050605_EntityPinned";
    private readonly SqliteConnection _connection = new("Data Source=:memory:");

    public ClosureGateMigrationTests() => _connection.Open();

    private AppDbContext NewContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);

    private static StageGate Gate(StageGateTrigger trigger, params string[] checks)
    {
        var gate = new StageGate { Trigger = trigger, Name = trigger.ToString(), IsActive = true, CreatedBy = "admin", CreatedAtUtc = DateTimeOffset.UtcNow };
        var order = 1;
        foreach (var key in checks)
            gate.Requirements.Add(new StageGateRequirement
            {
                Kind = GateRequirementKind.MachineCheck, CheckKey = key, Label = GateCheckRegistry.Label(key),
                IsBlocking = true, Order = order++
            });
        return gate;
    }

    [Fact]
    public async Task Upgrading_adds_the_check_to_close_gates_that_lack_it()
    {
        await using (var db = NewContext())
        {
            await db.GetService<IMigrator>().MigrateAsync(Before);
            db.StageGates.AddRange(
                Gate(StageGateTrigger.CloseCase, GateCheckKeys.SummaryPresent, GateCheckKeys.AtLeastOneReport),
                Gate(StageGateTrigger.EscalateToBreach, GateCheckKeys.SummaryPresent));
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
            await db.Database.MigrateAsync();

        await using (var db = NewContext())
        {
            var gates = await db.StageGates.Include(g => g.Requirements).AsNoTracking().ToListAsync();
            var close = gates.Single(g => g.Trigger == StageGateTrigger.CloseCase);
            var added = close.Requirements.Should().ContainSingle(r => r.CheckKey == GateCheckKeys.NotificationsRecorded).Subject;
            added.Kind.Should().Be(GateRequirementKind.MachineCheck);
            added.IsBlocking.Should().BeTrue();
            added.Order.Should().Be(3);
            added.Label.Should().Be("Required regulatory notifications recorded");
            added.Id.Should().NotBe(Guid.Empty);

            gates.Single(g => g.Trigger == StageGateTrigger.EscalateToBreach).Requirements
                .Should().NotContain(r => r.CheckKey == GateCheckKeys.NotificationsRecorded);
        }
    }

    [Fact]
    public async Task A_close_gate_that_already_has_the_check_keeps_one()
    {
        await using (var db = NewContext())
        {
            await db.GetService<IMigrator>().MigrateAsync(Before);
            db.StageGates.Add(Gate(StageGateTrigger.CloseCase, GateCheckKeys.NotificationsRecorded));
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
            await db.Database.MigrateAsync();

        await using (var db = NewContext())
            (await db.StageGateRequirements.CountAsync(r => r.CheckKey == GateCheckKeys.NotificationsRecorded)).Should().Be(1);
    }

    public void Dispose() => _connection.Dispose();
}
