using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;
using System;

namespace IncidentManager.IntegrationTests;

/// <summary>PROD-11: superseding a duplicate case.</summary>
public sealed class SupersedeTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "analyst1", RoleSet = [AppRole.IncidentCommander] };

    public SupersedeTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;


    private async Task<(AppDbContext Db, CaseService Svc, Guid Dup, Guid Primary)> SeedAsync()
    {
        var db = new AppDbContext(Options());
        await db.Database.EnsureCreatedAsync();
        var primary = Case.Open(2026, 1, "Main", "Phishing wave", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "analyst1", _clock.UtcNow);
        primary.AddEntity(EntityType.IpAddress, "203.0.113.66", "C2 (main)", EntityDisposition.Malicious, null, "EDR", "analyst1", _clock.UtcNow);
        var dup = Case.Open(2026, 2, "Dup", "User-reported phish", Classification.Incident, Severity.Medium,
            CaseOrigin.InternalDetection, "analyst1", _clock.UtcNow);
        dup.AddEntity(EntityType.IpAddress, "203.0.113.66", "C2 (dup)", EntityDisposition.Suspicious, null, "User", "analyst1", _clock.UtcNow);
        dup.AddEntity(EntityType.Domain, "lure.attacker.test", null, EntityDisposition.Malicious, null, "Proofpoint", "analyst1", _clock.UtcNow);
        db.Cases.AddRange(primary, dup);
        await db.SaveChangesAsync();
        var svc = new CaseService(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
        return (db, svc, dup.Id, primary.Id);
    }

    [Fact]
    public async Task Superseding_links_copies_missing_indicators_and_notes_both_cases_without_closing()
    {
        var (db, svc, dup, primary) = await SeedAsync();
        await using var _ = db;

        var result = await svc.SupersedeAsync(dup, primary, copyIndicators: true, "Same wave, filed twice");

        result.IndicatorsCopied.Should().Be(1, "the IP was already on the kept case");
        result.LinkAdded.Should().BeTrue();

        await using var read = new AppDbContext(Options());
        var kept = await read.CaseEntities.AsNoTracking().Where(e => e.CaseId == primary).ToListAsync();
        kept.Single(e => e.Type == EntityType.IpAddress).Label.Should().Be("C2 (main)", "an existing indicator is never overwritten");
        kept.Single(e => e.Type == EntityType.Domain).Source.Should().Be("Copied from 2026-02_Dup (Proofpoint)");

        var link = await read.CaseLinks.AsNoTracking().SingleAsync();
        (link.CaseId, link.RelatedCaseId, link.Type).Should().Be((dup, primary, CaseLinkType.DuplicateOf));

        (await read.Notes.AsNoTracking().Where(n => n.CaseId == dup).Select(n => n.Body).SingleAsync())
            .Should().StartWith("**Superseded by 2026-01_Main.**").And.Contain("Same wave, filed twice");
        (await read.Notes.AsNoTracking().Where(n => n.CaseId == primary).Select(n => n.Body).SingleAsync())
            .Should().Contain("1 indicator copied");

        (await read.Cases.AsNoTracking().SingleAsync(c => c.Id == dup)).Phase.Should().NotBe(CasePhase.Closed,
            "closing stays a separate, gated human act");
        _hasher.VerifyChain(await read.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Superseding_needs_a_reason_a_different_visible_case_and_edit_rights()
    {
        var (db, svc, dup, primary) = await SeedAsync();
        await using var _ = db;

        await svc.Invoking(s => s.SupersedeAsync(dup, dup, true, "x")).Should().ThrowAsync<ArgumentException>();
        await svc.Invoking(s => s.SupersedeAsync(dup, primary, true, " ")).Should().ThrowAsync<ArgumentException>();

        (await db.Cases.SingleAsync(c => c.Id == primary)).IsRestricted = true;
        await db.SaveChangesAsync();
        _user.UserId = "outsider";
        _user.RoleSet = [AppRole.Analyst];
        await svc.Invoking(s => s.SupersedeAsync(dup, primary, true, "x")).Should().ThrowAsync<InvalidOperationException>();

        _user.RoleSet = [AppRole.Manager];
        await svc.Invoking(s => s.SupersedeAsync(dup, primary, true, "x"))
            .Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
    }

    public void Dispose() => _connection.Dispose();
}
