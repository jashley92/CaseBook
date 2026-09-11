using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Export;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// The malicious-IOC blocklist feed (E-13): confirmed IOC-like indicators across the caller's
/// visible cases, deduped, need-to-know scoped — the flat feed pushed to SIEM / firewalls / EDR.
/// </summary>
public sealed class IocFeedTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 14, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public IocFeedTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private sealed class NoOpCaseNotifications : IncidentManager.Application.Abstractions.ICaseNotifications
    {
        public System.Threading.Tasks.Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string assigneeUserId, string assigneeDisplayName, IncidentManager.Domain.Enums.CaseAssignmentRole role, string assignedByUserId, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsOverdueAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.OverdueActionItem> items, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsDueSoonAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.DueSoonActionItem> items, int leadHours, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
    }

    private static CreateCaseRequest Req(string name) => new()
    {
        DescriptiveName = name,
        Title = $"{name} case",
        Classification = Classification.Incident,
        Severity = Severity.Medium,
        Origin = CaseOrigin.InternalDetection
    };

    [Fact]
    public async Task Feed_carries_only_confirmed_malicious_ioc_like_indicators()
    {
        _user.RoleSet = [AppRole.Manager]; // sees all cases
        await using var db = NewContext();
        var svc = NewService(db);
        var c = await svc.CreateAsync(Req("Alpha"));

        await svc.AddEntityAsync(c.Id, EntityType.IpAddress, "203.0.113.10", null, EntityDisposition.Malicious, null, "SIEM");
        await svc.AddEntityAsync(c.Id, EntityType.Domain, "evil.example", null, EntityDisposition.Malicious, null, "VT");
        await svc.AddEntityAsync(c.Id, EntityType.IpAddress, "203.0.113.99", null, EntityDisposition.Suspicious, null, null); // not confirmed
        await svc.AddEntityAsync(c.Id, EntityType.Host, "FIN-WKS-04", null, EntityDisposition.Malicious, null, null);       // an asset, not an IOC
        await svc.AddEntityAsync(c.Id, EntityType.Account, "jdoe", null, EntityDisposition.Malicious, null, null);          // an asset, not an IOC

        var feed = await new IocFeedService(NewFactory(), _user).GetMaliciousIocsAsync();

        feed.Select(f => f.Value).Should().BeEquivalentTo("203.0.113.10", "evil.example");
        feed.Should().OnlyContain(f => f.Type == EntityType.IpAddress || f.Type == EntityType.Domain);
    }

    [Fact]
    public async Task Same_indicator_on_two_cases_is_deduped_with_span_and_source_cases()
    {
        _user.RoleSet = [AppRole.Manager];
        Guid alpha, beta;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
            beta = (await svc.CreateAsync(Req("Beta"))).Id;
            // Same IP, differing case: earlier on Alpha, later (and different casing is n/a for an IP) on Beta.
            await svc.AddEntityAsync(alpha, EntityType.IpAddress, "198.51.100.7", null, EntityDisposition.Malicious, null, "SIEM");
        }
        _clock.UtcNow = _clock.UtcNow.AddHours(6);
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            await svc.AddEntityAsync(beta, EntityType.IpAddress, "198.51.100.7", null, EntityDisposition.Malicious, null, "EDR");
        }

        await using (var db = NewContext())
        {
            var feed = await new IocFeedService(NewFactory(), _user).GetMaliciousIocsAsync();

            var row = feed.Should().ContainSingle().Subject;
            row.Value.Should().Be("198.51.100.7");
            row.Cases.Should().HaveCount(2);
            row.Sources.Should().BeEquivalentTo("SIEM", "EDR");
            row.FirstSeenUtc.Should().Be(new DateTimeOffset(2026, 8, 14, 0, 0, 0, TimeSpan.Zero));
            row.LastSeenUtc.Should().Be(new DateTimeOffset(2026, 8, 14, 6, 0, 0, TimeSpan.Zero));
        }
    }

    [Fact]
    public async Task A_malicious_ioc_only_on_a_restricted_case_the_caller_cannot_see_is_excluded()
    {
        // Default TestCurrentUser is an Analyst with no ViewAllCases → need-to-know scoping applies.
        _user.UserId = "analyst-not-assigned";
        _user.RoleSet = [AppRole.Analyst];

        await using (var db = NewContext())
        {
            var visible = IncidentManager.Domain.Entities.Case.Open(2026, 1, "Visible", "Visible",
                Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "system", _clock.UtcNow);
            var restricted = IncidentManager.Domain.Entities.Case.Open(2026, 2, "Restricted", "Restricted",
                Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
            restricted.IsRestricted = true; // analyst is neither IC nor assigned → cannot see it
            db.Cases.AddRange(visible, restricted);

            db.CaseEntities.Add(new IncidentManager.Domain.Entities.CaseEntity
            {
                CaseId = visible.Id, Type = EntityType.Domain, Value = "seen.example",
                Disposition = EntityDisposition.Malicious
            });
            db.CaseEntities.Add(new IncidentManager.Domain.Entities.CaseEntity
            {
                CaseId = restricted.Id, Type = EntityType.Domain, Value = "hidden.example",
                Disposition = EntityDisposition.Malicious
            });
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var feed = await new IocFeedService(NewFactory(), _user).GetMaliciousIocsAsync();
            feed.Select(f => f.Value).Should().ContainSingle().Which.Should().Be("seen.example");
        }
    }

    public void Dispose() => _connection.Dispose();
}
