using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Export;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>E-07: a case's entity graph exports as a valid, self-describing STIX 2.1 bundle, need-to-know scoped.</summary>
public sealed class StixExportServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 10, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();   // analyst1, Analyst role (no ViewAllCases)

    public StixExportServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    private AppDbContext NewContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

    private sealed class Monitor(ReportingOptions v) : IOptionsMonitor<ReportingOptions>
    {
        public ReportingOptions CurrentValue { get; } = v;
        public ReportingOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ReportingOptions, string?> listener) => null;
    }

    private StixExportService NewService(string org = "Northwind Mutual") =>
        new(NewFactory(), _user, _clock, new Monitor(new ReportingOptions { OrganizationName = org }));

    private Guid SeedGraph(bool restricted = false)
    {
        using var db = NewContext();
        var c = Case.Open(2026, 1, "Phishing Wave", "Credential phishing", Classification.Incident,
            Severity.High, CaseOrigin.InternalDetection, "ic1", _clock.UtcNow);
        c.Summary = "A phishing campaign against Finance.";
        c.IsRestricted = restricted;

        var ip = new CaseEntity { Id = Guid.NewGuid(), CaseId = c.Id, Type = EntityType.IpAddress, Value = "185.220.101.47", Disposition = EntityDisposition.Malicious, Source = "SIEM" };
        var domain = new CaseEntity { Id = Guid.NewGuid(), CaseId = c.Id, Type = EntityType.Domain, Value = "evil.example", Disposition = EntityDisposition.Suspicious, Label = "phish host" };
        var hash = new CaseEntity { Id = Guid.NewGuid(), CaseId = c.Id, Type = EntityType.FileHash, Value = "44d88612fea8a8f36de82e1278abb02f", Disposition = EntityDisposition.Malicious };
        var host = new CaseEntity { Id = Guid.NewGuid(), CaseId = c.Id, Type = EntityType.Host, Value = "FIN-WS-07", Disposition = EntityDisposition.Benign };
        c.Entities.Add(ip); c.Entities.Add(domain); c.Entities.Add(hash); c.Entities.Add(host);

        c.EntityRelationships.Add(new EntityRelationship
        {
            Id = Guid.NewGuid(), CaseId = c.Id, SourceEntityId = domain.Id, TargetEntityId = ip.Id,
            Type = EntityRelationshipType.ResolvedTo, Description = "DNS resolution"
        });
        c.EntityRelationships.Add(new EntityRelationship
        {
            Id = Guid.NewGuid(), CaseId = c.Id, SourceEntityId = host.Id, TargetEntityId = ip.Id,
            Type = EntityRelationshipType.CommunicatedWith
        });

        db.Cases.Add(c);
        db.SaveChanges();
        return c.Id;
    }

    private static IReadOnlyList<Dictionary<string, object?>> Objects(StixBundleResult r) =>
        ((IEnumerable<Dictionary<string, object?>>)r.Bundle["objects"]!).ToList();

    [Fact]
    public async Task Produces_a_bundle_with_identity_report_scos_and_relationships()
    {
        var id = SeedGraph();
        var result = (await NewService().BuildAsync(id))!;

        result.CaseNumber.Should().StartWith("2026-01");
        result.Bundle["type"].Should().Be("bundle");
        ((string)result.Bundle["id"]!).Should().StartWith("bundle--");

        var objs = Objects(result);
        objs.Should().Contain(o => (string)o["type"]! == "identity" && (string)o["name"]! == "Northwind Mutual");
        objs.Count(o => (string)o["type"]! == "report").Should().Be(1);
        objs.Count(o => (string)o["type"]! == "relationship").Should().Be(2);
        objs.Should().Contain(o => (string)o["type"]! == "ipv4-addr" && (string)o["value"]! == "185.220.101.47");
        objs.Should().Contain(o => (string)o["type"]! == "domain-name" && (string)o["value"]! == "evil.example");
        objs.Should().Contain(o => (string)o["type"]! == "x-casebook-artifact" && (string)o["value"]! == "FIN-WS-07"); // Host has no native SCO
    }

    [Fact]
    public async Task Maps_a_file_hash_to_a_file_sco_with_the_right_algorithm()
    {
        var id = SeedGraph();
        var file = Objects((await NewService().BuildAsync(id))!).Single(o => (string)o["type"]! == "file");

        var hashes = (Dictionary<string, object?>)file["hashes"]!;
        hashes.Should().ContainKey("MD5");   // 32-char digest ⇒ MD5
        hashes["MD5"].Should().Be("44d88612fea8a8f36de82e1278abb02f");
    }

    [Fact]
    public async Task Carries_the_analyst_verdict_as_a_custom_property()
    {
        var id = SeedGraph();
        var ip = Objects((await NewService().BuildAsync(id))!).Single(o => (string)o["type"]! == "ipv4-addr");

        ip["x_casebook_disposition"].Should().Be("Malicious");
        ip["x_casebook_source"].Should().Be("SIEM");
    }

    [Fact]
    public async Task Relationships_reference_the_entity_scos_and_kebab_the_verb()
    {
        var id = SeedGraph();
        var objs = Objects((await NewService().BuildAsync(id))!);

        var ipId = (string)objs.Single(o => (string)o["type"]! == "ipv4-addr")["id"]!;
        var resolved = objs.Single(o => (string?)o.GetValueOrDefault("relationship_type") == "resolved-to");
        resolved["target_ref"].Should().Be(ipId);
        resolved["description"].Should().Be("DNS resolution");
        objs.Should().Contain(o => (string?)o.GetValueOrDefault("relationship_type") == "communicated-with");
    }

    [Fact]
    public async Task Report_lists_every_object_and_the_case_metadata()
    {
        var id = SeedGraph();
        var objs = Objects((await NewService().BuildAsync(id))!);

        var report = objs.Single(o => (string)o["type"]! == "report");
        ((string)report["x_casebook_case_number"]!).Should().StartWith("2026-01");
        var refs = ((IEnumerable<string>)report["object_refs"]!).ToList();
        refs.Should().Contain((string)objs.First(o => (string)o["type"]! == "ipv4-addr")["id"]!);
        report["description"].Should().Be("A phishing campaign against Finance.");
    }

    [Fact]
    public async Task A_case_the_caller_cannot_see_returns_null()
    {
        var id = SeedGraph(restricted: true);   // analyst1 is neither IC nor assignee

        (await NewService().BuildAsync(id)).Should().BeNull();
    }

    public void Dispose() => _connection.Dispose();
}
