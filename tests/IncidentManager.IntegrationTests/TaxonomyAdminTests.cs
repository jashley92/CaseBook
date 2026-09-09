using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>X-02: admin-editable taxonomy display labels, stored as audited settings rows.</summary>
public sealed class TaxonomyAdminTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 4, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public TaxonomyAdminTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin];
        using (NewContext()) { }
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

    private TaxonomyAdminService NewService() => new(NewFactory(), _clock, _user, new NoOpReloader());

    private sealed class NoOpReloader : ISettingsReloader { public void Reload() { } }

    [Fact]
    public async Task Setting_a_label_stores_an_override_and_reports_it_as_effective()
    {
        var svc = NewService();
        await svc.SetLabelAsync("Classification", "Breach", "Major Incident");

        var kinds = await svc.GetEffectiveAsync();
        var breach = kinds.Single(k => k.Id == "Classification").Members.Single(m => m.Value == "Breach");
        breach.Override.Should().Be("Major Incident");
        breach.Effective.Should().Be("Major Incident");
        breach.IsOverridden.Should().BeTrue();

        // Untouched members still report their built-in default.
        var incident = kinds.Single(k => k.Id == "Classification").Members.Single(m => m.Value == "Incident");
        incident.IsOverridden.Should().BeFalse();
        incident.Effective.Should().Be("Incident");

        // The row is under the stable Taxonomy: key.
        await using var db = NewContext();
        (await db.AppSettings.AnyAsync(s => s.Key == "Taxonomy:Classification:Label:Breach")).Should().BeTrue();
    }

    [Fact]
    public async Task Blank_or_default_value_removes_the_override()
    {
        var svc = NewService();
        await svc.SetLabelAsync("CasePhase", "PostIncident", "Lessons Learned");
        await svc.SetLabelAsync("CasePhase", "PostIncident", "   "); // blank clears it

        var post = (await svc.GetEffectiveAsync()).Single(k => k.Id == "CasePhase").Members.Single(m => m.Value == "PostIncident");
        post.IsOverridden.Should().BeFalse();
        post.Effective.Should().Be("Post-Incident");

        // Setting a value equal to the default is also treated as "no override".
        await svc.SetLabelAsync("CasePhase", "Triage", "Triage");
        var triage = (await svc.GetEffectiveAsync()).Single(k => k.Id == "CasePhase").Members.Single(m => m.Value == "Triage");
        triage.IsOverridden.Should().BeFalse();

        await using var db = NewContext();
        (await db.AppSettings.CountAsync(s => s.Key.StartsWith("Taxonomy:"))).Should().Be(0);
    }

    [Fact]
    public async Task Unknown_kind_or_member_is_rejected()
    {
        var svc = NewService();
        var badKind = async () => await svc.SetLabelAsync("Nope", "Breach", "X");
        await badKind.Should().ThrowAsync<InvalidOperationException>();

        var badMember = async () => await svc.SetLabelAsync("Classification", "NotAMember", "X");
        await badMember.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task A_label_change_is_audited_and_the_chain_stays_valid()
    {
        await NewService().SetLabelAsync("Classification", "AdverseEvent", "Security Event");

        await using var db = NewContext();
        (await db.AuditLog.CountAsync(a => a.EntityType == "AppSetting")).Should().BeGreaterThan(0);
        var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    // --- X-02 slice 3: hide + reorder for the pick-list taxonomies ---

    [Fact]
    public async Task Hiding_and_reordering_are_stored_and_reported_in_effective_order()
    {
        var svc = NewService();
        await svc.SetVisibilityOrderAsync("EntityDisposition",
            new[] { "Malicious", "Benign", "Unknown", "Suspicious" }, new[] { "Suspicious" });

        var disp = (await svc.GetEffectiveAsync()).Single(k => k.Id == "EntityDisposition");
        disp.Members.Select(m => m.Value).Should().ContainInOrder("Malicious", "Benign", "Unknown", "Suspicious");
        disp.Members.Single(m => m.Value == "Suspicious").Hidden.Should().BeTrue();
        disp.Members.Single(m => m.Value == "Malicious").Hidden.Should().BeFalse();

        await using var db = NewContext();
        (await db.AppSettings.AnyAsync(s => s.Key == "Taxonomy:EntityDisposition:Order")).Should().BeTrue();
        (await db.AppSettings.AnyAsync(s => s.Key == "Taxonomy:EntityDisposition:Hidden:Suspicious")).Should().BeTrue();
    }

    [Fact]
    public async Task Restoring_the_default_order_with_nothing_hidden_removes_the_rows()
    {
        var svc = NewService();
        await svc.SetVisibilityOrderAsync("EntityDisposition",
            new[] { "Malicious", "Benign", "Unknown", "Suspicious" }, new[] { "Suspicious" });
        // Back to the built-in order with everything shown → no redundant rows kept.
        await svc.SetVisibilityOrderAsync("EntityDisposition",
            new[] { "Unknown", "Benign", "Suspicious", "Malicious" }, Array.Empty<string>());

        await using var db = NewContext();
        (await db.AppSettings.CountAsync(s => s.Key.StartsWith("Taxonomy:EntityDisposition:"))).Should().Be(0);
    }

    [Fact]
    public async Task Hiding_every_member_is_rejected()
    {
        var svc = NewService();
        var act = async () => await svc.SetVisibilityOrderAsync("EntityDisposition",
            new[] { "Unknown", "Benign", "Suspicious", "Malicious" },
            new[] { "Unknown", "Benign", "Suspicious", "Malicious" });
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task An_incomplete_order_is_rejected()
    {
        var svc = NewService();
        var act = async () => await svc.SetVisibilityOrderAsync("EntityDisposition",
            new[] { "Unknown", "Benign" }, Array.Empty<string>());
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Hiding_or_reordering_a_ladder_or_phase_kind_is_rejected()
    {
        var svc = NewService();
        var act = async () => await svc.SetVisibilityOrderAsync("Classification",
            new[] { "ComplexEvent", "AdverseEvent", "Incident", "Breach" }, Array.Empty<string>());
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task A_visibility_order_change_is_audited_and_the_chain_stays_valid()
    {
        await NewService().SetVisibilityOrderAsync("EntityType",
            new[] { "Other", "Account", "Host", "IpAddress", "Domain", "Url", "FileHash", "FileName", "EmailAddress", "Process", "RegistryKey" },
            new[] { "RegistryKey" });

        await using var db = NewContext();
        (await db.AuditLog.CountAsync(a => a.EntityType == "AppSetting")).Should().BeGreaterThan(0);
        var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    public void Dispose() => _connection.Dispose();
}
