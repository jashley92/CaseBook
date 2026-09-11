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

/// <summary>E-03b: admin-editable email templates, stored as audited settings rows; default = no override.</summary>
public sealed class EmailTemplateAdminServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 10, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public EmailTemplateAdminServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin];
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

    private EmailTemplateAdminService NewService() => new(NewFactory(), _clock, _user, new NoOpReloader());
    private sealed class NoOpReloader : ISettingsReloader { public void Reload() { } }

    [Fact]
    public async Task Defaults_are_returned_and_not_overridden()
    {
        var all = await NewService().GetAllAsync();

        all.Should().NotBeEmpty();
        var assignment = all.Single(t => t.Id == "assignment");
        assignment.IsOverridden.Should().BeFalse();
        assignment.EffectiveSubject.Should().Be(assignment.DefaultSubject);
    }

    [Fact]
    public async Task Saving_a_custom_value_stores_an_override()
    {
        var svc = NewService();
        await svc.SaveAsync("assignment", "Custom subject {{CaseNumber}}", "<h1>Hi {{Assignee}}</h1>");

        var view = await svc.GetAsync("assignment");
        view.IsOverridden.Should().BeTrue();
        view.EffectiveSubject.Should().Be("Custom subject {{CaseNumber}}");
        view.EffectiveBody.Should().Contain("Hi {{Assignee}}");
    }

    [Fact]
    public async Task Saving_the_default_value_stores_no_override()
    {
        var svc = NewService();
        var def = (await svc.GetAsync("assignment"));

        await svc.SaveAsync("assignment", def.DefaultSubject, def.DefaultBody);

        (await svc.GetAsync("assignment")).IsOverridden.Should().BeFalse();
    }

    [Fact]
    public async Task Reset_reverts_to_the_default()
    {
        var svc = NewService();
        await svc.SaveAsync("assignment", "Custom", "<p>custom</p>");
        (await svc.GetAsync("assignment")).IsOverridden.Should().BeTrue();

        await svc.ResetAsync("assignment");

        var view = await svc.GetAsync("assignment");
        view.IsOverridden.Should().BeFalse();
        view.EffectiveSubject.Should().Be(view.DefaultSubject);
    }

    [Fact]
    public async Task An_empty_subject_is_rejected()
    {
        var act = () => NewService().SaveAsync("assignment", "   ", "<p>body</p>");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    public void Dispose() => _connection.Dispose();
}
