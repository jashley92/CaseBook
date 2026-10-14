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
    public async Task A_reset_another_save_beat_to_it_still_resets(/* BUG-437 */)
    {
        await NewService().SaveAsync("assignment", "Custom", "<p>custom</p>");

        // Another admin's change removes the subject override between this reset's read and its delete of both.
        var race = new RaceCommandInterceptor("DELETE FROM \"AppSettings\"", "DELETE FROM \"AppSettings\" WHERE \"Key\" = $k",
            ("$k", EmailTemplateCatalog.SubjectKey("assignment")));
        var racing = new EmailTemplateAdminService(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()), race)
            .Options), _clock, _user, new NoOpReloader());

        await racing.ResetAsync("assignment");

        race.Ran.Should().BeTrue();
        (await NewService().GetAsync("assignment")).IsOverridden.Should().BeFalse("the body override went too");
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

    [Fact]
    public async Task The_body_limit_is_what_the_settings_column_holds(/* BUG-460 */)
    {
        var svc = NewService();
        var tooLong = () => svc.SaveAsync("assignment", "Subject", new string('x', 8001));
        await tooLong.Should().ThrowAsync<ArgumentException>().WithMessage("Body must be 8000 characters or fewer.");

        await svc.SaveAsync("assignment", "Subject", new string('x', 8000));   // the most the column holds is saved
        (await svc.GetAsync("assignment")).EffectiveBody.Should().HaveLength(8000);

        EmailTemplateCatalog.Templates.Should().OnlyContain(t => t.DefaultBodyHtml.Length <= 8000 && t.DefaultSubject.Length <= 200,
            "every default can be saved back as it is");
    }

    [Fact]
    public async Task A_save_from_a_stale_editor_is_refused(/* BUG-396 */)
    {
        var svc = NewService();
        var opened = (await svc.GetAsync("assignment")).Stamp;
        await svc.SaveAsync("assignment", "Another admin's subject", "<p>theirs</p>", opened);   // saved since

        var act = () => svc.SaveAsync("assignment", "Mine", "<p>mine</p>", opened);

        (await act.Should().ThrowAsync<InvalidOperationException>()).WithMessage("*since you opened it*");
        (await svc.GetAsync("assignment")).EffectiveSubject.Should().Be("Another admin's subject");

        var current = (await svc.GetAsync("assignment")).Stamp;
        await svc.SaveAsync("assignment", "Mine", "<p>mine</p>", current);
        (await svc.GetAsync("assignment")).EffectiveSubject.Should().Be("Mine");
        await svc.SaveAsync("assignment", "Import", "<p>import</p>");   // no stamp: not checked (a config import)
    }

    public void Dispose() => _connection.Dispose();
}
