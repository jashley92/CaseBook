using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Work;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// RD-16: the Desk. On top of My work's cases and tasks (tested in <see cref="MyWorkServiceTests"/>), it says the
/// caller's part in each case, what others changed since the caller last opened it, why each of the caller's tasks
/// exists, and what needs the caller in order of consequence. Need-to-know scoped throughout.
/// </summary>
public sealed class DeskServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private static readonly DateTimeOffset Now = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private readonly FixedClock _clock = new(Now);
    private readonly TestCurrentUser _me = new() { UserId = "analyst1", DisplayName = "Analyst One", RoleSet = [AppRole.Analyst] };

    public DeskServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);

    private DeskService NewDesk() => new(NewFactory(), _me, _clock, new MyWorkService(NewFactory(), _me, _clock),
        new NotificationDeadlineService(NewFactory(), new OffSettings(), new NotificationRuleService(NewFactory(), _me, _clock), _clock),
        new TestSlaTargets());

    private static DateTimeOffset H(int hoursFromNow) => Now.AddHours(hoursFromNow);

    [Fact]
    public async Task The_desk_says_your_part_what_changed_why_each_task_exists_and_what_needs_you()
    {
        Guid alpha, decisionId;
        await using (var db = NewContext())
        {
            // Alpha: I'm an analyst; a decision with a task of mine carrying it out (overdue); a question task due soon.
            var a = Case.Open(2026, 1, "alpha", "Alpha", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ivy", H(-96));
            a.Assign("analyst1", "Analyst One", CaseAssignmentRole.Analyst, "ivy", H(-2));   // added after I last looked
            var decision = new TimelineEntry
            {
                Kind = TimelineKind.Investigation, Type = TimelineEntryType.Decision, Description = "Block the IP",
                Rationale = "Malicious", OccurredAtUtc = H(-48), CreatedBy = "ivy", CreatedAtUtc = H(-48)
            };
            a.TimelineEntries.Add(decision);
            a.ActionItems.Add(new ActionItem { Title = "Block the IP at the proxy", Owner = "analyst1", DueAtUtc = H(-5),
                AboutRef = $"{ActionItem.AboutEntry}:{decision.Id}", CreatedBy = "ivy", CreatedAtUtc = H(-48) });
            a.ActionItems.Add(new ActionItem { Title = "Did anyone else click?", Owner = "analyst1", DueAtUtc = H(6),
                RaisedFromBriefId = Guid.NewGuid(), CreatedBy = "ivy", CreatedAtUtc = H(-40) });
            a.ActionItems.Add(new ActionItem { Title = "Someone else's", Owner = "lee", DueAtUtc = H(-1), CreatedBy = "ivy", CreatedAtUtc = H(-40) });
            a.Notes.Add(new AnalystNote { Body = "@Analyst One can you confirm the count?", MentionsCsv = "analyst1", CreatedBy = "ivy", CreatedAtUtc = H(-1) });
            alpha = a.Id;
            decisionId = decision.Id;

            // Delta: restricted and not mine: nothing from it may surface, not even a task owned by me.
            var d = Case.Open(2026, 2, "delta", "Delta", Classification.Incident, Severity.Critical, CaseOrigin.InternalDetection, "ivy", H(-96));
            d.IsRestricted = true;
            d.ActionItems.Add(new ActionItem { Title = "Secret", Owner = "analyst1", DueAtUtc = H(-5), CreatedBy = "ivy", CreatedAtUtc = H(-48) });

            db.Cases.AddRange(a, d);
            // I last opened Alpha three hours ago; since then Ivy and Lee changed it, and so did I.
            db.CaseAccessEvents.Add(new CaseAccessEvent { ActorUserId = "analyst1", CaseId = a.Id, CaseNumber = a.CaseNumber,
                AccessType = AccessType.CaseOpen, FirstSeenUtc = H(-4), LastSeenUtc = H(-3) });
            db.AuditLog.AddRange(
                new AuditLogEntry { Sequence = 1, AtUtc = H(-5), Actor = "ivy", EntityType = "Case", CaseNumber = a.CaseNumber },   // before
                new AuditLogEntry { Sequence = 2, AtUtc = H(-2), Actor = "ivy", EntityType = "Case", CaseNumber = a.CaseNumber },
                new AuditLogEntry { Sequence = 3, AtUtc = H(-1), Actor = "lee", EntityType = "Case", CaseNumber = a.CaseNumber },
                new AuditLogEntry { Sequence = 4, AtUtc = H(-1), Actor = "analyst1", EntityType = "Case", CaseNumber = a.CaseNumber },
                new AuditLogEntry { Sequence = 5, AtUtc = H(-1), Actor = "ivy", EntityType = "Case", CaseNumber = d.CaseNumber });
            await db.SaveChangesAsync();
        }

        var desk = await NewDesk().GetAsync();

        var c = desk.Cases.Should().ContainSingle().Which;
        c.Id.Should().Be(alpha);
        c.Role.Should().Be(CaseAssignmentRole.Analyst);
        c.NextForYou.Should().Be("Block the IP at the proxy");
        c.ChangesSince.Should().Be(2);
        c.ChangedBy.Should().BeEquivalentTo("ivy", "lee");
        desk.ChangesSince.Should().Be(2);

        desk.Next.Select(t => (t.Title, t.Why)).Should().Equal(
            ("Block the IP at the proxy", DeskWhy.Decision),
            ("Did anyone else click?", DeskWhy.Question));

        desk.Needs.Select(n => n.Kind).Should().Equal(DeskNeedKind.Overdue, DeskNeedKind.Mention, DeskNeedKind.Assigned, DeskNeedKind.DueSoon);
        desk.Needs.Single(n => n.Kind == DeskNeedKind.Mention).ByUserId.Should().Be("ivy");
        desk.Needs.Should().NotContain(n => n.Title == "Secret" || n.Title == "Someone else's");
        decisionId.Should().NotBeEmpty();
    }

    private sealed class OffSettings : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current { get; set; } = NotificationDeadlineSettings.Off;
    }

    public void Dispose() => _connection.Dispose();
}
