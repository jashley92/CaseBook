using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Application.Work;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// The analyst "My Work" landing (U-25): verifies each bucket — open cases, overdue tasks, recent
/// escalations, and cases carrying my indicators — is computed for the current user and, crucially,
/// respects need-to-know scoping (a restricted case the analyst can't see contributes to nothing).
/// </summary>
public sealed class MyWorkServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 13, 0, 0, 0, TimeSpan.Zero));
    // analyst1 is an Analyst (no ViewAllCases) so scoping is exercised.
    private readonly TestCurrentUser _me = new() { UserId = "analyst1", DisplayName = "Analyst One", RoleSet = [AppRole.Analyst] };

    public MyWorkServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    // No audit interceptor: the test sets timestamps directly.
    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);

    private static DateTimeOffset D(int day) => new(2026, 8, day, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task GetAsync_buckets_the_users_work_and_honours_need_to_know()
    {
        await using (var db = NewContext())
        {
            // A — mine (assigned), open, High. An overdue task + an upcoming task (both on my case,
            // owned by others) + a done one that must be excluded.
            var a = Case.Open(2026, 1, "alpha", "Alpha", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "analyst2", D(10));
            a.Assign("analyst1", "Analyst One", CaseAssignmentRole.Analyst, "analyst2", D(10));
            a.ActionItems.Add(Task_("Patch server", owner: null, due: D(1), ActionItemStatus.Open));      // overdue
            a.ActionItems.Add(Task_("Upcoming review", owner: null, due: D(20), ActionItemStatus.Open));  // upcoming
            a.ActionItems.Add(Task_("Old closed task", owner: null, due: D(1), ActionItemStatus.Done));   // excluded

            // B — mine (IC), open, Critical, escalated Incident→Breach two days ago (in window).
            // An undated task owned by me must appear, sorting to the bottom.
            var b = Case.Open(2026, 2, "bravo", "Bravo", Classification.Incident, Severity.Critical, CaseOrigin.InternalDetection, "analyst2", D(5));
            b.Assign("analyst1", "Analyst One", CaseAssignmentRole.IncidentCommander, "analyst2", D(5));
            b.Reclassify(Classification.Breach, "Confirmed exfiltration", "analyst1", D(11));
            b.ActionItems.Add(Task_("Draft lessons", owner: "analyst1", due: null, ActionItemStatus.Open));

            // C — NOT mine, visible. An old escalation here falls outside the 14-day window.
            var c = Case.Open(2026, 3, "charlie", "Charlie", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "analyst2", D(1));
            c.Assign("analyst2", "Analyst Two", CaseAssignmentRole.IncidentCommander, "analyst2", D(1));
            c.Reclassify(Classification.Breach, "Late determination", "analyst2",
                new DateTimeOffset(2026, 7, 15, 0, 0, 0, TimeSpan.Zero)); // outside the 14-day window

            // D — restricted, NOT mine → invisible to analyst1. None of its rows may surface,
            // even a task explicitly owned by me.
            var d = Case.Open(2026, 4, "delta", "Delta", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "analyst2", D(2));
            d.IsRestricted = true;
            d.Assign("analyst2", "Analyst Two", CaseAssignmentRole.IncidentCommander, "analyst2", D(2));
            d.ActionItems.Add(Task_("Secret overdue", owner: "analyst1", due: D(1), ActionItemStatus.Open));
            d.Reclassify(Classification.Breach, "Restricted escalation", "analyst2", D(12));

            // F — visible, NOT mine, but an overdue task is owned by me (matched by display name).
            var f = Case.Open(2026, 5, "foxtrot", "Foxtrot", Classification.Incident, Severity.Low, CaseOrigin.InternalDetection, "analyst2", D(6));
            f.Assign("analyst2", "Analyst Two", CaseAssignmentRole.IncidentCommander, "analyst2", D(6));
            f.ActionItems.Add(Task_("My follow-up", owner: "Analyst One", due: D(4), ActionItemStatus.Open));

            db.Cases.AddRange(a, b, c, d, f);
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var work = await new MyWorkService(NewFactory(), _me, _clock).GetAsync();

            // Open cases: A and B only, severity-desc so Critical (B) leads.
            work.OpenCases.Select(x => x.Title).Should().Equal("Bravo", "Alpha");

            // Tasks: my whole open worklist — overdue and upcoming — soonest-due first, undated last.
            // The done task, and D's task on an invisible case, are excluded.
            work.Tasks.Select(t => t.Title).Should().Equal(
                "Patch server",     // due  1st (overdue)
                "My follow-up",     // due  4th (overdue, mine-by-owner)
                "Upcoming review",  // due 20th (upcoming)
                "Draft lessons");   // no due date → last (mine-by-owner)

            work.Tasks.Single(t => t.Title == "My follow-up").OwnedByMe.Should().BeTrue();
            work.Tasks.Single(t => t.Title == "Draft lessons").OwnedByMe.Should().BeTrue();
            work.Tasks.Single(t => t.Title == "Patch server").OwnedByMe.Should().BeFalse();

            // Recent escalations: only B's in-window Incident→Breach; C's old one and D's (invisible) drop out.
            work.RecentEscalations.Should().ContainSingle()
                .Which.Should().Match<Escalation>(e =>
                    e.CaseNumber.Contains("bravo") && e.From == Classification.Incident && e.To == Classification.Breach);
        }
    }

    private ActionItem Task_(string title, string? owner, DateTimeOffset? due, ActionItemStatus status) => new()
    {
        Title = title, Owner = owner, DueAtUtc = due, Status = status,
        CreatedBy = "analyst2", CreatedAtUtc = D(1)
    };

    public void Dispose() => _connection.Dispose();
}
