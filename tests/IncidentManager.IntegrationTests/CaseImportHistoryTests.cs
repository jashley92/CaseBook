using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Import;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-35: historical and closed cases come in through schema v2 (a new case's phase history, outcome, conclusion,
/// incident commander and team), applied through the audited writes at their effective times, and a reviewer can confirm
/// a submitter's queue together, at most 25 at a time, each as its own confirm. A v1 document reads as it always did.
/// Runs on SQLite and, when a server is configured, on SQL Server.
/// </summary>
public sealed class CaseImportHistoryTests : IDisposable
{
    private TestDatabase? _db;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly HashChainService _hasher = new();
    private readonly CapturingSecurityEventSink _siem = new();
    private readonly TestCurrentUser _xsiam = new() { UserId = "apitoken:xsiam", RoleSet = [AppRole.Analyst] };
    private readonly TestCurrentUser _reviewer = new() { UserId = "analyst2", RoleSet = [AppRole.Analyst] };
    private readonly ListedUserDirectory _users = new(
        new UserSummary("ic-lee", "Dana Lee", "dana.lee@contoso.example", "dana.lee@contoso.example", "Analyst"),
        ListedUserDirectory.User("analyst9", "Analyst"));

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private void Open(string provider)
    {
        _db = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _reviewer, _clock, new CaseChangeNotifier()));
        using var db = _db.NewContext();
        DevDataSeeder.SeedCaseOutcomesAsync(db, _clock).GetAwaiter().GetResult();
    }

    private CaseImportService Import(TestCurrentUser user) =>
        new(_db!.Factory(), user, _clock, new CaseService(_db.Factory(), user, _clock, new CaseNumberGenerator(_db.Factory()),
            new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(),
            new TestSlaTargets(), siem: _siem, users: _users), users: _users, siem: _siem);

    private DateTimeOffset Ago(int days) => _clock.UtcNow.AddDays(-days);

    // A case worked and closed before CaseBook: detected ten days ago, through every phase, closed four days ago.
    private CaseImportDocument Historical(string title = "Wire fraud attempt, March", int schemaVersion = 2) => new()
    {
        Format = CaseImportJson.FormatTag,
        SchemaVersion = schemaVersion,
        Origin = "Legacy tracker",
        Target = new CaseImportTarget
        {
            NewCase = new CaseImportNewCase
            {
                Title = title, Classification = "Incident", Severity = "High", DetectedAt = Ago(10), Summary = "A payment redirect was attempted.",
                History =
                [
                    new() { Phase = "Triage", At = Ago(9) },
                    new() { Phase = "Containment", At = Ago(8), Reason = "Mailbox rule removed" },
                    new() { Phase = "Eradication", At = Ago(7) },
                    new() { Phase = "Recovery", At = Ago(6) },
                    new() { Phase = "PostIncident", At = Ago(5) },
                    new() { Phase = "Closed", At = Ago(4) },
                ],
                Outcome = CaseOutcomeCatalog.Confirmed,
                Conclusion = "Stopped before any payment left.",
                IncidentCommander = "DANA.LEE@contoso.example",   // by UPN
                Assignments = [new() { User = "analyst9" }, new() { User = "ghost.user", Role = "Observer" }],
            },
        },
        Timeline = [new CaseImportTimelineEntry { OccurredAt = Ago(9), Description = "Finance reported the request." }],
    };

    private static string Json(CaseImportDocument doc) => JsonSerializer.Serialize(doc, CaseImportJson.Options);

    private static CaseImportDocument Parsed(CaseImportDocument doc) => CaseImportService.Parse(Json(doc)).Document!;

    private async Task<Guid> SubmitAs(TestCurrentUser who, CaseImportDocument doc) =>
        (await Import(who).SubmitAsync(Json(doc), Parsed(doc))).Id;

    private async Task<Case> LoadAsync(Guid id)
    {
        await using var db = _db!.NewContext();
        return await db.Cases.AsNoTracking().AsSplitQuery().Include(c => c.StatusChanges).Include(c => c.Assignments)
            .Include(c => c.GatePassages).SingleAsync(c => c.Id == id);
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_v1_document_reads_as_it_always_did_and_v2_parts_in_one_are_ignored(string provider)
    {
        Open(provider);
        var plain = Historical(schemaVersion: 1);
        plain.Target!.NewCase!.History = null;
        plain.Target.NewCase.Outcome = plain.Target.NewCase.Conclusion = plain.Target.NewCase.IncidentCommander = null;
        plain.Target.NewCase.Assignments = null;
        var preview = await Import(_reviewer).BuildPreviewAsync(Parsed(plain));
        (preview.HasHistory, preview.HistoryProblem, preview.IncludedItemCount).Should().Be((false, (string?)null, 1));
        var result = await Import(_reviewer).ApplyAsync(preview);
        (await LoadAsync(result.CaseId)).Phase.Should().Be(CasePhase.New, "a v1 import lands open, as before");

        var mixed = await Import(_reviewer).BuildPreviewAsync(Parsed(Historical(schemaVersion: 1)));
        mixed.History.Should().BeEmpty();
        mixed.Warnings.Should().Contain(w => w.Contains("need \"schemaVersion\": 2"));
        CaseImportService.Parse(Json(Historical(schemaVersion: 3))).Error.Should().Contain("newer than this app supports (v2)");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_v2_history_closes_the_case_with_its_milestones_at_the_times_given(string provider)
    {
        Open(provider);
        var svc = Import(_reviewer);
        var preview = await svc.BuildPreviewAsync(Parsed(Historical()));
        preview.HistoryProblem.Should().BeNull();
        preview.IncidentCommander!.UserId.Should().Be("ic-lee");

        var result = await svc.ApplyAsync(preview);
        var c = await LoadAsync(result.CaseId);
        c.Phase.Should().Be(CasePhase.Closed);
        (c.ContainedAtUtc, c.ResolvedAtUtc, c.ClosedAtUtc).Should().Be((Ago(8), Ago(6), Ago(4)), "the milestones derive from the effective times");
        c.OutcomeKey.Should().Be(CaseOutcomeCatalog.Confirmed);
        c.StatusChanges.Where(s => s.From is not null).OrderBy(s => s.EffectiveAt).Select(s => (s.To, s.EffectiveAt)).Should().Equal(
            (CasePhase.Triage, Ago(9)), (CasePhase.Containment, Ago(8)), (CasePhase.Eradication, Ago(7)), (CasePhase.Recovery, Ago(6)),
            (CasePhase.PostIncident, Ago(5)), (CasePhase.Closed, Ago(4)));
        c.StatusChanges.Should().OnlyContain(s => s.ChangedBy == "analyst2", "the confirmer's name is on each write");
        c.StatusChanges.Single(s => s.To == CasePhase.Triage).Reason.Should().Be("imported record: Legacy tracker");
        c.StatusChanges.Single(s => s.To == CasePhase.Containment).Reason.Should().Be("Mailbox rule removed");
        c.IncidentCommander.Should().Be("ic-lee");
        c.Assignments.Select(a => a.UserId).Should().BeEquivalentTo(["ic-lee", "analyst9"]);
        var milestones = CaseMilestones.Project(c, new MilestoneLabels(x => "", s => "", p => "", m => ""));
        milestones.Should().Contain(m => m.Kind == MilestoneKind.Phase && m.AtUtc == Ago(4));
        _siem.Events.Where(e => e.Action == "ImportApplied").Should().ContainSingle();
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_history_out_of_order_or_before_detection_is_refused_before_anything_is_written(string provider)
    {
        Open(provider);
        var svc = Import(_reviewer);
        var doc = Historical();
        doc.Target!.NewCase!.History![2].At = Ago(9).AddHours(-1);   // Eradication before Containment
        var preview = await svc.BuildPreviewAsync(Parsed(doc));
        preview.HistoryProblem.Should().Contain("History step 3").And.Contain("give the history in order");
        await svc.Invoking(s => s.ApplyAsync(preview)).Should().ThrowAsync<ArgumentException>().WithMessage("History step 3*");
        svc.CheckHistory(Parsed(doc)).Should().NotBeNull("the API refuses it before queueing");
        await using (var db = _db!.NewContext())
            (await db.Cases.CountAsync()).Should().Be(0, "nothing was written");

        var early = Historical();
        early.Target!.NewCase!.History![0].At = Ago(11);
        (await svc.BuildPreviewAsync(Parsed(early))).HistoryProblem.Should().Contain("before the case was detected");
        var future = Historical();
        future.Target!.NewCase!.History![5].At = _clock.UtcNow.AddHours(2);
        (await svc.BuildPreviewAsync(Parsed(future))).HistoryProblem.Should().Contain("in the future");
        var noOutcome = Historical();
        noOutcome.Target!.NewCase!.Outcome = null;
        (await svc.BuildPreviewAsync(Parsed(noOutcome))).HistoryProblem.Should().Contain("\"outcome\"");
        var unknownOutcome = Historical();
        unknownOutcome.Target!.NewCase!.Outcome = "made-up";
        (await svc.BuildPreviewAsync(Parsed(unknownOutcome))).HistoryProblem.Should().Contain("isn't an active outcome");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_close_whose_gate_checks_cant_be_met_is_overridden_as_an_imported_record(string provider)
    {
        Open(provider);
        await using (var db = _db!.NewContext())
        {
            var gate = new StageGate { Trigger = StageGateTrigger.CloseCase, Name = "Closure readiness", IsActive = true,
                CreatedBy = "system", CreatedAtUtc = _clock.UtcNow };
            gate.Requirements.Add(new StageGateRequirement { GateId = gate.Id, Order = 0, Kind = GateRequirementKind.Attestation,
                Label = "Lessons review held", IsBlocking = true });
            db.StageGates.Add(gate);
            await db.SaveChangesAsync();
        }
        var result = await Import(_reviewer).ApplyAsync(await Import(_reviewer).BuildPreviewAsync(Parsed(Historical())));

        var c = await LoadAsync(result.CaseId);
        c.Phase.Should().Be(CasePhase.Closed);
        var passage = c.GatePassages.Single(p => p.Trigger == StageGateTrigger.CloseCase);
        (passage.WasOverridden, passage.OverrideJustification, passage.PassedBy).Should().Be((true, "imported record: Legacy tracker", "analyst2"));
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task Someone_the_directory_doesnt_know_is_a_warning_not_a_silent_drop(string provider)
    {
        Open(provider);
        var preview = await Import(_reviewer).BuildPreviewAsync(Parsed(Historical()));
        preview.Warnings.Should().Contain(w => w.Contains("\"ghost.user\"") && w.Contains("won't be added"));
        preview.Assignments.Single(a => a.Named == "ghost.user").UserId.Should().BeNull();
        var result = await Import(_reviewer).ApplyAsync(preview);
        (await LoadAsync(result.CaseId)).Assignments.Should().NotContain(a => a.UserId == "ghost.user");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_batch_confirm_applies_a_submitters_imports_each_on_its_own_and_reports_each(string provider)
    {
        Open(provider);
        var first = await SubmitAs(_xsiam, Historical("First"));
        var second = await SubmitAs(_xsiam, Historical("Second"));
        var bad = Historical("Bad");
        bad.Target!.NewCase!.Outcome = "made-up";   // queued (the producer's view can't judge it), refused at review
        var third = await SubmitAs(_xsiam, bad);
        var other = await SubmitAs(new TestCurrentUser { UserId = "apitoken:other", RoleSet = [AppRole.Analyst] }, Historical("Other"));

        var svc = Import(_reviewer);
        (await svc.ListBatchFromSubmitterAsync(_xsiam.UserId)).Select(p => p.Id).Should().Equal(first, second, third);
        await svc.Invoking(s => s.ConfirmBatchAsync(_xsiam.UserId, Enumerable.Range(0, 26).Select(_ => Guid.NewGuid()).ToList()))
            .Should().ThrowAsync<ArgumentException>().WithMessage("Confirm up to 25*");

        var results = await svc.ConfirmBatchAsync(_xsiam.UserId, [first, second, third, other]);
        results.Select(r => (r.PendingImportId, r.Applied)).Should().Equal((first, true), (second, true), (third, false), (other, false));
        results[2].Message.Should().Contain("isn't an active outcome");
        results[3].Message.Should().Contain("another submitter");
        foreach (var r in results.Where(r => r.Applied))
            (await LoadAsync(r.CaseId!.Value)).Phase.Should().Be(CasePhase.Closed);
        _siem.Events.Count(e => e.Action == "ImportApplied").Should().Be(2, "one per case applied");

        // CAP-13: the producer sees each as it stands; the one left needing review is still pending.
        var producer = Import(_xsiam);
        (await producer.GetSubmissionStatusAsync(first))!.Status.Should().Be("applied");
        (await producer.GetSubmissionStatusAsync(third))!.Status.Should().Be("pending");
        (await svc.ListBatchFromSubmitterAsync(_xsiam.UserId)).Select(p => p.Id).Should().Equal(third);

        // A second confirm of the same ones finds them decided.
        (await svc.ConfirmBatchAsync(_xsiam.UserId, [first])).Single().Message.Should().Contain("no longer waiting");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_history_aimed_at_an_existing_case_by_detection_id_is_left_out(string provider /* CAP-14 */)
    {
        Open(provider);
        await using (var db = _db!.NewContext())
        {
            var open = Case.Open(2026, 1, "open", "Open case", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", Ago(3));
            open.DetectionCaseId = "4812";
            db.Cases.Add(open);
            await db.SaveChangesAsync();
        }
        var doc = Historical();
        doc.Target!.DetectionCaseId = "4812";
        var preview = await Import(_reviewer).BuildPreviewAsync(Parsed(doc));
        preview.TargetKind.Should().Be(CaseImportTargetKind.ExistingCase);
        preview.Warnings.Should().Contain(w => w.Contains("aren't applied to an existing one"));
        var result = await Import(_reviewer).ApplyAsync(preview);
        (await LoadAsync(result.CaseId)).Phase.Should().Be(CasePhase.New);
    }

    public void Dispose() => _db?.Dispose();
}
