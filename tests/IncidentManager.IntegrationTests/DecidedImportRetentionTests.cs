using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Import;
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
/// CAP-31: a decided import's stored document (the submitted JSON and a part-way apply's saved preview) is cleared once
/// the decision is older than Retention:DecidedImportDays; the decision row stays, so the sender's status answer (CAP-13)
/// and the queue are unchanged. Imports still waiting, or claimed and being applied, keep theirs. Each run that clears
/// anything is an audit-trail entry. On both providers, since the clearing is a batched bulk update.
/// </summary>
public sealed class DecidedImportRetentionTests : IDisposable
{
    private TestDatabase? _db;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 6, 1, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _xsiam = new() { UserId = "apitoken:xsiam", RoleSet = [AppRole.Analyst] };
    private readonly TestCurrentUser _reviewer = new() { UserId = "analyst2", RoleSet = [AppRole.Analyst] };

    private void Open(string provider) =>
        _db = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _reviewer, _clock, new CaseChangeNotifier()));

    private CaseImportService Import(TestCurrentUser user) =>
        new(_db!.Factory(), user, _clock, new CaseService(_db.Factory(), user, _clock, new CaseNumberGenerator(_db.Factory()),
            new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(),
            new TestSlaTargets()));

    private DecidedImportRetention Retention() =>
        new(_db!.Factory(), new AuditWriter(_db.Factory(), _hasher, new TestCurrentUser(), _clock), _clock);

    private async Task<Guid> Submit(string origin)
    {
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            SchemaVersion = 1,
            Origin = origin,
            Target = new CaseImportTarget { NewCase = new CaseImportNewCase { Title = "Impossible travel " + origin } },
            Entities = [new CaseImportEntity { Value = "203.0.113.66", Disposition = "Malicious" }],
        };
        var json = JsonSerializer.Serialize(doc, CaseImportJson.Options);
        return (await Import(_xsiam).SubmitAsync(json, CaseImportService.Parse(json).Document!)).Id;
    }

    private async Task Apply(Guid id, Case target)
    {
        var claim = await Import(_reviewer).ClaimPendingAsync(id);
        await Import(_reviewer).MarkPendingAppliedAsync(id, new CaseImportResult(target.Id, target.CaseNumber, false, 0, 0, 1, 0), claim);
    }

    private Case AddCase()
    {
        using var db = _db!.NewContext();
        var c = Case.Open(2026, 1, "target", "Target", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", _clock.UtcNow);
        db.Cases.Add(c);
        db.SaveChanges();
        return c;
    }

    private async Task<PendingImport> Row(Guid id)
    {
        await using var db = _db!.NewContext();
        return await db.PendingImports.AsNoTracking().SingleAsync(p => p.Id == id);
    }

    private async Task SetResume(Guid id, string resume)
    {
        await using var db = _db!.NewContext();
        await db.PendingImports.Where(p => p.Id == id).ExecuteUpdateAsync(s => s.SetProperty(p => p.ResumeJson, resume));
    }

    private async Task<int> AuditCountAsync()
    {
        await using var db = _db!.NewContext();
        return await db.AuditLog.CountAsync();
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Decided_imports_past_the_retention_lose_their_document_and_keep_their_decision(string provider)
    {
        Open(provider);
        var target = AddCase();

        // A hundred days ago: one applied, one rejected (after a part-way apply left its preview), one still waiting (with
        // a saved preview of its own), one claimed by a reviewer and never finished.
        var applied = await Submit("applied");
        var rejected = await Submit("rejected");
        var waiting = await Submit("waiting");
        var claimed = await Submit("claimed");
        await Apply(applied, target);
        await SetResume(rejected, "{\"resume\":1}");
        (await Import(_reviewer).RejectPendingAsync(rejected, "duplicate")).Should().BeTrue();
        await SetResume(waiting, "{\"resume\":2}");
        (await Import(_reviewer).ClaimPendingAsync(claimed)).Should().NotBeNull();
        var before = await Row(applied);

        // Ten days ago: one applied recently.
        _clock.UtcNow = _clock.UtcNow.AddDays(90);
        var recent = await Submit("recent");
        await Apply(recent, target);
        _clock.UtcNow = _clock.UtcNow.AddDays(10);
        var entriesBefore = await AuditCountAsync();

        (await Retention().ClearAsync(90)).Should().Be(2);

        var a = await Row(applied);
        a.RawJson.Should().BeEmpty();
        a.ResumeJson.Should().BeNull();
        a.Should().BeEquivalentTo(before, o => o.Excluding(p => p.RawJson), "who sent it, who decided, when and the case are kept");
        a.RawJsonSha256.Should().NotBeNullOrEmpty("the document's hash still says what was sent");
        var r = await Row(rejected);
        (r.RawJson, r.ResumeJson, r.Status, r.DecidedBy, r.DecisionNote).Should().Be(("", null, PendingImportStatus.Rejected, "analyst2", "duplicate"));

        (await Row(waiting)).RawJson.Should().NotBeEmpty("an import still waiting keeps its document");
        (await Row(waiting)).ResumeJson.Should().Be("{\"resume\":2}");
        (await Row(claimed)).RawJson.Should().NotBeEmpty("one being applied (claimed, no case yet) keeps its document");
        (await Row(recent)).RawJson.Should().NotBeEmpty("decided within the retention");

        await using (var db = _db!.NewContext())
        {
            (await db.AuditLog.CountAsync()).Should().Be(entriesBefore + 1);
            var entry = await db.AuditLog.OrderByDescending(x => x.Sequence).FirstAsync();
            entry.Action.Should().Be(AuditAction.Update);
            entry.EntityType.Should().Be(DecidedImportRetention.AuditEntityType);
            entry.Summary.Should().Contain("2 decided imports").And.Contain("2026-06-11").And.Contain("90 days");
            _hasher.VerifyChain(await db.AuditLog.OrderBy(x => x.Sequence).ToListAsync()).IsValid.Should().BeTrue();
        }

        (await Retention().ClearAsync(90)).Should().Be(0);
        (await AuditCountAsync()).Should().Be(entriesBefore + 1, "a run that clears nothing records nothing");
        (await Retention().ClearAsync(0)).Should().Be(0, "0 keeps every document");
        (await Retention().ClearAsync(5)).Should().Be(1, "a shorter retention reaches the recent one");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_status_answer_and_the_queue_work_after_clearing(string provider /* CAP-13 */)
    {
        Open(provider);
        var target = AddCase();
        var applied = await Submit("applied");
        var rejected = await Submit("rejected");
        var stuck = await Submit("stuck");
        await Apply(applied, target);
        await Import(_reviewer).RejectPendingAsync(rejected, null);
        (await Import(_reviewer).ClaimPendingAsync(stuck)).Should().NotBeNull();
        var decidedAt = _clock.UtcNow;
        _clock.UtcNow = _clock.UtcNow.AddDays(120);

        (await Retention().ClearAsync(90)).Should().Be(2);

        (await Import(_xsiam).GetSubmissionStatusAsync(applied))
            .Should().Be(new ImportSubmissionStatus("applied", decidedAt, target.CaseNumber, target.Id));
        (await Import(_xsiam).GetSubmissionStatusAsync(rejected))
            .Should().Be(new ImportSubmissionStatus("rejected", decidedAt, null, null));
        (await Import(_xsiam).GetSubmissionStatusAsync(stuck))!.Status.Should().Be("pending");

        // The queue lists the stuck claim (WF-18), which kept its document, so it can be put back and reviewed.
        var queue = await Import(_reviewer).ListPendingAsync();
        queue.Select(q => q.Id).Should().Equal(stuck);
        (await Import(_reviewer).ReopenStuckAsync(stuck)).Should().BeTrue();
        (await Import(_reviewer).BuildPreviewForPendingAsync(stuck)).Should().NotBeNull();
        (await Import(_reviewer).BuildPreviewForPendingAsync(applied)).Should().BeNull("a decided import isn't reviewed again");
    }

    public void Dispose() => _db?.Dispose();
}
