using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Import;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-14: an import aimed at an existing case by the detection platform's incident id, resolved to the one open case that
/// carries it as the reviewer sees cases when it's reviewed (never as the producer's token saw them: the BUG-279 lesson).
/// CAP-13: what an import's sender can learn of what became of it.
/// Runs on SQLite and, when a server is configured, on SQL Server (<see cref="TestDatabase"/>).
/// </summary>
public sealed class ImportTargetingTests : IDisposable
{
    private TestDatabase? _db;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero));

    // The producer's token (a system token with an Analyst-like role), a reviewer outside the restricted case, and its commander.
    private readonly TestCurrentUser _xsiam = new() { UserId = "apitoken:xsiam", RoleSet = [AppRole.Analyst] };
    private readonly TestCurrentUser _reviewer = new() { UserId = "analyst2", RoleSet = [AppRole.Analyst] };
    private readonly TestCurrentUser _commander = new() { UserId = "commander1", RoleSet = [AppRole.Analyst] };

    private AppDbContext NewContext() => _db!.NewContext();

    private CaseImportService Import(TestCurrentUser user) =>
        new(_db!.Factory(), user, _clock, new CaseService(_db.Factory(), user, _clock, new CaseNumberGenerator(_db.Factory()),
            new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(),
            new TestSlaTargets()));

    private Case Add(int seq, string? detection, bool restricted = false, bool closed = false)
    {
        using var db = NewContext();
        var c = Case.Open(2026, seq, $"case{seq}", $"Case {seq}", Classification.Incident, Severity.High, CaseOrigin.InternalDetection,
            "ic1", _clock.UtcNow.AddDays(-3));
        c.DetectionCaseId = detection;
        c.IsRestricted = restricted;
        c.IncidentCommander = _commander.UserId;
        if (closed) c.ChangePhase(CasePhase.Closed, "Done", "ic1", _clock.UtcNow.AddDays(-1));
        db.Cases.Add(c);
        db.SaveChanges();
        return c;
    }

    private static CaseImportDocument Doc(string? detection, Guid? caseId = null) => new()
    {
        Format = CaseImportJson.FormatTag,
        SchemaVersion = 1,
        Origin = "XSIAM incident 4812",
        Target = new CaseImportTarget
        {
            CaseId = caseId,
            DetectionCaseId = detection,
            NewCase = new CaseImportNewCase { Title = "Impossible travel for jdoe", DetectionCaseId = detection },
        },
        Entities = [new CaseImportEntity { Value = "203.0.113.66", Disposition = "Malicious" }],
    };

    private async Task<Guid> SubmitAs(TestCurrentUser who, CaseImportDocument doc)
    {
        var json = JsonSerializer.Serialize(doc, CaseImportJson.Options);
        return (await Import(who).SubmitAsync(json, CaseImportService.Parse(json).Document!)).Id;
    }

    // ── CAP-14 ───────────────────────────────────────────────────────────────────────────────────

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_detection_id_resolves_to_the_one_open_case_carrying_it_and_none_or_several_leave_the_choice(string provider)
    {
        _db = TestDatabase.Open(provider);
        var svc = Import(_reviewer);

        var none = await svc.BuildPreviewAsync(Doc("4812"));
        none.TargetKind.Should().Be(CaseImportTargetKind.NewCase, "the new case the document describes is prepared");
        none.Warnings.Should().Contain(w => w.Contains("No open case you can see carries detection case id \"4812\""));

        Add(1, "4812", closed: true);   // closed: not a case to add to
        (await svc.BuildPreviewAsync(Doc("4812"))).TargetKind.Should().Be(CaseImportTargetKind.NewCase);

        var open = Add(2, "inc-4812");
        var one = await svc.BuildPreviewAsync(Doc(" INC-4812 "));   // as the database compares it on either engine: no case, trimmed
        one.TargetKind.Should().Be(CaseImportTargetKind.ExistingCase);
        one.ExistingCaseId.Should().Be(open.Id);
        one.ExistingCaseNumber.Should().Be(open.CaseNumber);
        one.Warnings.Should().NotContain(w => w.Contains("detection case id"));

        var twin = Add(3, "INC-4812");
        var several = await svc.BuildPreviewAsync(Doc("inc-4812"));
        several.TargetKind.Should().Be(CaseImportTargetKind.ExistingCase);
        several.ExistingCaseId.Should().BeNull("the reviewer picks");
        several.Warnings.Should().Contain(w => w.Contains("More than one open case") && w.Contains(open.CaseNumber) && w.Contains(twin.CaseNumber));
        several.NewCase.Should().NotBeNull("switching back to a new case needs no rebuild");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_detection_id_is_resolved_under_the_reviewer_when_reviewed_not_under_the_producers_token(string provider)
    {
        _db = TestDatabase.Open(provider);
        var secret = Add(1, "4812", restricted: true);
        var cleared = new TestCurrentUser { UserId = "apitoken:cleared", RoleSet = [AppRole.IncidentCommander] };   // sees every case

        var json = JsonSerializer.Serialize(Doc("4812"), CaseImportJson.Options);
        var (pid, response) = await Import(cleared).SubmitAsync(json, CaseImportService.Parse(json).Document!);
        response.Warnings.Should().Contain(w => w.Contains("decided when it's reviewed"));
        await using (var db = NewContext())
        {
            var row = await db.PendingImports.AsNoTracking().SingleAsync(p => p.Id == pid);
            row.TargetCaseId.Should().BeNull("nothing is resolved as the producer saw the cases");
            row.Summary.Should().Contain("detection case id 4812").And.NotContain(secret.CaseNumber);
        }

        // Every reviewer sees it waiting; each resolves it as they see the cases.
        (await Import(_reviewer).ListPendingAsync()).Should().Contain(p => p.Id == pid);
        var outside = await Import(_reviewer).BuildPreviewForPendingAsync(pid);
        outside!.TargetKind.Should().Be(CaseImportTargetKind.NewCase);
        outside.ExistingCaseId.Should().BeNull("the restricted case isn't this reviewer's to see");
        outside.Warnings.Should().Contain(w => w.Contains("No open case you can see"));

        var inside = await Import(_commander).BuildPreviewForPendingAsync(pid);
        inside!.TargetKind.Should().Be(CaseImportTargetKind.ExistingCase);
        inside.ExistingCaseId.Should().Be(secret.Id);

        // And the other way round: a producer that can't see the case doesn't stop a reviewer who can.
        var blindPid = await SubmitAs(_xsiam, Doc("4812"));
        (await Import(_commander).BuildPreviewForPendingAsync(blindPid))!.ExistingCaseId.Should().Be(secret.Id);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_case_id_and_a_detection_id_must_name_the_same_case(string provider)
    {
        _db = TestDatabase.Open(provider);
        var a = Add(1, "4812");
        Add(2, "4813");
        var unmarked = Add(3, null);
        var secret = Add(4, "9999", restricted: true);
        var svc = Import(_xsiam);

        (await svc.CheckTargetAsync(Doc("4812", a.Id))).Should().BeNull();
        (await svc.CheckTargetAsync(Doc(" 4812", a.Id))).Should().BeNull();
        (await svc.CheckTargetAsync(Doc("4813", a.Id))).Should().Contain("name different cases").And.Contain("detection case id \"4812\"");
        (await svc.CheckTargetAsync(Doc("4812", unmarked.Id))).Should().Contain("no detection case id");
        (await svc.CheckTargetAsync(Doc("4812", secret.Id))).Should().BeNull("a case the caller can't see isn't judged, so the answer doesn't say it's there");
        (await svc.CheckTargetAsync(Doc(null, a.Id))).Should().BeNull();
        (await svc.CheckTargetAsync(Doc("4813"))).Should().BeNull();

        // Agreeing, it's an ordinary case-id target.
        var agreed = await svc.BuildPreviewAsync(Doc("4812", a.Id));
        agreed.ExistingCaseId.Should().Be(a.Id);

        // BUG-334 for the pair: the producer couldn't see the case id, so neither half resolves again under a reviewer who can.
        var pid = await SubmitAs(_xsiam, Doc("9999", secret.Id));
        var review = await Import(_commander).BuildPreviewForPendingAsync(pid);
        review!.TargetKind.Should().Be(CaseImportTargetKind.NewCase);
        review.ExistingCaseId.Should().BeNull();
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_stored_id_with_a_stray_space_or_a_non_ascii_letter_matches_once_and_as_the_target_check_does(string provider)
    {
        // CAP-14 review: ids saved before CaseService trimmed them (set here directly, as an old row holds them), and a
        // non-ASCII one. Each resolves to exactly one case on either database, and CheckTargetAsync agrees.
        _db = TestDatabase.Open(provider);
        var svc = Import(_reviewer);
        var leading = Add(1, " INC-1001");
        var trailing = Add(2, "INC-1002 ");
        var accented = Add(3, "Café-1003");

        foreach (var (search, expected) in new[] { ("inc-1001", leading), ("INC-1002", trailing), ("CAFé-1003", accented), (" café-1003 ", accented) })
        {
            var found = await svc.FindOpenByDetectionIdAsync(search);
            found.Should().ContainSingle(search).Which.Id.Should().Be(expected.Id);
            (await svc.CheckTargetAsync(Doc(search, expected.Id))).Should().BeNull($"\"{search}\" is the id {expected.CaseNumber} carries");
        }

        // ASCII letters fold, others are compared as written, on SQL Server (whose UPPER folds É) as on SQLite (whose doesn't).
        (await svc.FindOpenByDetectionIdAsync("CAFÉ-1003")).Should().BeEmpty();
        (await svc.CheckTargetAsync(Doc("CAFÉ-1003", accented.Id))).Should().Contain("name different cases");

        // R1: SQL TRIM strips spaces only, so an old id ending in other whitespace matches on neither path, and both say so.
        var noBreak = Add(4, "INC-1004 ");
        var tab = Add(5, "	INC-1005");
        foreach (var (search, stored) in new[] { ("INC-1004", noBreak), ("INC-1005", tab), ("INC-1004 ", noBreak), ("	INC-1005", tab) })
        {
            (await svc.FindOpenByDetectionIdAsync(search)).Should().BeEmpty(search);
            (await svc.CheckTargetAsync(Doc(search, stored.Id))).Should().Contain("name different cases", "as the search finds no match");
        }
    }

    [Fact]
    public void A_detection_id_is_trimmed_when_a_case_is_edited()
    {
        var now = _clock.UtcNow;
        var c = Case.Open(2026, 1, "case1", "Case 1", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", now.AddDays(-1));
        c.UpdateDetails(c.Title, c.Summary, "  INC-2001 ", null, null, c.DetectedAtUtc ?? now, null, "ic1", now);
        c.DetectionCaseId.Should().Be("INC-2001");
    }

    // ── CAP-13 ───────────────────────────────────────────────────────────────────────────────────

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_sender_sees_its_own_submissions_and_a_reviewer_those_it_could_review(string provider)
    {
        _db = TestDatabase.Open(provider);
        var secret = Add(1, null, restricted: true);
        var cleared = new TestCurrentUser { UserId = "apitoken:cleared", RoleSet = [AppRole.IncidentCommander] };

        var mine = await SubmitAs(_xsiam, Doc(null));
        var intoSecret = await SubmitAs(cleared, Doc(null, secret.Id));

        var status = await Import(_xsiam).GetSubmissionStatusAsync(mine);
        status.Should().Be(new ImportSubmissionStatus("pending", null, null, null));

        // Another token: without EditCases, nobody else's; with it, those in the queue it could review.
        var reader = new TestCurrentUser { UserId = "apitoken:reader", PermissionSet = [Permission.ViewCases] };
        (await Import(reader).GetSubmissionStatusAsync(mine)).Should().BeNull();
        (await Import(_reviewer).GetSubmissionStatusAsync(mine))!.Status.Should().Be("pending");
        (await Import(_reviewer).GetSubmissionStatusAsync(intoSecret)).Should().BeNull("a submission into a case it can't see is, to it, not there");
        (await Import(_commander).GetSubmissionStatusAsync(intoSecret))!.Status.Should().Be("pending");
        (await Import(_xsiam).GetSubmissionStatusAsync(Guid.NewGuid())).Should().BeNull();

        // Own submissions stay visible to the sender even when it no longer reviews imports.
        var demoted = new TestCurrentUser { UserId = _xsiam.UserId, PermissionSet = [] };
        (await Import(demoted).GetSubmissionStatusAsync(mine))!.Status.Should().Be("pending");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_status_follows_the_decision_and_names_the_case_only_to_a_caller_who_can_see_it(string provider)
    {
        _db = TestDatabase.Open(provider);
        var target = Add(1, null);
        var applied = await SubmitAs(_xsiam, Doc(null));
        var rejected = await SubmitAs(_xsiam, Doc("4812"));

        // Claimed by a reviewer and still being applied: nothing is decided yet.
        var claim = await Import(_reviewer).ClaimPendingAsync(applied);
        claim.Should().NotBeNull();
        (await Import(_xsiam).GetSubmissionStatusAsync(applied)).Should().Be(new ImportSubmissionStatus("pending", null, null, null));

        _clock.UtcNow = _clock.UtcNow.AddMinutes(5);
        await Import(_reviewer).MarkPendingAppliedAsync(applied, new CaseImportResult(target.Id, "stored-number", false, 0, 0, 1, 0), claim);
        var done = await Import(_xsiam).GetSubmissionStatusAsync(applied);
        done.Should().Be(new ImportSubmissionStatus("applied", _clock.UtcNow, target.CaseNumber, target.Id),
            "the case as numbered now, not as recorded when it was applied");

        await Import(_reviewer).RejectPendingAsync(rejected, "duplicate");
        (await Import(_xsiam).GetSubmissionStatusAsync(rejected)).Should().Be(new ImportSubmissionStatus("rejected", _clock.UtcNow, null, null));

        // The case restricted since: still applied, but the number and id are no longer the sender's to see.
        await using (var db = NewContext())
        {
            var c = await db.Cases.SingleAsync(x => x.Id == target.Id);
            c.IsRestricted = true;
            await db.SaveChangesAsync();
        }
        (await Import(_xsiam).GetSubmissionStatusAsync(applied)).Should().Be(new ImportSubmissionStatus("applied", _clock.UtcNow, null, null));
        (await Import(_commander).GetSubmissionStatusAsync(applied))!.ResolvedCaseId.Should().Be(target.Id);
    }

    public void Dispose() => _db?.Dispose();
}
