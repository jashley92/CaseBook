using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
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
/// FR-06: single-field edits (case details, impact assessment) use an expected-value optimistic-concurrency
/// check so two authors editing the same case during a live incident can't silently clobber each other. A
/// save whose baseline no longer matches the persisted fields is refused; a matching (or opted-out null)
/// baseline saves; and the check is scoped per editor, so an unrelated change never false-conflicts.
/// </summary>
public sealed class CaseConcurrencyTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseConcurrencyTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin];
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
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());


    private async Task<Guid> NewCaseAsync(CaseService svc)
    {
        var created = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Concurrency",
            Title = "Concurrency case",
            Classification = Classification.Incident,
            Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });
        return created.Id;
    }

    private async Task<string> DetailsStampAsync(Guid id)
    {
        await using var db = NewContext();
        return (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).DetailsConcurrencyStamp();
    }

    private async Task<string> ImpactStampAsync(Guid id)
    {
        await using var db = NewContext();
        return (await db.Cases.AsNoTracking().Include(c => c.DataElements)
            .FirstAsync(c => c.Id == id)).ImpactConcurrencyStamp();
    }

    [Fact]
    public async Task A_stale_details_save_is_rejected_and_the_other_authors_value_survives()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);

        var authorA = await DetailsStampAsync(id); // A opens the editor

        // B edits and saves first, against the same baseline.
        await svc.UpdateDetailsAsync(id, "B's title", "B summary", null, null, null,
            _clock.UtcNow, null, expectedStamp: authorA);

        // A now saves against the stale baseline — refused.
        var act = async () => await svc.UpdateDetailsAsync(id, "A's title", "A summary", null, null, null,
            _clock.UtcNow, null, expectedStamp: authorA);

        await act.Should().ThrowAsync<StaleEditException>();

        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id);
        reloaded.Title.Should().Be("B's title"); // B's write was not clobbered
    }

    [Fact]
    public async Task A_stale_save_carries_the_current_stamp_so_a_deliberate_resave_succeeds()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var stale = await DetailsStampAsync(id);

        await svc.UpdateDetailsAsync(id, "B's title", null, null, null, null, _clock.UtcNow, null, expectedStamp: stale);

        var ex = await Assert.ThrowsAsync<StaleEditException>(() =>
            svc.UpdateDetailsAsync(id, "A's title", null, null, null, null, _clock.UtcNow, null, expectedStamp: stale));

        // Re-baseline to the current stamp the exception carries → the intentional overwrite goes through.
        await svc.UpdateDetailsAsync(id, "A's title", null, null, null, null, _clock.UtcNow, null, expectedStamp: ex.CurrentStamp);

        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id);
        reloaded.Title.Should().Be("A's title");
    }

    [Fact]
    public async Task A_matching_baseline_saves_and_a_null_baseline_opts_out_of_the_check()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);

        // Matching baseline → saves.
        await svc.UpdateDetailsAsync(id, "First", null, null, null, null, _clock.UtcNow, null,
            expectedStamp: await DetailsStampAsync(id));
        (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).Title.Should().Be("First");

        // Null baseline → legacy last-write-wins path (no check), still writes.
        await svc.UpdateDetailsAsync(id, "Second", null, null, null, null, _clock.UtcNow, null, expectedStamp: null);
        (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).Title.Should().Be("Second");
    }

    [Fact]
    public async Task An_unrelated_change_does_not_false_conflict_with_a_details_save()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var detailsBaseline = await DetailsStampAsync(id);

        // A concurrent, unrelated edit to the same row (severity) touches ModifiedAtUtc but not the details fields.
        await svc.ChangeSeverityAsync(id, Severity.High, "Scope grew");

        // The details save still succeeds — the stamp is scoped to the details fields only.
        var act = async () => await svc.UpdateDetailsAsync(id, "Retitled", null, null, null, null,
            _clock.UtcNow, null, expectedStamp: detailsBaseline);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task A_stale_impact_assessment_save_is_rejected()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var baseline = await ImpactStampAsync(id);

        await svc.UpdateImpactAssessmentAsync(id, 500, new[] { "Name" }, "NY", expectedStamp: baseline);

        var act = async () => await svc.UpdateImpactAssessmentAsync(id, 999, new[] { "SSN" }, "NJ", expectedStamp: baseline);

        await act.Should().ThrowAsync<StaleEditException>();

        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id);
        reloaded.AffectedIndividualsCount.Should().Be(500); // first author's assessment survives
    }

    private async Task<string> LegalStampAsync(Guid id)
    {
        await using var db = NewContext();
        return (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).LegalReferralConcurrencyStamp();
    }

    private async Task<string> MaterialityStampAsync(Guid id)
    {
        await using var db = NewContext();
        return (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).MaterialityConcurrencyStamp();
    }

    // REL-02: the FR-06 optimistic-concurrency check now also covers the two remaining think-time modals —
    // the Legal referral and the materiality determination — both of which carry free-text an author types
    // over time (a relevance note / a rationale) and previously overwrote each other silently.

    [Fact]
    public async Task A_stale_legal_referral_save_is_rejected_and_the_other_authors_referral_survives()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);

        var baseline = await LegalStampAsync(id); // both authors open the referral modal

        // B refers first, against the shared baseline.
        await svc.ReferToLegalAsync(id, "GC-B", "B relevance note", expectedStamp: baseline);

        // A refers against the now-stale baseline — refused.
        var act = async () => await svc.ReferToLegalAsync(id, "GC-A", "A relevance note", expectedStamp: baseline);
        await act.Should().ThrowAsync<StaleEditException>();

        var reloaded = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id);
        reloaded.LegalReferral.ReferredToContact.Should().Be("GC-B"); // B's referral was not clobbered
    }

    // BUG-519: the bulk "Refer to Legal" judges "already referred" on the case as it stands, not on the list's snapshot,
    // so a referral made meanwhile keeps its contact and note. The workspace modal (no flag) still edits the referral.
    [Fact]
    public async Task A_bulk_referral_keeps_a_referral_made_meanwhile_and_the_modal_still_edits_it()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var other = await NewCaseAsync(svc);

        // Another analyst refers the case after the bulk selection was made.
        await svc.ReferToLegalAsync(id, "GC-B", "B relevance note");

        (await svc.ReferToLegalAsync(id, "Bulk contact", "Bulk note", onlyIfNotReferred: true)).Should().BeFalse();
        (await svc.ReferToLegalAsync(other, "Bulk contact", "Bulk note", onlyIfNotReferred: true)).Should().BeTrue();

        var kept = await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id);
        kept.LegalReferral.ReferredToContact.Should().Be("GC-B");
        kept.LegalReferral.RegulatoryRelevanceNote.Should().Be("B relevance note");
        (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == other)).LegalReferral.ReferredToContact.Should().Be("Bulk contact");

        (await svc.ReferToLegalAsync(id, "GC-C", "C note", expectedStamp: await LegalStampAsync(id))).Should().BeTrue();
        (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).LegalReferral.ReferredToContact.Should().Be("GC-C");
    }

    [Fact]
    public async Task A_stale_materiality_save_is_rejected_but_a_rebaselined_resave_succeeds()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc); // an Incident — materiality is allowed
        var baseline = await MaterialityStampAsync(id);

        // B records a determination first, against the shared baseline.
        await svc.RecordMaterialityAsync(id, MaterialityStatus.Material, "Committee-B", _clock.UtcNow,
            "B: reasonable likelihood of harm.", expectedStamp: baseline);

        // A records against the stale baseline — refused, and B's determination survives.
        var ex = await Assert.ThrowsAsync<StaleEditException>(() =>
            svc.RecordMaterialityAsync(id, MaterialityStatus.NotMaterial, "Committee-A", _clock.UtcNow,
                "A: no material impact.", expectedStamp: baseline));
        (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).Materiality.Status
            .Should().Be(MaterialityStatus.Material);

        // Re-baselined to the stamp the exception carries → a deliberate overwrite goes through.
        await svc.RecordMaterialityAsync(id, MaterialityStatus.NotMaterial, "Committee-A", _clock.UtcNow,
            "A: no material impact.", expectedStamp: ex.CurrentStamp);
        (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).Materiality.Status
            .Should().Be(MaterialityStatus.NotMaterial);
    }

    [Fact]
    public async Task A_stale_page_cannot_overwrite_a_colleagues_reported_time(/* BUG-594 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var colleague = _clock.UtcNow.AddMinutes(5);
        _clock.UtcNow = _clock.UtcNow.AddHours(1);

        // Both pages showed "not reported"; the colleague records first.
        await svc.MarkReportedAsync(id, colleague, Shown.Of<DateTimeOffset?>(null));
        var ex = await Assert.ThrowsAsync<StaleEditException>(() => svc.MarkReportedAsync(id, _clock.UtcNow, Shown.Of<DateTimeOffset?>(null)));
        (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).ReportedAtUtc.Should().Be(colleague);
        ex.CurrentStamp.Should().NotBeEmpty();

        // A page showing the colleague's time corrects it; the old call shape (no value shown) still saves as before.
        await svc.MarkReportedAsync(id, colleague.AddMinutes(1), Shown.Of<DateTimeOffset?>(colleague));
        await svc.MarkReportedAsync(id, colleague.AddMinutes(2));
        (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == id)).ReportedAtUtc.Should().Be(colleague.AddMinutes(2));
    }

    [Fact]
    public async Task A_stale_page_cannot_overwrite_a_colleagues_notice(/* BUG-594 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        var colleague = _clock.UtcNow.AddMinutes(5);
        _clock.UtcNow = _clock.UtcNow.AddHours(1);

        await svc.RecordNoticeAsync(id, "NY", colleague, Shown.Of<DateTimeOffset?>(null));
        await Assert.ThrowsAsync<StaleEditException>(() => svc.RecordNoticeAsync(id, "ny", _clock.UtcNow, Shown.Of<DateTimeOffset?>(null)));
        (await db.JurisdictionNotices.AsNoTracking().SingleAsync(n => n.CaseId == id)).NotifiedAtUtc.Should().Be(colleague);

        // Another regulator isn't affected, and a page showing the colleague's time corrects it.
        await svc.RecordNoticeAsync(id, "CA", _clock.UtcNow, Shown.Of<DateTimeOffset?>(null));
        await svc.RecordNoticeAsync(id, "NY", colleague.AddMinutes(1), Shown.Of<DateTimeOffset?>(colleague));
        (await db.JurisdictionNotices.AsNoTracking().SingleAsync(n => n.CaseId == id && n.Jurisdiction == "NY")).NotifiedAtUtc
            .Should().Be(colleague.AddMinutes(1));
    }

    private async Task<Domain.Entities.CaseBrief> CurrentBriefAsync(Guid id)
    {
        await using var db = NewContext();
        return await db.CaseBriefs.AsNoTracking().SingleAsync(b => b.CaseId == id && b.IsCurrent);
    }

    [Fact]
    public async Task The_brief_editor_keeps_lines_added_meanwhile_and_saves(/* BUG-595 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        await svc.ReviseBriefAsync(id, null, "Phish reached Finance", "Commodity kit", "- Lure from a lookalike domain", null);
        var opened = (await CurrentBriefAsync(id)).Id;

        // While the editor is open, the same user adds a question (Question mode) - an appended version.
        await svc.AddOpenQuestionAsync(id, "Did anyone enter credentials?", followUp: false);

        (await svc.ReviseBriefAsync(id, opened, "Phish reached Finance; one mailbox accessed", "Commodity kit",
            "- Lure from a lookalike domain\n- MFA prompt approved", null)).Should().BeTrue();
        var saved = await CurrentBriefAsync(id);
        saved.Summary.Should().Be("Phish reached Finance; one mailbox accessed");
        saved.Known.Should().Be("- Lure from a lookalike domain\n- MFA prompt approved");
        saved.OpenQuestions.Should().Be("- Did anyone enter credentials?", "the question added meanwhile is kept, not dropped");
        saved.Appended.Should().BeFalse();
    }

    [Fact]
    public async Task The_brief_editor_appends_lines_added_meanwhile_to_a_part_it_changed(/* BUG-595 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        await svc.ReviseBriefAsync(id, null, "Phish", null, null, "- Who clicked?");
        var opened = (await CurrentBriefAsync(id)).Id;
        await svc.AddOpenQuestionAsync(id, "Was MFA bypassed?", followUp: false);

        await svc.ReviseBriefAsync(id, opened, "Phish", null, null, "- Who clicked? (two users)");
        (await CurrentBriefAsync(id)).OpenQuestions.Should().Be("- Who clicked? (two users)\n- Was MFA bypassed?");
    }

    [Fact]
    public async Task The_brief_editor_is_still_refused_over_a_colleagues_revision(/* BUG-595 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        await svc.ReviseBriefAsync(id, null, "Phish", "Commodity", null, null);
        var opened = (await CurrentBriefAsync(id)).Id;
        await svc.AddOpenQuestionAsync(id, "Was MFA bypassed?", followUp: false);
        await svc.ReviseBriefAsync(id, (await CurrentBriefAsync(id)).Id, "Phish", "Targeted", null, "- Was MFA bypassed?");   // a revision

        await Assert.ThrowsAsync<StaleEditException>(() => svc.ReviseBriefAsync(id, opened, "Phish", "Commodity kit", null, null));
        (await CurrentBriefAsync(id)).WorkingAssessment.Should().Be("Targeted");
    }

    [Fact]
    public async Task The_brief_editor_is_refused_when_a_part_it_changed_was_replaced_meanwhile(/* BUG-595 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = await NewCaseAsync(svc);
        await svc.ReviseBriefAsync(id, null, "Phish", "Commodity", null, null);
        var opened = (await CurrentBriefAsync(id)).Id;
        // A summary edit in the case details is an appended version too (WF-30), but it replaces the summary.
        var c = await db.Cases.AsNoTracking().FirstAsync(x => x.Id == id);
        await svc.UpdateDetailsAsync(id, c.Title, "Phish, contained", null, null, null, c.DetectedAtUtc ?? _clock.UtcNow, null);

        await Assert.ThrowsAsync<StaleEditException>(() => svc.ReviseBriefAsync(id, opened, "Phish (finance)", "Commodity", null, null));
        (await CurrentBriefAsync(id)).Summary.Should().Be("Phish, contained");

        // Left alone in the editor, the replaced summary is taken as it now stands.
        await svc.ReviseBriefAsync(id, opened, "Phish", "Targeted", null, null);
        var saved = await CurrentBriefAsync(id);
        (saved.Summary, saved.WorkingAssessment).Should().Be(("Phish, contained", "Targeted"));
    }

    public void Dispose() => _connection.Dispose();
}
