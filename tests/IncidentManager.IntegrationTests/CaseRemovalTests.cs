using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Security;
using IncidentManager.Application.StageGates;
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
/// An administrator's removal of an archived case opened by mistake (or a bad import): refused unless archived, confirmed
/// with its number, with a reason and not under a legal hold; once removed, left out of every query (the case, its IOCs,
/// links to it, lookup by number) but still holding its number; restorable; purged after the undo window or at once, which
/// deletes what was filed under it, purges its evidence files (records and custody kept), leaves a stub that still
/// verifies, and frees its number, with the old entries under it kept apart from its next holder. On both providers.
/// </summary>
public sealed class CaseRemovalTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 21, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _admin = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly TestOptionsMonitor<CaseRetentionOptions> _retention = new(new CaseRetentionOptions { RemovedCaseDays = 30 });
    private readonly Store _store = new();

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _admin, _clock, new CaseChangeNotifier()));

    /// <summary>Records what a purge deleted from the stores.</summary>
    private sealed class Store : IEvidenceStore, IReportStore
    {
        public List<string> Purged { get; } = [];
        public Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default) => throw new NotSupportedException();
        public Task PurgeAsync(string storagePath, CancellationToken ct = default) { Purged.Add(storagePath); return Task.CompletedTask; }
        Task<StoredReport> IReportStore.SaveAsync(Guid caseId, string fileName, byte[] content, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string storagePath, CancellationToken ct = default) { Purged.Add(storagePath); return Task.CompletedTask; }
    }

    private CaseRemovalService Removal(TestDatabase database, ICurrentUser? user = null) =>
        new(database.Factory(), user ?? _admin, _clock, new CaseContentPurger(), _retention, _store, _store);

    private CaseService Cases(TestDatabase database) =>
        new(database.Factory(), _admin, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(), new TestSlaTargets());

    private sealed record Seeded(Guid Bad, string BadNumber, Guid Other);

    /// <summary>Two cases of 2026: 01 (kept) and 02, the bad import, archived, with an IOC, an attack step, a file, a link
    /// to case 01 and one from it.</summary>
    private async Task<Seeded> SeedAsync(TestDatabase database, bool archive = true)
    {
        await using var db = database.NewContext();
        var now = _clock.UtcNow;
        var other = Case.Open(2026, 1, "Kept", "A real case", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", now.AddDays(-3));
        var bad = Case.Open(2026, 2, "Bad_Import", "Imported twice", Classification.Incident, Severity.Low, CaseOrigin.InternalDetection, "ic1", now.AddDays(-2));
        bad.Entities.Add(new CaseEntity { Id = Guid.NewGuid(), CaseId = bad.Id, Type = EntityType.IpAddress, Value = "203.0.113.250",
            Disposition = EntityDisposition.Malicious, CreatedAtUtc = now, CreatedBy = "ic1" });
        bad.AddEventStep(now.AddDays(-2), [MitreTactic.InitialAccess], null, null, null, "Phish opened", null, "ic1", now);
        bad.Evidence.Add(new Evidence { CaseId = bad.Id, OriginalFileName = "dupe.eml", Sha256 = new string('b', 64), StoragePath = "bad/dupe.eml",
            CreatedBy = "ic1", CreatedAtUtc = now });
        db.Cases.AddRange(other, bad);
        db.CaseLinks.Add(new CaseLink { CaseId = other.Id, RelatedCaseId = bad.Id, Type = CaseLinkType.RelatedTo });
        db.CaseLinks.Add(new CaseLink { CaseId = bad.Id, RelatedCaseId = other.Id, Type = CaseLinkType.RelatedTo });
        if (archive) bad.Archive("ic1", now);
        await db.SaveChangesAsync();
        return new Seeded(bad.Id, bad.CaseNumber, other.Id);
    }

    /// <summary>BUG-700: removing and restoring a case with data elements hashes it with them, so the record check still
    /// verifies (it loads them, and was reporting a tamper).</summary>
    [Theory, MemberData(nameof(Providers))]
    public async Task Removing_and_restoring_a_case_with_data_elements_keeps_the_record_check_clean(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database, archive: false);
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.Include(x => x.DataElements).SingleAsync(x => x.Id == s.Bad);
            c.SetImpactAssessment(2, ["SSN", "DL"], null, "ic1", _clock.UtcNow);
            c.Archive("ic1", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        var removal = Removal(database);

        await removal.RemoveAsync(s.Bad, s.BadNumber, "Imported twice");
        await Verify();
        await removal.RestoreAsync(s.Bad);
        await Verify();

        async Task Verify()
        {
            await using var db = database.NewContext();
            var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
            (await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain)).Should().BeNull();
        }
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task Only_an_archived_case_confirmed_by_its_number_with_a_reason_and_no_hold_is_removed(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database, archive: false);
        var removal = Removal(database);

        await removal.Invoking(r => r.RemoveAsync(s.Bad, s.BadNumber, "Imported twice")).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*archived*");
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.SingleAsync(x => x.Id == s.Bad);
            c.Archive("ic1", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        await removal.Invoking(r => r.RemoveAsync(s.Bad, "2026-02", "Imported twice")).Should()
            .ThrowAsync<ArgumentException>().WithMessage("*Type the case number*");
        await removal.Invoking(r => r.RemoveAsync(s.Bad, s.BadNumber, "  ")).Should()
            .ThrowAsync<ArgumentException>().WithMessage("*why*");
        var analyst = new TestCurrentUser { UserId = "a1", RoleSet = [AppRole.Analyst] };
        await Removal(database, analyst).Invoking(r => r.RemoveAsync(s.Bad, s.BadNumber, "Imported twice")).Should()
            .ThrowAsync<ForbiddenException>();
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.SingleAsync(x => x.Id == s.Bad);
            c.LegalHold = true;
            await db.SaveChangesAsync();
        }
        await removal.Invoking(r => r.RemoveAsync(s.Bad, s.BadNumber, "Imported twice")).Should()
            .ThrowAsync<InvalidOperationException>().WithMessage("*legal hold*");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_removed_case_is_left_out_of_everything_keeps_its_number_and_can_be_restored(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        await Removal(database).RemoveAsync(s.Bad, s.BadNumber.ToLowerInvariant(), "Imported twice");

        await using (var db = database.NewContext())
        {
            (await db.Cases.Select(c => c.Id).ToListAsync()).Should().Equal(s.Other);
            (await db.CaseEntities.AnyAsync(e => e.Value == "203.0.113.250")).Should().BeFalse("its IOCs match nothing");
            (await db.TimelineEntries.AnyAsync(t => t.CaseId == s.Bad)).Should().BeFalse();
            (await db.Evidence.AnyAsync(e => e.CaseId == s.Bad)).Should().BeFalse();
            (await db.CaseLinks.AnyAsync()).Should().BeFalse("a link to or from it leads nowhere now");
            (await db.Cases.IgnoreQueryFilters().SingleAsync(c => c.Id == s.Bad)).RemovedReason.Should().Be("Imported twice");
        }
        var cases = Cases(database);
        (await cases.FindIdByNumberAsync(s.BadNumber)).Should().BeNull("a lookup by its number finds nothing");
        (await cases.IsCaseNumberAvailableAsync(s.BadNumber)).Should().BeFalse("it holds its number until it's purged");
        (await new CaseNumberGenerator(database.NewContext()).NextSequenceAsync(2026)).Should().Be(3);

        var listed = (await Removal(database).ListAsync()).Should().ContainSingle().Subject;
        listed.Number.Should().Be(s.BadNumber);
        listed.RestorableUntilUtc.Should().Be(_clock.UtcNow.AddDays(30));

        await Removal(database).RestoreAsync(s.Bad);
        await using (var db = database.NewContext())
        {
            (await db.Cases.CountAsync()).Should().Be(2);
            (await db.CaseEntities.AnyAsync(e => e.Value == "203.0.113.250")).Should().BeTrue();
            (await db.CaseLinks.CountAsync()).Should().Be(2);
            (await db.Cases.SingleAsync(c => c.Id == s.Bad)).IsArchived.Should().BeTrue("it comes back as it was");
        }
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_purge_leaves_a_stub_that_verifies_keeps_custody_and_frees_the_number(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        var removal = Removal(database);
        await removal.RemoveAsync(s.Bad, s.BadNumber, "Imported twice");

        await removal.Invoking(r => r.PurgeNowAsync(s.Bad, "nope")).Should().ThrowAsync<ArgumentException>();
        (await removal.PurgeNowAsync(s.Bad, s.BadNumber)).Should().BeNull("both stores took the deletes");

        await using (var db = database.NewContext())
        {
            var stub = await db.Cases.IgnoreQueryFilters().SingleAsync(c => c.Id == s.Bad);
            stub.CaseNumber.Should().Be($"REMOVED-{s.Bad:N}");
            stub.Title.Should().Be("Removed case");
            stub.RemovedNumber.Should().Be(s.BadNumber);
            stub.PurgedAtUtc.Should().Be(_clock.UtcNow);
            (await db.CaseEntities.IgnoreQueryFilters().AnyAsync(e => e.CaseId == s.Bad)).Should().BeFalse();
            (await db.TimelineEntries.IgnoreQueryFilters().AnyAsync(e => e.CaseId == s.Bad)).Should().BeFalse();
            (await db.CaseLinks.IgnoreQueryFilters().AnyAsync()).Should().BeFalse("links both ways go with it");
            var file = await db.Evidence.IgnoreQueryFilters().Include(e => e.CustodyEvents).SingleAsync(e => e.CaseId == s.Bad);
            file.PurgedAtUtc.Should().NotBeNull("the record stays, its bytes gone");
            file.CustodyEvents.Select(c => c.Action).Should().Contain([Evidence.WithdrawnAction, Evidence.PurgedAction]);
            var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
            (await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain)).Should().BeNull("the purge is in the trail, row by row");
            (await db.AuditLog.HeldNow(db).AnyAsync(a => a.CaseNumber == s.BadNumber))
                .Should().BeFalse("what was written under the number is the removed case's, not its next holder's");
            (await db.AuditLog.AnyAsync(a => a.CaseNumber == s.BadNumber)).Should().BeTrue("the trail itself keeps it");
        }
        _store.Purged.Should().Equal("bad/dupe.eml");
        (await Cases(database).IsCaseNumberAvailableAsync(s.BadNumber)).Should().BeTrue("the number is free again");
        (await new CaseNumberGenerator(database.NewContext()).NextSequenceAsync(2026)).Should().Be(2, "the next case takes it back");
        await removal.Invoking(r => r.RestoreAsync(s.Bad)).Should().ThrowAsync<InvalidOperationException>().WithMessage("*purged*");
        (await removal.ListAsync()).Should().ContainSingle().Which.Title.Should().BeNull("a purged case keeps no title");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task The_nightly_purge_waits_out_the_undo_window_and_a_legal_hold(string provider)
    {
        using var database = Open(provider);
        var s = await SeedAsync(database);
        await Removal(database).RemoveAsync(s.Bad, s.BadNumber, "Imported twice");

        _clock.UtcNow = _clock.UtcNow.AddDays(29);
        (await Removal(database).PurgeDueAsync()).Should().Be(0, "still in its undo window");
        _clock.UtcNow = _clock.UtcNow.AddDays(2);
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.IgnoreQueryFilters().SingleAsync(x => x.Id == s.Bad);
            c.LegalHold = true;
            await db.SaveChangesAsync();
        }
        (await Removal(database).PurgeDueAsync()).Should().Be(0, "nothing under a legal hold is purged");
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.IgnoreQueryFilters().SingleAsync(x => x.Id == s.Bad);
            c.LegalHold = false;
            await db.SaveChangesAsync();
        }
        (await Removal(database).PurgeDueAsync()).Should().Be(1);
        await using (var check = database.NewContext())
            (await check.Cases.IgnoreQueryFilters().SingleAsync(x => x.Id == s.Bad)).IsPurged.Should().BeTrue();
    }
}
