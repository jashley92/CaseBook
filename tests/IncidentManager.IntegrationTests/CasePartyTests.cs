using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Reporting;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-34: outside parties on a case (counsel, forensics, the insurer, law enforcement) with their references. Recorded,
/// edited and removed through the audited writes, hashed from the first row, refused when stale, held to the case's
/// need-to-know, and printed in the report's legal lines, the <c>party.*</c> template fields and the legal register. Runs
/// on SQLite always and on SQL Server when <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class CasePartyTests : IDisposable
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 15, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.SysAdmin] };
    private readonly string _reportDir = Path.Combine(Path.GetTempPath(), "im-party-tests", Guid.NewGuid().ToString("N"));

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private CaseService NewService(TestDatabase database, TestCurrentUser? user = null) =>
        new(database.Factory(), user ?? _user, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private async Task<Guid> NewCaseAsync(CaseService svc, string name = "Party") =>
        (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = name, Title = $"{name} breach", Classification = Classification.Breach, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-2),
        })).Id;

    private static async Task<List<CaseParty>> PartiesAsync(TestDatabase database, Guid caseId)
    {
        await using var db = database.NewContext();
        return await db.CaseParties.AsNoTracking().Where(p => p.CaseId == caseId).ToListAsync();
    }

    private static PartyDetails Counsel(string reference = "MAT-2026-114") =>
        new(PartyRole.Counsel, "  Lee & Park LLP ", "Dana Lee | 555-0100", reference, null, "Engaged under the breach retainer.");

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_party_round_trips_hashed_and_audited_and_is_edited_and_removed(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        var engaged = _clock.UtcNow.AddHours(-20);

        var partyId = await svc.AddPartyAsync(id, Counsel() with { EngagedAtUtc = engaged });
        var p = (await PartiesAsync(database, id)).Single();
        (p.Id, p.Role, p.Name, p.Contact, p.Reference, p.EngagedAtUtc, p.Notes, p.CreatedBy)
            .Should().Be((partyId, PartyRole.Counsel, "Lee & Park LLP", "Dana Lee | 555-0100", "MAT-2026-114", engaged,
                "Engaged under the breach retainer.", "ic1"));
        p.RowHash.Should().StartWith(Canonical.PrefixOf(Canonical.CurrentFormat));
        _hasher.RowHashMatches(p, p.RowHash!).Should().BeTrue();
        (await svc.GetDetailAsync(id))!.Parties.Should().ContainSingle(x => x.Id == partyId);

        _clock.UtcNow = _clock.UtcNow.AddMinutes(5);
        (await svc.UpdatePartyAsync(id, partyId, new PartyDetails(PartyRole.Insurer, "Acme Mutual", null, "CLM-2207", engaged), p.RowHash))
            .Should().BeTrue();
        var edited = (await PartiesAsync(database, id)).Single();
        (edited.Role, edited.Name, edited.Contact, edited.Reference, edited.Notes).Should().Be((PartyRole.Insurer, "Acme Mutual", (string?)null, "CLM-2207", (string?)null));
        edited.CreatedAtUtc.Should().Be(p.CreatedAtUtc);
        (await svc.UpdatePartyAsync(id, partyId, new PartyDetails(PartyRole.Insurer, "Acme Mutual", " ", "CLM-2207", engaged)))
            .Should().BeFalse("nothing changed");

        await svc.RemovePartyAsync(id, partyId, edited.RowHash);
        (await PartiesAsync(database, id)).Should().BeEmpty();
        await svc.RemovePartyAsync(id, partyId);   // a second remove finds nothing and says nothing

        await using var db = database.NewContext();
        var entries = await db.AuditLog.AsNoTracking().Where(a => a.EntityType == nameof(CaseParty)).OrderBy(a => a.Sequence).ToListAsync();
        entries.Select(e => e.Action).Should().Equal(AuditAction.Create, AuditAction.Update, AuditAction.Delete);
        entries[0].AfterJson.Should().Contain("MAT-2026-114");
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        (await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain)).Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_party_changed_or_planted_in_the_database_is_caught(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        var partyId = await svc.AddPartyAsync(id, Counsel());

        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            var row = await raw.CaseParties.SingleAsync(x => x.Id == partyId);
            row.Reference = "MAT-0000";   // a reference rewritten outside CaseBook
            await raw.SaveChangesAsync();
        }
        await using (var db = database.NewContext())
        {
            var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
            var bad = await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain);
            bad.Should().NotBeNull();
            (bad!.EntityType, bad.Id).Should().Be((nameof(CaseParty), partyId));
        }

        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            raw.CaseParties.Single(x => x.Id == partyId).Reference = "MAT-2026-114";   // put back
            raw.CaseParties.Add(new CaseParty { CaseId = id, Role = PartyRole.Forensics, Name = "Planted", CreatedBy = "x", CreatedAtUtc = _clock.UtcNow });
            await raw.SaveChangesAsync();
        }
        await using (var db = database.NewContext())
        {
            var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
            var bad = await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain);
            bad!.EntityType.Should().Be(nameof(CaseParty));
            bad.Detail.Should().Contain("has no hash", "every party has had one from the first row");
        }
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task What_a_party_record_takes_is_checked(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);

        await svc.Invoking(s => s.AddPartyAsync(id, new PartyDetails(PartyRole.Counsel, "  ")))
            .Should().ThrowAsync<ArgumentException>().WithMessage("Name the party*");
        await svc.Invoking(s => s.AddPartyAsync(id, new PartyDetails((PartyRole)42, "Someone")))
            .Should().ThrowAsync<ArgumentException>().WithMessage("Choose the party's role*");
        await svc.Invoking(s => s.AddPartyAsync(id, new PartyDetails(PartyRole.Other, "Someone", Reference: new string('r', CaseParty.MaxReferenceLength + 1))))
            .Should().ThrowAsync<ArgumentException>();
        await svc.Invoking(s => s.AddPartyAsync(id, new PartyDetails(PartyRole.LawEnforcement, "FBI IC3", EngagedAtUtc: _clock.UtcNow.AddHours(2))))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*can't be in the future*");
        await svc.Invoking(s => s.UpdatePartyAsync(id, Guid.NewGuid(), Counsel()))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("That party isn't on this case*");
        (await PartiesAsync(database, id)).Should().BeEmpty();

        // The role is read by name only (C16): "3" isn't LawEnforcement.
        EnumNames.TryParse<PartyRole>("3", out _).Should().BeFalse();
        EnumNames.TryParse<PartyRole>("LawEnforcement", out var le).Should().BeTrue();
        le.Should().Be(PartyRole.LawEnforcement);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_stale_edit_or_removal_is_refused_and_a_deliberate_second_save_lands(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        var partyId = await svc.AddPartyAsync(id, Counsel());
        var opened = (await PartiesAsync(database, id)).Single().RowHash!;

        // A colleague corrects the reference first; the form opened before it is refused, and told what's there now.
        await svc.UpdatePartyAsync(id, partyId, Counsel("MAT-2026-115"), opened);
        var ex = await Assert.ThrowsAsync<StaleEditException>(() => svc.UpdatePartyAsync(id, partyId, Counsel("MAT-9"), opened));
        ex.CurrentStamp.Should().Be((await PartiesAsync(database, id)).Single().RowHash);
        (await PartiesAsync(database, id)).Single().Reference.Should().Be("MAT-2026-115");
        await Assert.ThrowsAsync<StaleEditException>(() => svc.RemovePartyAsync(id, partyId, opened));
        (await PartiesAsync(database, id)).Should().ContainSingle("a stale page doesn't remove what a colleague just corrected");

        (await svc.UpdatePartyAsync(id, partyId, Counsel("MAT-9"), ex.CurrentStamp)).Should().BeTrue();
        (await PartiesAsync(database, id)).Single().Reference.Should().Be("MAT-9");

        // Removed meanwhile: refused as stale, not recreated.
        var stamp = (await PartiesAsync(database, id)).Single().RowHash!;
        await svc.RemovePartyAsync(id, partyId, stamp);
        (await Assert.ThrowsAsync<StaleEditException>(() => svc.UpdatePartyAsync(id, partyId, Counsel(), stamp)))
            .Message.Should().Contain("removed");
        (await PartiesAsync(database, id)).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_restricted_cases_parties_are_out_of_reach_without_need_to_know(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        var partyId = await svc.AddPartyAsync(id, Counsel());
        await svc.SetRestrictedAsync(id, true, "Insider matter");

        var outsider = NewService(database, new TestCurrentUser { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] });
        await outsider.Invoking(s => s.AddPartyAsync(id, Counsel()))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("Case not found or not accessible.");
        await outsider.Invoking(s => s.UpdatePartyAsync(id, partyId, Counsel("X-1")))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("Case not found or not accessible.");
        await outsider.Invoking(s => s.RemovePartyAsync(id, partyId))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("Case not found or not accessible.");
        (await outsider.GetDetailAsync(id)).Should().BeNull();
        (await PartiesAsync(database, id)).Single().Reference.Should().Be("MAT-2026-114");

        // A read-only role can't write one on a case it can see.
        var viewer = NewService(database, new TestCurrentUser { UserId = "ic1", PermissionSet = [Permission.ViewCases, Permission.ViewAllCases, Permission.ViewRestricted] });
        await viewer.Invoking(s => s.AddPartyAsync(id, Counsel())).Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();

        // The legal register under the outsider leaves the case (and its parties) out.
        var register = Register(database, new TestCurrentUser { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] });
        (await register.BuildAsync()).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Parties_reach_the_report_its_template_fields_and_the_legal_register(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var id = await NewCaseAsync(svc);
        var engaged = _clock.UtcNow.AddHours(-30);
        await svc.AddPartyAsync(id, new PartyDetails(PartyRole.LawEnforcement, "FBI IC3", null, "I-2026-5521", engaged.AddHours(5)));
        await svc.AddPartyAsync(id, Counsel() with { EngagedAtUtc = engaged });

        // The report prints them with the legal lines (Business Impact here), facts only: the notes stay out.
        var model = await NewReportService(database).BuildPreviewModelAsync(id, null);
        model.Parties.Select(x => x.Name).Should().Equal("Lee & Park LLP", "FBI IC3");
        model.BusinessImpactLines.Should().Contain(
                $"Outside counsel: Lee & Park LLP (contact Dana Lee | 555-0100), reference MAT-2026-114, engaged {engaged.UtcDateTime:yyyy-MM-dd HH:mm} UTC.")
            .And.Contain($"Law enforcement: FBI IC3, reference I-2026-5521, engaged {engaged.AddHours(5).UtcDateTime:yyyy-MM-dd HH:mm} UTC.");
        string.Join("\n", model.BusinessImpactLines).Should().NotContain("retainer", "a party's notes aren't in the built-in report (ADR 0012)");
        (model with { Sections = [ReportSection.Summary] }).FactsLines.Should().Contain(l => l.StartsWith("Outside counsel: Lee & Park LLP", StringComparison.Ordinal),
            "without Business Impact the facts carry them");
        model.FactsLines.Should().ContainSingle().Which.Should().Be("Outside parties: see Business Impact.");

        // The party.* template fields.
        ReportTemplateFields.CollectionFor("party.reference").Should().Be("party");
        foreach (var f in new[] { "party.role", "party.name", "party.contact", "party.reference", "party.engaged", "party.notes" })
            ReportTemplateFields.IsKnown(f).Should().BeTrue(f);
        var counsel = ReportTemplateFields.Items(model, "party")[0];
        (counsel("party.role"), counsel("party.name"), counsel("party.contact"), counsel("party.reference"), counsel("party.notes"))
            .Should().Be(("Outside counsel", "Lee & Park LLP", "Dana Lee | 555-0100", "MAT-2026-114", "Engaged under the breach retainer."));
        counsel("party.engaged").Should().Be($"{engaged.UtcDateTime:yyyy-MM-dd HH:mm} UTC");
        ReportTemplateFields.Items(model, "party")[1]("party.contact").Should().BeEmpty();

        // The legal register's outside parties column (a Breach is on the register).
        var row = (await Register(database, _user).BuildAsync()).Single();
        row.OutsideParties.Should().Be("Outside counsel: Lee & Park LLP (MAT-2026-114); Law enforcement: FBI IC3 (I-2026-5521)");
        var csv = LegalRegisterService.ToCsv([row], _clock.UtcNow);
        csv.Should().Contain(",notice_references,outside_parties,notification_status\r\n")   // CAP-38: the last column now
            .And.Contain(",,Outside counsel: Lee & Park LLP (MAT-2026-114); Law enforcement: FBI IC3 (I-2026-5521),\r\n");
    }

    private LegalRegisterService Register(TestDatabase database, TestCurrentUser user) =>
        new(database.Factory(), user,
            new NotificationDeadlineService(database.Factory(), new OffSettings(), new IncidentManager.Application.Admin.NotificationRuleService(database.Factory(), user, _clock), _clock),
            new StubUserDirectory());

    private ReportService NewReportService(TestDatabase database) =>
        new(database.Factory(), new ReportGenerator(),
            new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _reportDir })), _hasher, _user, _clock,
            new IncidentManager.Application.Content.MarkdownService(), new TestOptionsMonitor<ReportingOptions>(new ReportingOptions()),
            new FileReportBrandingStore(Options.Create(new ReportBrandingOptions { RootPath = Path.Combine(_reportDir, "branding") })),
            new StubUserDirectory(),
            new IncidentManager.Infrastructure.Severities.ConfigurationSeverityLabels(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build()));

    private sealed class OffSettings : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current => NotificationDeadlineSettings.Off;
    }

    private sealed class StubUserDirectory : IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => [];
        public UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_reportDir)) Directory.Delete(_reportDir, recursive: true); }
        catch (IOException) { /* best effort */ }
    }
}
