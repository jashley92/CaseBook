using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Integrity;
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
/// End-to-end proof that the audit trail says <em>what</em> changed, not just that "something" did: a case
/// mutation is written through the real <see cref="AuditChainInterceptor"/>, then the resulting audit entry
/// is read back and its enriched summary + parsed field diff are asserted. Covers the "setting a legal hold
/// only logged 'update case'" gap.
/// </summary>
public sealed class AuditChangeVerbosityTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };

    public AuditChangeVerbosityTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
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


    [Fact]
    public async Task Bulk_assign_leaves_a_case_the_person_is_already_on_as_it_is(/* REV-26 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Lead", Title = "Lead case", Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });
        await svc.AssignAsync(c.Id, "dana", "Dana", CaseAssignmentRole.IncidentCommander);

        (await svc.AddAssigneeAsync(c.Id, "dana", "Dana", CaseAssignmentRole.Analyst)).Should().BeFalse();
        (await svc.AddAssigneeAsync(c.Id, "sam", "Sam", CaseAssignmentRole.Analyst)).Should().BeTrue();

        var detail = (await svc.GetDetailAsync(c.Id))!;
        detail.IncidentCommander.Should().Be("dana", "the bulk assign didn't demote the incident commander");
        detail.Assignments.Should().Contain(a => a.UserId == "sam" && a.Role == CaseAssignmentRole.Analyst);
    }

    [Fact]
    public async Task Rebalancing_passes_an_incident_commanders_seat_and_never_demotes_one(/* BUG-306 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        async Task<Guid> Open(string name) => (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = name, Title = name, Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        })).Id;
        var led = await Open("Led");
        await svc.AssignAsync(led, "alice", "Alice", CaseAssignmentRole.IncidentCommander);
        var worked = await Open("Worked");
        await svc.AssignAsync(worked, "alice", "Alice", CaseAssignmentRole.Analyst);
        await svc.AssignAsync(worked, "bob", "Bob", CaseAssignmentRole.IncidentCommander);

        // Alice's queue to Bob, as analysts: Bob takes the seat Alice leaves, and keeps the one he has.
        (await svc.ReassignAsync(led, "alice", "bob", "Bob", CaseAssignmentRole.Analyst)).Should().BeTrue();
        (await svc.ReassignAsync(worked, "alice", "bob", "Bob", CaseAssignmentRole.Analyst)).Should().BeTrue();

        foreach (var id in new[] { led, worked })
        {
            var d = (await svc.GetDetailAsync(id))!;
            d.IncidentCommander.Should().Be("bob");
            d.Assignments.Should().NotContain(a => a.UserId == "alice");
        }
    }

    [Fact]
    public async Task Rebalancing_onto_an_observer_puts_them_to_work_on_the_case(/* BUG-405 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var id = (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Watched", Title = "Watched", Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        })).Id;
        await svc.AssignAsync(id, "dana", "Dana", CaseAssignmentRole.IncidentCommander);
        await svc.AssignAsync(id, "alice", "Alice", CaseAssignmentRole.Analyst);
        await svc.AssignAsync(id, "bob", "Bob", CaseAssignmentRole.Observer);

        (await svc.ReassignAsync(id, "alice", "bob", "Bob", CaseAssignmentRole.Analyst)).Should().BeTrue();

        var d = (await svc.GetDetailAsync(id))!;
        d.Assignments.Should().ContainSingle(a => a.UserId == "bob").Which.Role.Should().Be(CaseAssignmentRole.Analyst);
        d.Assignments.Should().NotContain(a => a.UserId == "alice");
        d.IncidentCommander.Should().Be("dana", "the incident commander keeps the seat");

        // Someone already working it keeps their role (BUG-306): moving Bob's queue to Dana leaves her commanding.
        (await svc.ReassignAsync(id, "bob", "dana", "Dana", CaseAssignmentRole.Analyst)).Should().BeTrue();
        (await svc.GetDetailAsync(id))!.IncidentCommander.Should().Be("dana");
    }

    [Fact]
    public async Task Placing_a_legal_hold_records_what_changed()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Hold", Title = "Hold case",
            Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });

        await svc.SetLegalHoldAsync(c.Id, held: true);

        // The audit line for the hold: the most recent in-place update to the Case row.
        await using var read = NewContext();
        var entry = await read.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == "Case" && a.Action == AuditAction.Update)
            .OrderByDescending(a => a.Sequence)
            .FirstAsync();

        // (3) The stored summary now names the field, instead of a bare "Update Case".
        entry.Summary.Should().Be("Update Case — Legal hold");

        // (1) The captured before/after parses into a readable field diff.
        var changes = AuditChangeDetail.Changes(entry);
        changes.Should().ContainSingle();
        changes[0].Should().Be(new AuditChangeDetail.FieldChange("Legal hold", "No", "Yes"));
    }

    [Fact]
    public async Task A_pure_touch_is_not_audited_as_a_case_update()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Touch", Title = "Touch case",
            Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });

        // Assigning adds a CaseAssignment and only "touches" the case (bumps ModifiedAtUtc/ModifiedBy).
        await svc.AssignAsync(c.Id, "analyst-2", "Second Analyst", CaseAssignmentRole.Analyst);

        await using var read = NewContext();

        // The substantive action is audited...
        (await read.AuditLog.AsNoTracking()
            .AnyAsync(a => a.EntityType == "CaseAssignment" && a.Action == AuditAction.Create))
            .Should().BeTrue();

        // ...but the parent-case touch it triggered is not logged as a no-op "Update Case".
        (await read.AuditLog.AsNoTracking()
            .CountAsync(a => a.EntityType == "Case" && a.Action == AuditAction.Update))
            .Should().Be(0);
    }

    [Fact]
    public async Task Referring_to_legal_shows_the_change_on_the_case_line()
    {
        await using var db = NewContext();
        var svc = NewService(db);

        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Referral", Title = "Referral case",
            Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });

        // A referral changes an owned value object (LegalReferral), which shares the case row.
        await svc.ReferToLegalAsync(c.Id, "General Counsel", "NY NPI involved");

        await using var read = NewContext();
        var entry = await read.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == "Case" && a.Action == AuditAction.Update)
            .OrderByDescending(a => a.Sequence)
            .FirstAsync();

        // The owned-VO change is folded into the case entry's diff (previously this was an empty "Update Case").
        entry.Summary.Should().Be("Update Case — Legal referral");
        AuditChangeDetail.Changes(entry).Should()
            .Contain(x => x.Label == "Referred to Legal" && x.Before == "No" && x.After == "Yes");
    }

    [Fact]
    public async Task Re_recording_materiality_and_editing_a_referral_audit_the_real_before_values(/* BUG-333 */)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Rerecord", Title = "Rerecord case",
            Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.InternalDetection
        });

        async Task<IncidentManager.Domain.Entities.AuditLogEntry> LastCaseUpdate()
        {
            await using var read = NewContext();
            return await read.AuditLog.AsNoTracking()
                .Where(a => a.EntityType == "Case" && a.Action == AuditAction.Update)
                .OrderByDescending(a => a.Sequence).FirstAsync();
        }
        static Dictionary<string, System.Text.Json.JsonElement> Parse(string? json) =>
            System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(json!)!;

        // Materiality: Under review, then re-recorded as Material. The second line's before is Under review with its
        // rationale, not the type's defaults, and only what moved is listed.
        await svc.RecordMaterialityAsync(c.Id, MaterialityStatus.UnderReview, null, null, "With counsel");
        var first = await LastCaseUpdate();
        AuditChangeDetail.Changes(first).Should().Contain(new AuditChangeDetail.FieldChange("Materiality", "Undetermined", "Under review"));

        _clock.UtcNow = _clock.UtcNow.AddMinutes(5);   // a later save, as in use (the touch moves the case row)
        await svc.RecordMaterialityAsync(c.Id, MaterialityStatus.Material, "General Counsel", _clock.UtcNow, "With counsel");
        var second = await LastCaseUpdate();
        second.Summary.Should().Be("Update Case — Materiality");
        var before = Parse(second.BeforeJson);
        before["Materiality.Status"].GetInt32().Should().Be((int)MaterialityStatus.UnderReview);
        before.Should().NotContainKey("Materiality.Rationale", "the rationale didn't change");
        Parse(second.AfterJson).Should().NotContainKey("Materiality.Rationale");
        AuditChangeDetail.Changes(second).Should().BeEquivalentTo(new[]
        {
            new AuditChangeDetail.FieldChange("Materiality", "Under review", "Material"),
            new AuditChangeDetail.FieldChange("Materiality decision-maker", "—", "General Counsel"),
            new AuditChangeDetail.FieldChange("Materiality decision date", "—", AuditChangeDetail.Changes(second)
                .Single(x => x.Label == "Materiality decision date").After),
        });

        // Legal referral: referred, then only the contact edited. Before is "referred, old contact"; IsReferred and the
        // note aren't listed as changed.
        await svc.ReferToLegalAsync(c.Id, "General Counsel", "NY NPI involved");
        _clock.UtcNow = _clock.UtcNow.AddMinutes(5);
        await svc.ReferToLegalAsync(c.Id, "Privacy Office", "NY NPI involved");
        var edit = await LastCaseUpdate();
        edit.Summary.Should().Be("Update Case — Legal referral");
        var b = Parse(edit.BeforeJson);
        b["LegalReferral.ReferredToContact"].GetString().Should().Be("General Counsel");
        b.Should().NotContainKey("LegalReferral.IsReferred");
        b.Should().NotContainKey("LegalReferral.RegulatoryRelevanceNote");
        AuditChangeDetail.Changes(edit).Should().ContainSingle()
            .Which.Should().Be(new AuditChangeDetail.FieldChange("Legal contact", "General Counsel", "Privacy Office"));

        // The chain still verifies.
        await using var check = NewContext();
        var entries = await check.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(entries).IsValid.Should().BeTrue();
    }

    [Fact]
    public void A_reference_guid_in_a_diff_resolves_to_its_label()
    {
        var actorId = Guid.NewGuid();
        var entry = new IncidentManager.Domain.Entities.AuditLogEntry
        {
            Action = AuditAction.Update,
            EntityType = "TimelineEntry",
            BeforeJson = "{\"ActorEntityId\":null}",
            AfterJson = $"{{\"ActorEntityId\":\"{actorId}\"}}",
        };

        // No resolver: the field is named, but the value is the raw GUID.
        var raw = AuditChangeDetail.Changes(entry).Single();
        raw.Label.Should().Be("Actor");
        raw.After.Should().Be(actorId.ToString());

        // With a resolver: the GUID renders as the IOC's label.
        var resolved = AuditChangeDetail.Changes(entry,
            id => id == actorId.ToString() ? "203.0.113.66" : null).Single();
        resolved.Label.Should().Be("Actor");
        resolved.Before.Should().Be("—");
        resolved.After.Should().Be("203.0.113.66");
    }

    [Fact]
    public async Task A_cases_create_and_delete_lines_carry_its_vendor_details(/* BUG-392 */)
    {
        await using var db = NewContext();
        var c = await NewService(db).CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Vendor", Title = "Vendor breach", Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.ThirdParty, VendorName = "Acme Hosting", VendorReference = "INC-42",
        });
        static Dictionary<string, System.Text.Json.JsonElement> Parse(string? json) =>
            System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(json!)!;

        await using (var read = NewContext())
        {
            var create = await read.AuditLog.AsNoTracking()
                .SingleAsync(a => a.EntityType == "Case" && a.Action == AuditAction.Create && a.EntityId == c.Id.ToString());
            var after = Parse(create.AfterJson);
            after["ThirdParty.VendorName"].GetString().Should().Be("Acme Hosting");
            after["ThirdParty.VendorReference"].GetString().Should().Be("INC-42");
            after.Should().ContainKey("Materiality.Status");
        }

        await using (var del = NewContext())
        {
            del.Cases.Remove(await del.Cases.SingleAsync(x => x.Id == c.Id));
            await del.SaveChangesAsync();
        }
        await using var check = NewContext();
        var delete = await check.AuditLog.AsNoTracking()
            .SingleAsync(a => a.EntityType == "Case" && a.Action == AuditAction.Delete && a.EntityId == c.Id.ToString());
        Parse(delete.BeforeJson)["ThirdParty.VendorName"].GetString().Should().Be("Acme Hosting");
        _hasher.VerifyChain(await check.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task Changing_only_an_owned_value_still_audits_and_rehashes_the_case(/* BUG-392 */)
    {
        await using var db = NewContext();
        var c = await NewService(db).CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Vendor2", Title = "Vendor case", Classification = Classification.Incident, Severity = Severity.Medium,
            Origin = CaseOrigin.ThirdParty, VendorName = "Acme Hosting",
        });

        await using (var edit = NewContext())
        {
            var tracked = await edit.Cases.SingleAsync(x => x.Id == c.Id);
            tracked.ThirdParty!.VendorContact = "soc@acme.example";   // only the owned value; no touch on the case row
            await edit.SaveChangesAsync();
        }

        await using var check = NewContext();
        var update = await check.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == "Case" && a.Action == AuditAction.Update && a.EntityId == c.Id.ToString())
            .OrderByDescending(a => a.Sequence).FirstOrDefaultAsync();
        update.Should().NotBeNull("the change to the vendor contact is a change to the case");
        update!.AfterJson.Should().Contain("ThirdParty.VendorContact");
        var stored = await check.Cases.AsNoTracking().SingleAsync(x => x.Id == c.Id);
        stored.RowHash.Should().Be(_hasher.ComputeRowHash(stored), "the case's row hash covers its vendor details");
    }

    public void Dispose() => _connection.Dispose();
}
