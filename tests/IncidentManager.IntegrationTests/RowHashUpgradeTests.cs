using System.Reflection;
using System.Text.Json.Nodes;
using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Common;
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
/// C18: the start-up upgrade (RowHashUpgrade) and the strict record check it switches on. Before it, a row planted in
/// the database with no hash and no trail entry passed in most tables (BUG-620), a migration's cleared hashes excused a
/// whole table (BUG-621), a row last updated before v1.5.1 could be rewritten with its hash recomputed (BUG-629), and a
/// hash in an older format didn't cover values format 4 brought in. The upgrade records the hash of every row that
/// agrees with its trail (or holds what a migration wrote), leaves the rest for the check to report, and marks the check
/// strict; a failure leaves the check as it was. Several tests rewrite audit entries to look as an older release wrote
/// them, so they check the records, not the chain's links.
/// </summary>
public sealed class RowHashUpgradeTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Seeded(string provider)
    {
        var database = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        using var db = database.NewContext();
        // The reference data a first start seeds, then the sample cases.
        DevDataSeeder.SeedStarterTemplatesAsync(db, _clock).GetAwaiter().GetResult();
        DevDataSeeder.SeedDefaultStageGatesAsync(db, _clock).GetAwaiter().GetResult();
        DevDataSeeder.SeedDefaultReportProfilesAsync(db, _clock).GetAwaiter().GetResult();
        DevDataSeeder.SeedDataElementsAsync(db, _clock).GetAwaiter().GetResult();
        DevDataSeeder.SeedCaseOutcomesAsync(db, _clock).GetAwaiter().GetResult();
        DevDataSeeder.SeedNotificationRulesAsync(db, _clock).GetAwaiter().GetResult();
        DevDataSeeder.SeedAsync(db, _clock).GetAwaiter().GetResult();
        DevDataSeeder.SeedHistoricalDemoAsync(db, _clock).GetAwaiter().GetResult();
        return database;
    }

    private async Task<RowIntegrityVerifier.RowMismatch?> VerifyRecordsAsync(TestDatabase database)
    {
        await using var db = database.NewContext();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        return await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain);
    }

    private async Task<RowHashUpgrade.Result> UpgradeAsync(TestDatabase database)
    {
        await using var db = database.NewContext();
        return await RowHashUpgrade.RunAsync(db, _hasher, _clock);
    }

    // As an older release (or a migration) left a record's trail: the RowHash taken out of its entries.
    private static async Task UnrecordHashAsync(TestDatabase database, string type, Guid id, bool createToo = false)
    {
        await using var raw = new AppDbContext(database.OptionsWithoutInterceptors);
        var key = id.ToString();
        foreach (var entry in await raw.AuditLog.Where(a => a.EntityType == type && a.EntityId == key && a.AfterJson != null).ToListAsync())
        {
            if (entry.Action == AuditAction.Create && !createToo) continue;
            var after = JsonNode.Parse(entry.AfterJson!)!.AsObject();
            after.Remove(nameof(IHashableEntity.RowHash));
            entry.AfterJson = after.ToJsonString();
        }
        await raw.SaveChangesAsync();
    }

    // An entry appended to the chain as CaseBook would (its links intact), with a snapshot the interceptor can't write now.
    private async Task AppendAsync(TestDatabase database, AuditAction action, string type, Guid id, string? afterJson)
    {
        await using var db = new AppDbContext(database.OptionsWithoutInterceptors);
        var head = await db.AuditLog.AsNoTracking().OrderByDescending(a => a.Sequence).FirstOrDefaultAsync();
        var entry = new AuditLogEntry
        {
            AtUtc = _clock.UtcNow, Actor = "admin1", Action = action, EntityType = type, EntityId = id.ToString(), AfterJson = afterJson,
        };
        _hasher.ChainAppend(entry, head);
        db.AuditLog.Add(entry);
        await db.SaveChangesAsync();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task On_ordinary_data_the_upgrade_marks_the_check_strict_and_nothing_is_flagged(string provider)
    {
        using var database = Seeded(provider);
        var result = await UpgradeAsync(database);
        result.Marked.Should().BeTrue();
        result.Left.Should().BeEmpty("every record CaseBook wrote agrees with its trail");
        await using (var db = database.NewContext()) (await RowIntegrityVerifier.UpgradedAsync(db)).Should().BeTrue();
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull("no false alarm once strict");
        (await UpgradeAsync(database)).Should().Be(new RowHashUpgrade.Result(0, [], false), "once marked it does nothing");
    }

    public static TheoryData<string, string> EveryTable()
    {
        var rows = new TheoryData<string, string>();
        foreach (var provider in ((IEnumerable<object[]>)TestDatabase.Providers).Select(r => (string)r[0]))
            foreach (var type in typeof(Case).Assembly.GetTypes().Where(t => typeof(IHashableEntity).IsAssignableFrom(t) && !t.IsAbstract)
                         .OrderBy(t => t.Name, StringComparer.Ordinal))
                rows.Add(provider, type.Name);
        return rows;
    }

    [Theory]
    [MemberData(nameof(EveryTable))]
    public async Task A_row_planted_without_a_hash_or_a_trail_entry_is_flagged_in_every_table(string provider, string typeName /* BUG-620 */)
    {
        using var database = Seeded(provider);
        var type = typeof(Case).Assembly.GetTypes().Single(t => t.Name == typeName && typeof(IHashableEntity).IsAssignableFrom(t));
        Guid planted;
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors)) planted = await PlantAsync(raw, type);

        var result = await UpgradeAsync(database);
        result.Left.Should().ContainSingle().Which.Should().StartWith($"{typeName} {planted}", "a planted row isn't signed off");
        var bad = await VerifyRecordsAsync(database);
        bad.Should().NotBeNull($"a {typeName} with no hash and no trail entry was added outside CaseBook");
        bad!.Id.Should().Be(planted);
        bad.Detail.Should().Contain("has no hash");
    }

    // A row of the type, inserted without the interceptor: every value set, its foreign keys pointing at existing rows, the
    // values of its unique indexes new.
    private static async Task<Guid> PlantAsync(AppDbContext raw, Type type)
    {
        var et = raw.Model.FindEntityType(type)!;
        var row = (Entity)Activator.CreateInstance(type, nonPublic: true)!;
        var n = 0;
        foreach (var p in type.GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(p => p.GetSetMethod(true) is not null))
        {
            var u = Nullable.GetUnderlyingType(p.PropertyType) ?? p.PropertyType;
            object? v = u == typeof(string) ? $"p{Guid.NewGuid():N}"[..9]
                : u == typeof(bool) ? false
                : u == typeof(int) ? 900000 + ++n
                : u == typeof(long) ? 1L
                : u == typeof(DateTimeOffset) ? new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero)
                : u.IsEnum ? Enum.GetValues(u).GetValue(0)
                : u == typeof(Guid) ? Guid.NewGuid()
                : u.Namespace == "IncidentManager.Domain.ValueObjects" && p.PropertyType.IsClass && et.FindNavigation(p.Name) is null
                  && et.FindOwnership() is null && !IsOptionalOwned(et, p.Name) ? Activator.CreateInstance(u, nonPublic: true)
                : p.GetValue(row);
            if (p.Name == nameof(IHashableEntity.RowHash)) v = null;
            p.GetSetMethod(true)!.Invoke(row, [v]);
        }
        foreach (var fk in et.GetForeignKeys().Where(f => !f.IsOwnership))
        {
            var principal = fk.PrincipalEntityType.ClrType;
            var ids = await ((IQueryable<Entity>)typeof(DbContext).GetMethod(nameof(DbContext.Set), Type.EmptyTypes)!
                .MakeGenericMethod(principal).Invoke(raw, null)!).Select(e => e.Id).ToListAsync();
            if (ids.Count == 0 && !fk.IsRequired)
            {
                fk.Properties[0].PropertyInfo!.SetValue(row, null);
                continue;
            }
            if (ids.Count == 0) throw new InvalidOperationException($"no {principal.Name} to point {type.Name} at");
            // A unique index on the key alone (one review per case): a parent without one.
            var used = fk.Properties.Count == 1 && et.GetIndexes().Any(i => i.IsUnique && i.Properties.SequenceEqual(fk.Properties))
                ? (await ((IQueryable<Entity>)typeof(DbContext).GetMethod(nameof(DbContext.Set), Type.EmptyTypes)!
                    .MakeGenericMethod(type).Invoke(raw, null)!).ToListAsync())
                    .Select(e => fk.Properties[0].PropertyInfo!.GetValue(e)).OfType<Guid>().ToHashSet()
                : [];
            var pick = ids.FirstOrDefault(i => !used.Contains(i));
            if (pick == Guid.Empty) throw new InvalidOperationException($"every {principal.Name} already has a {type.Name}");
            fk.Properties[0].PropertyInfo!.SetValue(row, pick);
        }
        raw.Add(row);
        await raw.SaveChangesAsync();
        return row.Id;
    }

    private static bool IsOptionalOwned(Microsoft.EntityFrameworkCore.Metadata.IEntityType et, string name) =>
        et.FindNavigation(name) is { } nav && nav.ForeignKey.IsOwnership && !nav.ForeignKey.IsRequiredDependent;

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_row_last_updated_before_v151_is_recorded_and_then_a_rewrite_with_its_hash_recomputed_is_caught(string provider /* BUG-629 */)
    {
        using var database = Seeded(provider);
        Guid id;
        await using (var db = database.NewContext())
        {
            var note = await db.TimelineEntries.Include(t => t.Tactics).FirstAsync(t => t.IsCurrent && t.Kind == TimelineKind.Investigation);
            note.Source = "updated in an old release";
            await db.SaveChangesAsync();
            id = note.Id;
        }
        await UnrecordHashAsync(database, nameof(TimelineEntry), id);   // its update entry, as v1.0-v1.5.0 wrote it

        (await UpgradeAsync(database)).Left.Should().BeEmpty();
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull();

        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            var row = await raw.TimelineEntries.Include(t => t.Tactics).SingleAsync(t => t.Id == id);
            row.Description = "Nothing happened.";
            row.RowHash = _hasher.ComputeRowHash(row);
            await raw.SaveChangesAsync();
        }
        var bad = await VerifyRecordsAsync(database);
        bad!.Id.Should().Be(id);
        bad.Detail.Should().Contain("doesn't match its last recorded change");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_row_rewritten_before_the_upgrade_isnt_signed_off(string provider /* BUG-629 */)
    {
        using var database = Seeded(provider);
        Guid id;
        await using (var db = database.NewContext())
        {
            var e = await db.TimelineEntries.Include(t => t.Tactics).FirstAsync(t => t.IsCurrent && t.Kind == TimelineKind.Investigation);
            e.Source = "updated in an old release";
            await db.SaveChangesAsync();
            id = e.Id;
        }
        await UnrecordHashAsync(database, nameof(TimelineEntry), id);
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            var row = await raw.TimelineEntries.Include(t => t.Tactics).SingleAsync(t => t.Id == id);
            row.Source = "someone else";   // rewritten, its hash recomputed: today this passes
            row.RowHash = _hasher.ComputeRowHash(row);
            await raw.SaveChangesAsync();
        }
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull("before the upgrade nothing can tell (BUG-629)");

        (await UpgradeAsync(database)).Left.Should().ContainSingle().Which.Should().Contain("doesn't agree with its audit trail");
        var bad = await VerifyRecordsAsync(database);
        bad!.Id.Should().Be(id);
        bad.Detail.Should().Contain("doesn't record its hash");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_cleared_hash_on_a_row_whose_trail_never_recorded_one_is_caught_once_strict(string provider /* BUG-620 */)
    {
        using var database = Seeded(provider);
        Guid id;
        await using (var db = database.NewContext()) id = await db.Notes.Where(n => n.IsCurrent).Select(n => n.Id).FirstAsync();
        await UnrecordHashAsync(database, nameof(AnalystNote), id, createToo: true);   // as a row from before row hashes
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
            await raw.Notes.Where(n => n.Id == id).ExecuteUpdateAsync(s => s.SetProperty(n => n.Body, "Edited").SetProperty(n => n.RowHash, (string?)null));
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull("today a hashless row is taken for one from before row hashes");

        (await UpgradeAsync(database)).Left.Should().ContainSingle().Which.Should().Contain("doesn't agree with its audit trail");
        var bad = await VerifyRecordsAsync(database);
        bad!.Id.Should().Be(id);
        bad.Detail.Should().Contain("has no hash");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Rows_a_migration_wrote_are_recorded_when_they_hold_what_it_wrote_and_not_otherwise(string provider /* BUG-621 */)
    {
        using var database = Seeded(provider);
        Guid gate, rewritten;
        await using (var db = database.NewContext())
        {
            gate = await db.StageGates.Where(g => (int)g.Trigger == 3).Select(g => g.Id).FirstAsync();
            var attestation = new StageGateRequirement
            {
                GateId = gate, Order = 90, Kind = (GateRequirementKind)1, Label = "Post-incident review complete", IsBlocking = true,
            };
            db.StageGateRequirements.Add(attestation);
            await db.SaveChangesAsync();
            rewritten = attestation.Id;
        }
        var honest = Guid.NewGuid();
        var weakened = Guid.NewGuid();
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            // As ClosureGateHonestChecks left them: the attestation rewritten (its hash cleared) and a check inserted ...
            await raw.StageGateRequirements.Where(r => r.Id == rewritten).ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Kind, (GateRequirementKind)0).SetProperty(r => r.CheckKey, "LessonsCaptured")
                .SetProperty(r => r.Label, "Post-incident review recorded (Incidents & Breaches)").SetProperty(r => r.RowHash, (string?)null));
            raw.StageGateRequirements.Add(new StageGateRequirement
            {
                Id = honest, GateId = gate, Order = 91, Kind = 0, CheckKey = "EntitiesAssessed",
                Label = "Every entity / IOC has a verdict (none left Unknown)", IsBlocking = false,
            });
            // ... and as ClosureGateNotificationsRecorded wrote one, then made advisory in the database (BUG-621's example).
            raw.StageGateRequirements.Add(new StageGateRequirement
            {
                Id = weakened, GateId = gate, Order = 92, Kind = 0, CheckKey = "NotificationsRecorded",
                Label = "Required regulatory notifications recorded", IsBlocking = false,
            });
            await raw.SaveChangesAsync();
        }
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull("today the migration's exemption covers all three");

        var result = await UpgradeAsync(database);
        result.Left.Should().ContainSingle().Which.Should().StartWith($"{nameof(StageGateRequirement)} {weakened}");
        var bad = await VerifyRecordsAsync(database);
        bad!.Id.Should().Be(weakened);
        bad.Detail.Should().Contain("has no hash");

        // The honest two are recorded: changing one now is caught as any change is.
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            await raw.StageGateRequirements.Where(r => r.Id == weakened).ExecuteDeleteAsync();
            await raw.StageGateRequirements.Where(r => r.Id == rewritten).ExecuteUpdateAsync(s => s.SetProperty(r => r.IsBlocking, false));
        }
        bad = await VerifyRecordsAsync(database);
        bad!.Id.Should().Be(rewritten);
        bad.Detail.Should().Contain("no longer matches its hash");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_template_the_library_migration_made_from_a_profile_is_recorded_when_it_matches_the_profiles_trail(string provider)
    {
        using var database = Seeded(provider);
        Guid profileId, other;
        await using (var db = database.NewContext())
        {
            var ids = await db.ReportProfiles.Select(p => p.Id).Take(2).ToListAsync();
            (profileId, other) = (ids[0], ids[1]);
        }
        // The profiles' trails as the release before the library recorded their Word templates.
        await AppendAsync(database, AuditAction.Update, nameof(ReportProfile), profileId,
            """{"TemplateFileName":"Examiner pack.docx","TemplateSha256":"abc"}""");
        await AppendAsync(database, AuditAction.Update, nameof(ReportProfile), other,
            """{"TemplateFileName":"Board.docx","TemplateSha256":"def"}""");
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            raw.ReportTemplates.Add(new ReportTemplate { Id = profileId, Name = "Examiner pack", FileName = "Examiner pack.docx", Sha256 = "abc", SizeBytes = 0, IsActive = true, CreatedBy = "admin1", CreatedAtUtc = _clock.UtcNow });
            // This one's file swapped in the database since (the SHA-256 isn't the one the profile recorded).
            raw.ReportTemplates.Add(new ReportTemplate { Id = other, Name = "Board", FileName = "Board.docx", Sha256 = "fff", SizeBytes = 0, IsActive = true, CreatedBy = "admin1", CreatedAtUtc = _clock.UtcNow });
            await raw.SaveChangesAsync();
        }

        var result = await UpgradeAsync(database);
        result.Left.Should().ContainSingle().Which.Should().StartWith($"{nameof(ReportTemplate)} {other}");
        (await VerifyRecordsAsync(database))!.Id.Should().Be(other);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Reports_from_before_they_were_hashed_are_recorded_unless_changed_since(string provider /* BUG-633 */)
    {
        using var database = Seeded(provider);
        Guid honest, renamed;
        await using (var db = database.NewContext())
        {
            var caseId = await db.Cases.Select(c => c.Id).FirstAsync();
            Report Make(int v) => new()
            {
                CaseId = caseId, Version = v, Format = ReportFormat.Word, FileName = $"r{v}.docx", StoragePath = $"r/{v}.docx",
                ContentSha256 = new string('a', 64), CreatedBy = "alice", CreatedAtUtc = _clock.UtcNow,
            };
            var (a, b) = (Make(1), Make(2));
            db.Reports.AddRange(a, b);
            await db.SaveChangesAsync();
            (honest, renamed) = (a.Id, b.Id);
        }
        // As v1.6.12 left them: no row hash, and Create entries that recorded none.
        foreach (var id in new[] { honest, renamed }) await UnrecordHashAsync(database, nameof(Report), id, createToo: true);
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            await raw.Reports.ExecuteUpdateAsync(s => s.SetProperty(r => r.RowHash, (string?)null));
            // Its generator renamed in the database, so alice could approve her own report.
            await raw.Reports.Where(r => r.Id == renamed).ExecuteUpdateAsync(s => s.SetProperty(r => r.CreatedBy, "bob"));
        }

        var result = await UpgradeAsync(database);
        result.Left.Should().ContainSingle().Which.Should().StartWith($"{nameof(Report)} {renamed}");
        var bad = await VerifyRecordsAsync(database);
        bad!.Id.Should().Be(renamed);
        bad.Detail.Should().Contain("has no hash");
        await using (var db = database.NewContext())
            (await db.Reports.AsNoTracking().SingleAsync(r => r.Id == honest)).RowHash.Should().StartWith(Canonical.V4Prefix);
    }

    // A row hashed in format 3, as v1.6.3-v1.6.12 left it: its hash, and its latest entry's, in that format.
    private async Task AsFormat3Async(TestDatabase database, string type, Guid id, Func<AppDbContext, Task<IHashableEntity>> load)
    {
        await using var raw = new AppDbContext(database.OptionsWithoutInterceptors);
        var row = await load(raw);
        var v4 = row.RowHash!;
        var v3 = Canonical.V3Prefix + _hasher.Hash(Canonical.InFormat(3, row.BuildCanonicalContent));
        row.RowHash = v3;
        var key = id.ToString();
        foreach (var e in await raw.AuditLog.Where(a => a.EntityType == type && a.EntityId == key && a.AfterJson != null).ToListAsync())
            e.AfterJson = e.AfterJson!.Replace(v4, v3, StringComparison.Ordinal);
        await raw.SaveChangesAsync();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_value_format_4_brought_in_is_hashed_at_the_upgrade_and_one_changed_before_it_is_caught(string provider /* BUG-630 */)
    {
        using var database = Seeded(provider);
        Guid kept, moved;
        await using (var db = database.NewContext())
        {
            var caseId = await db.Cases.Select(c => c.Id).FirstAsync();
            JurisdictionNotice Notice(string code) => new()
            {
                CaseId = caseId, Jurisdiction = code, NotifiedAtUtc = _clock.UtcNow.AddHours(-2), DueAtUtc = _clock.UtcNow.AddHours(-1),
                CreatedBy = "alice", CreatedAtUtc = _clock.UtcNow,
            };
            var (a, b) = (Notice("NY"), Notice("CA"));
            db.JurisdictionNotices.AddRange(a, b);
            await db.SaveChangesAsync();
            (kept, moved) = (a.Id, b.Id);
        }
        foreach (var id in new[] { kept, moved })
            await AsFormat3Async(database, nameof(JurisdictionNotice), id, async raw => await raw.JurisdictionNotices.SingleAsync(n => n.Id == id));
        // The deadline moved past the notice in the database: a format-3 hash can't show it.
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
            await raw.JurisdictionNotices.Where(n => n.Id == moved).ExecuteUpdateAsync(s => s.SetProperty(n => n.DueAtUtc, _clock.UtcNow.AddDays(3)));
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull("before the upgrade nothing can tell");

        var result = await UpgradeAsync(database);
        result.Left.Should().ContainSingle().Which.Should().StartWith($"{nameof(JurisdictionNotice)} {moved}");
        await using (var db = database.NewContext())
            (await db.JurisdictionNotices.AsNoTracking().SingleAsync(n => n.Id == kept)).RowHash.Should().StartWith(Canonical.V4Prefix);
        var bad = await VerifyRecordsAsync(database);
        bad!.Id.Should().Be(moved);
        bad.Detail.Should().Contain("doesn't cover");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_failed_upgrade_marks_nothing_and_the_check_stays_as_it_was(string provider)
    {
        using var database = Seeded(provider);
        Guid caseId, noteId;
        await using (var db = database.NewContext())
        {
            caseId = await db.Cases.Select(c => c.Id).FirstAsync();
            noteId = await db.Notes.Where(n => n.IsCurrent).Select(n => n.Id).FirstAsync();
        }
        // Two records from before row hashes were recorded, in two tables; the upgrade fails on the second.
        await UnrecordHashAsync(database, nameof(Case), caseId, createToo: true);
        await UnrecordHashAsync(database, nameof(AnalystNote), noteId, createToo: true);
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
            await raw.Notes.Where(n => n.Id == noteId).ExecuteUpdateAsync(s => s.SetProperty(n => n.RowHash, (string?)null));

        await using (var db = database.NewContext())
        {
            var act = () => RowHashUpgrade.RunAsync(db, new FailingHasher(_hasher, failOn: typeof(TimelineEntry)), _clock);
            await act.Should().ThrowAsync<InvalidOperationException>();
        }
        await using (var db = database.NewContext()) (await RowIntegrityVerifier.UpgradedAsync(db)).Should().BeFalse("nothing is marked");
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull("the check behaves as before the upgrade");

        // The next start carries on from there.
        var result = await UpgradeAsync(database);
        result.Marked.Should().BeTrue();
        result.Left.Should().BeEmpty();
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_record_whose_save_fails_doesnt_stop_the_others_being_recorded(string provider /* BUG-641 */)
    {
        var hasher = new SaveFailsFor(_hasher);
        var database = TestDatabase.Open(provider, new AuditChainInterceptor(hasher, _user, _clock, new CaseChangeNotifier()));
        using var _ = database;
        await using (var db = database.NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            await DevDataSeeder.SeedHistoricalDemoAsync(db, _clock);
        }
        List<Guid> rows;
        await using (var db = database.NewContext()) rows = await db.ActionItems.OrderBy(a => a.Id).Select(a => a.Id).Take(3).ToListAsync();
        rows.Should().HaveCount(3);
        // Three records from before row hashes were recorded, in one table (one batch); the save of the middle one fails.
        foreach (var id in rows) await UnrecordHashAsync(database, nameof(ActionItem), id, createToo: true);
        hasher.FailId = rows[1];

        var result = await UpgradeAsync(database);
        result.Left.Should().ContainSingle().Which.Should().StartWith($"{nameof(ActionItem)} {rows[1]}").And.Contain("couldn't be saved");
        result.Recorded.Should().BeGreaterThanOrEqualTo(2, "the others in its batch are still recorded");
        result.Marked.Should().BeFalse("the check isn't strict while a record that agrees with its trail is unrecorded");
        await using (var db = database.NewContext())
        {
            (await RowIntegrityVerifier.UpgradedAsync(db)).Should().BeFalse();
            foreach (var id in new[] { rows[0], rows[2] })
            {
                var key = id.ToString();
                (await db.AuditLog.AsNoTracking().Where(a => a.EntityType == nameof(ActionItem) && a.EntityId == key)
                    .OrderByDescending(a => a.Sequence).FirstAsync()).AfterJson.Should().Contain(nameof(IHashableEntity.RowHash));
            }
        }
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull("the check stays as it was");

        // Once it saves, the next start records it and marks the check strict.
        hasher.FailId = null;
        result = await UpgradeAsync(database);
        result.Left.Should().BeEmpty();
        result.Marked.Should().BeTrue();
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull();
    }

    // A hasher whose row hash for one record throws, as a save that keeps failing on that record would.
    private sealed class SaveFailsFor(HashChainService inner) : Application.Abstractions.IHashChainService
    {
        public Guid? FailId { get; set; }
        public string Hash(string content) => inner.Hash(content);
        public string ComputeRowHash(IHashableEntity entity) =>
            entity is Entity e && e.Id == FailId ? throw new InvalidOperationException("this record's save fails") : inner.ComputeRowHash(entity);
        public bool RowHashMatches(IHashableEntity entity, string stored) => inner.RowHashMatches(entity, stored);
        public void ChainAppend(AuditLogEntry entry, AuditLogEntry? previous) => inner.ChainAppend(entry, previous);
        public Application.Abstractions.ChainVerificationResult VerifyChain(IReadOnlyList<AuditLogEntry> orderedEntries, long? keyedFrom = null) =>
            inner.VerifyChain(orderedEntries, keyedFrom);
        public Application.Abstractions.IChainVerifier BeginVerify(long? keyedFrom = null) => inner.BeginVerify(keyedFrom);
    }

    // A hasher that fails when it reaches a table (the timeline comes after the cases), as a database error part way would.
    private sealed class FailingHasher(HashChainService inner, Type failOn) : Application.Abstractions.IHashChainService
    {
        public string Hash(string content) => inner.Hash(content);
        public string ComputeRowHash(IHashableEntity entity) => inner.ComputeRowHash(entity);
        public bool RowHashMatches(IHashableEntity entity, string stored) =>
            entity.GetType() == failOn ? throw new InvalidOperationException("failed part way") : inner.RowHashMatches(entity, stored);
        public void ChainAppend(AuditLogEntry entry, AuditLogEntry? previous) => inner.ChainAppend(entry, previous);
        public Application.Abstractions.ChainVerificationResult VerifyChain(IReadOnlyList<AuditLogEntry> orderedEntries, long? keyedFrom = null) =>
            inner.VerifyChain(orderedEntries, keyedFrom);
        public Application.Abstractions.IChainVerifier BeginVerify(long? keyedFrom = null) => inner.BeginVerify(keyedFrom);
    }

    public static TheoryData<string, string> LineageTampers()
    {
        var rows = new TheoryData<string, string>();
        foreach (var provider in ((IEnumerable<object[]>)TestDatabase.Providers).Select(r => (string)r[0]))
            foreach (var tamper in new[] { "note unlinked", "note hidden", "entry unlinked", "entry hidden", "brief swapped", "report renumbered" })
                rows.Add(provider, tamper);
        return rows;
    }

    [Theory]
    [MemberData(nameof(LineageTampers))]
    public async Task A_version_lineage_changed_in_the_database_is_caught(string provider, string tamper /* BUG-622, BUG-634 */)
    {
        using var database = Seeded(provider);
        Guid note1, note2, entry1, entry2, brief1, report;
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.Include(x => x.Notes).Include(x => x.TimelineEntries).ThenInclude(t => t.Tactics)
                .Include(x => x.Briefs).Include(x => x.Citations).Include(x => x.DataElements).FirstAsync();
            var n = new AnalystNote { CaseId = c.Id, Body = "First wording", CreatedBy = "alice", CreatedAtUtc = _clock.UtcNow };
            c.Notes.Add(n);
            var e = new TimelineEntry { CaseId = c.Id, Kind = TimelineKind.Investigation, Description = "First account", OccurredAtUtc = _clock.UtcNow, CreatedBy = "alice", CreatedAtUtc = _clock.UtcNow };
            c.TimelineEntries.Add(e);
            await db.SaveChangesAsync();
            note2 = c.EditNote(n.Id, "Second wording", "alice", _clock.UtcNow).Id;
            entry2 = c.EditInvestigationEntry(e.Id, e.Type, e.OccurredAtUtc, "Second account", null, "alice", _clock.UtcNow).Id;
            brief1 = c.Briefs.SingleOrDefault(b => b.IsCurrent)?.Id ?? Guid.Empty;
            c.ReviseBrief("Summary one", "Assessment", null, null, null, "alice", _clock.UtcNow);
            if (brief1 == Guid.Empty) brief1 = c.Briefs.Single(b => b.IsCurrent).Id;
            await db.SaveChangesAsync();
            c.ReviseBrief("Summary two", "Assessment", null, null, null, "alice", _clock.UtcNow);
            var r = new Report { CaseId = c.Id, Version = 1, FileName = "r.docx", StoragePath = "r/1", ContentSha256 = new string('a', 64), CreatedBy = "alice", CreatedAtUtc = _clock.UtcNow };
            db.Reports.Add(r);
            await db.SaveChangesAsync();
            (note1, entry1, report) = (n.Id, e.Id, r.Id);
            if (brief1 == c.Briefs.Single(b => b.IsCurrent).Id) brief1 = c.Briefs.Where(b => !b.IsCurrent).OrderByDescending(b => b.Version).First().Id;
        }
        (await UpgradeAsync(database)).Left.Should().BeEmpty();
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull();

        Guid expected;
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
            switch (tamper)
            {
                case "note unlinked":   // the edit unlinked and hidden, the first wording put back as current
                    await raw.Notes.Where(x => x.Id == note2).ExecuteUpdateAsync(s => s.SetProperty(x => x.SupersedesNoteId, (Guid?)null));
                    await raw.Notes.Where(x => x.Id == note1).ExecuteUpdateAsync(s => s.SetProperty(x => x.IsCurrent, true));
                    expected = note2;
                    break;
                case "note hidden":
                    await raw.Notes.Where(x => x.Id == note2).ExecuteUpdateAsync(s => s.SetProperty(x => x.IsCurrent, false));
                    expected = note2;
                    break;
                case "entry unlinked":
                    await raw.TimelineEntries.Where(x => x.Id == entry2).ExecuteUpdateAsync(s => s.SetProperty(x => x.SupersedesEntryId, (Guid?)null));
                    await raw.TimelineEntries.Where(x => x.Id == entry1).ExecuteUpdateAsync(s => s.SetProperty(x => x.IsCurrent, true));
                    expected = entry2;
                    break;
                case "entry hidden":
                    await raw.TimelineEntries.Where(x => x.Id == entry2).ExecuteUpdateAsync(s => s.SetProperty(x => x.IsCurrent, false));
                    expected = entry2;
                    break;
                case "brief swapped":
                    var caseId = await raw.CaseBriefs.Where(b => b.Id == brief1).Select(b => b.CaseId).FirstAsync();
                    await raw.CaseBriefs.Where(b => b.CaseId == caseId && b.IsCurrent).ExecuteUpdateAsync(s => s.SetProperty(b => b.IsCurrent, false));
                    await raw.CaseBriefs.Where(b => b.Id == brief1).ExecuteUpdateAsync(s => s.SetProperty(b => b.IsCurrent, true));
                    expected = brief1;
                    break;
                default:   // "report renumbered": a later draft passed off as the first
                    await raw.Reports.Where(x => x.Id == report).ExecuteUpdateAsync(s => s.SetProperty(x => x.Version, 7));
                    expected = report;
                    break;
            }

        var bad = await VerifyRecordsAsync(database);
        bad.Should().NotBeNull($"{tamper} is caught");
        bad!.Id.Should().Be(expected);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_retracted_entry_isnt_taken_for_a_hidden_one(string provider /* BUG-634 */)
    {
        using var database = Seeded(provider);
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.Include(x => x.TimelineEntries).ThenInclude(t => t.Tactics).Include(x => x.DataElements)
                .FirstAsync(x => x.TimelineEntries.Any(t => t.IsCurrent));
            c.RetractTimelineEntry(c.TimelineEntries.First(t => t.IsCurrent).Id, "Logged against the wrong host.", "alice", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        (await UpgradeAsync(database)).Left.Should().BeEmpty();
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull("retracting takes an entry off the record openly");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_upgrades_entries_arent_changes_after_closure(string provider)
    {
        using var database = Seeded(provider);
        Guid caseId;
        int before;
        await using (var db = database.NewContext())
        {
            caseId = Guid.Empty;
            before = 0;
            foreach (var c in await db.Cases.Where(x => x.Phase == CasePhase.Closed).Select(x => x.Id).ToListAsync())
                if (await AfterClosure.QueryAsync(db, c) is { } a) { (caseId, before) = (c, a.Count); break; }
            caseId.Should().NotBe(Guid.Empty);
        }
        await UnrecordHashAsync(database, nameof(Case), caseId, createToo: true);   // the whole case's trail from before row hashes
        _clock.UtcNow = _clock.UtcNow.AddDays(1);
        var result = await UpgradeAsync(database);
        result.Recorded.Should().BeGreaterThan(0);
        await using (var db = database.NewContext())
        {
            (await AfterClosure.QueryAsync(db, caseId))!.Count.Should().Be(before, "the upgrade's upkeep isn't a change to the record");
            (await db.AuditLog.AsNoTracking().OrderByDescending(a => a.Sequence).Skip(1).FirstAsync()).Reason.Should().Be(IntegrityUpkeep.Reason);
        }
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull();
    }
}
