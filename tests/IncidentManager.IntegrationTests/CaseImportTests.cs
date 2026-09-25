using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Import;
using IncidentManager.Domain.Entities;
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
/// PROD-31: the structured case import. Parsing/preview treat the document as untrusted (format + schema
/// guard, enum fallback, clamps, refang/dedupe, future-date exclusion); apply reuses the guarded/audited
/// CaseService writes, stamps provenance, and is resume-safe.
/// </summary>
public sealed class CaseImportTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 20, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "analyst1", RoleSet = [AppRole.SysAdmin] };

    public CaseImportTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var _ = NewContext();
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

    private CaseService NewCaseService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private CaseImportService NewImportService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, NewCaseService(db));


    // ── Parse (pure) ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Parse_rejects_bad_json_a_foreign_file_and_a_too_new_schema()
    {
        CaseImportService.Parse("{ not json").Ok.Should().BeFalse();
        CaseImportService.Parse("{\"format\":\"something-else\"}").Error.Should().Contain("case-import document");
        CaseImportService.Parse("{\"format\":\"casebook-case-import\",\"schemaVersion\":99}").Error
            .Should().Contain("newer than this app supports");
        CaseImportService.Parse("{\"format\":\"casebook-case-import\",\"schemaVersion\":1}").Ok.Should().BeTrue();
    }

    // ── JSON Schema (pure, PROD-35) ──────────────────────────────────────────────────────────────

    private static string[] SchemaEnum(JsonObject root, string def, string prop) =>
        root["$defs"]![def]!["properties"]![prop]!["enum"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();

    [Fact]
    public void The_schema_is_valid_json_and_pins_the_format_and_version()
    {
        var act = () => JsonNode.Parse(CaseImportSchema.Build());
        act.Should().NotThrow();

        var root = CaseImportSchema.Root();
        root["properties"]!["format"]!["const"]!.GetValue<string>().Should().Be(CaseImportJson.FormatTag);
        root["properties"]!["schemaVersion"]!["const"]!.GetValue<int>().Should().Be(CaseImportJson.CurrentSchemaVersion);
    }

    [Fact]
    public void The_schema_enums_match_the_domain_enums()
    {
        var root = CaseImportSchema.Root();
        SchemaEnum(root, "entity", "type").Should().BeEquivalentTo(Enum.GetNames<EntityType>());
        SchemaEnum(root, "entity", "disposition").Should().BeEquivalentTo(Enum.GetNames<EntityDisposition>());
        SchemaEnum(root, "timelineEntry", "kind").Should().BeEquivalentTo(Enum.GetNames<TimelineKind>());
        SchemaEnum(root, "timelineEntry", "type").Should().BeEquivalentTo(Enum.GetNames<TimelineEntryType>());
        SchemaEnum(root, "newCase", "severity").Should().BeEquivalentTo(Enum.GetNames<Severity>());
        SchemaEnum(root, "newCase", "origin").Should().BeEquivalentTo(Enum.GetNames<CaseOrigin>());
        SchemaEnum(root, "newCase", "classification").Should()
            .Contain("ComplexEvent").And.Contain(Enum.GetNames<Classification>());
    }

    [Fact]
    public void The_committed_schema_file_matches_the_builder()
    {
        var repoRoot = FindRepoRoot();
        repoRoot.Should().NotBeNull("the repo root (with IncidentManager.sln) should be locatable from the test output");
        var path = Path.Combine(repoRoot!, "docs", "case-import.schema.json");
        File.Exists(path).Should().BeTrue(
            $"the committed schema should exist at {path} — regenerate it from GET /api/import/cases/schema");

        // Compare structurally (parse → compact) so line-ending/indentation differences don't matter.
        var onDisk = JsonNode.Parse(File.ReadAllText(path))!.ToJsonString();
        var built = JsonNode.Parse(CaseImportSchema.Build())!.ToJsonString();
        onDisk.Should().Be(built, "docs/case-import.schema.json must match CaseImportSchema.Build() — regenerate it");
    }

    private static string? FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
            dir = dir.Parent;
        }
        return null;
    }

    // ── Prompt builder (pure, PROD-32) ───────────────────────────────────────────────────────────

    [Fact]
    public void Prompt_for_a_new_case_embeds_the_schema_rules_and_enum_values()
    {
        var prompt = CaseImportPrompt.Build(new CaseImportPromptOptions(ToolName: "Copilot"));

        prompt.Should().Contain(CaseImportJson.FormatTag);
        prompt.Should().Contain("Output ONLY the JSON");
        prompt.Should().Contain("AI-assisted (Copilot)");
        prompt.Should().Contain("\"target\"").And.Contain("newCase");
        // Enum values are derived from the real types, so the prompt can't drift from the importer.
        prompt.Should().Contain("Malicious").And.Contain("IpAddress").And.Contain("Breach");
    }

    [Fact]
    public void Prompt_for_an_existing_case_omits_the_target_block()
    {
        var prompt = CaseImportPrompt.Build(new CaseImportPromptOptions(TargetIsExisting: true));

        prompt.Should().NotContain("newCase");
        prompt.Should().Contain("Do NOT include a \"target\"");
    }

    [Fact]
    public void Prompt_pins_a_classification_hint_when_given()
    {
        var prompt = CaseImportPrompt.Build(new CaseImportPromptOptions(Classification: Classification.Incident));
        prompt.Should().Contain("\"classification\": \"Incident\"");
    }

    // ── Preview (pure) ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Preview_refangs_auto_types_and_dedupes_indicators_and_defaults_provenance()
    {
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Origin = "AI-assisted (Copilot)",
            Entities = new()
            {
                new() { Value = "1.1.1[.]1" },                          // defanged IP → refang + auto-type
                new() { Value = "1.1.1.1" },                            // duplicate of the above once refanged
                new() { Type = "EmailAddress", Value = "a@b.com" }
            }
        };

        var p = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow);

        p.Entities.Should().HaveCount(2, "the defanged and live IP collapse to one");
        var ip = p.Entities.Single(e => e.Type == EntityType.IpAddress);
        ip.Value.Should().Be("1.1.1.1");
        ip.Source.Should().Be("AI-assisted (Copilot)", "origin is the default provenance for each item");
    }

    [Fact]
    public void Preview_falls_back_on_unknown_enums_and_flags_them()
    {
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Timeline = new() { new() { OccurredAtUtc = _clock.UtcNow.AddHours(-1), Type = "Nonsense", Description = "x" } },
            Entities = new() { new() { Type = "Bogus", Value = "10.0.0.5" } }
        };

        var p = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow);

        p.Timeline.Single().Type.Should().Be(TimelineEntryType.Communication);
        p.Entities.Single().Type.Should().Be(EntityType.IpAddress, "an unknown type auto-detects from the value");
        p.Warnings.Should().Contain(w => w.Contains("Nonsense"));
        p.Warnings.Should().Contain(w => w.Contains("Bogus"));
    }

    [Fact]
    public void The_xsiam_playbook_sample_imports_cleanly(/* PROD-05 */)
    {
        var root = FindRepoRoot();
        root.Should().NotBeNull();
        var json = File.ReadAllText(Path.Combine(root!, "integrations", "xsiam", "sample-elevation.json"));

        var parsed = CaseImportService.Parse(json);
        parsed.Ok.Should().BeTrue(parsed.Error);
        var p = CaseImportService.BuildPreviewCore(parsed.Document!, _clock.UtcNow);

        p.Warnings.Should().BeEmpty();
        p.NewCase!.Classification.Should().BeNull();
        p.NewCase.Severity.Should().Be(Severity.High);
        p.NewCase.DetectionCaseId.Should().Be("4812");
        p.Entities.Should().ContainSingle(e => e.Value == "203.0.113.66" && e.Disposition == EntityDisposition.Malicious);
        p.Timeline.Should().ContainSingle(t => t.Type == TimelineEntryType.Escalation && t.Kind == TimelineKind.Investigation);
    }

    [Fact]
    public void A_new_case_without_a_classification_is_a_complex_event_and_keeps_its_detection_id(/* PROD-05 */)
    {
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Target = new() { NewCase = new() { Title = "Elevated from XSIAM", DetectionCaseId = "XSIAM-4812" } },
        };

        var p = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow);

        p.NewCase!.Classification.Should().BeNull("an omitted classification files intake, as the schema documents");
        p.NewCase.DetectionCaseId.Should().Be("XSIAM-4812");
    }

    [Fact]
    public void Preview_excludes_future_timeline_and_defaults_a_missing_timestamp()
    {
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Timeline = new()
            {
                new() { OccurredAtUtc = _clock.UtcNow.AddDays(1), Description = "future" },
                new() { Description = "no timestamp" }
            }
        };

        var p = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow);

        var future = p.Timeline.Single(t => t.Description == "future");
        future.Include.Should().BeFalse("a future-dated entry is excluded until corrected");
        var missing = p.Timeline.Single(t => t.Description == "no timestamp");
        missing.OccurredAtUtc.Should().Be(_clock.UtcNow);
        missing.Warning.Should().Contain("defaulted");
    }

    // ── PROD-06: STIX round trip ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_stix_export_imports_into_another_case_with_its_verdicts(/* PROD-06 */)
    {
        await using var db = NewContext();
        var cases = NewCaseService(db);
        var source = await cases.CreateAsync(new CreateCaseRequest
            { DescriptiveName = "Source", Title = "Source case", Classification = Classification.Incident, Severity = Severity.High });
        var target = await cases.CreateAsync(new CreateCaseRequest
            { DescriptiveName = "Target", Title = "Partner share", Classification = Classification.Incident, Severity = Severity.Medium });
        await cases.AddEntityAsync(source.Id, EntityType.IpAddress, "203.0.113.66", "C2", EntityDisposition.Malicious, null, "EDR");
        await cases.AddEntityAsync(source.Id, EntityType.Host, "FIN-WKS-07", null, EntityDisposition.Compromised, null, null);

        var stix = await new IncidentManager.Application.Export.StixExportService(NewFactory(), _user, _clock,
            new TestOptionsMonitor<IncidentManager.Application.Reporting.ReportingOptions>(new())).BuildAsync(source.Id);
        var json = JsonSerializer.Serialize(stix!.Bundle);

        var converted = IocImportConverter.Convert(json);
        converted.Format.Should().Be(ImportSourceFormat.StixBundle);
        var svc = NewImportService(db);
        var preview = await svc.BuildPreviewAsync(converted.Document!, target.Id);
        preview.TargetKind.Should().Be(CaseImportTargetKind.ExistingCase);
        await svc.ApplyAsync(preview);

        var imported = await db.CaseEntities.AsNoTracking().Where(e => e.CaseId == target.Id)
            .OrderBy(e => e.Value).ToListAsync();
        imported.Select(e => (e.Type, e.Value, e.Disposition, e.Label, e.Source)).Should().Equal(
            (EntityType.IpAddress, "203.0.113.66", EntityDisposition.Malicious, "C2", "EDR"),
            (EntityType.Host, "FIN-WKS-07", EntityDisposition.Compromised, (string?)null, "STIX 2.1 bundle (CaseBook)"));
    }

    // ── Apply (integration) ──────────────────────────────────────────────────────────────────────

    private static CaseImportDocument FullDoc() => new()
    {
        Format = CaseImportJson.FormatTag,
        Origin = "manual",
        Target = new() { NewCase = new() { Title = "Phishing wave", Classification = "Incident", Severity = "High" } },
        Summary = "Assembled from the reporting email thread.",
        Timeline = new() { new() { OccurredAtUtc = new DateTimeOffset(2026, 9, 19, 8, 0, 0, TimeSpan.Zero), Type = "Communication", Description = "User reported a suspicious email." } },
        Entities = new() { new() { Value = "hxxp://evil[.]example[.]com/x" }, new() { Type = "EmailAddress", Value = "attacker@evil.example.com", Disposition = "Malicious" } },
        ActionItems = new() { new() { Title = "Reset affected credentials", Owner = "soc" } }
    };

    [Fact]
    public async Task Apply_into_a_new_case_writes_every_section_with_provenance_and_keeps_the_chain_valid()
    {
        Guid caseId;
        await using (var db = NewContext())
        {
            var svc = NewImportService(db);
            var preview = await svc.BuildPreviewAsync(FullDoc());
            preview.TargetKind.Should().Be(CaseImportTargetKind.NewCase);

            var result = await svc.ApplyAsync(preview);
            result.CaseCreated.Should().BeTrue();
            result.Notes.Should().Be(1);
            result.Timeline.Should().Be(1);
            result.Entities.Should().Be(2);
            result.ActionItems.Should().Be(1);
            caseId = result.CaseId;
        }

        await using (var verify = NewContext())
        {
            (await verify.Set<AnalystNote>().CountAsync(n => n.CaseId == caseId)).Should().Be(1);
            (await verify.Set<ActionItem>().CountAsync(a => a.CaseId == caseId)).Should().Be(1);

            var entities = await verify.Set<CaseEntity>().Where(e => e.CaseId == caseId).ToListAsync();
            entities.Should().HaveCount(2);
            entities.Should().OnlyContain(e => e.Source == "manual", "origin is stamped as the entity source");
            entities.Should().Contain(e => e.Type == EntityType.Url && e.Value == "http://evil.example.com/x", "the URL was refanged");

            var timeline = await verify.Set<TimelineEntry>().Where(t => t.CaseId == caseId).ToListAsync();
            timeline.Should().ContainSingle().Which.Source.Should().Be("manual");

            var chain = await verify.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task Apply_into_an_existing_case_adds_items_to_it()
    {
        Guid caseId;
        await using (var db = NewContext())
        {
            var created = await NewCaseService(db).CreateAsync(new CreateCaseRequest
            {
                DescriptiveName = "Existing", Title = "Existing case",
                Classification = Classification.Incident, Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
            });
            caseId = created.Id;
        }

        await using (var db = NewContext())
        {
            var svc = NewImportService(db);
            var preview = await svc.BuildPreviewAsync(FullDoc(), intoCaseId: caseId);
            preview.TargetKind.Should().Be(CaseImportTargetKind.ExistingCase);
            preview.ExistingCaseId.Should().Be(caseId);

            var result = await svc.ApplyAsync(preview);
            result.CaseCreated.Should().BeFalse();
            result.CaseId.Should().Be(caseId);
            result.Total.Should().Be(5);
        }

        await using (var verify = NewContext())
        {
            (await verify.Set<CaseEntity>().CountAsync(e => e.CaseId == caseId)).Should().Be(2);
            (await verify.Set<TimelineEntry>().CountAsync(t => t.CaseId == caseId)).Should().Be(1);
        }
    }

    [Fact]
    public async Task Apply_is_resume_safe_and_does_not_duplicate_on_a_second_call()
    {
        await using var db = NewContext();
        var svc = NewImportService(db);
        var preview = await svc.BuildPreviewAsync(FullDoc());

        await svc.ApplyAsync(preview);
        await svc.ApplyAsync(preview);   // a retry must not re-write already-applied items

        await using var verify = NewContext();
        (await verify.Set<TimelineEntry>().CountAsync(t => t.CaseId == preview.CreatedCaseId)).Should().Be(1);
        (await verify.Set<AnalystNote>().CountAsync(n => n.CaseId == preview.CreatedCaseId)).Should().Be(1);
        (await verify.Set<ActionItem>().CountAsync(a => a.CaseId == preview.CreatedCaseId)).Should().Be(1);
    }

    // ── Pending imports queue (PROD-33) ──────────────────────────────────────────────────────────

    private static string FullDocJson() => JsonSerializer.Serialize(FullDoc(), CaseImportJson.Options);

    [Fact]
    public async Task Submit_stages_a_pending_import_and_writes_nothing_yet()
    {
        Guid pid;
        await using (var db = NewContext())
        {
            var svc = NewImportService(db);
            var json = FullDocJson();
            var submit = await svc.SubmitAsync(json, CaseImportService.Parse(json).Document!);
            pid = submit.Id;
            submit.Preview.IncludedItemCount.Should().Be(5);
            (await svc.ListPendingAsync()).Should().ContainSingle(x => x.Id == pid);
            (await svc.CountPendingAsync()).Should().Be(1);
        }

        await using (var verify = NewContext())
        {
            var row = await verify.Set<PendingImport>().FirstAsync(p => p.Id == pid);
            row.Status.Should().Be(PendingImportStatus.Pending);
            row.SubmittedBy.Should().Be("analyst1");
            (await verify.Set<CaseEntity>().CountAsync()).Should().Be(0, "nothing is written until a human confirms");
        }
    }

    [Fact]
    public async Task Confirming_a_pending_import_applies_it_and_marks_it_applied()
    {
        Guid pid;
        await using (var db = NewContext())
        {
            var json = FullDocJson();
            (pid, _) = await NewImportService(db).SubmitAsync(json, CaseImportService.Parse(json).Document!);
        }

        Guid caseId;
        await using (var db = NewContext())
        {
            var svc = NewImportService(db);
            var preview = await svc.BuildPreviewForPendingAsync(pid);
            preview.Should().NotBeNull();
            var result = await svc.ApplyAsync(preview!);
            await svc.MarkPendingAppliedAsync(pid, result);
            caseId = result.CaseId;
        }

        await using (var verify = NewContext())
        {
            var row = await verify.Set<PendingImport>().FirstAsync(p => p.Id == pid);
            row.Status.Should().Be(PendingImportStatus.Applied);
            row.ResolvedCaseId.Should().Be(caseId);
            (await verify.Set<CaseEntity>().CountAsync(e => e.CaseId == caseId)).Should().Be(2);
            // It has left the pending queue.
            (await NewImportService(verify).BuildPreviewForPendingAsync(pid)).Should().BeNull();
        }
    }

    [Fact]
    public async Task Rejecting_a_pending_import_writes_nothing()
    {
        Guid pid;
        await using (var db = NewContext())
        {
            var json = FullDocJson();
            var svc = NewImportService(db);
            (pid, _) = await svc.SubmitAsync(json, CaseImportService.Parse(json).Document!);
            await svc.RejectPendingAsync(pid, "duplicate of an existing case");
        }

        await using (var verify = NewContext())
        {
            var row = await verify.Set<PendingImport>().FirstAsync(p => p.Id == pid);
            row.Status.Should().Be(PendingImportStatus.Rejected);
            row.DecisionNote.Should().Be("duplicate of an existing case");
            (await verify.Set<CaseEntity>().CountAsync()).Should().Be(0);
            (await NewImportService(verify).CountPendingAsync()).Should().Be(0);
        }
    }

    public void Dispose() => _connection.Dispose();
}
