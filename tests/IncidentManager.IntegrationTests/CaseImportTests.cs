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
    public void A_time_without_an_offset_is_read_as_UTC_not_server_local(/* BUG-207 */)
    {
        var json = """
            { "format": "casebook-case-import", "schemaVersion": 1, "target": { "newCase": { "title": "T" } },
              "timeline": [
                { "occurredAtUtc": "2026-09-19T13:05:00", "description": "no offset" },
                { "occurredAtUtc": "2026-09-19T13:05:00+02:00", "description": "an offset" },
                { "occurredAtUtc": "2026-09-19T13:05:00Z", "description": "Z" } ] }
            """;
        var timeline = CaseImportService.Parse(json).Document!.Timeline!;
        timeline[0].OccurredAtUtc.Should().Be(new DateTimeOffset(2026, 9, 19, 13, 5, 0, TimeSpan.Zero));
        timeline[1].OccurredAtUtc.Should().Be(new DateTimeOffset(2026, 9, 19, 11, 5, 0, TimeSpan.Zero), "a stated offset is kept");
        timeline[2].OccurredAtUtc.Should().Be(new DateTimeOffset(2026, 9, 19, 13, 5, 0, TimeSpan.Zero));
        CaseImportService.Parse(json.Replace("2026-09-19T13:05:00Z", "19/09/2026")).Ok.Should().BeFalse("still ISO 8601 only");
    }

    [Fact]
    public void Parse_rejects_more_items_than_one_import_takes(/* BUG-202 */)
    {
        var entities = string.Join(",", Enumerable.Range(1, CaseImportService.MaxEntities + 1)
            .Select(i => $$"""{ "value": "10.0.{{i / 256}}.{{i % 256}}" }"""));
        var json = $$"""{ "format": "casebook-case-import", "schemaVersion": 1, "target": { "newCase": { "title": "Big" } }, "entities": [{{entities}}] }""";
        CaseImportService.Parse(json).Error.Should().Contain("up to 2,000").And.Contain("Split it");
    }

    [Fact]
    public async Task Many_indicators_are_added_in_batches_and_matched_as_one_at_a_time_would_be(/* BUG-202 */)
    {
        Guid caseId;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        }
        await using var ctx = NewContext();
        var before = await ctx.Set<CaseEntity>().CountAsync(e => e.CaseId == caseId);
        var items = Enumerable.Range(0, 450)
            .Select(i => new CaseService.EntityToAdd(EntityType.IpAddress, $"10.9.{i / 256}.{i % 256}", null,
                EntityDisposition.Suspicious, null, "bulk", i == 5 ? TlpLevel.Amber : null))
            .Append(new CaseService.EntityToAdd(EntityType.IpAddress, "10.9.0.0", null, EntityDisposition.Suspicious, null, "bulk"))
            .ToList();

        var results = await NewCaseService(ctx).AddOrMatchEntitiesAsync(caseId, items);

        results.Should().HaveCount(451);
        results.Count(r => r.AlreadyOnCase).Should().Be(1, "the repeat matches the one added earlier in the list");
        (await ctx.Set<CaseEntity>().CountAsync(e => e.CaseId == caseId)).Should().Be(before + 450);
        (await ctx.Set<CaseEntity>().AsNoTracking().SingleAsync(e => e.CaseId == caseId && e.Value == "10.9.0.5")).Tlp.Should().Be(TlpLevel.Amber);
    }

    [Fact]
    public async Task A_pasted_verdict_on_an_unknown_indicator_says_so_and_records_why(/* WF-29 */)
    {
        Guid caseId;
        await using (var db = NewContext())
        {
            await DevDataSeeder.SeedAsync(db, _clock);
            caseId = (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
        }
        await using var ctx = NewContext();
        var svc = NewCaseService(ctx);
        await svc.AddOrMatchEntitiesAsync(caseId, [new CaseService.EntityToAdd(EntityType.IpAddress, "10.8.0.1", null, EntityDisposition.Unknown, null, "bulk")]);

        var results = await svc.AddOrMatchEntitiesAsync(caseId,
            [new CaseService.EntityToAdd(EntityType.IpAddress, "10.8.0.1", null, EntityDisposition.Malicious, null, "bulk")], "Set by paste");

        results.Single().VerdictChanged.Should().BeTrue();
        (await ctx.Set<EntityVerdictChange>().AsNoTracking().SingleAsync(v => v.CaseId == caseId && v.EntityLabel == "10.8.0.1"))
            .Reason.Should().Be("Set by paste");
    }

    [Fact]
    public void The_schema_is_valid_json_and_pins_the_format_and_version()
    {
        var act = () => JsonNode.Parse(CaseImportSchema.Build());
        act.Should().NotThrow();

        var root = CaseImportSchema.Root();
        root["properties"]!["format"]!["const"]!.GetValue<string>().Should().Be(CaseImportJson.FormatTag);
        // CAP-35: v1 documents are still read, so the schema takes 1 and the current version.
        root["properties"]!["schemaVersion"]!["enum"]!.AsArray().Select(v => v!.GetValue<int>())
            .Should().Equal(1, CaseImportJson.CurrentSchemaVersion);
        SchemaEnum(root, "phaseChange", "phase").Should().BeEquivalentTo(Enum.GetNames<CasePhase>());
        root["then"]!["properties"]!["target"]!["properties"]!["newCase"]!["properties"]!.AsObject().Select(p => p.Key)
            .Should().BeEquivalentTo(CaseImportSchema.V2NewCaseFields(), "a v1 document may not carry the v2 fields");
    }

    [Fact]
    public void The_schema_enums_match_the_domain_enums()
    {
        var root = CaseImportSchema.Root();
        SchemaEnum(root, "entity", "type").Should().BeEquivalentTo(Enum.GetNames<EntityType>());
        SchemaEnum(root, "entity", "disposition").Should().BeEquivalentTo(Enum.GetNames<EntityDisposition>());
        SchemaEnum(root, "timelineEntry", "kind").Should().BeEquivalentTo(Enum.GetNames<TimelineKind>());
        // INV-06 / INV-15: Decision and Handoff aren't importable.
        SchemaEnum(root, "timelineEntry", "type").Should().BeEquivalentTo(
            Enum.GetNames<TimelineEntryType>().Where(n => !CaseImportSchema.NotImportableTimelineTypes.Contains(n)));
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

        prompt.Should().NotContain("\"newCase\": {").And.NotContain("- target.");
        prompt.Should().Contain("Do NOT include a \"target\"");
    }

    [Fact]
    public void The_prompt_describes_every_field_the_schema_has_so_a_new_one_reaches_the_AI()
    {
        // The prompt's FIELDS are generated from CaseImportSchema; this walks the schema on its own and checks each
        // field the importer reads (deprecated names aside) is there with its allowed values.
        var schema = JsonNode.Parse(CaseImportSchema.Build())!.AsObject();
        var defs = schema["$defs"]!.AsObject();
        var expected = new List<(string Path, JsonArray? Values)>();
        void Walk(string path, JsonObject obj)
        {
            foreach (var (name, node) in (obj["properties"] as JsonObject) ?? [])
            {
                var p = node!.AsObject();
                if (p["deprecated"]?.GetValue<bool>() == true) continue;
                var array = p["type"]?.GetValue<string>() == "array";
                var shape = (array ? p["items"] : p)!.AsObject();
                var full = (path.Length == 0 ? name : $"{path}.{name}") + (array ? "[]" : "");
                if (shape["$ref"]?.GetValue<string>() is { } r) Walk(full, defs[r.Split('/')[^1]]!.AsObject());
                else expected.Add((full, shape["enum"] as JsonArray));
            }
        }
        Walk("", schema);

        var prompt = CaseImportPrompt.Build();
        expected.Should().Contain(e => e.Path == "timeline[].tactics[]", "the walk reaches nested arrays");
        foreach (var (path, values) in expected)
        {
            var line = prompt.Split(Environment.NewLine.ToCharArray(), StringSplitOptions.RemoveEmptyEntries).FirstOrDefault(l => l.StartsWith($"- {path}:", StringComparison.Ordinal) || l.StartsWith($"- {path} (required):", StringComparison.Ordinal));
            line.Should().NotBeNull($"the schema's {path} should be in the prompt");
            foreach (var v in values ?? []) line.Should().Contain(v!.ToString());
        }
    }

    [Fact]
    public void Prompt_asks_for_the_cases_origin_and_the_attack_detail_that_tells_steps_from_milestones()
    {
        var open = CaseImportPrompt.Build(new CaseImportPromptOptions(ToolName: "Copilot"));
        open.Should().Contain("\"origin\": \"<InternalDetection or ThirdParty>\"").And.Contain("\"vendorName\"");
        open.Should().Contain("It is NOT who found the", "the document's provenance and the case's origin are told apart");
        open.Should().Contain("\"tactics\"").And.Contain("\"techniqueId\"").And.Contain("\"environment\"");
        open.Should().Contain("InitialAccess").And.Contain("Vendor, Ours", "allowed values come from the real enums");
        open.Should().Contain("disclosure milestones");

        var vendor = CaseImportPrompt.Build(new CaseImportPromptOptions(Origin: CaseOrigin.ThirdParty));
        vendor.Should().Contain("\"origin\": \"ThirdParty\"").And.Contain("disclosed to us by a vendor");

        // Whatever the AI writes, the preview reads it back: the document the prompt describes imports as it says.
        var p = CaseImportService.BuildPreviewCore(CaseImportService.Parse("""
            { "format": "casebook-case-import", "schemaVersion": 1, "origin": "AI-assisted (Copilot)",
              "target": { "newCase": { "title": "Payroll vendor breach", "origin": "ThirdParty", "vendorName": "Acme" } },
              "timeline": [
                { "occurredAt": "2026-10-01T10:00:00Z", "kind": "Event", "type": "Other", "tactics": ["InitialAccess"],
                  "techniqueId": "T1190", "environment": "Vendor", "description": "Exploited the transfer server" },
                { "occurredAt": "2026-10-03T10:00:00Z", "kind": "Event", "type": "Notified", "description": "Acme told us" } ] }
            """).Document!, _clock.UtcNow);
        p.NewCase!.Origin.Should().Be(CaseOrigin.ThirdParty);
        p.Timeline[0].HasAttackDetail.Should().BeTrue();
        p.Timeline[1].HasAttackDetail.Should().BeFalse();
        p.Warnings.Should().BeEmpty();
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
    public void Preview_clamps_to_the_database_column_lengths()
    {
        // BUG-02: SQL Server enforces these (SQLite doesn't), so an over-long value would fail the whole apply.
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Origin = new string('o', 500),
            Timeline = new() { new() { OccurredAtUtc = _clock.UtcNow.AddHours(-1), Description = "x", Source = new string('s', 500) } },
            Entities = new() { new() { Value = "10.0.0.5", Description = new string('d', 6000), Source = new string('s', 500) } }
        };

        var p = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow);

        p.Origin!.Length.Should().Be(200);
        p.Timeline.Single().Source!.Length.Should().Be(200);
        p.Entities.Single().Source!.Length.Should().Be(200);
        p.Entities.Single().Description!.Length.Should().Be(4000);
        p.Warnings.Should().Contain(w => w.Contains("Entity description"));
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

    [Theory]
    [InlineData("AdverseEvent,Incident")]   // flags 1|2 would read as Breach
    [InlineData("7")]                        // no such rung
    [InlineData("2")]                        // a number, even one that exists, isn't a name
    public void An_enum_value_must_be_a_name(string classification /* BUG-115 */)
    {
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Target = new CaseImportTarget { NewCase = new CaseImportNewCase { Title = "t", Classification = classification, Severity = "9" } },
            Entities = new() { new() { Type = "99", Value = "203.0.113.9" } }
        };

        var p = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow);

        p.NewCase!.Classification.Should().BeNull("an unknown classification files a Complex Event, with a warning");
        p.NewCase.Severity.Should().Be(Severity.Medium);
        p.Entities.Single().Type.Should().Be(EntityType.IpAddress, "an unknown type is detected from the value");
        p.Warnings.Should().Contain(w => w.Contains(classification));
    }

    [Fact]
    public void A_third_party_import_carries_its_vendor(/* BUG-117 */)
    {
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Target = new CaseImportTarget { NewCase = new CaseImportNewCase { Title = "Vendor breach", Origin = "ThirdParty", VendorName = "ClaimStream" } }
        };

        var nc = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow).NewCase!;

        nc.Origin.Should().Be(CaseOrigin.ThirdParty);
        nc.VendorName.Should().Be("ClaimStream");
        new IncidentManager.Application.Cases.CreateCaseValidator().Validate(nc).IsValid.Should().BeTrue();
    }

    [Fact]
    public void The_xsiam_playbook_sample_imports_cleanly(/* PROD-05 */)
    {
        var root = FindRepoRoot();
        root.Should().NotBeNull();
        var json = File.ReadAllText(Path.Combine(root!, "integrations", "xsiam", "sample-elevation.json"));

        var parsed = CaseImportService.Parse(json);
        parsed.Ok.Should().BeTrue(parsed.Error);
        // BUG-528: previewed after the sample's detection (this class's clock is earlier), as any real import of it is.
        var p = CaseImportService.BuildPreviewCore(parsed.Document!, parsed.Document!.Target!.NewCase!.DetectedAtUtc!.Value.AddDays(1));

        p.Warnings.Should().BeEmpty();
        p.NewCase!.DetectedAtUtc.Should().NotBeNull();
        p.NewCase.Classification.Should().BeNull();
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
    public void A_null_row_in_any_list_is_skipped_and_counted_not_a_crash(/* BUG-473 */)
    {
        const string json = """
            { "format": "casebook-case-import", "schemaVersion": 1,
              "timeline": [ null, { "description": "Seen", "occurredAtUtc": "2026-09-19T13:05:00Z" } ],
              "entities": [ null, null, { "value": "203.0.113.66" } ],
              "actionItems": [ null ] }
            """;

        var parsed = CaseImportService.Parse(json);
        parsed.Ok.Should().BeTrue(parsed.Error);
        var p = CaseImportService.BuildPreviewCore(parsed.Document!, _clock.UtcNow);

        p.Timeline.Should().ContainSingle(t => t.Description == "Seen");
        p.Entities.Should().ContainSingle(e => e.Value == "203.0.113.66");
        p.ActionItems.Should().BeEmpty();
        p.Warnings.Should().Contain("1 timeline entry had no description and was skipped.")
            .And.Contain("2 entities had no value and were skipped.")
            .And.Contain("1 task had no title and was skipped.");
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

    // ── ST-03: event steps with their times as stated ──────────────────────────────────────────

    [Fact]
    public async Task Event_steps_import_with_their_times_as_stated_in_document_order()
    {
        var d = new DateTimeOffset(2026, 9, 2, 0, 0, 0, TimeSpan.Zero);
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Origin = "AI-assisted",
            Target = new() { NewCase = new() { Title = "Vendor breach", Classification = "Incident", Severity = "High" } },
            Timeline = new()
            {
                new() { Kind = "Event", Type = "Other", Description = "Phished an engineer", OccurredAtUtc = d, TimePrecision = "Window", OccurredUntilUtc = d.AddDays(3) },
                new() { Kind = "Event", Type = "Other", Description = "Read the claims API", TimePrecision = "NotStated" },
                new() { Kind = "Event", Type = "Other", Description = "Exported the data", OccurredAtUtc = d.AddDays(6), TimePrecision = "day" },
                new() { Kind = "Event", Type = "Other", Description = "No date given", TimePrecision = "OnOrBefore" },
            }
        };

        var p = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow);
        p.Timeline.Select(t => t.Precision).Should().Equal(TimePrecision.Window, TimePrecision.NotStated, TimePrecision.Day, TimePrecision.NotStated);
        p.Timeline[1].Warning.Should().BeNull("a step with no stated time isn't missing a timestamp");
        p.Timeline[3].Warning.Should().Contain("time not stated");

        await using var db = NewContext();
        var result = await NewImportService(db).ApplyAsync(await NewImportService(db).BuildPreviewAsync(doc));
        await using var verify = NewContext();
        var steps = (await verify.Set<TimelineEntry>().Where(t => t.CaseId == result.CaseId).ToListAsync()).InTimelineOrder().ToList();
        steps.Select(s => s.Description).Should().Equal("Phished an engineer", "Read the claims API", "Exported the data", "No date given");
        steps[0].OccurredUntilUtc.Should().Be(new DateTimeOffset(2026, 9, 5, 12, 0, 0, TimeSpan.Zero));
        steps[3].OccurredPrecision.Should().Be(TimePrecision.NotStated);
    }

    [Fact]
    public async Task A_long_timeline_and_task_list_import_in_batches_in_document_order(/* BUG-255 */)
    {
        // Past one batch (EntitiesPerSave), with not-stated steps that follow the one before them across the boundary.
        var d = new DateTimeOffset(2026, 9, 2, 0, 0, 0, TimeSpan.Zero);
        var n = CaseService.EntitiesPerSave + 50;
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Target = new() { NewCase = new() { Title = "Long record", Classification = "Incident", Severity = "High" } },
            Timeline = Enumerable.Range(0, n).Select(i => i % 3 == 2
                ? new CaseImportTimelineEntry { Kind = "Event", Type = "Other", Description = $"Step {i}", TimePrecision = "NotStated" }
                : new CaseImportTimelineEntry { Kind = "Event", Type = "Other", Description = $"Step {i}", OccurredAtUtc = d.AddMinutes(i) }).ToList(),
            ActionItems = Enumerable.Range(0, n).Select(i => new CaseImportActionItem { Title = $"Task {i}" }).ToList(),
        };

        await using var db = NewContext();
        var svc = NewImportService(db);
        var result = await svc.ApplyAsync(await svc.BuildPreviewAsync(doc));
        result.Timeline.Should().Be(n);
        await using var verify = NewContext();
        var steps = (await verify.Set<TimelineEntry>().Where(t => t.CaseId == result.CaseId).ToListAsync()).InTimelineOrder().ToList();
        steps.Select(s => s.Description).Should().Equal(Enumerable.Range(0, n).Select(i => $"Step {i}"));
        (await verify.ActionItems.CountAsync(a => a.CaseId == result.CaseId)).Should().Be(n);
    }

    [Fact]
    public async Task An_import_can_create_a_tabletop_case_with_a_chosen_number(/* BUG-635, BUG-637 */)
    {
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Target = new() { NewCase = new() { Title = "Ransomware tabletop", Classification = "Incident", Severity = "High", Exercise = true } },
            Entities = [new CaseImportEntity { Type = "IpAddress", Value = "203.0.113.77" }],
        };

        await using var db = NewContext();
        var svc = NewImportService(db);
        var preview = await svc.BuildPreviewAsync(doc);
        preview.NewCase!.IsExercise.Should().BeTrue("the document asks for a tabletop case");
        preview.NewCase.CaseNumber = "TTX-2026-Q4";   // chosen on the preview, as on the New case form
        var result = await svc.ApplyAsync(preview);

        await using var verify = NewContext();
        var c = await verify.Cases.AsNoTracking().SingleAsync(x => x.Id == result.CaseId);
        c.IsExercise.Should().BeTrue();
        c.CaseNumber.Should().Be("TTX-2026-Q4");

        var live = await NewImportService(db).BuildPreviewAsync(new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Target = new() { NewCase = new() { Title = "Live one", Severity = "Low" } },
        });
        live.NewCase!.IsExercise.Should().BeFalse("a document that doesn't say so makes a live case");
    }

    [Fact]
    public async Task A_retried_import_places_a_not_stated_step_after_the_step_applied_last_time()
    {
        // BUG-15: the retry skipped already-applied rows without remembering them, so the next not-stated step went first.
        var d = new DateTimeOffset(2026, 9, 2, 9, 0, 0, TimeSpan.Zero);
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Target = new() { NewCase = new() { Title = "Vendor breach", Classification = "Incident", Severity = "High" } },
            Timeline = new()
            {
                new() { Kind = "Event", Type = "Other", Description = "Initial access", OccurredAtUtc = d },
                new() { Kind = "Event", Type = "Other", Description = "Lateral movement", TimePrecision = "NotStated" },
                new() { Kind = "Event", Type = "Other", Description = "Exfiltration", OccurredAtUtc = d.AddDays(5) },
            }
        };
        await using var db = NewContext();
        var svc = NewImportService(db);
        var p = await svc.BuildPreviewAsync(doc);

        // The first attempt gets as far as the first step, then stops.
        p.Timeline[1].Include = p.Timeline[2].Include = false;
        var first = await svc.ApplyAsync(p);
        p.Timeline[1].Include = p.Timeline[2].Include = true;
        await svc.ApplyAsync(p);

        await using var verify = NewContext();
        var steps = (await verify.Set<TimelineEntry>().Where(t => t.CaseId == first.CaseId).ToListAsync()).InTimelineOrder().ToList();
        steps.Select(s => s.Description).Should().Equal("Initial access", "Lateral movement", "Exfiltration");
    }

    [Fact]
    public async Task A_not_stated_step_that_opens_the_document_comes_before_the_stated_ones(/* BUG-118 */)
    {
        var d = new DateTimeOffset(2026, 9, 1, 9, 0, 0, TimeSpan.Zero);
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Target = new() { NewCase = new() { Title = "Intrusion", Classification = "Incident", Severity = "High" } },
            Timeline = new()
            {
                new() { Kind = "Event", Type = "Other", Description = "Initial access", TimePrecision = "NotStated" },
                new() { Kind = "Event", Type = "Other", Description = "Lateral movement", OccurredAtUtc = d },
            }
        };
        await using var db = NewContext();
        var svc = NewImportService(db);
        var result = await svc.ApplyAsync(await svc.BuildPreviewAsync(doc));

        await using var verify = NewContext();
        var steps = (await verify.Set<TimelineEntry>().Where(t => t.CaseId == result.CaseId && t.Kind == TimelineKind.Event)
            .ToListAsync()).InTimelineOrder().ToList();
        steps.Select(s => s.Description).Should().Equal("Initial access", "Lateral movement");
        steps[0].OccurredAtUtc.Should().BeOnOrBefore(d, "it isn't dated at import time, after the step it precedes");
    }

    [Fact]
    public async Task A_not_stated_opening_step_comes_before_a_date_only_one_written_late_in_its_day(/* BUG-174 */)
    {
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Target = new() { NewCase = new() { Title = "Intrusion", Classification = "Incident", Severity = "High" } },
            Timeline = new()
            {
                new() { Kind = "Event", Type = "Other", Description = "Initial access", TimePrecision = "NotStated" },
                new() { Kind = "Event", Type = "Other", Description = "Exfiltration", TimePrecision = "Day",
                    OccurredAtUtc = new DateTimeOffset(2026, 3, 1, 18, 0, 0, TimeSpan.Zero) },
            }
        };
        await using var db = NewContext();
        var svc = NewImportService(db);
        var result = await svc.ApplyAsync(await svc.BuildPreviewAsync(doc));

        await using var verify = NewContext();
        (await verify.Set<TimelineEntry>().Where(t => t.CaseId == result.CaseId && t.Kind == TimelineKind.Event).ToListAsync())
            .InTimelineOrder().Select(s => s.Description).Should().Equal("Initial access", "Exfiltration");
    }

    [Fact]
    public void A_long_indicator_is_kept_whole_up_to_its_column_and_left_out_beyond_it(/* BUG-175 */)
    {
        var url1500 = "https://phish.example/" + new string('a', 1478);
        var url2100 = "hxxps://phish[.]example/" + new string('b', 2076);
        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Entities = new() { new() { Value = url1500 }, new() { Value = url2100 } }
        };

        var p = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow);

        p.Entities.Should().ContainSingle().Which.Value.Should().Be(url1500, "it fits the column, so it isn't cut");
        p.Warnings.Should().Contain(w => w.Contains("2,098 characters") && w.Contains("wasn't imported"));
    }

    // ── Apply (integration) ──────────────────────────────────────────────────────────────────────

    public static TheoryData<int?, int?, bool, bool> BadCaseTimes => new()
    {
        // detected (days from now), occurred (days from now), detected kept, occurred kept
        { 2, null, false, true },          // detected in the future
        { 2, -1, false, true },            // detected in the future; occurred checked against filing time instead
        { 2, 1, false, false },            // both in the future
        { -5, 1, true, false },            // activity in the future
        { -5, -2, true, false },           // activity after detection
        { null, 3, true, false },          // no detected time: activity after filing time
        { -5, -5 - 366 * 10, true, false },  // dwell over Case.MaxDwellYears
        { -5, -5 - 365 * 9, true, true },  // a long but plausible dwell is kept
    };

    [Theory, MemberData(nameof(BadCaseTimes))]
    public async Task A_new_case_time_create_would_refuse_is_left_out_with_a_warning_so_apply_succeeds(
        int? detectedDays, int? occurredDays, bool detectedKept, bool occurredKept /* BUG-528 */)
    {
        var now = _clock.UtcNow;
        DateTimeOffset? detected = detectedDays is { } d ? now.AddDays(d) : null;
        DateTimeOffset? occurred = occurredDays is { } o ? now.AddDays(o) : null;
        var doc = FullDoc();
        doc.Target!.NewCase!.DetectedAtUtc = detected;
        doc.Target.NewCase.OccurredAtUtc = occurred;

        await using var db = NewContext();
        var svc = NewImportService(db);
        var preview = await svc.BuildPreviewAsync(doc);
        preview.NewCase!.DetectedAtUtc.Should().Be(detectedKept ? detected : null);
        preview.NewCase.OccurredAtUtc.Should().Be(occurredKept ? occurred : null);
        preview.Warnings.Count(w => w.Contains("was left out")).Should().Be((detectedKept ? 0 : 1) + (occurredKept ? 0 : 1));

        var result = await svc.ApplyAsync(preview);   // refused by CreateAsync before the fix
        var c = await db.Cases.AsNoTracking().SingleAsync(x => x.Id == result.CaseId);
        c.DetectedAtUtc.Should().Be(detectedKept && detected is not null ? detected.Value : now);
        c.OccurredAtUtc.Should().Be(occurredKept ? occurred : null);
    }

    [Fact]
    public void A_detected_time_in_the_first_years_of_the_calendar_does_not_break_the_preview(/* BUG-528 */)
    {
        var doc = FullDoc();
        doc.Target!.NewCase!.DetectedAtUtc = new DateTimeOffset(5, 1, 1, 0, 0, 0, TimeSpan.Zero);
        doc.Target.NewCase.OccurredAtUtc = new DateTimeOffset(4, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var nc = CaseImportService.BuildPreviewCore(doc, _clock.UtcNow).NewCase!;

        nc.OccurredAtUtc.Should().BeNull("CreateAsync can't check its dwell, so it would refuse it");
    }

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
            timeline.Single().IsImported.Should().BeTrue("INV-23: marked as imported, not as recorded later");

            var chain = await verify.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task An_imported_indicator_keeps_its_TLP_and_only_raises_one_already_on_the_case(/* BUG-152 */)
    {
        Guid caseId, onCase;
        await using (var db = NewContext())
        {
            var cases = NewCaseService(db);
            caseId = (await cases.CreateAsync(new CreateCaseRequest
            {
                DescriptiveName = "Partner", Title = "Partner intel",
                Classification = Classification.Incident, Severity = Severity.Medium, Origin = CaseOrigin.InternalDetection
            })).Id;
            onCase = await cases.AddEntityAsync(caseId, EntityType.Domain, "partner-only.example", null, EntityDisposition.Malicious, null, null);
            await cases.SetEntityTlpAsync(caseId, onCase, TlpLevel.AmberStrict);
        }

        var doc = new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag,
            Entities = new()
            {
                new() { Value = "198.51.100.7", Tlp = "TLP:RED" },
                new() { Value = "partner-only.example", Tlp = "Green" },   // lower than the case has: kept as it is
                new() { Value = "open.example", Tlp = "Purple" },
            }
        };
        await using (var db = NewContext())
        {
            var svc = NewImportService(db);
            var preview = await svc.BuildPreviewAsync(doc, intoCaseId: caseId);
            preview.Warnings.Should().Contain(w => w.Contains("Unknown TLP marking 'Purple'"));
            await svc.ApplyAsync(preview);
        }

        await using var verify = NewContext();
        var tlp = await verify.Set<CaseEntity>().Where(e => e.CaseId == caseId).ToDictionaryAsync(e => e.Value, e => e.Tlp);
        tlp["198.51.100.7"].Should().Be(TlpLevel.Red);
        tlp["partner-only.example"].Should().Be(TlpLevel.AmberStrict, "an import never lowers a marking");
        tlp["open.example"].Should().BeNull();
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
    public async Task A_decision_imports_with_its_why_and_one_without_becomes_communication()
    {
        // INV-18: decisions travel through the import with their rationale.
        var doc = FullDoc();
        doc.Timeline = new()
        {
            new() { OccurredAtUtc = new DateTimeOffset(2026, 9, 19, 9, 0, 0, TimeSpan.Zero), Type = "Decision",
                    Description = "Reset all three users' credentials", Rationale = "Sign-in logs for two users are incomplete",
                    OptionsConsidered = "Reset only the confirmed user", DecidedBy = "Incident Commander" },
            new() { OccurredAtUtc = new DateTimeOffset(2026, 9, 19, 9, 30, 0, TimeSpan.Zero), Type = "Decision",
                    Description = "Notify the carrier" },
        };

        Guid caseId;
        await using (var db = NewContext())
        {
            var svc = NewImportService(db);
            var preview = await svc.BuildPreviewAsync(doc);
            preview.Timeline[0].Type.Should().Be(TimelineEntryType.Decision);
            preview.Timeline[1].Type.Should().Be(TimelineEntryType.Communication);
            preview.Timeline[1].Warning.Should().Contain("needs its why");
            caseId = (await svc.ApplyAsync(preview)).CaseId;
        }

        await using (var verify = NewContext())
        {
            var decision = await verify.Set<TimelineEntry>().SingleAsync(t => t.CaseId == caseId && t.Type == TimelineEntryType.Decision);
            decision.Rationale.Should().Be("Sign-in logs for two users are incomplete");
            decision.OptionsConsidered.Should().Be("Reset only the confirmed user");
            decision.DecidedBy.Should().Be("Incident Commander");
        }
    }

    [Fact]
    public async Task Applying_a_decision_row_without_a_why_is_refused_before_anything_is_written()
    {
        await using var db = NewContext();
        var svc = NewImportService(db);
        var preview = await svc.BuildPreviewAsync(FullDoc());
        preview.Timeline[0].Type = TimelineEntryType.Decision;   // changed in the preview, no why given

        var act = () => svc.ApplyAsync(preview);

        await act.Should().ThrowAsync<ArgumentException>();
        (await db.Cases.CountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task A_retried_api_submission_is_not_queued_twice(/* BUG-217 */)
    {
        await using var db = NewContext();
        var svc = NewImportService(db);
        var json = FullDocJson();
        var doc = CaseImportService.Parse(json).Document!;

        var first = await svc.SubmitOnceAsync(json, doc);
        var retry = await svc.SubmitOnceAsync(json, doc);
        retry.AlreadyQueued.Should().BeTrue();
        retry.Id.Should().Be(first.Id);
        (await svc.CountPendingAsync()).Should().Be(1);
        // WF-23: matched by the hash it's stored with; one queued before hashes were recorded is matched by its text.
        (await db.PendingImports.AsNoTracking().SingleAsync(p => p.Id == first.Id)).RawJsonSha256.Should().HaveLength(64);
        await db.PendingImports.Where(p => p.Id == first.Id).ExecuteUpdateAsync(u => u.SetProperty(p => p.RawJsonSha256, (string?)null));
        (await svc.SubmitOnceAsync(json, doc)).Id.Should().Be(first.Id);

        // REV-57: a body ending in spaces too (SQL Server's LEN ignores them; ReviewProviderTests runs this on SQL Server).
        var spaced = json + "  ";
        var once = await svc.SubmitOnceAsync(spaced, doc);
        (await svc.SubmitOnceAsync(spaced, doc)).Id.Should().Be(once.Id);
        (await svc.CountPendingAsync()).Should().Be(2);

        // A different document, or the same one a day later, is a new submission.
        (await svc.SubmitOnceAsync(json.Replace("Phishing", "Vishing"), CaseImportService.Parse(json.Replace("Phishing", "Vishing")).Document!))
            .AlreadyQueued.Should().BeFalse();
        _clock.UtcNow = _clock.UtcNow.Add(CaseImportService.RetryWindow).AddMinutes(1);
        (await svc.SubmitOnceAsync(json, doc)).AlreadyQueued.Should().BeFalse();
    }

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
    public async Task A_reject_reason_longer_than_its_column_is_refused_and_the_import_stays_waiting(/* C12 */)
    {
        // The reject is one ExecuteUpdate; on SQL Server a note over 2,000 characters failed it with a raw exception.
        Guid pid;
        await using (var db = NewContext())
        {
            var json = FullDocJson();
            (pid, _) = await NewImportService(db).SubmitAsync(json, CaseImportService.Parse(json).Document!);
        }
        await using var ctx = NewContext();
        var svc = NewImportService(ctx);

        await svc.Invoking(s => s.RejectPendingAsync(pid, new string('n', 2001)))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*2,000 characters*");
        (await ctx.Set<PendingImport>().AsNoTracking().FirstAsync(p => p.Id == pid)).Status.Should().Be(PendingImportStatus.Pending);

        (await svc.RejectPendingAsync(pid, new string('n', 2000))).Should().BeTrue();
        GeneratedTextFitsColumnTests.AssertFits(ctx, await ctx.Set<PendingImport>().AsNoTracking().FirstAsync(p => p.Id == pid));
    }

    [Fact]
    public async Task A_pending_import_can_be_claimed_by_one_reviewer_only()
    {
        // BUG-13: two reviewers (or two tabs) used to both apply it, creating two cases.
        Guid pid;
        await using (var db = NewContext())
        {
            var json = FullDocJson();
            (pid, _) = await NewImportService(db).SubmitAsync(json, CaseImportService.Parse(json).Document!);
        }

        await using var ctx = NewContext();
        var svc = NewImportService(ctx);
        (await svc.ClaimPendingAsync(pid)).Should().NotBeNull();
        // BUG-198: the same reviewer's other tab, while the first is still applying.
        (await svc.ClaimPendingAsync(pid)).Should().BeNull("an apply is in progress");

        var someoneElse = _user.UserId;
        _user.UserId = "analyst2";
        try
        {
            (await svc.ClaimPendingAsync(pid)).Should().BeNull("another reviewer has it");
            (await svc.RejectPendingAsync(pid, "dup")).Should().BeFalse("BUG-92: the reject says it didn't happen");
        }
        finally { _user.UserId = someoneElse; }

        var row = await ctx.Set<PendingImport>().AsNoTracking().FirstAsync(p => p.Id == pid);
        row.Status.Should().Be(PendingImportStatus.Applied, "a claimed import can't be rejected out from under its reviewer");
        row.DecidedBy.Should().Be(someoneElse);

        // A claim left behind (the apply and its release both failed) can be taken again once it's stale.
        _clock.UtcNow = _clock.UtcNow.Add(CaseImportService.StaleClaim);
        (await svc.ClaimPendingAsync(pid)).Should().NotBeNull();
    }

    [Fact]
    public async Task Any_reviewer_can_reopen_an_import_whose_apply_stopped(/* WF-18 */)
    {
        Guid pid;
        await using (var db = NewContext())
        {
            var json = FullDocJson();
            (pid, _) = await NewImportService(db).SubmitAsync(json, CaseImportService.Parse(json).Document!);
        }
        await using var ctx = NewContext();
        var audit = new IncidentManager.Infrastructure.Security.AuditWriter(NewFactory(), _hasher, _user, _clock);
        var svc = new CaseImportService(NewFactory(), _user, _clock, NewCaseService(ctx), audit);
        (await svc.ClaimPendingAsync(pid)).Should().NotBeNull();   // then the process recycles mid-apply

        (await svc.ListPendingAsync()).Should().NotContain(p => p.Id == pid, "an apply may still be running");
        (await svc.ReopenStuckAsync(pid)).Should().BeFalse();

        _clock.UtcNow = _clock.UtcNow.Add(CaseImportService.StaleClaim).AddMinutes(1);
        (await svc.ListPendingAsync()).Should().ContainSingle(p => p.Id == pid).Which.StuckClaimedBy.Should().Be(_user.UserId);

        var claimer = _user.UserId;
        _user.UserId = "analyst2";   // another reviewer
        var culture = System.Globalization.CultureInfo.CurrentCulture;
        System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("th-TH");   // BUG-531
        try { (await svc.ReopenStuckAsync(pid)).Should().BeTrue(); }
        finally { _user.UserId = claimer; System.Globalization.CultureInfo.CurrentCulture = culture; }

        (await svc.ListPendingAsync()).Should().ContainSingle(p => p.Id == pid).Which.StuckClaimedBy.Should().BeNull();
        (await svc.BuildPreviewForPendingAsync(pid)).Should().NotBeNull();
        // BUG-531: saved text is in the invariant calendar, whatever the server culture (reopened below under th-TH).
        (await ctx.PendingImports.AsNoTracking().SingleAsync(p => p.Id == pid)).DecisionNote.Should().Contain("at 2026-09-20 12:00 UTC");
        (await ctx.AuditLog.AsNoTracking().AnyAsync(a => a.EntityType == "PendingImport" && a.Summary!.Contains("Reopened a stuck import") && a.Summary.Contains("at 2026-09-20 12:00 UTC")))
            .Should().BeTrue();
    }

    [Fact]
    public async Task A_second_tabs_apply_cannot_record_or_release_the_first_tabs_claim(/* BUG-198 */)
    {
        Guid pid;
        await using (var db = NewContext())
        {
            var json = FullDocJson();
            (pid, _) = await NewImportService(db).SubmitAsync(json, CaseImportService.Parse(json).Document!);
        }
        await using var ctx = NewContext();
        var svc = NewImportService(ctx);
        var preview = (await svc.BuildPreviewForPendingAsync(pid))!;
        var first = await svc.ClaimPendingAsync(pid);

        await svc.ReleaseClaimAsync(pid, preview, first!.Value.AddTicks(1));   // not this claim
        (await ctx.Set<PendingImport>().AsNoTracking().FirstAsync(p => p.Id == pid)).Status
            .Should().Be(PendingImportStatus.Applied, "the first tab is still applying");

        var result = await svc.ApplyAsync(preview);
        await svc.MarkPendingAppliedAsync(pid, result, first);
        (await ctx.Set<PendingImport>().AsNoTracking().FirstAsync(p => p.Id == pid)).ResolvedCaseId.Should().Be(result.CaseId);
    }

    [Fact]
    public async Task A_failed_apply_puts_the_import_back_in_the_queue_and_reopening_it_writes_nothing_twice(/* BUG-116, BUG-146 */)
    {
        Guid pid;
        await using (var db = NewContext())
        {
            var json = FullDocJson();
            (pid, _) = await NewImportService(db).SubmitAsync(json, CaseImportService.Parse(json).Document!);
        }

        Guid caseId;
        await using (var ctx = NewContext())
        {
            // Everything is written, then recording the result fails, so the page puts the import back.
            var svc = NewImportService(ctx);
            var preview = (await svc.BuildPreviewForPendingAsync(pid))!;
            var claim = await svc.ClaimPendingAsync(pid);
            claim.Should().NotBeNull();
            caseId = (await svc.ApplyAsync(preview)).CaseId;
            await svc.ReleaseClaimAsync(pid, preview, claim);

            var row = await ctx.Set<PendingImport>().AsNoTracking().FirstAsync(p => p.Id == pid);
            row.Status.Should().Be(PendingImportStatus.Pending);
            row.DecidedBy.Should().BeNull();
            row.TargetCaseId.Should().Be(caseId, "a retry carries on into the case the first try created");
            (await svc.ListPendingAsync()).Should().Contain(p => p.Id == pid);
        }

        async Task<int[]> Counts(AppDbContext db) =>
        [
            await db.Set<Case>().CountAsync(),
            await db.Set<AnalystNote>().CountAsync(n => n.CaseId == caseId),
            await db.Set<TimelineEntry>().CountAsync(t => t.CaseId == caseId),
            await db.Set<ActionItem>().CountAsync(a => a.CaseId == caseId),
            await db.Set<CaseEntity>().CountAsync(e => e.CaseId == caseId),
        ];

        await using (var again = NewContext())
        {
            var before = await Counts(again);
            var svc = NewImportService(again);
            var reopened = (await svc.BuildPreviewForPendingAsync(pid))!;
            reopened.CreatedCaseId.Should().Be(caseId);
            CaseImportService.HasApplied(reopened).Should().BeTrue("the target stays locked to the created case");
            reopened.Warnings.Should().Contain(w => w.Contains("stopped part-way"));

            var claim = await svc.ClaimPendingAsync(pid);
            claim.Should().NotBeNull();
            var result = await svc.ApplyAsync(reopened);
            await svc.MarkPendingAppliedAsync(pid, result, claim);

            result.CaseId.Should().Be(caseId);
            (await Counts(again)).Should().Equal(before, "nothing the first apply wrote is written again");
            (await again.Set<PendingImport>().AsNoTracking().FirstAsync(p => p.Id == pid)).ResumeJson.Should().BeNull();
        }
    }

    [Fact]
    public async Task A_resumed_import_reopened_after_a_stopped_apply_warns_it_may_write_again(/* BUG-541 */)
    {
        Guid pid;
        await using (var db = NewContext())
        {
            var json = FullDocJson();
            (pid, _) = await NewImportService(db).SubmitAsync(json, CaseImportService.Parse(json).Document!);
        }
        await using var ctx = NewContext();
        var svc = NewImportService(ctx);

        // A first apply fails part-way and is put back with what it wrote (ResumeJson).
        var preview = (await svc.BuildPreviewForPendingAsync(pid))!;
        var claim = await svc.ClaimPendingAsync(pid);
        preview.Timeline.ForEach(t => t.Include = false);
        await svc.ApplyAsync(preview);
        preview.Timeline.ForEach(t => t.Include = true);
        await svc.ReleaseClaimAsync(pid, preview, claim);
        (await ctx.PendingImports.AsNoTracking().SingleAsync(p => p.Id == pid)).ResumeJson.Should().NotBeNull();

        // A second one is claimed and then stops without recording or releasing (a recycle), and is reopened.
        var resumed = (await svc.BuildPreviewForPendingAsync(pid))!;
        resumed.Warnings.Should().Contain(w => w.Contains("won't be written again"));
        // BUG-556: a second failed apply saves the resumed preview, warnings and all, before the stopped one.
        var claim2 = await svc.ClaimPendingAsync(pid);
        await svc.ReleaseClaimAsync(pid, resumed, claim2);
        (await svc.BuildPreviewForPendingAsync(pid))!.Warnings.Should().ContainSingle(w => w.Contains("won't be written again"));
        (await svc.ClaimPendingAsync(pid)).Should().NotBeNull();
        _clock.UtcNow = _clock.UtcNow.Add(CaseImportService.StaleClaim).AddMinutes(1);
        (await svc.ReopenStuckAsync(pid)).Should().BeTrue();

        var reopened = (await svc.BuildPreviewForPendingAsync(pid))!;
        reopened.CreatedCaseId.Should().Be(preview.CreatedCaseId, "known writes stay marked, so the case isn't filed twice");
        reopened.Warnings.Should().Contain(w => w.Contains("stopped without finishing") && w.Contains(_user.UserId)
                                              && w.Contains("may have written more than the items marked"));
        reopened.Warnings.Should().NotContain(w => w.Contains("won't be written again"),
            "the stopped apply's own writes were never recorded");

        // And one more failed apply after the reopen still shows the warning once.
        var claim3 = await svc.ClaimPendingAsync(pid);
        await svc.ReleaseClaimAsync(pid, reopened, claim3);
        (await svc.BuildPreviewForPendingAsync(pid))!.Warnings.Should()
            .ContainSingle(w => w.Contains("may have written more than the items marked"))
            .And.NotContain(w => w.Contains("won't be written again"));
    }

    [Fact]
    public async Task A_classification_the_role_cannot_file_is_dropped_from_the_preview(/* BUG-542 */)
    {
        _user.PermissionSet = [Permission.ViewCases, Permission.EditCases];   // no ChangeClassification (REV-14)
        await using var db = NewContext();
        var svc = NewImportService(db);
        var preview = await svc.BuildPreviewAsync(FullDoc());
        preview.NewCase!.Classification.Should().BeNull("the role files Complex Events");
        preview.Warnings.Should().Contain(w => w.Contains("Incident") && w.Contains("can't file"));

        var result = await svc.ApplyAsync(preview);   // not Forbidden
        (await db.Set<Case>().AsNoTracking().SingleAsync(c => c.Id == result.CaseId)).Classification.Should().BeNull();

        // Queued through the API by this role, a reviewer who can classify sees the document's classification.
        var json = FullDocJson();
        var (pid, submitted) = await svc.SubmitAsync(json, CaseImportService.Parse(json).Document!);
        submitted.NewCase!.Classification.Should().BeNull();
        _user.PermissionSet = null;
        var reviewed = (await NewImportService(db).BuildPreviewForPendingAsync(pid))!;
        reviewed.NewCase!.Classification.Should().Be(Classification.Incident);
        reviewed.Warnings.Should().NotContain(w => w.Contains("can't file"));
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

    [Fact]
    public async Task The_pending_queue_hides_submissions_into_a_case_the_reviewer_cannot_see()
    {
        // A restricted case the reviewer neither commands nor is assigned to.
        Guid restrictedId;
        string restrictedNumber;
        await using (var db = NewContext())
        {
            var c = Case.Open(2026, 77, "Secret", "Restricted matter", Classification.Breach, Severity.High,
                CaseOrigin.InternalDetection, "analyst1", _clock.UtcNow);
            c.IsRestricted = true;
            c.IncidentCommander = "commander1";
            db.Cases.Add(c);
            await db.SaveChangesAsync();
            (restrictedId, restrictedNumber) = (c.Id, c.CaseNumber);
        }

        // Submitted by someone who can see it (so its summary names the case), plus one with no target and one
        // whose target doesn't exist (it previews as a new case).
        Guid intoRestricted, untargeted, missingTarget;
        await using (var db = NewContext())
        {
            var svc = NewImportService(db);
            async Task<Guid> Submit(Guid? target)
            {
                var doc = FullDoc();
                doc.Target = new CaseImportTarget { CaseId = target, NewCase = doc.Target?.NewCase };
                var json = JsonSerializer.Serialize(doc, CaseImportJson.Options);
                return (await svc.SubmitAsync(json, CaseImportService.Parse(json).Document!)).Id;
            }
            intoRestricted = await Submit(restrictedId);
            untargeted = await Submit(null);
            missingTarget = await Submit(Guid.NewGuid());
            (await svc.ListPendingAsync()).Should().Contain(x => x.Id == intoRestricted && x.Summary.Contains(restrictedNumber));
        }

        var reviewer = new TestCurrentUser { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] };
        await using (var db = NewContext())
        {
            var svc = new CaseImportService(NewFactory(), reviewer, _clock, NewCaseService(db));
            var queue = await svc.ListPendingAsync();
            queue.Select(x => x.Id).Should().BeEquivalentTo([untargeted, missingTarget]);
            queue.Should().NotContain(x => x.Summary.Contains(restrictedNumber));
            (await svc.CountPendingAsync()).Should().Be(2);
            (await svc.BuildPreviewForPendingAsync(intoRestricted)).Should().BeNull();
            await svc.RejectPendingAsync(intoRestricted, "not mine");
        }

        await using (var verify = NewContext())
            (await verify.Set<PendingImport>().FirstAsync(p => p.Id == intoRestricted)).Status
                .Should().Be(PendingImportStatus.Pending, "a reviewer can't decide a submission they can't see");

        var commander = new TestCurrentUser { UserId = "commander1", RoleSet = [AppRole.Analyst] };
        await using (var db = NewContext())
            (await new CaseImportService(NewFactory(), commander, _clock, NewCaseService(db)).ListPendingAsync())
                .Should().Contain(x => x.Id == intoRestricted);

        // BUG-279: submitted by someone who can't see it, it's queued as the new case its preview prepared: listed to
        // reviewers, and never applied into the restricted case.
        Guid blindId;
        await using (var db = NewContext())
        {
            var svc = new CaseImportService(NewFactory(), reviewer, _clock, NewCaseService(db));
            var doc = FullDoc();
            doc.Target = new CaseImportTarget { CaseId = restrictedId, NewCase = doc.Target?.NewCase };
            var json = JsonSerializer.Serialize(doc, CaseImportJson.Options);
            var (blind, _) = await svc.SubmitAsync(json, CaseImportService.Parse(json).Document!);
            (await svc.ListPendingAsync()).Should().Contain(x => x.Id == blind);
            (await db.Set<PendingImport>().FirstAsync(p => p.Id == blind)).TargetCaseId.Should().BeNull();
            blindId = blind;
        }

        // BUG-334: and a reviewer who can see the case still previews it as the new case, not into the restricted one.
        await using (var db = NewContext())
        {
            var preview = await new CaseImportService(NewFactory(), commander, _clock, NewCaseService(db))
                .BuildPreviewForPendingAsync(blindId);
            preview.Should().NotBeNull();
            preview!.TargetKind.Should().Be(CaseImportTargetKind.NewCase);
            preview.ExistingCaseId.Should().BeNull();

            // A row queued into the case (by someone who could see it) still previews into it.
            var into = await new CaseImportService(NewFactory(), commander, _clock, NewCaseService(db))
                .BuildPreviewForPendingAsync(intoRestricted);
            into!.TargetKind.Should().Be(CaseImportTargetKind.ExistingCase);
            into.ExistingCaseId.Should().Be(restrictedId);
        }
    }

    // ── Origin: who found the case, and a third-party case's attack steps ────────────────────────────────────────

    private static CaseImportDocument OriginDoc(string? origin = null, string? vendor = null, string? docOrigin = null,
        params CaseImportTimelineEntry[] timeline) => new()
    {
        Format = CaseImportJson.FormatTag,
        Origin = docOrigin,
        Target = new CaseImportTarget { NewCase = new CaseImportNewCase { Title = "Vendor breach", Origin = origin, VendorName = vendor } },
        Timeline = timeline.ToList(),
    };

    [Fact]
    public void A_new_cases_origin_is_read_from_newCase_or_a_named_vendor_and_the_preview_says_which()
    {
        var plain = CaseImportService.BuildPreviewCore(OriginDoc(), _clock.UtcNow);
        plain.NewCase!.Origin.Should().Be(CaseOrigin.InternalDetection);
        plain.NewCaseOriginNote.Should().Contain("doesn't say");

        var vendor = CaseImportService.BuildPreviewCore(OriginDoc(vendor: "Acme Payroll"), _clock.UtcNow);
        vendor.NewCase!.Origin.Should().Be(CaseOrigin.ThirdParty, "a named vendor means a vendor told us");
        vendor.NewCaseOriginNote.Should().Contain("names a vendor");

        var word = CaseImportService.BuildPreviewCore(OriginDoc(origin: "third-party", vendor: "Acme"), _clock.UtcNow);
        word.NewCase!.Origin.Should().Be(CaseOrigin.ThirdParty);
        word.Warnings.Should().BeEmpty();

        // The document-level origin is provenance; a case origin written there is pointed out.
        var misplaced = CaseImportService.BuildPreviewCore(OriginDoc(docOrigin: "ThirdParty"), _clock.UtcNow);
        misplaced.NewCase!.Origin.Should().Be(CaseOrigin.InternalDetection);
        misplaced.Warnings.Should().Contain(w => w.Contains("where the import came from") && w.Contains("target.newCase.origin"));
    }

    [Fact]
    public void Event_steps_carry_their_attack_detail_and_one_without_is_a_disclosure_milestone()
    {
        var p = CaseImportService.BuildPreviewCore(OriginDoc("ThirdParty", "Acme", null,
            new CaseImportTimelineEntry
            {
                OccurredAtUtc = _clock.UtcNow.AddDays(-5), Kind = "Event", Description = "Exploited the vendor's transfer server",
                Tactics = ["Initial Access", "defense-evasion", "NotATactic"], TechniqueId = "t1190", Environment = "Vendor",
            },
            new CaseImportTimelineEntry { OccurredAtUtc = _clock.UtcNow.AddDays(-4), Kind = "Event", Description = "Reached our VPN", Environment = "our environment" },
            new CaseImportTimelineEntry { OccurredAtUtc = _clock.UtcNow.AddDays(-2), Kind = "Event", Type = "Notified", Description = "Vendor told us" },
            new CaseImportTimelineEntry { OccurredAtUtc = _clock.UtcNow.AddDays(-1), Kind = "Event", Description = "Bad id", TechniqueId = "X99" }), _clock.UtcNow);

        p.IntoThirdParty.Should().BeTrue();
        var exploit = p.Timeline[0];
        exploit.Tactics.Should().Equal(MitreTactic.InitialAccess, MitreTactic.Stealth);
        exploit.TechniqueId.Should().Be("T1190");
        exploit.Environment.Should().Be(StepEnvironment.Vendor);
        p.Timeline[1].Environment.Should().Be(StepEnvironment.Ours);
        p.Timeline[1].HasAttackDetail.Should().BeTrue();
        p.Timeline[2].HasAttackDetail.Should().BeFalse("a disclosure milestone");
        p.Timeline[3].TechniqueId.Should().BeNull();
        p.Warnings.Should().Contain(w => w.Contains("NotATactic")).And.Contain(w => w.Contains("X99"));
    }

    [Fact]
    public async Task Applied_to_a_third_party_case_the_attack_steps_and_milestones_come_out_as_previewed()
    {
        Guid caseId;
        await using (var db = NewContext())
        {
            var svc = NewImportService(db);
            var preview = await svc.BuildPreviewAsync(OriginDoc("ThirdParty", "Acme Payroll", "manual",
                new CaseImportTimelineEntry { OccurredAtUtc = _clock.UtcNow.AddDays(-5), Kind = "Event", Description = "Exploited the vendor's server",
                    Tactics = ["InitialAccess"], TechniqueId = "T1190" },
                new CaseImportTimelineEntry { OccurredAtUtc = _clock.UtcNow.AddDays(-4), Kind = "Event", Description = "Logged in to our VPN", Environment = "Ours" },
                new CaseImportTimelineEntry { OccurredAtUtc = _clock.UtcNow.AddDays(-2), Kind = "Event", Type = "Notified", Description = "Vendor told us" }));
            caseId = (await svc.ApplyAsync(preview)).CaseId;
        }
        await using (var verify = NewContext())
        {
            var c = await verify.Cases.Include(x => x.TimelineEntries).ThenInclude(t => t.Tactics).SingleAsync(x => x.Id == caseId);
            c.Origin.Should().Be(CaseOrigin.ThirdParty);
            var steps = c.TimelineEntries.OrderBy(t => t.OccurredAtUtc).ToList();
            EventSteps.IsAttack(c, steps[0]).Should().BeTrue();
            EventSteps.Where(c, steps[0]).Should().Be(StepEnvironment.Vendor);
            steps[0].TechniqueId.Should().Be("T1190");
            EventSteps.Where(c, steps[1]).Should().Be(StepEnvironment.Ours);
            EventSteps.IsDisclosure(c, steps[2]).Should().BeTrue();
            _hasher.VerifyChain(await verify.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
        }
    }

    [Fact]
    public async Task A_case_imported_as_internal_can_be_made_third_party_and_its_steps_stay_attack_steps()
    {
        Guid caseId;
        await using (var db = NewContext())
        {
            var svc = NewImportService(db);
            var preview = await svc.BuildPreviewAsync(OriginDoc(null, null, "manual",
                new CaseImportTimelineEntry { OccurredAtUtc = _clock.UtcNow.AddDays(-3), Kind = "Event", Description = "Phish delivered" }));
            caseId = (await svc.ApplyAsync(preview)).CaseId;
        }
        await using (var db = NewContext())
        {
            var cases = NewCaseService(db);
            var noVendor = () => cases.ChangeOriginAsync(caseId, CaseOrigin.ThirdParty, " ", null, null, "imported as the wrong origin");
            await noVendor.Should().ThrowAsync<ArgumentException>().WithMessage("*vendor*");
            var noReason = () => cases.ChangeOriginAsync(caseId, CaseOrigin.ThirdParty, "Acme", null, null, " ");
            await noReason.Should().ThrowAsync<ArgumentException>();
            await cases.ChangeOriginAsync(caseId, CaseOrigin.ThirdParty, "Acme Payroll", "security@acme.example", null, "imported as internal; Acme disclosed it",
                StepEnvironment.Vendor);
        }
        await using (var verify = NewContext())
        {
            var c = await verify.Cases.Include(x => x.TimelineEntries).ThenInclude(t => t.Tactics).SingleAsync(x => x.Id == caseId);
            c.Origin.Should().Be(CaseOrigin.ThirdParty);
            c.ThirdParty!.VendorName.Should().Be("Acme Payroll");
            var step = c.TimelineEntries.Single(t => t.Kind == TimelineKind.Event);
            EventSteps.IsAttack(c, step).Should().BeTrue("it was an attack step on the internal case, and stays one");
            EventSteps.Where(c, step).Should().Be(StepEnvironment.Vendor, "the person changing it said where the steps happened");
            c.TimelineEntries.Should().Contain(t => t.Kind == TimelineKind.Investigation && t.Description.Contains("Origin changed from internal detection to third-party (Acme Payroll)")
                && t.Description.Contains("1 attack step recorded before is marked as at the vendor"));
            _hasher.VerifyChain(await verify.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync()).IsValid.Should().BeTrue();
        }
        await using (var db = NewContext())
        {
            // Back to internal: its one step is an attack step, so it's allowed, and the vendor is cleared.
            await NewCaseService(db).ChangeOriginAsync(caseId, CaseOrigin.InternalDetection, null, null, null, "it was ours after all");
        }
        await using (var verify = NewContext())
        {
            var c = await verify.Cases.Include(x => x.TimelineEntries).SingleAsync(x => x.Id == caseId);
            c.Origin.Should().Be(CaseOrigin.InternalDetection);
            c.ThirdParty.Should().BeNull();
            c.TimelineEntries.Single(t => t.Kind == TimelineKind.Event).Environment.Should().BeNull();
        }
    }

    [Fact]
    public async Task A_third_party_case_with_disclosure_milestones_is_not_made_internal()
    {
        Guid caseId;
        await using (var db = NewContext())
        {
            var svc = NewImportService(db);
            var preview = await svc.BuildPreviewAsync(OriginDoc("ThirdParty", "Acme", "manual",
                new CaseImportTimelineEntry { OccurredAtUtc = _clock.UtcNow.AddDays(-2), Kind = "Event", Type = "Notified", Description = "Vendor told us" }));
            caseId = (await svc.ApplyAsync(preview)).CaseId;
        }
        await using (var db = NewContext())
        {
            var act = () => NewCaseService(db).ChangeOriginAsync(caseId, CaseOrigin.InternalDetection, null, null, null, "wrong");
            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*1 disclosure milestone*");
        }
        await using (var verify = NewContext())
            (await verify.Cases.SingleAsync(x => x.Id == caseId)).Origin.Should().Be(CaseOrigin.ThirdParty);
    }

    public void Dispose() => _connection.Dispose();
}
