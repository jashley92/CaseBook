using System.Reflection;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-06: the SIEM event ids are a contract (SOC rules pin to them), so each is used once and each is in the catalog
/// operators read (OPERATIONS.md §5); and the lifecycle events carry ids and labels only, capped, marked for an exercise.
/// </summary>
public sealed class SecurityEventCatalogTests
{
    private static readonly IReadOnlyList<(string Name, int Id)> Ids = typeof(SecurityEventIds)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.IsLiteral && f.FieldType == typeof(int))
        .Select(f => (f.Name, (int)f.GetRawConstantValue()!))
        .ToList();

    [Fact]
    public void Every_event_id_is_used_once()
    {
        Ids.Count.Should().BeGreaterThan(30);
        Ids.GroupBy(i => i.Id).Where(g => g.Count() > 1).Select(g => g.Key).Should().BeEmpty("an id names one event, for good");
    }

    [Fact]
    public void Every_event_id_is_in_the_operations_catalog()
    {
        var doc = File.ReadAllText(Path.Combine(ComponentSourceScanner.RepoRoot(), "docs", "OPERATIONS.md"));
        Ids.Where(i => !doc.Contains($"| {i.Id} |", StringComparison.Ordinal)).Select(i => $"{i.Id} {i.Name}")
            .Should().BeEmpty("OPERATIONS.md §5 lists every id a SIEM rule can pin to");
    }

    private static readonly CaseSubject Subject = new("2026-07_Takeover", "XSIAM-4412", false);

    [Fact]
    public void A_lifecycle_event_carries_the_case_the_actor_and_the_detection_id_last()
    {
        var e = SecurityEvents.CasePhaseChanged(Subject, CasePhase.Triage, CasePhase.Containment, "u1", "u1@contoso.example");

        e.EventId.Should().Be(SecurityEventIds.CasePhaseChanged);
        e.CaseNumber.Should().Be("2026-07_Takeover");
        (e.Actor, e.ActorUpn).Should().Be(("u1", "u1@contoso.example"));
        e.Detail.Should().Be("from=Triage to=Containment detection=XSIAM-4412");
    }

    [Fact]
    public void An_exercise_is_marked_and_a_long_detection_id_is_cut()
    {
        var e = SecurityEvents.CaseReopened(Subject with { IsExercise = true, DetectionCaseId = new string('x', 500) }, "u1", null);

        e.Detail.Should().StartWith(ExerciseMarking.Prefix + "detection=");
        e.Detail!.Length.Should().BeLessThan(130, "the id is cut to the column's 100 characters");
    }

    [Theory]
    [InlineData(MaterialityStatus.Material, SecuritySeverity.Warning)]
    [InlineData(MaterialityStatus.NotMaterial, SecuritySeverity.Info)]
    [InlineData(MaterialityStatus.UnderReview, SecuritySeverity.Info)]
    public void Only_a_Material_call_is_a_Warning(MaterialityStatus status, SecuritySeverity severity) =>
        SecurityEvents.MaterialityRecorded(Subject, status, "u1", null).Severity.Should().Be(severity);

    [Fact]
    public void Promoting_a_Complex_Event_is_a_reclassification_not_a_downgrade()
    {
        var e = SecurityEvents.CaseReclassified(Subject, null, Classification.AdverseEvent, "u1", null);
        (e.Action, e.Severity).Should().Be(("CaseReclassified", SecuritySeverity.Info));
        e.Detail.Should().StartWith("from=ComplexEvent to=AdverseEvent");
    }

    [Theory]
    [InlineData(ReferenceDataKinds.CaseOutcome, ReferenceDataAction.Created, SecuritySeverity.Info)]
    [InlineData(ReferenceDataKinds.CaseOutcome, ReferenceDataAction.Deleted, SecuritySeverity.Warning)]
    [InlineData(ReferenceDataKinds.StageGate, ReferenceDataAction.Changed, SecuritySeverity.Warning)]
    [InlineData(ReferenceDataKinds.DeadlineRule, ReferenceDataAction.Created, SecuritySeverity.Warning)]
    public void Reference_data_severity_follows_what_the_change_can_weaken(string kind, ReferenceDataAction action, SecuritySeverity severity)
    {
        var e = SecurityEvents.ReferenceDataChanged(kind, new string('n', 400), action, "admin1", null);
        e.Severity.Should().Be(severity);
        e.Detail!.Length.Should().Be(300, "a name is capped like any detail");
    }

    [Fact]
    public void A_withdrawal_is_a_Warning_naming_the_file_by_id_only(/* CAP-21 */)
    {
        var id = Guid.NewGuid();
        var e = SecurityEvents.EvidenceWithdrawn(Subject, id, "u1", null);
        (e.EventId, e.Category, e.Action, e.Severity).Should().Be((SecurityEventIds.EvidenceWithdrawn, "Governance", "EvidenceWithdrawn", SecuritySeverity.Warning));
        (e.CaseNumber, e.TargetType, e.TargetId).Should().Be(("2026-07_Takeover", "Evidence", id.ToString()));
        e.Detail.Should().Be("detection=XSIAM-4412", "no file name or reason");
    }

    [Theory]
    [InlineData(false, SecuritySeverity.Warning)]
    [InlineData(true, SecuritySeverity.High)]
    public void An_evidence_package_is_a_Warning_and_High_on_a_restricted_case(bool restricted, SecuritySeverity severity /* CAP-12 */)
    {
        var id = Guid.NewGuid();
        var e = SecurityEvents.CaseAccess(AccessType.EvidencePackage, restricted, "u1", null, "2026-07_Takeover", id, "Evidence package: 3 files, 2.0 MB");
        (e.EventId, e.Category, e.Action, e.Severity).Should().Be((SecurityEventIds.EvidencePackaged, "DataAccess", "EvidencePackaged", severity));
        (e.TargetType, e.TargetId, e.Detail).Should().Be(("EvidencePackage", id.ToString(), "Evidence package: 3 files, 2.0 MB"));
    }

    [Fact]
    public void A_null_sink_or_a_failing_build_is_never_an_error()
    {
        ISecurityEventSink? none = null;
        none.EmitSafely(() => throw new InvalidOperationException("never built"));
        var sink = new Recording();
        sink.EmitSafely(() => throw new FormatException("a factory met a value it didn't expect"));
        sink.Events.Should().BeEmpty();
    }

    private sealed class Recording : ISecurityEventSink
    {
        public List<SecurityEvent> Events { get; } = [];
        public void Emit(SecurityEvent e) => Events.Add(e);
    }
}
