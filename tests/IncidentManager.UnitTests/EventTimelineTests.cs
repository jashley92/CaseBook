using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// The Event-timeline attack model (U-08c): steps carry MITRE ATT&CK tactics and actor→target
/// attribution to the case's own entities, and folding the event fields into the canonical hash must
/// leave Investigation entries' hashes untouched.
/// </summary>
public class EventTimelineTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 12, 0, 0, TimeSpan.Zero);

    private static Case NewCase() => Case.Open(
        2026, 1, "VPN Abuse", "Anomalous VPN logins",
        Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "analyst1", Now);

    [Fact]
    public void AddEventStep_records_tactics_technique_and_attribution()
    {
        var c = NewCase();
        var attacker = c.AddEntity(EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, null, "analyst1", Now);
        var victim = c.AddEntity(EntityType.Account, "jdoe", "John Doe", EntityDisposition.Benign, null, null, "analyst1", Now);

        var step = c.AddEventStep(Now.AddMinutes(5),
            new[] { MitreTactic.InitialAccess, MitreTactic.CredentialAccess },
            "T1078", attacker.Id, victim.Id, "Logged in with valid creds", "SIEM", "analyst1", Now);

        step.Kind.Should().Be(TimelineKind.Event);
        step.Tactics.Select(t => t.Tactic).Should().BeEquivalentTo(new[] { MitreTactic.InitialAccess, MitreTactic.CredentialAccess });
        step.TechniqueId.Should().Be("T1078");
        step.ActorEntityId.Should().Be(attacker.Id);
        step.TargetEntityId.Should().Be(victim.Id);
        c.TimelineEntries.Should().ContainSingle();
    }

    [Fact]
    public void A_pasted_screenshot_links_via_EvidenceId_and_folds_into_the_canonical_only_when_set()
    {
        var c = NewCase();

        // Same step content, once without a screenshot and once with — the linked evidence must change the
        // canonical (it's tamper-evident) but a screenshot-less step must NOT carry the "ev" segment.
        var plain = c.AddEventStep(Now, new[] { MitreTactic.Execution }, null, null, null, "ran a tool", null, "analyst1", Now);
        plain.EvidenceId.Should().BeNull();
        plain.BuildCanonicalContent().Should().NotContain("|ev|");

        var shot = Guid.NewGuid();
        var withShot = c.AddEventStep(Now.AddMinutes(1), new[] { MitreTactic.Execution }, null, null, null,
            "ran a tool", null, "analyst1", Now, evidenceId: shot);
        withShot.EvidenceId.Should().Be(shot);
        withShot.BuildCanonicalContent().Should().EndWith($"|ev|{shot}");
    }

    [Fact]
    public void Editing_an_investigation_entry_carries_its_screenshot_to_the_new_version()
    {
        var c = NewCase();
        var shot = Guid.NewGuid();
        c.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c.Id, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Analysis,
            OccurredAtUtc = Now, Description = "first pass", EvidenceId = shot, CreatedBy = "analyst1", CreatedAtUtc = Now
        });
        var original = c.TimelineEntries.Single();

        var next = c.EditInvestigationEntry(original.Id, TimelineEntryType.Analysis, Now, "clarified", null, "analyst1", Now.AddHours(1));

        next.Version.Should().Be(2);
        next.EvidenceId.Should().Be(shot, "the attached screenshot survives a correction");
    }

    [Fact]
    public void AddEventStep_rejects_an_actor_not_on_the_case()
    {
        var c = NewCase();
        var act = () => c.AddEventStep(Now, new[] { MitreTactic.Execution }, null, Guid.NewGuid(), null,
            "did something", null, "analyst1", Now);

        act.Should().Throw<ArgumentException>().WithMessage("*actor*");
    }

    [Fact]
    public void AddEventStep_normalises_and_validates_the_technique_id()
    {
        var c = NewCase();

        c.AddEventStep(Now, new[] { MitreTactic.Execution }, "t1059.001", null, null, "ran a script", null, "analyst1", Now)
            .TechniqueId.Should().Be("T1059.001");

        var bad = () => c.AddEventStep(Now, new[] { MitreTactic.Execution }, "nope", null, null, "x", null, "analyst1", Now);
        bad.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Investigation_canonical_is_unchanged_by_the_event_fields()
    {
        // An Investigation entry must hash exactly as it did before event attribution existed:
        // base fields joined, with no trailing separators for the (absent) event columns.
        var entry = new TimelineEntry
        {
            CaseId = Guid.Empty,
            Kind = TimelineKind.Investigation,
            OccurredAtUtc = Now,
            Type = TimelineEntryType.Analysis,
            Description = "Reviewed logs",
            Source = "analyst1",
            CreatedBy = "analyst1",
            CreatedAtUtc = Now
        };

        var expected = string.Join('|',
            entry.CaseId, (int)entry.Kind, entry.OccurredAtUtc.ToString("o"), (int)entry.Type,
            entry.Description, entry.Source, entry.CreatedBy, entry.CreatedAtUtc.ToString("o"));

        entry.BuildCanonicalContent().Should().Be(expected);
    }

    [Fact]
    public void Event_canonical_includes_tactics_and_attribution()
    {
        var actor = Guid.NewGuid();
        var entry = new TimelineEntry
        {
            Kind = TimelineKind.Event,
            OccurredAtUtc = Now,
            Type = TimelineEntryType.Other,
            Description = "Initial access",
            CreatedBy = "analyst1",
            CreatedAtUtc = Now,
            TechniqueId = "T1078",
            ActorEntityId = actor
        };
        entry.Tactics.Add(new EventStepTactic { Tactic = MitreTactic.InitialAccess });

        var canonical = entry.BuildCanonicalContent();

        canonical.Should().Contain("T1078");
        canonical.Should().Contain(actor.ToString());
        canonical.Should().Contain(((int)MitreTactic.InitialAccess).ToString());
    }
}
