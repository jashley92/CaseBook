using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-32: an entity can be pinned, and an Unknown entity the case keeps referring to is flagged for review.</summary>
public class EntityMentionsTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 8, 0, 0, TimeSpan.Zero);

    private static Case NewCase() => Case.Open(2026, 7, "Phish", "Credential phishing", Classification.Incident,
        Severity.High, CaseOrigin.InternalDetection, "ic1", T0);

    private static void Entry(Case c, string text, Guid? actor = null, Guid? target = null) =>
        c.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c.Id, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Analysis, OccurredAtUtc = T0,
            Description = text, ActorEntityId = actor, TargetEntityId = target, CreatedBy = "an1", CreatedAtUtc = T0
        });

    [Fact]
    public void References_from_the_timeline_notes_and_brief_are_counted_and_an_often_referenced_unknown_needs_review()
    {
        var c = NewCase();
        var jane = c.AddEntity(EntityType.Account, "CONTOSO\\jdoe", "Jane Doe", EntityDisposition.Unknown, null, "SIEM", "an1", T0);
        var ip = c.AddEntity(EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, "SIEM", "an1", T0);
        var host = c.AddEntity(EntityType.Host, "FIN-WKS-07", null, EntityDisposition.Unknown, null, "SIEM", "an1", T0);

        Entry(c, "Sign-in from the ASN", actor: ip.Id, target: jane.Id);
        Entry(c, $"[Jane Doe](entity:{jane.Id}) entered credentials");
        c.Notes.Add(new AnalystNote { CaseId = c.Id, Body = $"Ask HR about [Jane](entity:{jane.Id})", CreatedBy = "an1", CreatedAtUtc = T0 });
        c.ReviseBrief($"[Jane Doe](entity:{jane.Id})'s mailbox was accessed.", null, null, null, null, "ic1", T0);
        Entry(c, $"Checked [FIN-WKS-07](entity:{host.Id})");

        EntityMentions.Count(c, jane.Id).Should().Be(4);
        EntityMentions.Count(c, host.Id).Should().Be(1);
        EntityMentions.NeedingReview(c).Should().ContainSingle().Which.Entity.Should().BeSameAs(jane, "the malicious IP is already dispositioned");
    }

    [Fact]
    public void Pinning_is_recorded_and_leaves_the_row_hash_alone()
    {
        var c = NewCase();
        var jane = c.AddEntity(EntityType.Account, "CONTOSO\\jdoe", "Jane Doe", EntityDisposition.Unknown, null, "SIEM", "an1", T0);
        var before = jane.BuildCanonicalContent();

        c.SetEntityPinned(jane.Id, true, "an1", T0.AddHours(1));

        jane.IsPinned.Should().BeTrue();
        jane.ModifiedBy.Should().Be("an1");
        jane.BuildCanonicalContent().Should().Be(before);
    }
}
