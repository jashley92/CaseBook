using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>INV-10: timeline entries citing the evidence that supports them.</summary>
public class EvidenceCitationTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 16, 8, 0, 0, TimeSpan.Zero);

    private static (Case Case, TimelineEntry Entry, Evidence A, Evidence B) Setup()
    {
        var c = Case.Open(2026, 1, "Phish", "Phishing", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "an1", T0);
        var a = new Evidence { CaseId = c.Id, OriginalFileName = "signin.csv" };
        var b = new Evidence { CaseId = c.Id, OriginalFileName = "mailbox-audit.csv" };
        c.Evidence.Add(a);
        c.Evidence.Add(b);
        var e = new TimelineEntry { CaseId = c.Id, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Analysis, Description = "Reviewed sign-ins", OccurredAtUtc = T0 };
        c.TimelineEntries.Add(e);
        return (c, e, a, b);
    }

    [Fact]
    public void Citing_sets_exactly_the_chosen_evidence()
    {
        var (c, e, a, b) = Setup();

        c.SetCitations(e.Id, [a.Id, b.Id], "an1", T0);
        c.SetCitations(e.Id, [b.Id], "an1", T0);

        c.Citations.Should().ContainSingle().Which.EvidenceId.Should().Be(b.Id);
    }

    [Fact]
    public void Evidence_from_another_case_cannot_be_cited()
    {
        var (c, e, _, _) = Setup();

        var act = () => c.SetCitations(e.Id, [Guid.NewGuid()], "an1", T0);

        act.Should().Throw<InvalidOperationException>();
        c.Citations.Should().BeEmpty();
    }

    [Fact]
    public void Citations_move_to_the_new_version_when_an_entry_is_edited()
    {
        var (c, e, a, _) = Setup();
        c.SetCitations(e.Id, [a.Id], "an1", T0);

        var next = c.EditInvestigationEntry(e.Id, TimelineEntryType.Analysis, T0, "Reviewed sign-ins for all three users", null, "an1", T0.AddHours(1));

        c.Citations.Should().ContainSingle().Which.TimelineEntryId.Should().Be(next.Id);
    }
}
