using FluentAssertions;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>HR-12: attestations show the record's facts beside them; no entity left Unknown.</summary>
public class GateFactsTests
{
    private static readonly GateCaseFacts Base = new(true, true, true, true, true, 3, 1, 0, 0, true);

    private static GateRequirementResult Attest(string label) =>
        new(Guid.NewGuid(), 0, GateRequirementKind.Attestation, null, label, true, false);

    private static GateRequirementResult Check(string key) =>
        new(Guid.NewGuid(), 0, GateRequirementKind.MachineCheck, key, GateCheckRegistry.Label(key), false, false);

    [Fact]
    public void An_evidence_attestation_shows_what_evidence_there_is()
    {
        var a = Attest("Evidence preserved and chain of custody complete");

        GateFacts.For(a, Base).Should().Be("No evidence files attached");
        GateFacts.For(a, Base with { EvidenceCount = 1 }).Should().Be("1 evidence file · custody log on it");
        GateFacts.For(a, Base with { EvidenceCount = 3, EvidenceWithoutCustody = 1 }).Should().Be("3 evidence files · 1 without a custody log");
    }

    [Fact]
    public void A_review_attestation_shows_whether_a_review_was_recorded()
    {
        var a = Attest("Post-incident review complete");
        var at = new DateTimeOffset(2026, 10, 3, 14, 0, 0, TimeSpan.Zero);

        GateFacts.For(a, Base).Should().Be("No post-incident review recorded");
        GateFacts.For(a, Base with { ReviewRecordedAtUtc = at, ImprovementActionCount = 2 })
            .Should().Be("Review recorded 3 Oct 2026 · 2 improvement actions");
        GateFacts.For(a, Base with { ReviewRecordedAtUtc = at, NoActionsIdentified = true })
            .Should().Be("Review recorded 3 Oct 2026 · no actions identified");
    }

    [Fact]
    public void An_attestation_about_something_else_shows_nothing()
    {
        GateFacts.For(Attest("Impact assessment reviewed with leadership / Legal"), Base).Should().BeNull();
        GateFacts.For(Attest("Leadership briefed"), Base).Should().BeNull();
    }

    [Fact]
    public void Entities_left_Unknown_fail_the_assessed_check_and_say_how_many()
    {
        GateCheckRegistry.IsSatisfied(GateCheckKeys.EntitiesAssessed, Base).Should().BeTrue();
        var f = Base with { UnknownEntityCount = 2 };
        GateCheckRegistry.IsSatisfied(GateCheckKeys.EntitiesAssessed, f).Should().BeFalse();
        GateFacts.For(Check(GateCheckKeys.EntitiesAssessed), f).Should().Be("2 still Unknown");
    }

    [Fact]
    public void A_gate_passage_records_what_was_shown_beside_an_attestation()
    {
        var a = Attest("Evidence preserved and chain of custody complete");
        var eval = new GateEvaluation(true, StageGateTrigger.CloseCase, "Closure readiness", [a], 0, Base with { EvidenceCount = 1 });

        GateDetail.Summarize(eval, new HashSet<Guid> { a.RequirementId })
            .Should().Contain("[MET] Evidence preserved and chain of custody complete (attest; shown: 1 evidence file · custody log on it)");
    }

    [Fact]
    public void A_large_gate_s_detail_fits_its_column_with_room_for_the_close_note_and_counts_what_it_leaves_out(/* BUG-485 */)
    {
        // 40 requirements with 400-character labels (the label column's limit), as a climb through several gates can reach.
        var reqs = Enumerable.Range(0, 40)
            .Select(i => Attest($"R{i:00} " + new string('x', 396)) with { Order = i }).ToList();
        var eval = new GateEvaluation(true, StageGateTrigger.EscalateToBreach, new string('G', 200) + " + " + new string('H', 200), reqs);

        var detail = GateDetail.Summarize(eval, new HashSet<Guid>());

        detail.Length.Should().BeLessThanOrEqualTo(GateDetail.MaxLength);
        (GateDetail.MaxLength + 200).Should().BeLessThanOrEqualTo(GateDetail.ColumnLength, "the WF-13 note is appended after");
        var shown = Enumerable.Range(0, 40).Count(i => detail.Contains($"R{i:00} "));
        shown.Should().BeGreaterThan(0);
        detail.Should().EndWith($"; … {40 - shown} more requirements");
        detail.Should().Contain("[UNMET(OVERRIDDEN)] R00 ");
    }

    [Fact]
    public void A_gate_that_fits_is_written_whole(/* BUG-485 */)
    {
        var reqs = Enumerable.Range(0, 3).Select(i => Attest($"Step {i}") with { Order = i }).ToList();
        var eval = new GateEvaluation(true, StageGateTrigger.CloseCase, "Close", reqs);

        GateDetail.Summarize(eval, new HashSet<Guid> { reqs[0].RequirementId }).Should()
            .Be("Gate 'Close': [MET] Step 0 (attest); [UNMET(OVERRIDDEN)] Step 1 (attest); [UNMET(OVERRIDDEN)] Step 2 (attest)");
        GateDetail.Summarize(eval with { Requirements = [] }, new HashSet<Guid>()).Should().Be("Gate 'Close': ");
    }

    [Fact]
    public void A_shown_date_is_written_as_the_caller_says(/* WF-15 */)
    {
        var a = Attest("Post-incident review complete");
        var ny = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");
        // Saved 3 Oct 21:00 in New York, which is 4 Oct in UTC.
        var eval = new GateEvaluation(true, StageGateTrigger.CloseCase, "Closure readiness", [a], 0,
            Base with { ReviewRecordedAtUtc = new DateTimeOffset(2026, 10, 4, 1, 0, 0, TimeSpan.Zero), NoActionsIdentified = true });

        GateDetail.Summarize(eval, new HashSet<Guid> { a.RequirementId }, d => TimeZoneInfo.ConvertTime(d, ny).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture))
            .Should().Contain("shown: Review recorded 2026-10-03 · no actions identified");
    }
}
