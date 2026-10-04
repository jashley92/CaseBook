using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>HR-18: the bring-your-own-AI closing-brief prompt, and reading the reply back.</summary>
public class ClosingBriefPromptTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 9, 12, 0, TimeSpan.Zero);
    private static readonly string[] Keys = ["Confirmed", "PolicyViolation", "FalsePositive"];

    private static Case NewCase()
    {
        var c = Case.Open(2026, 126, "Takeover", "Impossible-travel sign-in", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "ic1", T0);
        c.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c.Id, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Decision, OccurredAtUtc = T0.AddMinutes(43),
            Description = "Disable **j.morales** and revoke sessions.", Rationale = "Payment-capable account", CreatedBy = "a", CreatedAtUtc = T0.AddMinutes(43)
        });
        c.Entities.Add(new CaseEntity { CaseId = c.Id, Type = EntityType.IpAddress, Value = "185.220.101.4", Label = "Tor exit node", Disposition = EntityDisposition.Malicious });
        c.Entities.Add(new CaseEntity { CaseId = c.Id, Type = EntityType.Domain, Value = "unrelated.example", Disposition = EntityDisposition.Unknown });
        return c;
    }

    [Fact]
    public void The_prompt_carries_the_record_the_outcomes_and_the_reply_form()
    {
        var c = NewCase();
        var prompt = ClosingBriefPrompt.Build(c, "_Drafted from the case record on 2026-10-04. Review and edit before saving._\n\nAccount takeover via MFA fatigue.",
            [new("Confirmed", "Confirmed", "The activity happened as suspected"), new("FalsePositive", "False positive", null)],
            new Dictionary<Guid, TaskResult>(), id => id ?? "");

        prompt.Should().Contain("WHAT HAPPENED:").And.Contain("CONCLUSION:").And.Contain("OUTCOME:")
            .And.Contain("- Confirmed: Confirmed (The activity happened as suspected)")
            .And.Contain("Account takeover via MFA fatigue.")
            .And.Contain("2026-10-01 09:55 [Decision] Disable j.morales and revoke sessions. Why: Payment-capable account")
            .And.Contain("Tor exit node (185.220.101.4): Malicious")
            .And.NotContain("unrelated.example", "an Unknown verdict says nothing")
            .And.Contain("no legal conclusions")
            .And.NotContain("Review and edit before saving", "the draft's preamble is for the review editor");
    }

    [Fact]
    public void A_reply_is_read_back_into_the_two_parts_and_a_known_outcome()
    {
        var reply = """
            **WHAT HAPPENED:** An attacker used MFA fatigue to sign in as j.morales from Tor
            and set an inbox rule.

            **CONCLUSION:**
            Account takeover with preparation for payment fraud. No payment was made.

            OUTCOME: confirmed
            """;

        var d = ClosingBriefPrompt.Parse(reply, Keys);

        d.WhatHappened.Should().Be("An attacker used MFA fatigue to sign in as j.morales from Tor\nand set an inbox rule.");
        d.Conclusion.Should().Be("Account takeover with preparation for payment fraud. No payment was made.");
        d.OutcomeKey.Should().Be("Confirmed");
    }

    [Fact]
    public void An_unknown_outcome_or_a_missing_part_is_left_for_the_analyst()
    {
        var d = ClosingBriefPrompt.Parse("1. Conclusion: Benign admin activity.\nOutcome: none", Keys);

        d.WhatHappened.Should().BeNull();
        d.Conclusion.Should().Be("Benign admin activity.");
        d.OutcomeKey.Should().BeNull();
        ClosingBriefPrompt.Parse("Sorry, I can't help with that.", Keys).Should().Be(new ClosingBriefDraft(null, null, null));
    }
}
