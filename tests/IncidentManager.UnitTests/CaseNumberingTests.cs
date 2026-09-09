using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class CaseNumberingTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 20, 0, 0, 0, TimeSpan.Zero);

    private static Case Open(Classification? classification, int seq = 1) =>
        Case.Open(2026, seq, "Odd Beaconing", "Odd beaconing to a rare ASN",
            classification, Severity.Medium, CaseOrigin.InternalDetection, "sys", Now);

    [Fact]
    public void A_complex_event_uses_the_date_based_CE_scheme()
    {
        var c = Open(classification: null, seq: 14);
        c.CaseNumber.Should().Be("CE-2026-08-20_Odd_Beaconing"); // Now = 2026-08-20; no sequence
        c.HasCustomNumber.Should().BeFalse();
    }

    [Fact]
    public void A_classified_case_uses_the_IRP_scheme()
    {
        var c = Open(Classification.AdverseEvent, seq: 3);
        c.CaseNumber.Should().Be("2026-03_Odd_Beaconing");
    }

    [Fact]
    public void Renumbering_to_irp_switches_the_scheme_and_keeps_the_name()
    {
        var c = Open(classification: null, seq: 14);
        c.RenumberToIrp(5, "sys", Now);
        c.CaseNumber.Should().Be("2026-05_Odd_Beaconing");
        c.Sequence.Should().Be(5);
    }

    [Fact]
    public void A_custom_number_is_flagged_and_not_renumbered_on_promotion()
    {
        var c = Open(classification: null, seq: 14);
        c.AssignCustomNumber("SPECIAL-001", "sys", Now);
        c.HasCustomNumber.Should().BeTrue();
        c.CaseNumber.Should().Be("SPECIAL-001");

        c.RenumberToIrp(5, "sys", Now); // no-op for a custom-numbered case
        c.CaseNumber.Should().Be("SPECIAL-001");
    }

    [Fact]
    public void A_blank_custom_number_is_rejected()
    {
        var c = Open(Classification.Incident);
        var act = () => c.AssignCustomNumber("   ", "sys", Now);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void The_case_number_is_part_of_the_canonical_so_a_renumber_changes_the_hash()
    {
        var c = Open(classification: null, seq: 14);
        var before = c.BuildCanonicalContent();
        c.RenumberToIrp(5, "sys", Now);
        c.BuildCanonicalContent().Should().NotBe(before);
    }
}
