using FluentAssertions;
using IncidentManager.Application.Lessons;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-27: the deterministic "What happened" draft built from the case record.</summary>
public class CaseNarrativeTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 8, 0, 0, TimeSpan.Zero);

    private static string Sev(Severity s) => s == Severity.Critical ? "SEV-1" : s.ToString();

    [Fact]
    public void Draft_lists_key_times_the_sequence_and_the_decisions_in_order()
    {
        var c = Case.Open(2026, 7, "Phish", "Credential phishing against Finance", Classification.Incident,
            Severity.High, CaseOrigin.InternalDetection, "ic1", T0);
        c.OccurredAtUtc = T0.AddHours(-6);
        var ip = c.AddEntity(EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, null, "ic1", T0);
        var acct = c.AddEntity(EntityType.Account, "jdoe", "John Doe", EntityDisposition.Compromised, null, null, "ic1", T0);
        c.AddEventStep(T0.AddHours(-5), [MitreTactic.InitialAccess], "T1566", null, acct.Id, "Phishing email opened", "EDR", "ic1", T0);
        c.AddEventStep(T0.AddHours(-4), [MitreTactic.CredentialAccess], null, ip.Id, acct.Id, "credentials captured", null, "ic1", T0);
        c.ChangeSeverity(Severity.Critical, "Payroll data in scope", "ic1", T0.AddHours(2));
        c.Reclassify(Classification.Breach, "PII of 1,200 customers exposed", "ic1", T0.AddHours(3));

        var md = CaseNarrative.Draft(c, id => id == ip.Id ? "203.0.113.66" : id == acct.Id ? "John Doe" : null, Sev, T0.AddDays(10));

        md.Should().StartWith("_Drafted from the case record on 2026-09-11.");
        md.Should().Contain("Credential phishing against Finance. Recorded as a breach of SEV-1 severity, identified internally.");
        md.Should().Contain("- **Activity began:** 2026-09-01 02:00 UTC");
        md.Should().Contain("- **Detected:** 2026-09-01 08:00 UTC (6 hours after activity began)");
        md.Should().Contain("- 2026-09-01 03:00 UTC (Initial Access, T1566): Phishing email opened. (affecting John Doe)");
        md.Should().Contain("- 2026-09-01 04:00 UTC (Credential Access): credentials captured. (203.0.113.66 → John Doe)");
        md.Should().Contain("Severity changed from High to SEV-1. Reason given: Payroll data in scope.");
        md.Should().Contain("Classification changed from incident to breach. Reason given: PII of 1,200 customers exposed.");
        md.IndexOf("Severity changed", StringComparison.Ordinal).Should().BeLessThan(md.IndexOf("Classification changed", StringComparison.Ordinal));

        // The opening classification/severity/phase are the starting point, not decisions.
        md.Should().NotContain("Initial classification").And.NotContain("Initial severity");
    }

    [Fact]
    public void A_vendor_matter_reads_as_a_disclosure_sequence_and_a_promotion_is_a_decision()
    {
        var c = Case.Open(2026, 8, "Vendor", "Vendor disclosed a breach", null, Severity.Medium, CaseOrigin.ThirdParty, "ic1", T0);
        c.AddEventStep(T0, [], null, null, null, "Vendor notified us", null, "ic1", T0, type: TimelineEntryType.Notified);
        c.Reclassify(Classification.Incident, "Our data in scope", "ic1", T0.AddHours(1));

        var md = CaseNarrative.Draft(c, _ => null, Sev, T0.AddDays(1));

        md.Should().Contain("reported to us by a third party");
        md.Should().Contain("### Disclosure sequence");
        md.Should().Contain("(vendor notified us): Vendor notified us.");
        md.Should().Contain("Classification changed from complex event to incident");
    }

    [Fact]
    public void An_empty_record_says_so()
    {
        var c = Case.Open(2026, 9, "Empty", "Nothing yet", Classification.AdverseEvent, Severity.Low, CaseOrigin.InternalDetection, "ic1", T0);

        CaseNarrative.Draft(c, _ => null, Sev, T0).Should()
            .Contain("Recorded as an adverse event of Low severity")
            .And.Contain("no event timeline or recorded decisions yet");
    }
}
