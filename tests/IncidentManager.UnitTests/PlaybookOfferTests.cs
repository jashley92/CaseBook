using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-11: after an escalation, or a case filed at a rung, the rung's playbooks are offered with the steps whose titles
/// aren't already tasks (trimmed, ignoring case), each title once. A suggestion only: nothing here writes.
/// </summary>
public class PlaybookOfferTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 8, 0, 0, TimeSpan.Zero);

    private static TemplateView Playbook(string name, Classification? rung, params string[] steps) => new(
        Guid.NewGuid(), name, null, IsActive: true, SortOrder: 0, rung, null, null, null,
        steps.Select((s, i) => new TemplateStepView(Guid.NewGuid(), i + 1, s, null, null, null)).ToList());

    private static Case NewCase(Classification? rung = Classification.Incident) =>
        Case.Open(2026, 3, "Ransom", "Ransomware on a file server", rung, Severity.High, CaseOrigin.InternalDetection, "ic1", T0);

    private static void Task(Case c, string title, ActionItemStatus status = ActionItemStatus.Open) =>
        c.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = title, Status = status, CreatedAtUtc = T0 });

    [Fact]
    public void Steps_already_tasks_are_left_out_comparing_trimmed_titles_ignoring_case()
    {
        var c = NewCase(Classification.Breach);
        Task(c, "  notify LEGAL ");
        Task(c, "Preserve logs", ActionItemStatus.Done);
        Task(c, "Engage the forensic firm", ActionItemStatus.Cancelled);
        var breach = Playbook("Breach response", Classification.Breach,
            "Notify legal", "Preserve logs", "Engage the forensic firm", "Draft the regulator notice", " Brief the CISO ");

        var offer = PlaybookOffer.For(c, [breach]).Should().ContainSingle().Subject;

        offer.Template.Should().BeSameAs(breach);
        offer.Missing.Select(s => s.Title).Should().Equal("Draft the regulator notice", " Brief the CISO ");
    }

    [Fact]
    public void A_title_repeated_in_the_playbook_is_offered_once()
    {
        var c = NewCase();
        var p = Playbook("Incident", Classification.Incident, "Reset credentials", "Scope the access", "reset credentials ", "Scope the access");

        var missing = PlaybookOffer.MissingSteps(p, c.ActionItems.Select(t => t.Title));

        missing.Select(s => s.Title).Should().Equal("Reset credentials", "Scope the access");
        missing.Select(s => s.Id).Should().Equal(p.Steps[0].Id, p.Steps[1].Id);
        // And once one of those titles is a task, neither copy is offered.
        Task(c, "Reset credentials");
        PlaybookOffer.MissingSteps(p, c.ActionItems.Select(t => t.Title)).Select(s => s.Title).Should().Equal("Scope the access");
    }

    [Fact]
    public void Several_playbooks_for_the_rung_are_each_offered_in_picker_order_and_complete_ones_are_not()
    {
        var c = NewCase(Classification.Breach);
        Task(c, "Notify legal");
        var b = Playbook("Breach: data theft", Classification.Breach, "Notify legal", "Identify the data") with { SortOrder = 2 };
        var a = Playbook("Breach: ransomware", Classification.Breach, "Isolate hosts") with { SortOrder = 1 };
        var done = Playbook("Breach: basics", Classification.Breach, "notify legal");
        var other = Playbook("Incident", Classification.Incident, "Triage");
        var none = Playbook("Any case", null, "Open a bridge");
        var inactive = Playbook("Old breach", Classification.Breach, "Fax the regulator") with { IsActive = false };

        var offers = PlaybookOffer.For(c, [b, a, done, other, none, inactive]);

        offers.Select(o => o.Template.Name).Should().Equal("Breach: ransomware", "Breach: data theft");
        offers[1].Missing.Select(s => s.Title).Should().Equal("Identify the data");
    }

    [Fact]
    public void Offered_when_filed_at_or_escalated_to_the_rung_not_after_a_de_escalation_or_on_a_closed_case()
    {
        var incident = Playbook("Incident", Classification.Incident, "Scope the access");
        var breach = Playbook("Breach", Classification.Breach, "Notify legal");

        var filed = NewCase(Classification.Incident);
        PlaybookOffer.For(filed, [incident, breach]).Should().ContainSingle().Which.Template.Should().BeSameAs(incident);

        filed.Reclassify(Classification.Breach, "Data left the network", "ic1", T0.AddHours(1));
        PlaybookOffer.For(filed, [incident, breach]).Should().ContainSingle().Which.Template.Should().BeSameAs(breach);

        filed.Reclassify(Classification.Incident, "No data left after all", "ic1", T0.AddHours(2));
        PlaybookOffer.For(filed, [incident, breach]).Should().BeEmpty("a de-escalation doesn't call for the lower rung's playbook");

        var promoted = NewCase(null);
        PlaybookOffer.For(promoted, [incident, breach]).Should().BeEmpty("a Complex Event isn't on a rung");
        promoted.Reclassify(Classification.Incident, "Confirmed", "ic1", T0.AddHours(1));
        PlaybookOffer.For(promoted, [incident, breach]).Should().ContainSingle();

        var closed = NewCase(Classification.Incident);
        closed.ChangePhase(CasePhase.Containment, null, "ic1", T0.AddHours(1));
        closed.MarkContained("ic1", T0.AddHours(1));
        closed.ChangePhase(CasePhase.Recovery, null, "ic1", T0.AddHours(2));
        closed.ChangePhase(CasePhase.Closed, "Done", "ic1", T0.AddHours(3));
        PlaybookOffer.For(closed, [incident]).Should().BeEmpty();
    }

    [Fact]
    public void A_site_with_no_templates_is_offered_nothing()
    {
        PlaybookOffer.For(NewCase(Classification.Breach), []).Should().BeEmpty();
    }

    [Fact]
    public void Add_them_again_keeps_a_card_already_open_as_offered_and_refuses_to_replace_other_work(/* CAP-11 review */)
    {
        Guid offered = Guid.NewGuid(), other = Guid.NewGuid(), s1 = Guid.NewGuid(), s2 = Guid.NewGuid();
        var missing = new HashSet<Guid> { s1, s2 };

        PlaybookOffer.Take(null, new HashSet<Guid>(), offered, missing).Should().Be(OfferTake.Open, "no card is open");
        PlaybookOffer.Take(offered, new HashSet<Guid> { s2, s1 }, offered, missing)
            .Should().Be(OfferTake.Keep, "the card already shows the offer, so the owner chosen in it isn't reset");
        PlaybookOffer.Take(offered, new HashSet<Guid> { s1 }, offered, missing).Should().Be(OfferTake.Refuse, "a step was unticked");
        PlaybookOffer.Take(other, missing, offered, missing).Should().Be(OfferTake.Refuse, "another playbook is open");
    }
}
