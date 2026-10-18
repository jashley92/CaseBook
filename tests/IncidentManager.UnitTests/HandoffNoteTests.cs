using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-20: the last handover's "watch for" on Now, read back from the handoff entry's text (current, old and edited), and
/// gone once the person who took the case revises or confirms the brief.
/// </summary>
public class HandoffNoteTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 8, 0, 0, TimeSpan.Zero);

    // The display names the directory gives; the entry names the recipient by theirs.
    private static string Name(string? id) => id switch { "an1" => "Alex Ng", "an2" => "Sam Ortiz", "ic1" => "Pat Lee", _ => id ?? "—" };

    // As the hand-off form writes it (CaseActionForm.HandoffBody), the lines being HandoffNote's.
    private static string Written(string to, string state, string? done = null, string? open = null, string? watch = null)
    {
        var parts = new List<string> { HandoffNote.HandedToLine(to), HandoffNote.Heading(HandoffNote.WhereItStands), state };
        if (done is not null) parts.AddRange([HandoffNote.Heading(HandoffNote.DoneSince), done]);
        if (open is not null) parts.AddRange([HandoffNote.Heading(HandoffNote.StillOpen), open]);
        if (watch is not null) parts.AddRange([HandoffNote.Heading(HandoffNote.WatchFor), watch]);
        return string.Join("\n\n", parts);
    }

    private static Case NewCase() => Case.Open(2026, 9, "Phish", "Credential phishing", Classification.Incident,
        Severity.High, CaseOrigin.InternalDetection, "ic1", T0);

    private static TimelineEntry Handoff(Case c, string text, DateTimeOffset at, string by = "ic1")
    {
        var e = new TimelineEntry
        {
            CaseId = c.Id, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Handoff, Description = text,
            Source = "Handoff", OccurredAtUtc = at, CreatedAtUtc = at, CreatedBy = by
        };
        c.TimelineEntries.Add(e);
        return e;
    }

    [Fact]
    public void Reads_every_part_the_form_writes()
    {
        var parts = HandoffNote.Parse(Written("Alex Ng", "Contained; two mailboxes left to review.",
            "- Reset jdoe\n- Blocked the sender", "- Mailbox review", "Logins from **203.0.113.7**\n\nand new MFA devices"));

        parts.HandedTo.Should().Be("Alex Ng");
        parts.WhereItStands.Should().Be("Contained; two mailboxes left to review.");
        parts.DoneSince.Should().Be("- Reset jdoe\n- Blocked the sender");
        parts.StillOpen.Should().Be("- Mailbox review");
        parts.WatchFor.Should().Be("Logins from **203.0.113.7**\n\nand new MFA devices");
    }

    [Fact]
    public void An_old_handoff_without_watch_for_or_one_written_another_way_has_no_note()
    {
        // Before a part was filled in, and handoffs from before the form had optional parts, the heading isn't there.
        HandoffNote.Parse(Written("Alex Ng", "Quiet overnight.")).WatchFor.Should().BeNull();
        // Free text (an entry rewritten in full) has no parts; a line merely starting with a label isn't a heading.
        var free = HandoffNote.Parse("Handing over to Alex.\nStill open questions are in the brief.\nWatch for anything odd");
        free.Should().Be(new HandoffParts(null, null, null, null, null));
        HandoffNote.Parse(null).WatchFor.Should().BeNull();
    }

    [Theory]
    [InlineData("**Watch for:**\n\nBeaconing to the new domain")]
    [InlineData("## Watch for\nBeaconing to the new domain")]
    [InlineData("Watch for:\r\nBeaconing to the new domain")]
    [InlineData("watch for: Beaconing to the new domain")]
    [InlineData("**Watch for**: Beaconing to the new domain")]
    [InlineData("__Watch for__\n\n  Beaconing to the new domain  ")]
    public void An_edited_entry_is_read_leniently(string tail)
    {
        var parts = HandoffNote.Parse("**Handed to Alex Ng**\n\n**Where it stands:** Contained.\n\n" + tail);

        parts.WatchFor.Should().Be("Beaconing to the new domain");
        parts.WhereItStands.Should().Be("Contained.");
        parts.HandedTo.Should().Be("Alex Ng");
    }

    [Fact]
    public void The_latest_handoff_counts_from_when_it_was_first_recorded_and_by_whom()
    {
        var c = NewCase();
        Handoff(c, Written("Alex Ng", "Day one.", watch: "The vendor's call back"), T0.AddHours(1));
        var latest = Handoff(c, Written("Sam Ortiz", "Day two.", watch: "Logins from abroad"), T0.AddHours(5), by: "an1");
        // Edited later (a typo) by someone else: still the same handoff, by the same person, at the same time.
        latest.IsCurrent = false;
        var edit = Handoff(c, Written("Sam Ortiz", "Day two.", watch: "Logins from abroad, and new MFA devices"), T0.AddHours(9), by: "ic1");
        edit.SupersedesEntryId = latest.Id;

        var w = HandoffNote.Latest(c)!;

        w.EntryId.Should().Be(edit.Id);
        w.HandedBy.Should().Be("an1");
        w.HandedAtUtc.Should().Be(T0.AddHours(5));
        w.HandedTo.Should().Be("Sam Ortiz");
        w.WatchFor.Should().Be("Logins from abroad, and new MFA devices");
        HandoffNote.IsRecipient(w, "an2", Name).Should().BeTrue();
        HandoffNote.IsRecipient(w, "an1", Name).Should().BeFalse();

        // A later handoff with nothing to watch for replaces the note rather than bringing back an older one.
        Handoff(c, Written("Pat Lee", "Day three."), T0.AddHours(12), by: "an2");
        HandoffNote.Latest(c).Should().BeNull();
    }

    [Fact]
    public void The_card_goes_once_the_recipient_revises_or_confirms_the_brief()
    {
        var c = NewCase();
        c.ReviseBrief("Phishing", "Likely contained", null, null, null, "ic1", T0.AddMinutes(30));
        Handoff(c, Written("Alex Ng", "Contained.", watch: "Logins from abroad"), T0.AddHours(1));
        HandoffNote.ForNow(c, Name).Should().NotBeNull();

        // Someone else's revision, the one who handed off confirming, and a version CaseBook appended for the recipient
        // (a question from the composer, WF-30) don't count.
        c.ReviseBrief("Phishing", "Contained", null, null, null, "an2", T0.AddHours(2));
        c.ConfirmBrief("ic1", T0.AddHours(3));
        c.ReviseBrief("Phishing", "Contained", null, "- Was MFA bypassed?", null, "an1", T0.AddHours(4), appended: true);
        HandoffNote.ForNow(c, Name).Should().NotBeNull();

        c.ConfirmBrief("an1", T0.AddHours(5));
        HandoffNote.ForNow(c, Name).Should().BeNull("confirming the brief is taking stock");

        var revised = NewCase();
        Handoff(revised, Written("Alex Ng", "Contained.", watch: "Logins from abroad"), T0.AddHours(1));
        revised.ReviseBrief("Phishing", "Contained; watching logins", null, null, null, "an1", T0.AddHours(2));
        HandoffNote.ForNow(revised, Name).Should().BeNull("revising it is too");
    }

    [Fact]
    public void A_brief_the_recipient_wrote_before_the_handoff_doesnt_count()
    {
        var c = NewCase();
        c.ReviseBrief("Phishing", "Early view", null, null, null, "an1", T0.AddMinutes(10));
        c.ConfirmBrief("an1", T0.AddMinutes(20));
        Handoff(c, Written("Alex Ng", "Contained.", watch: "Logins from abroad"), T0.AddHours(1));

        HandoffNote.ForNow(c, Name).Should().NotBeNull();
    }

    [Fact]
    public void When_the_recipient_cant_be_read_anyone_but_the_one_who_handed_off_takes_stock()
    {
        var c = NewCase();
        Handoff(c, "**Where it stands**\n\nContained.\n\n**Watch for**\n\nLogins from abroad", T0.AddHours(1));
        var w = HandoffNote.ForNow(c, Name)!;
        w.HandedTo.Should().BeNull();
        HandoffNote.IsRecipient(w, "an1", Name).Should().BeFalse();

        c.ReviseBrief("Phishing", "Contained", null, null, null, "ic1", T0.AddHours(2));
        HandoffNote.ForNow(c, Name).Should().NotBeNull();
        c.ConfirmBrief("an2", T0.AddHours(3));
        HandoffNote.ForNow(c, Name).Should().BeNull();
    }
}
