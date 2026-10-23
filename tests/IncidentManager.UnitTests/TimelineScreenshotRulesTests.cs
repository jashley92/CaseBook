using FluentAssertions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-722: the rules for an entry's screenshots: in order, at most ten, each once; an edit links only an image on this
/// case that stands, and an entry with one screenshot hashes exactly as it did before there could be more.
/// </summary>
public sealed class TimelineScreenshotRulesTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);

    private static Case NewCase() => Case.Open(2026, 1, "Phish", "Phishing", Classification.Incident, Severity.High,
        CaseOrigin.InternalDetection, "analyst1", Now);

    private static Evidence Image(Case c, string type = "image/png")
    {
        var ev = new Evidence { CaseId = c.Id, OriginalFileName = "x.png", ContentType = type, Sha256 = new string('a', 64), StoragePath = "p", CreatedBy = "analyst1", CreatedAtUtc = Now };
        c.Evidence.Add(ev);
        return ev;
    }

    [Fact]
    public void Screenshots_keep_their_order_up_to_ten_each_once()
    {
        var entry = new TimelineEntry();
        var ids = Enumerable.Range(0, 10).Select(_ => Guid.NewGuid()).ToList();
        entry.SetScreenshotIds(ids);
        entry.ScreenshotIds.Should().Equal(ids);
        entry.EvidenceId.Should().Be(ids[0]);

        var eleven = () => entry.SetScreenshotIds(ids.Append(Guid.NewGuid()));
        eleven.Should().Throw<ArgumentException>().WithMessage("*up to 10*");
        var twice = () => entry.SetScreenshotIds([ids[0], ids[0]]);
        twice.Should().Throw<ArgumentException>();

        entry.SetScreenshotIds([ids[1]]);
        (entry.EvidenceId, entry.MoreEvidenceIds).Should().Be((ids[1], null), "one screenshot is stored as it always was");
        entry.SetScreenshotIds([]);
        (entry.EvidenceId, entry.MoreEvidenceIds).Should().Be((null, null));
    }

    [Fact]
    public void One_screenshot_hashes_as_before_and_more_are_folded_in()
    {
        var c = NewCase();
        var entry = c.AddEventStep(Now, [MitreTactic.Execution], null, null, null, "Ran it", null, "analyst1", Now, evidenceId: Guid.NewGuid());
        string Canon() => Canonical.InFormat(Canonical.CurrentFormat, entry.BuildCanonicalContent);
        var single = Canon();
        single.Should().Contain($"|ev|{entry.EvidenceId}").And.NotContain("evs");

        var extra = Guid.NewGuid();
        entry.SetScreenshotIds([entry.EvidenceId!.Value, extra]);
        Canon().Should().Be(single + "|evs|" + extra.ToString("D"));
        Canonical.InFormat(8, entry.BuildCanonicalContent).Should().Be(single, "format 8 leaves them out, as it was released");
    }

    [Fact]
    public void A_screenshot_taken_off_is_remembered_once_and_folded_in(/* BUG-722 follow-up */)
    {
        var (a, b, d) = (Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        var entry = new TimelineEntry();
        entry.SetScreenshotIds([a, b, d]);
        entry.FormerEvidenceIds.Should().BeNull("nothing was taken off");
        string Canon() => Canonical.InFormat(Canonical.CurrentFormat, entry.BuildCanonicalContent);
        var before = Canon();

        entry.SetScreenshotIds([a]);
        entry.SetScreenshotIds([a, b]);   // linked again, then off again: once
        entry.SetScreenshotIds([]);
        entry.FormerScreenshotIds.Should().Equal(b, d, a);
        Canon().Should().EndWith("|was|" + string.Join(',', new[] { b, d, a }.Select(TimelineEntry.MoreKey)));
        before.Should().NotContain("|was|");
    }

    [Fact]
    public void An_edit_links_only_an_image_on_this_case_that_stands_and_unlinks_without_touching_the_evidence()
    {
        var c = NewCase();
        var (a, b) = (Image(c), Image(c));
        var step = c.AddEventStep(Now, [MitreTactic.Execution], null, null, null, "Ran it", null, "analyst1", Now);
        void Edit(params Guid[] shots) => c.EditEventStep(step.Id, Now, [MitreTactic.Execution], null, null, null, "Ran it", null,
            "analyst1", Now, screenshots: shots);

        Edit(a.Id, b.Id);
        step.ScreenshotIds.Should().Equal(a.Id, b.Id);

        var foreign = () => Edit(a.Id, Guid.NewGuid());
        foreign.Should().Throw<InvalidOperationException>().WithMessage("Only evidence on this case*");
        var csv = Image(c, "text/csv");
        var notImage = () => Edit(a.Id, csv.Id);
        notImage.Should().Throw<InvalidOperationException>().WithMessage("Only an image*");
        step.ScreenshotIds.Should().Equal([a.Id, b.Id], "a refused edit changes nothing");

        b.Withdraw("Wrong file", "analyst1", Now);
        Edit(a.Id, b.Id);   // linked before it was withdrawn, so it may stay
        Edit(a.Id);
        var relink = () => Edit(a.Id, b.Id);
        relink.Should().Throw<InvalidOperationException>().WithMessage("*withdrawn*");
        c.Evidence.Should().Contain(b, "unlinking takes nothing off the case");
    }

    [Fact]
    public void An_investigation_edit_carries_the_screenshots_or_the_ones_it_keeps()
    {
        var c = NewCase();
        var (a, b) = (Image(c), Image(c));
        var v1 = new TimelineEntry { CaseId = c.Id, Type = TimelineEntryType.Analysis, OccurredAtUtc = Now, Description = "Saw it", CreatedBy = "analyst1", CreatedAtUtc = Now };
        c.TimelineEntries.Add(v1);
        v1.SetScreenshotIds([a.Id, b.Id]);

        var v2 = c.EditInvestigationEntry(v1.Id, TimelineEntryType.Analysis, Now, "Saw it", null, "analyst1", Now);
        v2.ScreenshotIds.Should().Equal(a.Id, b.Id);
        var v3 = c.EditInvestigationEntry(v2.Id, TimelineEntryType.Analysis, Now, "Saw it", null, "analyst1", Now, screenshots: [b.Id]);
        v3.ScreenshotIds.Should().Equal(b.Id);
        v2.ScreenshotIds.Should().Equal([a.Id, b.Id], "the earlier version keeps what it showed");
    }
}
