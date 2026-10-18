using FluentAssertions;
using IncidentManager.Application.Evidence;
using IncidentManager.Domain.Entities;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-25: the Evidence tab's filter, chips and sort (the tab renders what <see cref="EvidenceListView"/> returns). The
/// filter matches a name, a description or the start of a hash; chips of one kind widen, the two kinds narrow; each
/// column sorts both ways with a stable tie-break, and files with no collection time sort last.
/// </summary>
public class EvidenceListViewTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 9, 0, 0, TimeSpan.Zero);

    private static Evidence File(string name, string type, long size, int uploadedHour, string? description = null,
        int? collectedHour = null, string sha = "0000") => new()
    {
        OriginalFileName = name, ContentType = type, SizeBytes = size, Description = description,
        Sha256 = sha.PadRight(64, '0'), CreatedAtUtc = T0.AddHours(uploadedHour),
        CollectedAtUtc = collectedHour is { } h ? T0.AddHours(h) : null,
    };

    private static readonly Evidence Shot = File("phish-screenshot.png", "image/png", 120_000, 1, "The lure", sha: "ab12cd");
    private static readonly Evidence Log = File("Security.evtx.txt", "text/plain", 9_000_000, 2, "Exported from WKS-0142", collectedHour: -20, sha: "ff00aa");
    private static readonly Evidence Dropper = File("invoice.js", "text/javascript", 4_000, 3, collectedHour: -30, sha: "ab99ee");
    private static readonly Evidence Memory = File("memory.dmp", "application/octet-stream", 2_000_000_000, 4, "Host RAM", sha: "123456");
    private static readonly Evidence[] All = [Shot, Log, Dropper, Memory];

    private static readonly HashSet<Guid> CitedIds = [Shot.Id, Dropper.Id];
    private static bool Cited(Evidence ev) => CitedIds.Contains(ev.Id);

    private static IReadOnlyList<string> Names(string? filter = null, EvidenceSort sort = EvidenceSort.Uploaded, bool? desc = null,
        params EvidenceChip[] chips) =>
        EvidenceListView.Apply(All, filter, chips.ToHashSet(), Cited, sort, desc ?? EvidenceListView.DefaultDescending(sort))
            .Select(e => e.OriginalFileName).ToList();

    [Fact]
    public void By_default_it_lists_every_file_newest_upload_first_as_before()
    {
        Names().Should().Equal("memory.dmp", "invoice.js", "Security.evtx.txt", "phish-screenshot.png");
    }

    [Theory]
    [InlineData("SCREENSHOT", "phish-screenshot.png")]   // the name, ignoring case
    [InlineData("wks-0142", "Security.evtx.txt")]        // the description
    [InlineData("ab12", "phish-screenshot.png")]         // the start of the hash
    [InlineData("  host ram ", "memory.dmp")]            // trimmed
    public void The_filter_matches_a_name_a_description_or_the_start_of_a_hash(string filter, string expected)
    {
        Names(filter).Should().Equal(expected);
    }

    [Fact]
    public void A_hash_is_matched_from_its_start_only_and_from_four_characters()
    {
        Names("cd").Should().BeEmpty("two hex digits would match nearly every hash");
        Names("99ee").Should().BeEmpty("the middle of a hash isn't its start");
        Names("ab99").Should().Equal("invoice.js");
    }

    [Fact]
    public void Chips_of_one_kind_widen_and_the_two_kinds_narrow()
    {
        Names(chips: EvidenceChip.Images).Should().Equal("phish-screenshot.png");
        Names(chips: EvidenceChip.CanRun).Should().Equal("invoice.js");
        Names(chips: [EvidenceChip.Images, EvidenceChip.Text]).Should().BeEquivalentTo("phish-screenshot.png", "Security.evtx.txt", "invoice.js");
        Names(chips: EvidenceChip.Uncited).Should().BeEquivalentTo("Security.evtx.txt", "memory.dmp");
        Names(chips: [EvidenceChip.Cited, EvidenceChip.Uncited]).Should().HaveCount(4, "cited or not is everything");
        Names(chips: [EvidenceChip.Text, EvidenceChip.Cited]).Should().ContainSingle("text, and cited").Which.Should().Be("invoice.js");
        Names("evtx", chips: EvidenceChip.Cited).Should().BeEmpty("the filter narrows the chips too");
    }

    [Fact]
    public void Each_column_sorts_both_ways()
    {
        Names(sort: EvidenceSort.Name).Should().Equal("invoice.js", "memory.dmp", "phish-screenshot.png", "Security.evtx.txt");
        Names(sort: EvidenceSort.Name, desc: true).Should().Equal("Security.evtx.txt", "phish-screenshot.png", "memory.dmp", "invoice.js");
        Names(sort: EvidenceSort.Size).Should().Equal("memory.dmp", "Security.evtx.txt", "phish-screenshot.png", "invoice.js");
        Names(sort: EvidenceSort.Size, desc: false).Should().Equal("invoice.js", "phish-screenshot.png", "Security.evtx.txt", "memory.dmp");
        Names(sort: EvidenceSort.Uploaded, desc: false).Should().Equal("phish-screenshot.png", "Security.evtx.txt", "invoice.js", "memory.dmp");
    }

    [Fact]
    public void Files_with_no_collection_time_sort_after_those_with_one_either_way()
    {
        Names(sort: EvidenceSort.Collected).Should().Equal("Security.evtx.txt", "invoice.js", "memory.dmp", "phish-screenshot.png");
        Names(sort: EvidenceSort.Collected, desc: false).Should().Equal("invoice.js", "Security.evtx.txt", "memory.dmp", "phish-screenshot.png");
    }

    [Fact]
    public void A_header_sorts_names_A_to_Z_first_and_everything_else_newest_or_largest_first()
    {
        EvidenceListView.DefaultDescending(EvidenceSort.Name).Should().BeFalse();
        EvidenceListView.DefaultDescending(EvidenceSort.Size).Should().BeTrue();
        EvidenceListView.DefaultDescending(EvidenceSort.Uploaded).Should().BeTrue();
        EvidenceListView.DefaultDescending(EvidenceSort.Collected).Should().BeTrue();
    }

    [Fact]
    public void A_withdrawn_file_is_listed_only_with_the_Withdrawn_chip_and_the_other_chips_still_apply(/* CAP-21 */)
    {
        var gone = File("wrong-case.png", "image/png", 10, 5, sha: "dd00dd");
        gone.Withdraw("Filed on the wrong case", "a1", T0.AddHours(6));
        Evidence[] items = [.. All, gone];
        IReadOnlyList<string> Of(params EvidenceChip[] chips) =>
            EvidenceListView.Apply(items, null, chips.ToHashSet(), Cited, EvidenceSort.Uploaded, true).Select(e => e.OriginalFileName).ToList();

        Of().Should().NotContain("wrong-case.png", "hidden by default, as a retracted entry is");
        Of(EvidenceChip.Withdrawn).Should().StartWith("wrong-case.png").And.HaveCount(5, "the chip adds the withdrawn files to the list");
        Of(EvidenceChip.Withdrawn, EvidenceChip.Images).Should().Equal("wrong-case.png", "phish-screenshot.png");
        EvidenceListView.Is(gone, EvidenceChip.Withdrawn, Cited).Should().BeTrue();
        EvidenceListView.Is(Shot, EvidenceChip.Withdrawn, Cited).Should().BeFalse();
    }

    [Fact]
    public void The_collection_reads_as_a_sentence_and_a_line()
    {
        EvidenceCollection.Source(" WKS-0142 ", " J. Rivera ").Should().Be("from WKS-0142 by J. Rivera");
        EvidenceCollection.Source("WKS-0142", null).Should().Be("from WKS-0142");
        EvidenceCollection.Source(null, "J. Rivera").Should().Be("by J. Rivera");
        EvidenceCollection.Source(" ", null).Should().BeNull();
        EvidenceCollection.Line(T0, "mx01", null).Should().Be("2026-10-01 09:00 UTC, from mx01");
        EvidenceCollection.Line(null, null, null).Should().BeEmpty();
    }
}
