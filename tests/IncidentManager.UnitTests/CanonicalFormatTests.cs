using FluentAssertions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Security;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>BUG-24: row hashes over an escaped canonical, so text can't move between two fields of a record unseen.</summary>
public class CanonicalFormatTests
{
    private readonly HashChainService _hasher = new();
    private static readonly Guid CaseId = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static CaseEntity Entity(string? description, string? source) => new()
    {
        CaseId = CaseId, Type = EntityType.Host, Value = "WKS-01", Label = "Finance laptop", Description = description,
        Source = source, CreatedBy = "a1", CreatedAtUtc = DateTimeOffset.UnixEpoch,
    };

    [Fact]
    public void Text_moved_across_a_field_boundary_changes_the_hash_in_format_2_but_not_in_the_first()
    {
        var before = Entity("seen beaconing|EDR", "triage");
        var after = Entity("seen beaconing", "EDR|triage");

        before.BuildCanonicalContent().Should().Be(after.BuildCanonicalContent(), "the first format couldn't tell them apart");
        _hasher.ComputeRowHash(before).Should().NotBe(_hasher.ComputeRowHash(after));
    }

    [Fact]
    public void A_new_row_hash_says_its_format_and_an_older_one_still_verifies_as_written()
    {
        var e = Entity("seen beaconing|EDR", "triage");
        var v3 = _hasher.ComputeRowHash(e);
        var v2 = Canonical.V2Prefix + _hasher.Hash(Canonical.InFormat(2, e.BuildCanonicalContent));   // written by v1.5.2-v1.6.2
        var v1 = _hasher.Hash(e.BuildCanonicalContent());   // as an existing row's hash was written

        v3.Should().StartWith(Canonical.V3Prefix).And.HaveLength(Canonical.V3Prefix.Length + 64);
        _hasher.RowHashMatches(e, v3).Should().BeTrue();
        _hasher.RowHashMatches(e, v2).Should().BeTrue("a format-2 hash is checked in format 2");
        _hasher.RowHashMatches(e, v1).Should().BeTrue("a hash without the prefix is checked in the first format");

        e.Description = "nothing to see";
        _hasher.RowHashMatches(e, v3).Should().BeFalse();
        _hasher.RowHashMatches(e, v2).Should().BeFalse();
        _hasher.RowHashMatches(e, v1).Should().BeFalse();
    }

    [Fact]
    public void Format_3_covers_an_indicators_marking_and_pin_and_earlier_formats_dont(/* BUG-316 */)
    {
        var e = Entity("seen beaconing", "EDR");
        e.Tlp = TlpLevel.Red;
        var v3 = _hasher.ComputeRowHash(e);
        var v2 = Canonical.V2Prefix + _hasher.Hash(Canonical.InFormat(2, e.BuildCanonicalContent));

        e.Tlp = TlpLevel.Clear;   // lowered in the database
        _hasher.RowHashMatches(e, v3).Should().BeFalse();
        _hasher.RowHashMatches(e, v2).Should().BeTrue("a row not saved since keeps verifying as it was written");

        e.Tlp = TlpLevel.Red;
        e.IsPinned = true;
        _hasher.RowHashMatches(e, v3).Should().BeFalse();

        var ev = new IncidentManager.Domain.Entities.Evidence { OriginalFileName = "a.csv", Sha256 = new string('a', 64), Description = "export" };
        var hash = _hasher.ComputeRowHash(ev);
        ev.Description = "nothing";
        _hasher.RowHashMatches(ev, hash).Should().BeFalse();
    }

    [Fact]
    public void Text_without_a_bar_or_backslash_builds_the_same_canonical_in_both_formats()
    {
        // So a row whose text holds neither has the same content in both; only the prefix and the input format differ.
        var e = Entity("seen beaconing", "EDR");
        Canonical.InFormat(2, e.BuildCanonicalContent).Should().Be(Canonical.InFormat(1, e.BuildCanonicalContent));
        Canonical.InFormat(2, () => Canonical.Text(@"a|b\c")!).Should().Be(@"a\|b\\c");
        Canonical.Text(@"a|b\c").Should().Be(@"a|b\c", "outside a format-2 build text is left alone");
    }
}
