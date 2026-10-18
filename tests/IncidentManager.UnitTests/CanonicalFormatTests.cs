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
        var v5 = _hasher.ComputeRowHash(e);
        var v4 = Canonical.V4Prefix + _hasher.Hash(Canonical.InFormat(4, e.BuildCanonicalContent));   // written by v1.6.13-v1.9.0
        var v3 = Canonical.V3Prefix + _hasher.Hash(Canonical.InFormat(3, e.BuildCanonicalContent));   // written by v1.6.3-v1.6.12
        var v2 = Canonical.V2Prefix + _hasher.Hash(Canonical.InFormat(2, e.BuildCanonicalContent));   // written by v1.5.2-v1.6.2
        var v1 = _hasher.Hash(e.BuildCanonicalContent());   // as an existing row's hash was written

        v5.Should().StartWith(Canonical.V5Prefix).And.HaveLength(Canonical.V5Prefix.Length + 64);
        _hasher.RowHashMatches(e, v5).Should().BeTrue();
        _hasher.RowHashMatches(e, v4).Should().BeTrue("a format-4 hash is checked in format 4");
        _hasher.RowHashMatches(e, v3).Should().BeTrue("a format-3 hash is checked in format 3");
        _hasher.RowHashMatches(e, v2).Should().BeTrue("a format-2 hash is checked in format 2");
        _hasher.RowHashMatches(e, v1).Should().BeTrue("a hash without the prefix is checked in the first format");

        e.Description = "nothing to see";
        _hasher.RowHashMatches(e, v5).Should().BeFalse();
        _hasher.RowHashMatches(e, v4).Should().BeFalse();
        _hasher.RowHashMatches(e, v3).Should().BeFalse();
        _hasher.RowHashMatches(e, v2).Should().BeFalse();
        _hasher.RowHashMatches(e, v1).Should().BeFalse();
    }

    [Fact]
    public void Format_4_covers_the_values_earlier_formats_left_out_and_says_when_an_older_hash_falls_short(/* C18 */)
    {
        var notice = new JurisdictionNotice { CaseId = CaseId, Jurisdiction = "NY", NotifiedAtUtc = DateTimeOffset.UnixEpoch, CreatedBy = "a1" };
        var v3 = Canonical.V3Prefix + _hasher.Hash(Canonical.InFormat(3, notice.BuildCanonicalContent));
        Canonical.InFormat(4, notice.BuildCanonicalContent).Should().Be(Canonical.InFormat(3, notice.BuildCanonicalContent),
            "a record without the new values builds what format 3 built, so it needn't be re-hashed");
        Canonical.Covers(3, notice.BuildCanonicalContent).Should().BeTrue();

        notice.DueAtUtc = DateTimeOffset.UnixEpoch.AddDays(3);   // a kept deadline moved (BUG-630)
        _hasher.RowHashMatches(notice, v3).Should().BeTrue("a format-3 hash can't show it");
        Canonical.Covers(3, notice.BuildCanonicalContent).Should().BeFalse("so it falls short of the record");
        Canonical.Covers(4, notice.BuildCanonicalContent).Should().BeTrue();
        var v4 = Canonical.V4Prefix + _hasher.Hash(Canonical.InFormat(4, notice.BuildCanonicalContent));
        notice.DueAtUtc = notice.DueAtUtc.Value.AddDays(30);
        _hasher.RowHashMatches(notice, v4).Should().BeFalse();

        // Format 3's own additions: a format-2 hash falls short of an entity whose marking is set, not of one without.
        var e = Entity("seen beaconing", "EDR");
        Canonical.Covers(2, e.BuildCanonicalContent).Should().BeTrue();
        e.Tlp = TlpLevel.Red;
        Canonical.Covers(2, e.BuildCanonicalContent).Should().BeFalse();
        Canonical.FormatOf(v3).Should().Be(3);
        Canonical.FormatOf(v4).Should().Be(4);
        Canonical.FormatOf(_hasher.Hash("x")).Should().Be(1);
    }

    [Fact]
    public void Format_5_covers_how_a_regulator_was_notified_and_a_notice_without_it_keeps_its_hash(/* CAP-07 */)
    {
        var notice = new JurisdictionNotice
        {
            CaseId = CaseId, Jurisdiction = "NY", NotifiedAtUtc = DateTimeOffset.UnixEpoch, CreatedBy = "a1",
            DueAtUtc = DateTimeOffset.UnixEpoch.AddDays(3),
        };
        var v4 = Canonical.V4Prefix + _hasher.Hash(Canonical.InFormat(4, notice.BuildCanonicalContent));
        Canonical.InFormat(5, notice.BuildCanonicalContent).Should().Be(Canonical.InFormat(4, notice.BuildCanonicalContent),
            "a notice without the details builds what format 4 built, so its hash doesn't change");
        _hasher.RowHashMatches(notice, v4).Should().BeTrue();
        Canonical.Covers(4, notice.BuildCanonicalContent).Should().BeTrue();

        notice.Reference = "NYDFS-114|x";   // set outside CaseBook on a row hashed in format 4
        _hasher.RowHashMatches(notice, v4).Should().BeTrue("a format-4 hash can't show it");
        Canonical.Covers(4, notice.BuildCanonicalContent).Should().BeFalse("so it falls short of the record");

        foreach (var change in new Action<JurisdictionNotice>[]
                 {
                     n => n.Method = NoticeMethod.Letter, n => n.Reference = "NYDFS-115", n => n.NotifiedBy = "Outside counsel",
                     n => n.EvidenceId = Guid.Parse("99999999-0000-4000-8000-000000000001"),
                 })
        {
            var v5 = _hasher.ComputeRowHash(notice);
            Canonical.FormatOf(v5).Should().Be(5);
            change(notice);
            _hasher.RowHashMatches(notice, v5).Should().BeFalse();
        }
    }

    [Fact]
    public void Format_5_covers_an_evidence_withdrawal_and_a_file_that_stands_keeps_its_hash(/* CAP-21 */)
    {
        var ev = new IncidentManager.Domain.Entities.Evidence
        {
            CaseId = CaseId, OriginalFileName = "a.csv", Sha256 = new string('a', 64), CreatedBy = "a1", CreatedAtUtc = DateTimeOffset.UnixEpoch,
        };
        var v4 = Canonical.V4Prefix + _hasher.Hash(Canonical.InFormat(4, ev.BuildCanonicalContent));
        Canonical.InFormat(5, ev.BuildCanonicalContent).Should().Be(Canonical.InFormat(4, ev.BuildCanonicalContent),
            "a file that stands builds what format 4 built, so its hash doesn't change");
        _hasher.RowHashMatches(ev, v4).Should().BeTrue();

        ev.Withdraw("Filed on the wrong case", "a2", DateTimeOffset.UnixEpoch.AddDays(1));
        Canonical.Covers(4, ev.BuildCanonicalContent).Should().BeFalse("a format-4 hash can't show a withdrawal");
        foreach (var change in new Action<IncidentManager.Domain.Entities.Evidence>[]
                 {
                     e => e.WithdrawnAtUtc = DateTimeOffset.UnixEpoch.AddDays(2), e => e.WithdrawnBy = "mallory",
                     e => e.WithdrawnReason = "nothing to see", e => e.WithdrawnAtUtc = null,
                 })
        {
            var v5 = _hasher.ComputeRowHash(ev);
            Canonical.FormatOf(v5).Should().Be(5);
            change(ev);
            _hasher.RowHashMatches(ev, v5).Should().BeFalse();
        }
    }

    [Fact]
    public void Format_5_covers_a_handoffs_recipient_and_an_older_handoff_keeps_its_hash(/* CAP-20 review */)
    {
        var e = new TimelineEntry
        {
            CaseId = CaseId, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Handoff, Description = "Over to you",
            Source = "Handoff", OccurredAtUtc = DateTimeOffset.UnixEpoch, CreatedBy = "a1", CreatedAtUtc = DateTimeOffset.UnixEpoch,
        };
        var v4 = Canonical.V4Prefix + _hasher.Hash(Canonical.InFormat(4, e.BuildCanonicalContent));
        Canonical.InFormat(5, e.BuildCanonicalContent).Should().Be(Canonical.InFormat(4, e.BuildCanonicalContent),
            "a handoff recorded before the recipient was kept builds what format 4 built");
        _hasher.RowHashMatches(e, v4).Should().BeTrue();

        e.HandedToUserId = "a2";
        Canonical.Covers(4, e.BuildCanonicalContent).Should().BeFalse("a format-4 hash can't show the recipient");
        var v5 = _hasher.ComputeRowHash(e);
        Canonical.FormatOf(v5).Should().Be(5);
        e.HandedToUserId = "mallory";
        _hasher.RowHashMatches(e, v5).Should().BeFalse();
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

    // C18: what each record's canonical is in every format, on fixed fixtures (CanonicalFixtures). A stored row hash is
    // checked by rebuilding its canonical in the format it was written in, so a change to what an earlier format builds
    // makes every row written in it fail its check. A new format adds an entry at the end of each list; an earlier entry
    // never changes. A new hashable record adds its rows here (the second test fails until it does).
    private static readonly Dictionary<string, string[]> Pinned = new(StringComparer.Ordinal)
    {
        ["AccountDirectorySnapshot/Full"] = ["baf0ebd850c1ee8976be5b1d141aae5f52869636ed19f70da1ea2bdfd3b78e77", "a5fd325ee4fc3a555c36fe9abdbad0a92f67e5ba9dfd96beb65f78a14cf5b80b", "a5fd325ee4fc3a555c36fe9abdbad0a92f67e5ba9dfd96beb65f78a14cf5b80b", "a5fd325ee4fc3a555c36fe9abdbad0a92f67e5ba9dfd96beb65f78a14cf5b80b", "a5fd325ee4fc3a555c36fe9abdbad0a92f67e5ba9dfd96beb65f78a14cf5b80b"],
        ["AccountDirectorySnapshot/Bare"] = ["1d452599465223e2cb51117ae696ccc41f7e45ce2994390c8b828f89e22c7217", "1d452599465223e2cb51117ae696ccc41f7e45ce2994390c8b828f89e22c7217", "1d452599465223e2cb51117ae696ccc41f7e45ce2994390c8b828f89e22c7217", "1d452599465223e2cb51117ae696ccc41f7e45ce2994390c8b828f89e22c7217", "1d452599465223e2cb51117ae696ccc41f7e45ce2994390c8b828f89e22c7217"],
        ["ActionItem/Full"] = ["93292900a8ea0b551c8bc0347df75bbe18cd2e0cfda2a97d37ff688b465afbea", "9664bc2d8402f9f256efd1a1af7c94aa36f14ddf3a46b67fe7ba1f24c0f89c32", "9664bc2d8402f9f256efd1a1af7c94aa36f14ddf3a46b67fe7ba1f24c0f89c32", "1872dbb547e53c254fd7df7a4ec447eb1c4115a3884a21776dab553a3ddaea7f", "1872dbb547e53c254fd7df7a4ec447eb1c4115a3884a21776dab553a3ddaea7f"],
        ["ActionItem/Bare"] = ["65c1cf73c6ea1313f18b6a4e7e2ad77fc625b4a604c8c33a9dd7f31025fa5cca", "65c1cf73c6ea1313f18b6a4e7e2ad77fc625b4a604c8c33a9dd7f31025fa5cca", "65c1cf73c6ea1313f18b6a4e7e2ad77fc625b4a604c8c33a9dd7f31025fa5cca", "65c1cf73c6ea1313f18b6a4e7e2ad77fc625b4a604c8c33a9dd7f31025fa5cca", "65c1cf73c6ea1313f18b6a4e7e2ad77fc625b4a604c8c33a9dd7f31025fa5cca"],
        ["ActionItemComment/Full"] = ["c7f9492daacb0ad486aaacd37dd6f7c7812965cc2695751e8bfbcf3159763e9c", "99bcdf8f6157ed00d167e7f0d2bf8940dd0b89863cf5eed689096021c383439c", "99bcdf8f6157ed00d167e7f0d2bf8940dd0b89863cf5eed689096021c383439c", "99bcdf8f6157ed00d167e7f0d2bf8940dd0b89863cf5eed689096021c383439c", "99bcdf8f6157ed00d167e7f0d2bf8940dd0b89863cf5eed689096021c383439c"],
        ["ActionItemComment/Bare"] = ["306bccb9f1877fd708a720580c75e741449200767d1404d54be0d3a9f5f890a8", "306bccb9f1877fd708a720580c75e741449200767d1404d54be0d3a9f5f890a8", "306bccb9f1877fd708a720580c75e741449200767d1404d54be0d3a9f5f890a8", "306bccb9f1877fd708a720580c75e741449200767d1404d54be0d3a9f5f890a8", "306bccb9f1877fd708a720580c75e741449200767d1404d54be0d3a9f5f890a8"],
        ["AdGroupRoleMapping/Full"] = ["df2f17897644f86ae89bfc908d3c031ef3025e2bfaa7c4b108922f6ceea4ebaf", "57ea9d8e2f37d54fa6405c63294eb759f0cb6aeeaa4f0f9b1d7efe2d2b0154e5", "57ea9d8e2f37d54fa6405c63294eb759f0cb6aeeaa4f0f9b1d7efe2d2b0154e5", "57ea9d8e2f37d54fa6405c63294eb759f0cb6aeeaa4f0f9b1d7efe2d2b0154e5", "57ea9d8e2f37d54fa6405c63294eb759f0cb6aeeaa4f0f9b1d7efe2d2b0154e5"],
        ["AdGroupRoleMapping/Bare"] = ["aa8612ccefea219f7a4afdebf05ee44ca84273c31c6e6f15e354c2ea21fe7ac0", "aa8612ccefea219f7a4afdebf05ee44ca84273c31c6e6f15e354c2ea21fe7ac0", "aa8612ccefea219f7a4afdebf05ee44ca84273c31c6e6f15e354c2ea21fe7ac0", "aa8612ccefea219f7a4afdebf05ee44ca84273c31c6e6f15e354c2ea21fe7ac0", "aa8612ccefea219f7a4afdebf05ee44ca84273c31c6e6f15e354c2ea21fe7ac0"],
        ["AnalystNote/Full"] = ["d7e18ac644e93fad62a6522ddcda46edc70a1335e863ef51c45abb95fe44a835", "d3b00ea6941dec3a0107a2460d2b4e242c3c97a48dcc8e65e0c12d5980b4589d", "d3b00ea6941dec3a0107a2460d2b4e242c3c97a48dcc8e65e0c12d5980b4589d", "f3848417e64eb448565307fb11d0f3bf26df35700f67892a2da1c72d9aa81cb2", "f3848417e64eb448565307fb11d0f3bf26df35700f67892a2da1c72d9aa81cb2"],
        ["AnalystNote/Bare"] = ["65180472a91203ed3e8e5a494c40a1f85d4c49ade5f89595feb571ebedd384f6", "65180472a91203ed3e8e5a494c40a1f85d4c49ade5f89595feb571ebedd384f6", "65180472a91203ed3e8e5a494c40a1f85d4c49ade5f89595feb571ebedd384f6", "65180472a91203ed3e8e5a494c40a1f85d4c49ade5f89595feb571ebedd384f6", "65180472a91203ed3e8e5a494c40a1f85d4c49ade5f89595feb571ebedd384f6"],
        ["ApiToken/Full"] = ["f254766c949875cd934f55f9c561fe3e11b6d6a5079741eda5b8afc03db1239f", "0a2a07cf626f559fa4b92f4aa4bece98949d6ef0dd8caf7d108ca12bb7ae0014", "0a2a07cf626f559fa4b92f4aa4bece98949d6ef0dd8caf7d108ca12bb7ae0014", "0a2a07cf626f559fa4b92f4aa4bece98949d6ef0dd8caf7d108ca12bb7ae0014", "0a2a07cf626f559fa4b92f4aa4bece98949d6ef0dd8caf7d108ca12bb7ae0014"],
        ["ApiToken/Bare"] = ["513f6c8cc95b77c7ce4b3c12d013b8ec013bd0b7d03323415c299e1972a9be82", "513f6c8cc95b77c7ce4b3c12d013b8ec013bd0b7d03323415c299e1972a9be82", "513f6c8cc95b77c7ce4b3c12d013b8ec013bd0b7d03323415c299e1972a9be82", "513f6c8cc95b77c7ce4b3c12d013b8ec013bd0b7d03323415c299e1972a9be82", "513f6c8cc95b77c7ce4b3c12d013b8ec013bd0b7d03323415c299e1972a9be82"],
        ["AppSetting/Full"] = ["92182aef657ab22d06194c17ac8616684fb95811e66818a3a26eae6101bc9970", "5b65f2c1ceed5de617ffb2c75ba400d3dd698821bdabae53bdc8f7238c6594da", "5b65f2c1ceed5de617ffb2c75ba400d3dd698821bdabae53bdc8f7238c6594da", "5b65f2c1ceed5de617ffb2c75ba400d3dd698821bdabae53bdc8f7238c6594da", "5b65f2c1ceed5de617ffb2c75ba400d3dd698821bdabae53bdc8f7238c6594da"],
        ["AppSetting/Bare"] = ["b6c17755d8e02c72f2c06655b7e618223a336c530125dad8836a038c9dab8db5", "b6c17755d8e02c72f2c06655b7e618223a336c530125dad8836a038c9dab8db5", "b6c17755d8e02c72f2c06655b7e618223a336c530125dad8836a038c9dab8db5", "b6c17755d8e02c72f2c06655b7e618223a336c530125dad8836a038c9dab8db5", "b6c17755d8e02c72f2c06655b7e618223a336c530125dad8836a038c9dab8db5"],
        ["AssignmentChange/Full"] = ["6e1c5562ca60403b933a1691a782abfb9b17669db8b7772d03f8c1cbb838c262", "a398e5a549262924233e0e312b7ca5d82e92d878478fce8a274f34da75dc0de4", "a398e5a549262924233e0e312b7ca5d82e92d878478fce8a274f34da75dc0de4", "a398e5a549262924233e0e312b7ca5d82e92d878478fce8a274f34da75dc0de4", "a398e5a549262924233e0e312b7ca5d82e92d878478fce8a274f34da75dc0de4"],
        ["AssignmentChange/Bare"] = ["874b14ace796c6ac577c515e32e3917699b5762970480c60fbf0a63f1bcae471", "874b14ace796c6ac577c515e32e3917699b5762970480c60fbf0a63f1bcae471", "874b14ace796c6ac577c515e32e3917699b5762970480c60fbf0a63f1bcae471", "874b14ace796c6ac577c515e32e3917699b5762970480c60fbf0a63f1bcae471", "874b14ace796c6ac577c515e32e3917699b5762970480c60fbf0a63f1bcae471"],
        ["Case/Full"] = ["a708fd35bc5b83ed3af8f0793e7fd2c4be054526719532d2b93e72401d2a169a", "18a61c5acac6b9c173b6922733e76257bb79f8d941c0f6ab5b674a0d6b41fece", "18a61c5acac6b9c173b6922733e76257bb79f8d941c0f6ab5b674a0d6b41fece", "edf21d418795beb8a41df83c72fd2cc7a1358c5bdb3c302e468b119414a2e696", "edf21d418795beb8a41df83c72fd2cc7a1358c5bdb3c302e468b119414a2e696"],
        ["Case/Bare"] = ["4a5f2fa9631c83e2b05a57b24a1af5926c422b2210903c39f9b30aaefa0c3d18", "4a5f2fa9631c83e2b05a57b24a1af5926c422b2210903c39f9b30aaefa0c3d18", "4a5f2fa9631c83e2b05a57b24a1af5926c422b2210903c39f9b30aaefa0c3d18", "4a5f2fa9631c83e2b05a57b24a1af5926c422b2210903c39f9b30aaefa0c3d18", "4a5f2fa9631c83e2b05a57b24a1af5926c422b2210903c39f9b30aaefa0c3d18"],
        ["CaseAssignment/Full"] = ["2175cc39bd673f91ad19f734354fb64e2006fe8c5bb59386f9bb20cc9af69b63", "cabd4aafb690ec1ab8ed20487e7b0eb1c564042bc277422bbc19386d1fd582a2", "cabd4aafb690ec1ab8ed20487e7b0eb1c564042bc277422bbc19386d1fd582a2", "cabd4aafb690ec1ab8ed20487e7b0eb1c564042bc277422bbc19386d1fd582a2", "cabd4aafb690ec1ab8ed20487e7b0eb1c564042bc277422bbc19386d1fd582a2"],
        ["CaseAssignment/Bare"] = ["6aa3867ffe0fc4f1a941bebca00f89df169d091c5eb3ef451e09ed9fe72edb71", "6aa3867ffe0fc4f1a941bebca00f89df169d091c5eb3ef451e09ed9fe72edb71", "6aa3867ffe0fc4f1a941bebca00f89df169d091c5eb3ef451e09ed9fe72edb71", "6aa3867ffe0fc4f1a941bebca00f89df169d091c5eb3ef451e09ed9fe72edb71", "6aa3867ffe0fc4f1a941bebca00f89df169d091c5eb3ef451e09ed9fe72edb71"],
        ["CaseBrief/Full"] = ["7709254112d376214ae172b081760749d6aaf7cb49a0025e9679bf06d8fa94d1", "edd81699c96c10211385a645ec07912c3b0d7519865431dbded678fc18101463", "edd81699c96c10211385a645ec07912c3b0d7519865431dbded678fc18101463", "edd81699c96c10211385a645ec07912c3b0d7519865431dbded678fc18101463", "edd81699c96c10211385a645ec07912c3b0d7519865431dbded678fc18101463"],
        ["CaseBrief/Bare"] = ["1b31559966b747669e0ba1c7db6245f0bd646e01de7781fa66a5cda0dc7ecc4b", "1b31559966b747669e0ba1c7db6245f0bd646e01de7781fa66a5cda0dc7ecc4b", "1b31559966b747669e0ba1c7db6245f0bd646e01de7781fa66a5cda0dc7ecc4b", "1b31559966b747669e0ba1c7db6245f0bd646e01de7781fa66a5cda0dc7ecc4b", "1b31559966b747669e0ba1c7db6245f0bd646e01de7781fa66a5cda0dc7ecc4b"],
        ["CaseEntity/Full"] = ["2309671b22dac81d20ad3ea6b61ce99309b28852b5f67920bb84e8641adcdd5e", "2c4d19ff90a6c45485422c8cb242e29dd3aa31b05c018943014c60b097d3cdf2", "df0f5ce25d6e80011e6682fc11607969732949a78c0efb8c5d7dd46df6e5fdd5", "df0f5ce25d6e80011e6682fc11607969732949a78c0efb8c5d7dd46df6e5fdd5", "df0f5ce25d6e80011e6682fc11607969732949a78c0efb8c5d7dd46df6e5fdd5"],
        ["CaseEntity/Bare"] = ["1ca91cf7f5437c9f861b19c23caeab805dcba822f59a163b3572b9fb7a769a37", "1ca91cf7f5437c9f861b19c23caeab805dcba822f59a163b3572b9fb7a769a37", "ed63f31e7e0457b65f9c4a8cd0713b4baa358a8a825341528eb5a2e6af61c569", "ed63f31e7e0457b65f9c4a8cd0713b4baa358a8a825341528eb5a2e6af61c569", "ed63f31e7e0457b65f9c4a8cd0713b4baa358a8a825341528eb5a2e6af61c569"],
        ["CaseLink/Full"] = ["dae0fdbd4fc8e549f3d55e2c4d0bce7db89091312690c64ccfa9e772cf4c280d", "a016404c98782726089b88dc10cddc68891ccb41a737a19cbd06b7003bafea64", "a016404c98782726089b88dc10cddc68891ccb41a737a19cbd06b7003bafea64", "a016404c98782726089b88dc10cddc68891ccb41a737a19cbd06b7003bafea64", "a016404c98782726089b88dc10cddc68891ccb41a737a19cbd06b7003bafea64"],
        ["CaseLink/Bare"] = ["c5369e218de78082c2c5e17b04b16ee06e4a8646d0c7c93fbf17f886a69c66df", "c5369e218de78082c2c5e17b04b16ee06e4a8646d0c7c93fbf17f886a69c66df", "c5369e218de78082c2c5e17b04b16ee06e4a8646d0c7c93fbf17f886a69c66df", "c5369e218de78082c2c5e17b04b16ee06e4a8646d0c7c93fbf17f886a69c66df", "c5369e218de78082c2c5e17b04b16ee06e4a8646d0c7c93fbf17f886a69c66df"],
        ["CaseOutcome/Full"] = ["3b8d385d52ccd1ce6240436e090e67a434bf5e6797067cd6140ead88178d890a", "7954a8ecb58247db8f91eacba3524fd4d6a4780cd0558294c308997107ffc276", "7954a8ecb58247db8f91eacba3524fd4d6a4780cd0558294c308997107ffc276", "7954a8ecb58247db8f91eacba3524fd4d6a4780cd0558294c308997107ffc276", "7954a8ecb58247db8f91eacba3524fd4d6a4780cd0558294c308997107ffc276"],
        ["CaseOutcome/Bare"] = ["1c245aa7b93b115580e72fd525b8285980fbb69ffd72440d29e92b9a1513b2bb", "1c245aa7b93b115580e72fd525b8285980fbb69ffd72440d29e92b9a1513b2bb", "1c245aa7b93b115580e72fd525b8285980fbb69ffd72440d29e92b9a1513b2bb", "1c245aa7b93b115580e72fd525b8285980fbb69ffd72440d29e92b9a1513b2bb", "1c245aa7b93b115580e72fd525b8285980fbb69ffd72440d29e92b9a1513b2bb"],
        ["CaseTechnique/Full"] = ["9b7e3f67493cf3e21c64085f2540cf2f5147404ad247d9dc24feb417c9d76f01", "03c4b055ba8290bf06e4d47db2b993bd7c1a8f3b770e233a183f7c2b10ac74e7", "03c4b055ba8290bf06e4d47db2b993bd7c1a8f3b770e233a183f7c2b10ac74e7", "03c4b055ba8290bf06e4d47db2b993bd7c1a8f3b770e233a183f7c2b10ac74e7", "03c4b055ba8290bf06e4d47db2b993bd7c1a8f3b770e233a183f7c2b10ac74e7"],
        ["CaseTechnique/Bare"] = ["06d0c3c2066691d716d665159e4902f83c45410c769885503b28b7c087adc358", "06d0c3c2066691d716d665159e4902f83c45410c769885503b28b7c087adc358", "06d0c3c2066691d716d665159e4902f83c45410c769885503b28b7c087adc358", "06d0c3c2066691d716d665159e4902f83c45410c769885503b28b7c087adc358", "06d0c3c2066691d716d665159e4902f83c45410c769885503b28b7c087adc358"],
        ["CaseTemplate/Full"] = ["fbfeb02d9e32cc6a878191bcafccd602c181468ad60060b0d2eb2a4a8deb5134", "05a2092e6b08cdd61caf1804da6686e64d2f20658aa340651c26bce95e3e891a", "05a2092e6b08cdd61caf1804da6686e64d2f20658aa340651c26bce95e3e891a", "05a2092e6b08cdd61caf1804da6686e64d2f20658aa340651c26bce95e3e891a", "05a2092e6b08cdd61caf1804da6686e64d2f20658aa340651c26bce95e3e891a"],
        ["CaseTemplate/Bare"] = ["464737da82b46ab25252b80525a7e9af363828a4cb1bbdce9d1697237be397ab", "464737da82b46ab25252b80525a7e9af363828a4cb1bbdce9d1697237be397ab", "464737da82b46ab25252b80525a7e9af363828a4cb1bbdce9d1697237be397ab", "464737da82b46ab25252b80525a7e9af363828a4cb1bbdce9d1697237be397ab", "464737da82b46ab25252b80525a7e9af363828a4cb1bbdce9d1697237be397ab"],
        ["CaseTemplateStep/Full"] = ["ffbea902fbcfeeee3f1fa5794ffc95c7773c72b19e1b49ce994ba1f07ce2d555", "959b7cf8469bfd3dcb464d3568fd9e0bc9e7b1a4d1df4c77bc05e0540967d418", "959b7cf8469bfd3dcb464d3568fd9e0bc9e7b1a4d1df4c77bc05e0540967d418", "959b7cf8469bfd3dcb464d3568fd9e0bc9e7b1a4d1df4c77bc05e0540967d418", "959b7cf8469bfd3dcb464d3568fd9e0bc9e7b1a4d1df4c77bc05e0540967d418"],
        ["CaseTemplateStep/Bare"] = ["927c09bd20436754221bf14cb61ef4ceb657cb51a0af0266169438b903a085c4", "927c09bd20436754221bf14cb61ef4ceb657cb51a0af0266169438b903a085c4", "927c09bd20436754221bf14cb61ef4ceb657cb51a0af0266169438b903a085c4", "927c09bd20436754221bf14cb61ef4ceb657cb51a0af0266169438b903a085c4", "927c09bd20436754221bf14cb61ef4ceb657cb51a0af0266169438b903a085c4"],
        ["ClassificationChange/Full"] = ["4f130b56e9fdd5a332faab2e3e394d1fde0dbe8b0f3cff936afe0b8a36d6bc7c", "aff141778f854dc2a901b13efbecf78e86cf458bd3a05578a859a13d495164a7", "aff141778f854dc2a901b13efbecf78e86cf458bd3a05578a859a13d495164a7", "aff141778f854dc2a901b13efbecf78e86cf458bd3a05578a859a13d495164a7", "aff141778f854dc2a901b13efbecf78e86cf458bd3a05578a859a13d495164a7"],
        ["ClassificationChange/Bare"] = ["8af0cae339f8c18dd9fcb089a7c71eb58fa25c41e7a86e6e884700aa183ebbc7", "8af0cae339f8c18dd9fcb089a7c71eb58fa25c41e7a86e6e884700aa183ebbc7", "8af0cae339f8c18dd9fcb089a7c71eb58fa25c41e7a86e6e884700aa183ebbc7", "8af0cae339f8c18dd9fcb089a7c71eb58fa25c41e7a86e6e884700aa183ebbc7", "8af0cae339f8c18dd9fcb089a7c71eb58fa25c41e7a86e6e884700aa183ebbc7"],
        ["DataElement/Full"] = ["ef1ff4ea5e74d75d24f184dfae8491c18c4dcea2460bb9072721f243196beca1", "72c6b0965f5399d2e6d136a6e34bfabad9ed129f8862a0a26ae32996a1585a73", "72c6b0965f5399d2e6d136a6e34bfabad9ed129f8862a0a26ae32996a1585a73", "72c6b0965f5399d2e6d136a6e34bfabad9ed129f8862a0a26ae32996a1585a73", "72c6b0965f5399d2e6d136a6e34bfabad9ed129f8862a0a26ae32996a1585a73"],
        ["DataElement/Bare"] = ["e2691541cd6aa4d252636b185aa06254fea0619039b7b6f86b1cdcfe436cf30e", "e2691541cd6aa4d252636b185aa06254fea0619039b7b6f86b1cdcfe436cf30e", "e2691541cd6aa4d252636b185aa06254fea0619039b7b6f86b1cdcfe436cf30e", "e2691541cd6aa4d252636b185aa06254fea0619039b7b6f86b1cdcfe436cf30e", "e2691541cd6aa4d252636b185aa06254fea0619039b7b6f86b1cdcfe436cf30e"],
        ["EntityRelationship/Full"] = ["d7567a6db0f0d5eb01b4f73a978e72a5909882345f807a0e1124f704fd7dc9b7", "e4cea143fa1a17fc5727178d7c6e64a02a33e821bad28100058d24a8aabd01a7", "e4cea143fa1a17fc5727178d7c6e64a02a33e821bad28100058d24a8aabd01a7", "e4cea143fa1a17fc5727178d7c6e64a02a33e821bad28100058d24a8aabd01a7", "e4cea143fa1a17fc5727178d7c6e64a02a33e821bad28100058d24a8aabd01a7"],
        ["EntityRelationship/Bare"] = ["780b16ddde260c64200dacb2e5e588b6277bf7b1021b84ad1b9c1bac2b3a2d48", "780b16ddde260c64200dacb2e5e588b6277bf7b1021b84ad1b9c1bac2b3a2d48", "780b16ddde260c64200dacb2e5e588b6277bf7b1021b84ad1b9c1bac2b3a2d48", "780b16ddde260c64200dacb2e5e588b6277bf7b1021b84ad1b9c1bac2b3a2d48", "780b16ddde260c64200dacb2e5e588b6277bf7b1021b84ad1b9c1bac2b3a2d48"],
        ["EntityVerdictChange/Full"] = ["0bde333ed91d54663097a3a94a2dcdd993f8f200d8990abb756d19af140719d1", "cf47f4b36ed273cea6e988e0819e1c539ea9e453a597a93fe1a29c84eafd17f6", "cf47f4b36ed273cea6e988e0819e1c539ea9e453a597a93fe1a29c84eafd17f6", "cf47f4b36ed273cea6e988e0819e1c539ea9e453a597a93fe1a29c84eafd17f6", "cf47f4b36ed273cea6e988e0819e1c539ea9e453a597a93fe1a29c84eafd17f6"],
        ["EntityVerdictChange/Bare"] = ["983359a5f0f14c398cb3cdd428c241639a7bae971d0f262f616ebfd02f425d68", "983359a5f0f14c398cb3cdd428c241639a7bae971d0f262f616ebfd02f425d68", "983359a5f0f14c398cb3cdd428c241639a7bae971d0f262f616ebfd02f425d68", "983359a5f0f14c398cb3cdd428c241639a7bae971d0f262f616ebfd02f425d68", "983359a5f0f14c398cb3cdd428c241639a7bae971d0f262f616ebfd02f425d68"],
        ["Evidence/Full"] = ["ec0ee009f4fe9872a9bc1c47a6b2800c26d095360c1a43b7dc9f16c71e5eee2b", "2c221e5c53985c801934f5b66ac07061a110629c60068dc5f76ccb801b8fb65a", "956c69ae70a3b1b5a7b9b7eda92e9fd58649500ba20e9a5241a34ce09e0ec652", "956c69ae70a3b1b5a7b9b7eda92e9fd58649500ba20e9a5241a34ce09e0ec652", "09fe86edf3cc5818124ed81c5fe94fa6ef6427f08fbe21207d898fa37716e460"],
        ["Evidence/Bare"] = ["9fb3dd8ee354a06ab3884c131b419ae3634803bb9a727861b19bf8617ebd14fc", "9fb3dd8ee354a06ab3884c131b419ae3634803bb9a727861b19bf8617ebd14fc", "b89e674485d5b11b5ec1756e94b74acd47a739c4efcc0ca14ae00abdd110c2aa", "b89e674485d5b11b5ec1756e94b74acd47a739c4efcc0ca14ae00abdd110c2aa", "b89e674485d5b11b5ec1756e94b74acd47a739c4efcc0ca14ae00abdd110c2aa"],
        ["EvidenceCitation/Full"] = ["de416220d4408791e5ccc8a9583fd9f3ac9a4e872de19660057dba7f92b224b6", "de416220d4408791e5ccc8a9583fd9f3ac9a4e872de19660057dba7f92b224b6", "de416220d4408791e5ccc8a9583fd9f3ac9a4e872de19660057dba7f92b224b6", "de416220d4408791e5ccc8a9583fd9f3ac9a4e872de19660057dba7f92b224b6", "de416220d4408791e5ccc8a9583fd9f3ac9a4e872de19660057dba7f92b224b6"],
        ["EvidenceCitation/Bare"] = ["de416220d4408791e5ccc8a9583fd9f3ac9a4e872de19660057dba7f92b224b6", "de416220d4408791e5ccc8a9583fd9f3ac9a4e872de19660057dba7f92b224b6", "de416220d4408791e5ccc8a9583fd9f3ac9a4e872de19660057dba7f92b224b6", "de416220d4408791e5ccc8a9583fd9f3ac9a4e872de19660057dba7f92b224b6", "de416220d4408791e5ccc8a9583fd9f3ac9a4e872de19660057dba7f92b224b6"],
        ["GatePassage/Full"] = ["948ee7aed79a4c1d6175b10a76923809b7a51d4eaae40b780be5be9f43d6244a", "022ef8ac91422211b0760e7e31b89bbeb4cf222843f8de40056ad37f6396dfe1", "022ef8ac91422211b0760e7e31b89bbeb4cf222843f8de40056ad37f6396dfe1", "022ef8ac91422211b0760e7e31b89bbeb4cf222843f8de40056ad37f6396dfe1", "022ef8ac91422211b0760e7e31b89bbeb4cf222843f8de40056ad37f6396dfe1"],
        ["GatePassage/Bare"] = ["2201c75ab08e77f8635ce5ed2cc8b21728846b6d6f09760df1d9ba9b64983d4a", "2201c75ab08e77f8635ce5ed2cc8b21728846b6d6f09760df1d9ba9b64983d4a", "2201c75ab08e77f8635ce5ed2cc8b21728846b6d6f09760df1d9ba9b64983d4a", "2201c75ab08e77f8635ce5ed2cc8b21728846b6d6f09760df1d9ba9b64983d4a", "2201c75ab08e77f8635ce5ed2cc8b21728846b6d6f09760df1d9ba9b64983d4a"],
        ["ImprovementAction/Full"] = ["2039f9fd3520b26c43dca87fa029f6a0ded1abdb1c4d88d6fb52d1fa3b49935b", "69eab83b87fe2a4ee3ce775d154cdc47c71c573f420d4a10ab945cd93bfd6d1f", "69eab83b87fe2a4ee3ce775d154cdc47c71c573f420d4a10ab945cd93bfd6d1f", "69eab83b87fe2a4ee3ce775d154cdc47c71c573f420d4a10ab945cd93bfd6d1f", "69eab83b87fe2a4ee3ce775d154cdc47c71c573f420d4a10ab945cd93bfd6d1f"],
        ["ImprovementAction/Bare"] = ["fc176fe2c9ca840cfa7fc9f5a5c1e8b10ae3dce64707e355dabf3f83db848c64", "fc176fe2c9ca840cfa7fc9f5a5c1e8b10ae3dce64707e355dabf3f83db848c64", "fc176fe2c9ca840cfa7fc9f5a5c1e8b10ae3dce64707e355dabf3f83db848c64", "fc176fe2c9ca840cfa7fc9f5a5c1e8b10ae3dce64707e355dabf3f83db848c64", "fc176fe2c9ca840cfa7fc9f5a5c1e8b10ae3dce64707e355dabf3f83db848c64"],
        ["JurisdictionNotice/Full"] = ["9c70ac031f7d9fe665a41fbb9ddc04b8f7f41ea15b87c26365a96fcd8f1e4c2f", "9c70ac031f7d9fe665a41fbb9ddc04b8f7f41ea15b87c26365a96fcd8f1e4c2f", "9c70ac031f7d9fe665a41fbb9ddc04b8f7f41ea15b87c26365a96fcd8f1e4c2f", "3f326a14467dce1ab7c526aaf8c67dd587cf074fbc7929e415dc4b6a4633e570", "da0694536693599adeea7a16a48e68e87799f8f23d90e2dad1ae4b33e8e64b54"],
        ["JurisdictionNotice/Bare"] = ["8ca193daea7a022b3ee41311cf17b5c37c6775c00d8f206dd339bcad7cbf4816", "8ca193daea7a022b3ee41311cf17b5c37c6775c00d8f206dd339bcad7cbf4816", "8ca193daea7a022b3ee41311cf17b5c37c6775c00d8f206dd339bcad7cbf4816", "8ca193daea7a022b3ee41311cf17b5c37c6775c00d8f206dd339bcad7cbf4816", "8ca193daea7a022b3ee41311cf17b5c37c6775c00d8f206dd339bcad7cbf4816"],
        ["MaterialityChange/Full"] = ["926baec191207045ab80454274803aa38675f80d5f3bccae18b7cd3b613fd542", "b9fd5ff50271150ac990c6c80baef0fc513a9f06aee8cb74b9f838794f8e9c12", "b9fd5ff50271150ac990c6c80baef0fc513a9f06aee8cb74b9f838794f8e9c12", "b9fd5ff50271150ac990c6c80baef0fc513a9f06aee8cb74b9f838794f8e9c12", "b9fd5ff50271150ac990c6c80baef0fc513a9f06aee8cb74b9f838794f8e9c12"],
        ["MaterialityChange/Bare"] = ["2e249ebb2a7782c3536c758d1257a04f80294c48d72de4610a0d24dd3df2b9cd", "2e249ebb2a7782c3536c758d1257a04f80294c48d72de4610a0d24dd3df2b9cd", "2e249ebb2a7782c3536c758d1257a04f80294c48d72de4610a0d24dd3df2b9cd", "2e249ebb2a7782c3536c758d1257a04f80294c48d72de4610a0d24dd3df2b9cd", "2e249ebb2a7782c3536c758d1257a04f80294c48d72de4610a0d24dd3df2b9cd"],
        ["NotificationRule/Full"] = ["dc774d6ecf3332b9c2dba0b377253a17dae380385f2c0754cde7f8aa03a9041d", "69e1e527fc120ee25a910f14b2e734e80e83adfd5c6d8ffd72bf2253a489609f", "69e1e527fc120ee25a910f14b2e734e80e83adfd5c6d8ffd72bf2253a489609f", "69e1e527fc120ee25a910f14b2e734e80e83adfd5c6d8ffd72bf2253a489609f", "69e1e527fc120ee25a910f14b2e734e80e83adfd5c6d8ffd72bf2253a489609f"],
        ["NotificationRule/Bare"] = ["915339e3e6440daefa450a3972c971d38bb9b7dc2f8c96b3b2cf0be8d84e0b33", "915339e3e6440daefa450a3972c971d38bb9b7dc2f8c96b3b2cf0be8d84e0b33", "915339e3e6440daefa450a3972c971d38bb9b7dc2f8c96b3b2cf0be8d84e0b33", "915339e3e6440daefa450a3972c971d38bb9b7dc2f8c96b3b2cf0be8d84e0b33", "915339e3e6440daefa450a3972c971d38bb9b7dc2f8c96b3b2cf0be8d84e0b33"],
        ["PostIncidentReview/Full"] = ["4868f041299e92870f250cc652561d308ac1b5bf388f5a85debd13a0b1d7fd9f", "c0707feec2fa998204d832bb92a8e490a5577bf31dcc2f326f144707966d782b", "c0707feec2fa998204d832bb92a8e490a5577bf31dcc2f326f144707966d782b", "c0707feec2fa998204d832bb92a8e490a5577bf31dcc2f326f144707966d782b", "c0707feec2fa998204d832bb92a8e490a5577bf31dcc2f326f144707966d782b"],
        ["PostIncidentReview/Bare"] = ["df4becb08982f6dbc9de9f3df478e5047749111e33cdd530aff27c148cb7ce99", "df4becb08982f6dbc9de9f3df478e5047749111e33cdd530aff27c148cb7ce99", "df4becb08982f6dbc9de9f3df478e5047749111e33cdd530aff27c148cb7ce99", "df4becb08982f6dbc9de9f3df478e5047749111e33cdd530aff27c148cb7ce99", "df4becb08982f6dbc9de9f3df478e5047749111e33cdd530aff27c148cb7ce99"],
        ["ReportProfile/Full"] = ["9b6e3789aec1e80801ffe2b8f78216ce315dac77bf44d36cbee476581dc44a90", "0190e2924b266f3a788a8ff681415928b1fe4becd742f1842bfce7ad37530c9d", "0190e2924b266f3a788a8ff681415928b1fe4becd742f1842bfce7ad37530c9d", "0190e2924b266f3a788a8ff681415928b1fe4becd742f1842bfce7ad37530c9d", "0190e2924b266f3a788a8ff681415928b1fe4becd742f1842bfce7ad37530c9d"],
        ["ReportProfile/Bare"] = ["1bb6e38987adba9564d260028acba7b9a0179e67d7bd08cd0df78671a6e8d3b1", "1bb6e38987adba9564d260028acba7b9a0179e67d7bd08cd0df78671a6e8d3b1", "1bb6e38987adba9564d260028acba7b9a0179e67d7bd08cd0df78671a6e8d3b1", "1bb6e38987adba9564d260028acba7b9a0179e67d7bd08cd0df78671a6e8d3b1", "1bb6e38987adba9564d260028acba7b9a0179e67d7bd08cd0df78671a6e8d3b1"],
        ["ReportTemplate/Full"] = ["129661ed3317e001e3837cc6bbd3b3d99e06c6db3b84626593e831e3d67318d0", "2cc1eeb7f17202d83fbcf4efe28f9b1c01d0e5b655f3555394be5233cf8ff488", "2cc1eeb7f17202d83fbcf4efe28f9b1c01d0e5b655f3555394be5233cf8ff488", "2cc1eeb7f17202d83fbcf4efe28f9b1c01d0e5b655f3555394be5233cf8ff488", "2cc1eeb7f17202d83fbcf4efe28f9b1c01d0e5b655f3555394be5233cf8ff488"],
        ["ReportTemplate/Bare"] = ["f2e298dc6c349170e6b91eeae3d66502b0dbc413bd4066b33f96585b1d4fa099", "f2e298dc6c349170e6b91eeae3d66502b0dbc413bd4066b33f96585b1d4fa099", "f2e298dc6c349170e6b91eeae3d66502b0dbc413bd4066b33f96585b1d4fa099", "f2e298dc6c349170e6b91eeae3d66502b0dbc413bd4066b33f96585b1d4fa099", "f2e298dc6c349170e6b91eeae3d66502b0dbc413bd4066b33f96585b1d4fa099"],
        ["Role/Full"] = ["dbda2cf5a2f64e90f251bd3a54b08f6ccf7ee75c868ca2a98418d6aa0dc14658", "342f5060da9d164a645580adfaba2557bff573269ca7e2d8a8bbf518380425f6", "342f5060da9d164a645580adfaba2557bff573269ca7e2d8a8bbf518380425f6", "342f5060da9d164a645580adfaba2557bff573269ca7e2d8a8bbf518380425f6", "342f5060da9d164a645580adfaba2557bff573269ca7e2d8a8bbf518380425f6"],
        ["Role/Bare"] = ["65db58f42de8db707a6bf2c9b785ea704c7a752c73c5abcf546df8ce504a274c", "65db58f42de8db707a6bf2c9b785ea704c7a752c73c5abcf546df8ce504a274c", "65db58f42de8db707a6bf2c9b785ea704c7a752c73c5abcf546df8ce504a274c", "65db58f42de8db707a6bf2c9b785ea704c7a752c73c5abcf546df8ce504a274c", "65db58f42de8db707a6bf2c9b785ea704c7a752c73c5abcf546df8ce504a274c"],
        ["SeverityChange/Full"] = ["9c86b891114350237272102b04eb28cb466e63cf4e588a69116c931777234036", "9ed31c868590ecd0929e3431704ee4c1096771f2d9bf78bab5bbf3213cc99c02", "9ed31c868590ecd0929e3431704ee4c1096771f2d9bf78bab5bbf3213cc99c02", "9ed31c868590ecd0929e3431704ee4c1096771f2d9bf78bab5bbf3213cc99c02", "9ed31c868590ecd0929e3431704ee4c1096771f2d9bf78bab5bbf3213cc99c02"],
        ["SeverityChange/Bare"] = ["64ae62b4dc613b33879a114005e422752788eebcf34fcf3dc6f6817e79cc24c1", "64ae62b4dc613b33879a114005e422752788eebcf34fcf3dc6f6817e79cc24c1", "64ae62b4dc613b33879a114005e422752788eebcf34fcf3dc6f6817e79cc24c1", "64ae62b4dc613b33879a114005e422752788eebcf34fcf3dc6f6817e79cc24c1", "64ae62b4dc613b33879a114005e422752788eebcf34fcf3dc6f6817e79cc24c1"],
        ["StageGate/Full"] = ["d9a00b8f2b1bcce763756bc98768605a82cd3d1fa448a935b7e664b0f172becb", "329f3132ff07c441f898c9273f1474d97e96aee96feb9ebdb83f23c1da6b0ce3", "329f3132ff07c441f898c9273f1474d97e96aee96feb9ebdb83f23c1da6b0ce3", "329f3132ff07c441f898c9273f1474d97e96aee96feb9ebdb83f23c1da6b0ce3", "329f3132ff07c441f898c9273f1474d97e96aee96feb9ebdb83f23c1da6b0ce3"],
        ["StageGate/Bare"] = ["f8e6389af939f70a23b6ca136977ad8ae7bbbb1c2f4cb9c37f5635b27a923e98", "f8e6389af939f70a23b6ca136977ad8ae7bbbb1c2f4cb9c37f5635b27a923e98", "f8e6389af939f70a23b6ca136977ad8ae7bbbb1c2f4cb9c37f5635b27a923e98", "f8e6389af939f70a23b6ca136977ad8ae7bbbb1c2f4cb9c37f5635b27a923e98", "f8e6389af939f70a23b6ca136977ad8ae7bbbb1c2f4cb9c37f5635b27a923e98"],
        ["StageGateRequirement/Full"] = ["1148d21e6a6418cdd2578bd0c061153c5332780ef593a7826b1d3292ea74dcc9", "6713eff3c7e8e175edc785e00fb82fda2834093212b6ebc1391fcb3f77f7cff7", "6713eff3c7e8e175edc785e00fb82fda2834093212b6ebc1391fcb3f77f7cff7", "6713eff3c7e8e175edc785e00fb82fda2834093212b6ebc1391fcb3f77f7cff7", "6713eff3c7e8e175edc785e00fb82fda2834093212b6ebc1391fcb3f77f7cff7"],
        ["StageGateRequirement/Bare"] = ["d8896f8ab25ce8a3dadf4072aa9f70709b8489199507f245a345538c5fbddc4a", "d8896f8ab25ce8a3dadf4072aa9f70709b8489199507f245a345538c5fbddc4a", "d8896f8ab25ce8a3dadf4072aa9f70709b8489199507f245a345538c5fbddc4a", "d8896f8ab25ce8a3dadf4072aa9f70709b8489199507f245a345538c5fbddc4a", "d8896f8ab25ce8a3dadf4072aa9f70709b8489199507f245a345538c5fbddc4a"],
        ["StatusChange/Full"] = ["253dc9ba3c490d0f30d3ef7abe0b7f4d0a6b9ab2d668a9bd5b4d2530c5c34c66", "617e160b7ca5062b296763e692354063eebd1970b9481a222e4b66bdff809447", "617e160b7ca5062b296763e692354063eebd1970b9481a222e4b66bdff809447", "617e160b7ca5062b296763e692354063eebd1970b9481a222e4b66bdff809447", "617e160b7ca5062b296763e692354063eebd1970b9481a222e4b66bdff809447"],
        ["StatusChange/Bare"] = ["dadee7a3470bb086c746105656a65e2ea2313a9fc3574d865ce3d2e0ceaba31b", "dadee7a3470bb086c746105656a65e2ea2313a9fc3574d865ce3d2e0ceaba31b", "dadee7a3470bb086c746105656a65e2ea2313a9fc3574d865ce3d2e0ceaba31b", "dadee7a3470bb086c746105656a65e2ea2313a9fc3574d865ce3d2e0ceaba31b", "dadee7a3470bb086c746105656a65e2ea2313a9fc3574d865ce3d2e0ceaba31b"],
        ["TimelineEntry/Full"] = ["ef32e22d787806b72211c4d6cc95dc4fc424cc441b0d3df178791513fed57807", "0200c8d8433a81634808a6a4454be9116cd4fec424576b4c7b4860a69a98dd0a", "0200c8d8433a81634808a6a4454be9116cd4fec424576b4c7b4860a69a98dd0a", "ef272a3bdfd97340c64c1199001150eb732a656ed3d8478fa9a2d1d00a1506f9", "3684529d967b8ddd89abcbad72462eb047d067a71a1ccb52f7fab51e27e73db6"],
        ["TimelineEntry/Bare"] = ["5a447b164669e41eafb62604c1f5d193df338d4b51054f28a5d0eaa1a95d3119", "5a447b164669e41eafb62604c1f5d193df338d4b51054f28a5d0eaa1a95d3119", "5a447b164669e41eafb62604c1f5d193df338d4b51054f28a5d0eaa1a95d3119", "5a447b164669e41eafb62604c1f5d193df338d4b51054f28a5d0eaa1a95d3119", "5a447b164669e41eafb62604c1f5d193df338d4b51054f28a5d0eaa1a95d3119"],
        ["TimelineEntry/Event"] = ["c5013e6eda6faea4fb0e84bda5677d0b1ef4a425cf569ec3dd02ffc75b9bc5d2", "82ced255fbf2cf309bfa453963e43c6af031c79880c86f51aa9b578b31ef7955", "82ced255fbf2cf309bfa453963e43c6af031c79880c86f51aa9b578b31ef7955", "87381629c1df08be53374b6092b8a611833d07821fabbb708fa6e2262023ca8b", "43bdf2fe5523aaf129f472e95bdc6d713b8905281b6c9cc5e6cc00cd4781f1f6"],
        ["TransitionTimeCorrection/Full"] = ["4265f4d3cdea74926a2b12b4325914b4c671e437a142f71ae250bbb9fb025c34", "5e5ebe1cb0480d19a9a9672c29d427e85a7dbbe7403c31fbd286bbd07110ea41", "5e5ebe1cb0480d19a9a9672c29d427e85a7dbbe7403c31fbd286bbd07110ea41", "5e5ebe1cb0480d19a9a9672c29d427e85a7dbbe7403c31fbd286bbd07110ea41", "5e5ebe1cb0480d19a9a9672c29d427e85a7dbbe7403c31fbd286bbd07110ea41"],
        ["TransitionTimeCorrection/Bare"] = ["1c0d2def37cdb013277fe3a86c11e19e6e9774d18e8122c4effbd639114e5b46", "1c0d2def37cdb013277fe3a86c11e19e6e9774d18e8122c4effbd639114e5b46", "1c0d2def37cdb013277fe3a86c11e19e6e9774d18e8122c4effbd639114e5b46", "1c0d2def37cdb013277fe3a86c11e19e6e9774d18e8122c4effbd639114e5b46", "1c0d2def37cdb013277fe3a86c11e19e6e9774d18e8122c4effbd639114e5b46"],
        ["Report/Bare"] = ["0321e32223d79920b79c6aae2d69962ece74d151b31a79518f8ff2a5a555b423", "0321e32223d79920b79c6aae2d69962ece74d151b31a79518f8ff2a5a555b423", "0321e32223d79920b79c6aae2d69962ece74d151b31a79518f8ff2a5a555b423", "0321e32223d79920b79c6aae2d69962ece74d151b31a79518f8ff2a5a555b423", "0321e32223d79920b79c6aae2d69962ece74d151b31a79518f8ff2a5a555b423"],
        ["Report/Full"] = ["86821b28791cccaab125e9d9327a1ff0b5fccf2a8713d2fec755a28aa649376d", "4401eb8099522fb5164b666ab8a1ba42c9c442ff51363c24aadd3902ee50b19b", "4401eb8099522fb5164b666ab8a1ba42c9c442ff51363c24aadd3902ee50b19b", "4401eb8099522fb5164b666ab8a1ba42c9c442ff51363c24aadd3902ee50b19b", "4401eb8099522fb5164b666ab8a1ba42c9c442ff51363c24aadd3902ee50b19b"],
    };

    public static TheoryData<string> PinnedShapes =>
        new(CanonicalFixtures.HashableTypes.SelectMany(t => CanonicalFixtures.Shapes(t).Select(s => t.Name + "/" + s.Name)));

    [Theory]
    [MemberData(nameof(PinnedShapes))]
    public void Every_format_still_builds_the_canonical_it_was_released_with(string shape /* C18 */)
    {
        Pinned.Should().ContainKey(shape, "a new hashable record (or shape) needs its canonical pinned here");
        var parts = shape.Split('/');
        var type = CanonicalFixtures.HashableTypes.Single(t => t.Name == parts[0]);
        var make = CanonicalFixtures.Shapes(type).Single(s => s.Name == parts[1]).Make;
        var pinned = Pinned[shape];
        for (var format = 1; format <= pinned.Length; format++)
            CanonicalFixtures.Sha(format, make()).Should().Be(pinned[format - 1], $"{shape} in format {format} must build what it was released with");
    }

    [Fact]
    public void Every_record_and_shape_is_pinned_in_every_format_up_to_the_current_one(/* C18 */)
    {
        var expected = CanonicalFixtures.HashableTypes.SelectMany(t => CanonicalFixtures.Shapes(t).Select(s => t.Name + "/" + s.Name)).ToHashSet();
        Pinned.Keys.Should().BeEquivalentTo(expected);
        Pinned.Where(p => p.Value.Length != Canonical.CurrentFormat).Select(p => p.Key).Should().BeEmpty(
            "each record is pinned in every format, the current one included");
    }
}
