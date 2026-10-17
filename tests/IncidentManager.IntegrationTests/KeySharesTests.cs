using System.Security.Cryptography;
using FluentAssertions;
using IncidentManager.Infrastructure.Security;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// PROD-57: the evidence key split into shares, any k of n rebuilding it. Every k-subset rebuilds the same key, fewer
/// refuse, and k-1 shares carry no information about the key (checked statistically). A mistyped, mixed-up, repeated or
/// foreign share is refused with a reason rather than rebuilding a wrong key. The field arithmetic is checked against
/// known values.
/// </summary>
public sealed class KeySharesTests
{
    private const string KeyId = "89abcdef01234567";

    [Fact]
    public void The_field_arithmetic_matches_known_values()
    {
        // FIPS-197 4.2: {57} x {83} = {c1}; {57} x {13} = {fe}.
        KeyShares.Mul(0x57, 0x83).Should().Be(0xC1);
        KeyShares.Mul(0x57, 0x13).Should().Be(0xFE);
        for (var a = 1; a < 256; a++)
            KeyShares.Mul((byte)a, KeyShares.Div(1, (byte)a)).Should().Be(1, $"{a} times its inverse is 1");
    }

    [Theory]
    [InlineData(2, 2)]
    [InlineData(2, 3)]
    [InlineData(3, 5)]
    [InlineData(4, 7)]
    public void Every_set_of_k_shares_rebuilds_the_key_and_fewer_refuse(int k, int n)
    {
        var secret = RandomNumberGenerator.GetBytes(64);
        var shares = KeyShares.Split(secret, KeyId, k, n);
        shares.Should().HaveCount(n).And.OnlyContain(s => s.StartsWith("CBS1-", StringComparison.Ordinal));
        foreach (var subset in Subsets(Enumerable.Range(0, n).ToList(), k))
            KeyShares.Combine(subset.Select(i => shares[i])).Should().Equal(secret);
        KeyShares.Combine(shares).Should().Equal(secret, "more than k work too");
        var tooFew = () => KeyShares.Combine(shares.Take(k - 1));
        tooFew.Should().Throw<ArgumentException>().WithMessage($"{k} shares are needed*");
    }

    [Fact]
    public void Fewer_than_k_shares_say_nothing_about_the_key()
    {
        // For two very different keys, the first byte of share 1 (k = 2) is spread evenly over all 256 values either way.
        foreach (var secretByte in new byte[] { 0x00, 0xFF })
        {
            var counts = new int[256];
            for (var i = 0; i < 25_600; i++)
                counts[KeyShares.Decode(KeyShares.Split([secretByte], KeyId, 2, 3)[0]).Bytes[0]]++;
            // Chi-square with 255 degrees of freedom: about 255 expected; 350 is well past chance either way.
            var chi = counts.Sum(c => Math.Pow(c - 100, 2) / 100);
            chi.Should().BeLessThan(350, $"share bytes for key byte {secretByte:x2} look uniform");
        }
    }

    [Fact]
    public void Shares_are_read_however_they_were_typed_and_a_wrong_one_is_refused()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var shares = KeyShares.Split(secret, KeyId, 2, 3);
        var typed = shares[0].ToLowerInvariant().Replace("-", " ");
        KeyShares.Combine([typed, shares[2]]).Should().Equal(secret);
        KeyShares.Decode(shares[1]).Should().Match<KeyShares.Share>(s => s.Number == 2 && s.Threshold == 2 && s.KeyId == KeyId);

        var mistyped = shares[0][..10] + (shares[0][10] == 'A' ? 'B' : 'A') + shares[0][11..];
        ((Action)(() => KeyShares.Decode(mistyped))).Should().Throw<ArgumentException>().WithMessage("*doesn't check out*");
        ((Action)(() => KeyShares.Decode(shares[0][..^6]))).Should().Throw<ArgumentException>();
        ((Action)(() => KeyShares.Decode("CBS1-0000O"))).Should().Throw<ArgumentException>();
        ((Action)(() => KeyShares.Decode("hello"))).Should().Throw<ArgumentException>().WithMessage("*CBS1-*");
        ((Action)(() => KeyShares.Combine([shares[0], shares[0]]))).Should().Throw<ArgumentException>().WithMessage("*twice*");

        var otherKey = KeyShares.Split(RandomNumberGenerator.GetBytes(32), "0000000000000000", 2, 3);
        ((Action)(() => KeyShares.Combine([shares[0], otherKey[1]]))).Should().Throw<ArgumentException>().WithMessage("*different keys*");
        var otherSplit = KeyShares.Split(secret, KeyId, 3, 3);
        ((Action)(() => KeyShares.Combine([shares[0], otherSplit[1]]))).Should().Throw<ArgumentException>().WithMessage("*different splits*");
    }

    [Fact]
    public void A_split_made_from_fixed_randomness_is_pinned()
    {
        // C4: the share format and the arithmetic can't change under shares already on paper.
        var shares = KeyShares.Split([0x01, 0x02, 0x03], KeyId, 2, 3, n => Enumerable.Repeat((byte)0x55, n).ToArray());
        KeyShares.Combine([shares[1], shares[2]]).Should().Equal(0x01, 0x02, 0x03);
        string.Join(" ", shares).Should().Be(PinnedShares, string.Join(" ", shares));
    }

    private const string PinnedShares =
        "CBS1-AGE2X-TPPAE-RUKZY-CAFKF-OVVUJ-3BZW CBS1-AGE2X-TPPAE-RUKZY-CAKV2-RKOPZ-TO6C CBS1-AGE2X-TPPAE-RUKZY-CAP7P-37BAW-CYOE";

    private static IEnumerable<List<int>> Subsets(List<int> items, int k)
    {
        if (k == 0) { yield return []; yield break; }
        for (var i = 0; i <= items.Count - k; i++)
            foreach (var rest in Subsets(items.Skip(i + 1).ToList(), k - 1))
                yield return [items[i], .. rest];
    }
}
