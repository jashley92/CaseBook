using System.Security.Cryptography;
using FluentAssertions;
using IncidentManager.Infrastructure.Storage;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// PROD-57: the encrypted file format. Every size round-trips (empty, under, at and across chunk boundaries); reads can
/// seek; and a file that's cut short, has bytes changed, chunks reordered or spliced in from another file, or is opened
/// with another key, fails instead of reading as something else. Pinned on a fixed fixture so the format can't change
/// under files already written (C4).
/// </summary>
public sealed class Cbe1FormatTests
{
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);
    private const string KeyId = "0123456789abcdef";

    private static byte[] Encrypt(byte[] plain, byte[]? key = null)
    {
        using var file = new MemoryStream();
        using (var w = new Cbe1WriteStream(file, KeyId, key ?? Key)) w.Write(plain);
        return file.ToArray();
    }

    private static byte[] Decrypt(byte[] file, byte[]? key = null)
    {
        using var r = new Cbe1ReadStream(new MemoryStream(file), key ?? Key);
        using var plain = new MemoryStream();
        r.CopyTo(plain);
        return plain.ToArray();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(Cbe1.ChunkSize - 1)]
    [InlineData(Cbe1.ChunkSize)]
    [InlineData(Cbe1.ChunkSize + 1)]
    [InlineData(3 * Cbe1.ChunkSize)]
    [InlineData(3 * Cbe1.ChunkSize + 777)]
    public void Every_size_round_trips_and_its_length_is_known_from_the_file(int size)
    {
        var plain = RandomNumberGenerator.GetBytes(size);
        var file = Encrypt(plain);
        Cbe1.IsCbe1(file).Should().BeTrue();
        Cbe1.KeyIdOf(file).Should().Be(KeyId);
        Cbe1.PlainLength(file.Length).Should().Be(size);
        Decrypt(file).Should().Equal(plain);
        if (size >= 16)
            file.AsSpan().IndexOf(plain.AsSpan(0, 16)).Should().Be(-1, "the content isn't in the file in the clear");
    }

    [Fact]
    public async Task Writing_asynchronously_gives_the_same_readable_file()
    {
        var plain = RandomNumberGenerator.GetBytes(2 * Cbe1.ChunkSize + 5);
        using var file = new MemoryStream();
        await using (var w = new Cbe1WriteStream(file, KeyId, Key)) await w.WriteAsync(plain);
        Decrypt(file.ToArray()).Should().Equal(plain);
    }

    [Fact]
    public void Reads_can_seek_anywhere_and_rewind()
    {
        var plain = RandomNumberGenerator.GetBytes(5 * Cbe1.ChunkSize + 123);
        using var r = new Cbe1ReadStream(new MemoryStream(Encrypt(plain)), Key);
        var buffer = new byte[100];
        foreach (var at in new long[] { 0, Cbe1.ChunkSize - 50, 3 * Cbe1.ChunkSize + 7, plain.Length - 100, 12 })
        {
            r.Position = at;
            r.ReadExactly(buffer);
            buffer.Should().Equal(plain.AsSpan((int)at, 100).ToArray());
        }
        r.Seek(0, SeekOrigin.Begin);
        r.ReadByte().Should().Be(plain[0]);
    }

    [Fact]
    public void A_changed_byte_anywhere_is_caught()
    {
        var plain = RandomNumberGenerator.GetBytes(2 * Cbe1.ChunkSize + 10);
        var file = Encrypt(plain);
        foreach (var at in new[] { 10, 40, Cbe1.HeaderSize + 5, Cbe1.HeaderSize + Cbe1.SealedChunk + 3, file.Length - 20, file.Length - 1 })
        {
            var bad = (byte[])file.Clone();
            bad[at] ^= 0x01;
            var read = () => Decrypt(bad);
            read.Should().Throw<CryptographicException>($"byte {at} was changed");
        }
    }

    [Fact]
    public void A_file_cut_short_or_with_chunks_moved_or_spliced_in_is_caught()
    {
        var plain = RandomNumberGenerator.GetBytes(3 * Cbe1.ChunkSize);
        var file = Encrypt(plain);

        // Cut after a whole chunk: a valid-looking length, but the last chunk isn't marked final.
        var cut = file.AsSpan(0, Cbe1.HeaderSize + 2 * Cbe1.SealedChunk + Cbe1.TagSize).ToArray();
        ((Action)(() => Decrypt(cut))).Should().Throw<CryptographicException>();
        ((Action)(() => Decrypt(file.AsSpan(0, file.Length - 5).ToArray()))).Should().Throw<CryptographicException>();

        // Two chunks swapped.
        var swapped = (byte[])file.Clone();
        file.AsSpan(Cbe1.HeaderSize, Cbe1.SealedChunk).CopyTo(swapped.AsSpan(Cbe1.HeaderSize + Cbe1.SealedChunk));
        file.AsSpan(Cbe1.HeaderSize + Cbe1.SealedChunk, Cbe1.SealedChunk).CopyTo(swapped.AsSpan(Cbe1.HeaderSize));
        ((Action)(() => Decrypt(swapped))).Should().Throw<CryptographicException>();

        // A chunk from another file under the same master key.
        var other = Encrypt(RandomNumberGenerator.GetBytes(3 * Cbe1.ChunkSize));
        var spliced = (byte[])file.Clone();
        other.AsSpan(Cbe1.HeaderSize + Cbe1.SealedChunk, Cbe1.SealedChunk).CopyTo(spliced.AsSpan(Cbe1.HeaderSize + Cbe1.SealedChunk));
        ((Action)(() => Decrypt(spliced))).Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Another_key_opens_nothing()
    {
        var file = Encrypt(RandomNumberGenerator.GetBytes(1000));
        ((Action)(() => Decrypt(file, RandomNumberGenerator.GetBytes(32)))).Should().Throw<CryptographicException>();
        Cbe1.IsCbe1("MZ\x90\0\x03"u8).Should().BeFalse();
        Cbe1.PlainLength(Cbe1.HeaderSize + 3).Should().Be(-1);
    }

    // C4: a file written by this version must open forever. Built once from fixed bytes; if the format changes, this fails.
    private const string PinnedKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    [Fact]
    public void The_format_is_pinned_on_a_fixed_file()
    {
        // Built from fixed values so it's the same on every run: header fields, then one chunk and the final chunk.
        var key = Convert.FromHexString(PinnedKey);
        var fileKey = Enumerable.Range(0x40, 32).Select(i => (byte)i).ToArray();
        var fileId = Enumerable.Range(0xA0, 16).Select(i => (byte)i).ToArray();
        var nonce = Enumerable.Range(0xB0, 12).Select(i => (byte)i).ToArray();
        var header = new byte[Cbe1.HeaderSize];
        "CBE1"u8.CopyTo(header);
        header[4] = 1;
        System.Text.Encoding.ASCII.GetBytes(KeyId).CopyTo(header, 5);
        fileId.CopyTo(header, 21);
        nonce.CopyTo(header, 37);
        using (var wrap = new AesGcm(key, 16))
            wrap.Encrypt(nonce, fileKey, header.AsSpan(49, 32), header.AsSpan(81, 16), [.. "CBE1 file key"u8, .. System.Text.Encoding.ASCII.GetBytes(KeyId), .. fileId]);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(97), Cbe1.ChunkSize);

        var plain = "CaseBook evidence"u8.ToArray();
        var file = new byte[Cbe1.HeaderSize + plain.Length + 16 + 16];
        header.CopyTo(file, 0);
        using (var gcm = new AesGcm(fileKey, 16))
        {
            Cbe1.SealChunk(gcm, fileId, 0, false, plain, file.AsSpan(Cbe1.HeaderSize, plain.Length + 16));
            Cbe1.SealChunk(gcm, fileId, 1, true, ReadOnlySpan<byte>.Empty, file.AsSpan(Cbe1.HeaderSize + plain.Length + 16, 16));
        }
        Decrypt(file, key).Should().Equal(plain, "the reader opens a file laid out as the format says");
        var pinned = Convert.ToHexString(SHA256.HashData(file));
        pinned.Should().Be(PinnedSha256, $"the fixed file's bytes never change (they hash to {pinned})");
    }

    private const string PinnedSha256 = "B5A9412A514B877354C4AA3BF1D5DDE5AC67883CB9B41D92AFF56598400D7D96";
}
