using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace IncidentManager.Infrastructure.Storage;

/// <summary>
/// PROD-57: CaseBook's encrypted file format, version 1 ("CBE1"), for evidence and reports at rest.
/// <para>
/// A header names the master key (by id) and holds this file's own random key, encrypted under the master key with
/// AES-GCM, and a random file id. The content follows in chunks of <see cref="ChunkSize"/> bytes, each encrypted with
/// AES-256-GCM under the file key: its nonce is the chunk's number, and its authenticated data is the file id, the
/// number and whether it's the final chunk. Every data chunk but the last is full, and the file always ends with an
/// empty final chunk, so a writer never has to know in advance where the data ends (a large upload arrives in parts).
/// Cutting chunks off the end, reordering them, or splicing in chunks from another file all fail authentication; so does
/// any changed byte. Reads can start anywhere (the chunk is worked out from the position), so a reader can rewind.
/// </para>
/// <para>
/// The file key is fresh and random per file, and each of its nonces is used once, so no nonce is ever reused under a
/// key. The master key is never written here, only its id; nothing in a file opens it without the master key.
/// </para>
/// </summary>
public static class Cbe1
{
    public const int ChunkSize = 64 * 1024;
    public const int TagSize = 16;
    public const int KeyIdLength = 16;
    private const int FileIdSize = 16, FileKeySize = 32, NonceSize = 12;
    private static readonly byte[] Magic = "CBE1"u8.ToArray();
    private const byte Version = 1;

    /// <summary>The header's length: magic, version, key id, file id, the wrapped file key (nonce, key, tag), chunk size.</summary>
    public const int HeaderSize = 4 + 1 + KeyIdLength + FileIdSize + NonceSize + FileKeySize + TagSize + 4;

    /// <summary>A chunk's length on disk.</summary>
    public const int SealedChunk = ChunkSize + TagSize;

    /// <summary>Whether <paramref name="start"/> (a file's first bytes) is a CBE1 file.</summary>
    public static bool IsCbe1(ReadOnlySpan<byte> start) => start.Length >= 5 && start.StartsWith(Magic) && start[4] == Version;

    /// <summary>A new file's header and its file key and id: the file key encrypted under <paramref name="masterKey"/>.</summary>
    public static (byte[] Header, byte[] FileKey, byte[] FileId) NewHeader(string keyId, byte[] masterKey)
    {
        if (keyId.Length != KeyIdLength || !keyId.All(char.IsAsciiHexDigitLower))
            throw new ArgumentException("A key id is 16 lower-case hex digits.", nameof(keyId));
        var fileKey = RandomNumberGenerator.GetBytes(FileKeySize);
        var fileId = RandomNumberGenerator.GetBytes(FileIdSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var header = new byte[HeaderSize];
        var at = 0;
        Magic.CopyTo(header, at); at += 4;
        header[at++] = Version;
        Encoding.ASCII.GetBytes(keyId).CopyTo(header, at); at += KeyIdLength;
        fileId.CopyTo(header, at); at += FileIdSize;
        nonce.CopyTo(header, at); at += NonceSize;
        using (var gcm = new AesGcm(masterKey, TagSize))
            gcm.Encrypt(nonce, fileKey, header.AsSpan(at, FileKeySize), header.AsSpan(at + FileKeySize, TagSize), WrapData(keyId, fileId));
        at += FileKeySize + TagSize;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(at), ChunkSize);
        return (header, fileKey, fileId);
    }

    /// <summary>The key id a header names (so the right master key can be found), or null if it isn't a CBE1 header.</summary>
    public static string? KeyIdOf(ReadOnlySpan<byte> header) =>
        header.Length >= HeaderSize && IsCbe1(header) ? Encoding.ASCII.GetString(header.Slice(5, KeyIdLength)) : null;

    /// <summary>Opens a header with its master key: the file key and id. Throws <see cref="CryptographicException"/> when the
    /// key is wrong or the header was changed.</summary>
    public static (byte[] FileKey, byte[] FileId) OpenHeader(ReadOnlySpan<byte> header, byte[] masterKey)
    {
        if (header.Length < HeaderSize || !IsCbe1(header)) throw new CryptographicException("Not a CBE1 file.");
        var keyId = Encoding.ASCII.GetString(header.Slice(5, KeyIdLength));
        var at = 5 + KeyIdLength;
        var fileId = header.Slice(at, FileIdSize).ToArray(); at += FileIdSize;
        var nonce = header.Slice(at, NonceSize); at += NonceSize;
        var fileKey = new byte[FileKeySize];
        using (var gcm = new AesGcm(masterKey, TagSize))
            gcm.Decrypt(nonce, header.Slice(at, FileKeySize), header.Slice(at + FileKeySize, TagSize), fileKey, WrapData(keyId, fileId));
        at += FileKeySize + TagSize;
        if (BinaryPrimitives.ReadInt32BigEndian(header[at..]) != ChunkSize) throw new CryptographicException("Unknown chunk size.");
        return (fileKey, fileId);
    }

    private static byte[] WrapData(string keyId, byte[] fileId) => [.. "CBE1 file key"u8, .. Encoding.ASCII.GetBytes(keyId), .. fileId];

    /// <summary>Encrypts one chunk's <paramref name="plain"/> into <paramref name="sealedChunk"/> (its length plus the tag).</summary>
    public static void SealChunk(AesGcm gcm, byte[] fileId, long index, bool final, ReadOnlySpan<byte> plain, Span<byte> sealedChunk)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        Span<byte> aad = stackalloc byte[FileIdSize + 9];
        Context(fileId, index, final, nonce, aad);
        gcm.Encrypt(nonce, plain, sealedChunk[..plain.Length], sealedChunk.Slice(plain.Length, TagSize), aad);
    }

    /// <summary>Decrypts one chunk; throws <see cref="CryptographicException"/> if it was changed, moved or came from another file.</summary>
    public static void OpenChunk(AesGcm gcm, byte[] fileId, long index, bool final, ReadOnlySpan<byte> sealedChunk, Span<byte> plain)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        Span<byte> aad = stackalloc byte[FileIdSize + 9];
        Context(fileId, index, final, nonce, aad);
        var length = sealedChunk.Length - TagSize;
        gcm.Decrypt(nonce, sealedChunk[..length], sealedChunk[length..], plain[..length], aad);
    }

    private static void Context(byte[] fileId, long index, bool final, Span<byte> nonce, Span<byte> aad)
    {
        nonce.Clear();
        BinaryPrimitives.WriteInt64BigEndian(nonce[4..], index);
        fileId.CopyTo(aad);
        BinaryPrimitives.WriteInt64BigEndian(aad[FileIdSize..], index);
        aad[^1] = final ? (byte)1 : (byte)0;
    }

    /// <summary>The plaintext length of a CBE1 file of <paramref name="fileLength"/> bytes, or -1 if no valid file has that length.</summary>
    public static long PlainLength(long fileLength)
    {
        var body = fileLength - HeaderSize - TagSize;   // the empty final chunk is just its tag
        if (body < 0) return -1;
        if (body == 0) return 0;
        var full = body / SealedChunk;
        var rest = body % SealedChunk;
        if (rest == 0) return full * ChunkSize;
        return rest > TagSize ? full * ChunkSize + rest - TagSize : -1;
    }

    /// <summary>Where data chunk <paramref name="index"/> starts in the file.</summary>
    public static long ChunkOffset(long index) => HeaderSize + index * SealedChunk;
}

/// <summary>
/// PROD-57: writes a CBE1 file: the header, then the content in chunks as it's written, then (on dispose) the empty
/// final chunk. Write-only and forward-only, so it streams an upload of any size.
/// </summary>
public sealed class Cbe1WriteStream : Stream
{
    private readonly Stream _inner;
    private readonly AesGcm _gcm;
    private readonly byte[] _fileId;
    private readonly byte[] _buffer = new byte[Cbe1.ChunkSize];
    private readonly byte[] _sealed = new byte[Cbe1.SealedChunk];
    private int _filled;
    private long _index;
    private long _written;
    private bool _finished;

    public Cbe1WriteStream(Stream inner, string keyId, byte[] masterKey)
    {
        _inner = inner;
        var (header, fileKey, fileId) = Cbe1.NewHeader(keyId, masterKey);
        _fileId = fileId;
        _gcm = new AesGcm(fileKey, Cbe1.TagSize);
        CryptographicOperations.ZeroMemory(fileKey);
        _inner.Write(header);
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => !_finished;
    public override long Length => _written;
    public override long Position { get => _written; set => throw new NotSupportedException(); }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> data)
    {
        while (data.Length > 0)
        {
            if (_filled == Cbe1.ChunkSize) SealFull();
            var n = Math.Min(data.Length, Cbe1.ChunkSize - _filled);
            data[..n].CopyTo(_buffer.AsSpan(_filled));
            _filled += n;
            _written += n;
            data = data[n..];
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        while (data.Length > 0)
        {
            if (_filled == Cbe1.ChunkSize) await SealFullAsync(ct);
            var n = Math.Min(data.Length, Cbe1.ChunkSize - _filled);
            data.Span[..n].CopyTo(_buffer.AsSpan(_filled));
            _filled += n;
            _written += n;
            data = data[n..];
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();

    private void SealFull()
    {
        Cbe1.SealChunk(_gcm, _fileId, _index++, false, _buffer, _sealed);
        _inner.Write(_sealed);
        _filled = 0;
    }

    private async ValueTask SealFullAsync(CancellationToken ct)
    {
        Cbe1.SealChunk(_gcm, _fileId, _index++, false, _buffer, _sealed);
        await _inner.WriteAsync(_sealed, ct);
        _filled = 0;
    }

    /// <summary>Writes the last data chunk and the empty final chunk. Called by dispose; call it to finish early.</summary>
    public async Task FinishAsync(CancellationToken ct = default)
    {
        if (_finished) return;
        if (_filled > 0)
        {
            Cbe1.SealChunk(_gcm, _fileId, _index++, false, _buffer.AsSpan(0, _filled), _sealed);
            await _inner.WriteAsync(_sealed.AsMemory(0, _filled + Cbe1.TagSize), ct);
            _filled = 0;
        }
        Cbe1.SealChunk(_gcm, _fileId, _index, true, ReadOnlySpan<byte>.Empty, _sealed);
        await _inner.WriteAsync(_sealed.AsMemory(0, Cbe1.TagSize), ct);
        await _inner.FlushAsync(ct);
        _finished = true;
    }

    public override void Flush() => _inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override async ValueTask DisposeAsync()
    {
        await FinishAsync();
        _gcm.Dispose();
        CryptographicOperations.ZeroMemory(_buffer);
        await base.DisposeAsync();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_finished) FinishAsync().GetAwaiter().GetResult();
        if (disposing) { _gcm.Dispose(); CryptographicOperations.ZeroMemory(_buffer); }
        base.Dispose(disposing);
    }
}

/// <summary>
/// PROD-57: reads a CBE1 file's content: seekable (the chunk is worked out from the position), each chunk authenticated as
/// it's read, and the final chunk checked when the end is reached, so a file cut short reads as damaged, not as shorter.
/// </summary>
public sealed class Cbe1ReadStream : Stream
{
    private readonly Stream _inner;
    private readonly AesGcm _gcm;
    private readonly byte[] _fileId;
    private readonly long _length;
    private readonly long _chunks;   // data chunks
    private readonly byte[] _sealed = new byte[Cbe1.SealedChunk];
    private readonly byte[] _plain = new byte[Cbe1.ChunkSize];
    private long _loaded = -1;       // the data chunk in _plain
    private int _loadedLength;
    private long _position;
    private bool _finalChecked;

    /// <summary>Opens <paramref name="inner"/> (seekable, at any position) with the master key its header names.</summary>
    public Cbe1ReadStream(Stream inner, byte[] masterKey)
    {
        _inner = inner;
        var header = new byte[Cbe1.HeaderSize];
        inner.Position = 0;
        inner.ReadExactly(header);
        var (fileKey, fileId) = Cbe1.OpenHeader(header, masterKey);
        _fileId = fileId;
        _gcm = new AesGcm(fileKey, Cbe1.TagSize);
        CryptographicOperations.ZeroMemory(fileKey);
        _length = Cbe1.PlainLength(inner.Length);
        if (_length < 0) throw new CryptographicException("The encrypted file's length isn't a whole file: it was cut short or added to.");
        _chunks = (_length + Cbe1.ChunkSize - 1) / Cbe1.ChunkSize;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set => _position = value is >= 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    }

    public override long Seek(long offset, SeekOrigin origin) => Position = origin switch
    {
        SeekOrigin.Begin => offset,
        SeekOrigin.Current => _position + offset,
        _ => _length + offset,
    };

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> destination)
    {
        if (_position >= _length)
        {
            CheckFinal();
            return 0;
        }
        var index = _position / Cbe1.ChunkSize;
        if (index != _loaded) Load(index);
        var within = (int)(_position % Cbe1.ChunkSize);
        var n = Math.Min(destination.Length, _loadedLength - within);
        _plain.AsSpan(within, n).CopyTo(destination);
        _position += n;
        return n;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
        ValueTask.FromResult(Read(buffer.Span));

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        Task.FromResult(Read(buffer.AsSpan(offset, count)));

    private void Load(long index)
    {
        var length = index == _chunks - 1 ? (int)(_length - index * Cbe1.ChunkSize) : Cbe1.ChunkSize;
        _inner.Position = Cbe1.ChunkOffset(index);
        _inner.ReadExactly(_sealed, 0, length + Cbe1.TagSize);
        Cbe1.OpenChunk(_gcm, _fileId, index, false, _sealed.AsSpan(0, length + Cbe1.TagSize), _plain);
        _loaded = index;
        _loadedLength = length;
    }

    // The empty final chunk proves nothing was cut off after the last data chunk.
    private void CheckFinal()
    {
        if (_finalChecked) return;
        _inner.Position = _inner.Length - Cbe1.TagSize;   // the length was checked whole when the file was opened
        Span<byte> tag = stackalloc byte[Cbe1.TagSize];
        _inner.ReadExactly(tag);
        Cbe1.OpenChunk(_gcm, _fileId, _chunks, true, tag, Span<byte>.Empty);
        _finalChecked = true;
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _gcm.Dispose();
            CryptographicOperations.ZeroMemory(_plain);
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }
}
