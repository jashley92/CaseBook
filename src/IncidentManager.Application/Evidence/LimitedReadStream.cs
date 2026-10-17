namespace IncidentManager.Application.Evidence;

/// <summary>
/// PROD-55: reads through to <c>inner</c>, and throws the given exception once more than <c>limit</c> bytes have been
/// read, so a file larger than the administrator allows is refused while it streams in, whatever size was declared for
/// it. The store deletes what it had written (FileEvidenceStore.SaveAsync), so nothing of it stays.
/// </summary>
internal sealed class LimitedReadStream(Stream inner, long limit, Func<Exception> tooLarge) : Stream
{
    private long _read;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => _read; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => Counted(inner.Read(buffer, offset, count));

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        Counted(await inner.ReadAsync(buffer, cancellationToken));

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    private int Counted(int n)
    {
        _read += n;
        if (_read > limit) throw tooLarge();
        return n;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
