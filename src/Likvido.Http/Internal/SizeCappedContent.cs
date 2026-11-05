using System.Net;

namespace Likvido.Http.Internal;

/// <summary>
/// Wraps a response body so that reading it stops with a refusal once it passes the cap.
/// <para>
/// A declared <c>Content-Length</c> is checked before this, but it is optional and self-reported,
/// so this count of the bytes actually read is the cap that holds. It applies however the caller
/// reads the body: buffered by <see cref="HttpClient"/>, as a string or as a stream.
/// </para>
/// </summary>
internal sealed class SizeCappedContent : HttpContent
{
    private readonly HttpContent _inner;
    private readonly long _maxBytes;
    private readonly Func<long, Exception> _refuse;

    internal SizeCappedContent(HttpContent inner, long maxBytes, Func<long, Exception> refuse)
    {
        _inner = inner;
        _maxBytes = maxBytes;
        _refuse = refuse;

        foreach (var header in inner.Headers)
        {
            Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override async Task SerializeToStreamAsync(
        Stream stream,
        TransportContext? context,
        CancellationToken cancellationToken)
    {
        await using var source = await CreateContentReadStreamAsync(cancellationToken);
        await source.CopyToAsync(stream, cancellationToken);
    }

    protected override void SerializeToStream(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
        using var source = CreateContentReadStream(cancellationToken);
        source.CopyTo(stream);
    }

    protected override Task<Stream> CreateContentReadStreamAsync() =>
        CreateContentReadStreamAsync(CancellationToken.None);

    protected override async Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken) =>
        new SizeCappedStream(await _inner.ReadAsStreamAsync(cancellationToken), _maxBytes, _refuse);

    protected override Stream CreateContentReadStream(CancellationToken cancellationToken) =>
        new SizeCappedStream(_inner.ReadAsStream(cancellationToken), _maxBytes, _refuse);

    // The length is unknown unless the response declared it, in which case the copied
    // Content-Length header answers and this is not asked.
    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// A read-only stream that throws once more than the cap has been read from it.
/// </summary>
internal sealed class SizeCappedStream(Stream inner, long maxBytes, Func<long, Exception> refuse) : Stream
{
    private long _total;
    private Exception? _refusal;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        ThrowIfRefused();
        return Count(inner.Read(buffer));
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfRefused();
        return Count(await inner.ReadAsync(buffer, cancellationToken));
    }

    public override int ReadByte()
    {
        Span<byte> one = stackalloc byte[1];
        return Read(one) == 0 ? -1 : one[0];
    }

    private int Count(int read)
    {
        _total += read;

        if (_total > maxBytes)
        {
            // Created once, so the refusal is logged once however often the caller reads again.
            _refusal = refuse(_total);
            throw _refusal;
        }

        return read;
    }

    private void ThrowIfRefused()
    {
        if (_refusal is not null)
        {
            throw _refusal;
        }
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        await inner.DisposeAsync();
        await base.DisposeAsync();
    }
}
