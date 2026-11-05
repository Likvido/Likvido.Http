using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Likvido.Http.Internal;

namespace Likvido.Http.Tests.Support;

/// <summary>
/// Resolves made-up host names to the addresses a test gives, records every connect, and connects
/// every approved connection to the loopback <see cref="TestServer"/> instead of the real address.
/// </summary>
internal sealed class FakeTransport(TestServer? server = null) : OutboundTransport
{
    private readonly ConcurrentDictionary<string, IPAddress[]> _names = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<IPAddress[]> _connects = new();

    internal IReadOnlyCollection<IPAddress[]> Connects => _connects;

    internal FakeTransport Resolve(string host, params string[] addresses)
    {
        _names[host] = addresses.Select(IPAddress.Parse).ToArray();
        return this;
    }

    internal override ValueTask<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
        _names.TryGetValue(host, out var addresses)
            ? ValueTask.FromResult(addresses)
            : throw new SocketException((int)SocketError.HostNotFound);

    internal override async ValueTask<Stream> ConnectAsync(IPAddress[] addresses, int port, CancellationToken cancellationToken)
    {
        _connects.Enqueue(addresses);

        if (server is null)
        {
            throw new InvalidOperationException("This test has no server, so no connection may be opened.");
        }

        var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, server.Port, cancellationToken);

        return client.GetStream();
    }

    internal override void ConfigureHandler(SocketsHttpHandler handler) =>
        handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
}
