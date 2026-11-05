using System.Net;
using System.Net.Sockets;

namespace Likvido.Http.Internal;

/// <summary>
/// Name resolution and the socket connect behind a guarded client. The tests replace it, through the
/// service provider, to resolve made-up names and to see whether a connection was opened.
/// </summary>
internal class OutboundTransport
{
    internal static readonly OutboundTransport Default = new();

    internal virtual async ValueTask<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
        await Dns.GetHostAddressesAsync(host, cancellationToken);

    /// <summary>
    /// Connects to one of the given addresses, never to a name, so the address that was checked is
    /// the address the socket reaches.
    /// </summary>
    internal virtual async ValueTask<Stream> ConnectAsync(
        IPAddress[] addresses,
        int port,
        CancellationToken cancellationToken)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

        try
        {
            await socket.ConnectAsync(addresses, port, cancellationToken);

            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>A hook for the tests, which trust a self-signed certificate. Does nothing here.</summary>
    internal virtual void ConfigureHandler(SocketsHttpHandler handler)
    {
    }
}
