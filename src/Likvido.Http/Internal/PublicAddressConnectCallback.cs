using System.Net;

namespace Likvido.Http.Internal;

/// <summary>
/// A <see cref="SocketsHttpHandler.ConnectCallback"/> that refuses to open a socket to anything but a
/// public IP address. Lifted from Likvido.Mcp's <c>McpConnectCallback</c>.
/// <para>
/// ⚠️ This, not a check of <c>Dns.GetHostAddresses</c> before the request, is what closes the hole.
/// Resolving the host, approving the answer and then handing the <em>name</em> to the socket layer
/// resolves it again, and a DNS rebinding attacker answers publicly for the check and
/// <c>127.0.0.1</c> for the connection. Here the socket connects to the <see cref="IPAddress"/> that
/// was approved.
/// </para>
/// </summary>
internal sealed class PublicAddressConnectCallback(OutboundTransport transport, RefusalReporter reporter)
{
    internal async ValueTask<Stream> ConnectAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var host = context.DnsEndPoint.Host;

        var addresses = IPAddress.TryParse(host, out var literal)
            ? [literal]
            : await transport.ResolveAsync(host, cancellationToken);

        if (addresses.Length == 0)
        {
            throw new HttpRequestException($"'{host}' did not resolve to any address.");
        }

        // Every resolved address must be public, not merely the one tried first: a host that
        // resolves to both a public address and 127.0.0.1 would otherwise be a coin flip, and the
        // socket's own failover would eventually reach the private one.
        foreach (var address in addresses)
        {
            if (!PublicAddressGuard.IsPublic(address, out var reason))
            {
                throw reporter.Refuse(
                    OutboundRequestRefusalReason.NonPublicAddress,
                    RefusalReporter.OriginOf(context.InitialRequestMessage.RequestUri),
                    $"{host} resolves to {address}, which is not a public address ({reason}). No connection was opened.");
            }
        }

        return await transport.ConnectAsync(addresses, context.DnsEndPoint.Port, cancellationToken);
    }
}
