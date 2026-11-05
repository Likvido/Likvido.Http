using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Likvido.Http.Tests.Support;

/// <summary>
/// A loopback HTTP/1.1 server that answers every request with one canned response and closes the
/// connection. With <c>tls: true</c> it serves https with a self-signed certificate, which
/// <see cref="FakeTransport"/> makes the client trust.
/// </summary>
internal sealed class TestServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly X509Certificate2? _certificate;
    private readonly byte[] _response;
    private readonly Task _loop;
    private readonly List<string> _requests = [];

    private TestServer(byte[] response, bool tls)
    {
        _response = response;
        _certificate = tls ? CreateCertificate() : null;
        _listener.Start();
        _loop = AcceptAsync();
    }

    internal int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>The request line of each request received, such as <c>GET /a HTTP/1.1</c>.</summary>
    internal IReadOnlyList<string> Requests
    {
        get
        {
            lock (_requests)
            {
                return _requests.ToArray();
            }
        }
    }

    internal static TestServer Respond(string head, byte[] body, bool tls = false) =>
        new([.. Encoding.ASCII.GetBytes(head.ReplaceLineEndings("\r\n") + "\r\n"), .. body], tls);

    internal static TestServer Ok(byte[] body, bool declareLength = true, bool tls = false, string extraHeaders = "") =>
        Respond(
            "HTTP/1.1 200 OK\nConnection: close\nContent-Type: application/octet-stream\n"
            + (declareLength ? $"Content-Length: {body.Length}\n" : string.Empty)
            + extraHeaders,
            body,
            tls);

    private async Task AcceptAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;

            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch (Exception) when (_stop.IsCancellationRequested)
            {
                return;
            }

            _ = HandleAsync(client);
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                Stream stream = client.GetStream();

                if (_certificate is not null)
                {
                    var ssl = new SslStream(stream);
                    await ssl.AuthenticateAsServerAsync(
                        new SslServerAuthenticationOptions { ServerCertificate = _certificate },
                        _stop.Token);
                    stream = ssl;
                }

                await using (stream)
                {
                    var head = await ReadHeadAsync(stream);

                    lock (_requests)
                    {
                        _requests.Add(head.Split("\r\n")[0]);
                    }

                    await stream.WriteAsync(_response, _stop.Token);
                    await stream.FlushAsync(_stop.Token);
                }
            }
            catch (Exception)
            {
                // A client that refuses the response part-way closes the connection; that is expected.
            }
        }
    }

    private async Task<string> ReadHeadAsync(Stream stream)
    {
        var head = new StringBuilder();
        var one = new byte[1];

        while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            if (await stream.ReadAsync(one, _stop.Token) == 0)
            {
                break;
            }

            head.Append((char)one[0]);
        }

        return head.ToString();
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=likvido-http-tests", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Round-tripped through PKCS#12 because macOS cannot serve TLS with an ephemeral key.
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pkcs12), password: null);
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        await _loop;
        _certificate?.Dispose();
        _stop.Dispose();
    }
}
