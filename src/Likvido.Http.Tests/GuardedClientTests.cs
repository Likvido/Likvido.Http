using System.IO.Compression;
using System.Net;
using System.Text;
using Likvido.Http.Tests.Support;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Shouldly;
using Xunit;

namespace Likvido.Http.Tests;

public class GuardedClientTests
{
    private const string PublicAddress = "93.184.216.34";
    private const string OtherPublicAddress = "93.184.216.35";

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("http://127.0.0.1/")]
    [InlineData("http://10.0.0.1/")]
    [InlineData("http://[::ffff:169.254.169.254]/")]
    [InlineData("http://internal.example.com/")]
    [InlineData("http://rebinding.example.com/")]
    public async Task RefusesANonPublicAddressWithoutOpeningAConnection(string url)
    {
        // Each origin is listed, so it is the address check that refuses, not the origin check.
        var transport = new FakeTransport()
            .Resolve("internal.example.com", "10.20.30.40")
            .Resolve("rebinding.example.com", PublicAddress, "127.0.0.1");
        using var guarded = new Guarded(Policy(new Uri(url).GetLeftPart(UriPartial.Authority)), transport);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(() => guarded.Client.GetAsync(url, Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.NonPublicAddress);
        transport.Connects.ShouldBeEmpty();
    }

    [Fact]
    public async Task RefusesARedirectFromAListedHttpsHostInsteadOfFollowingIt()
    {
        await using var server = TestServer.Respond(
            "HTTP/1.1 302 Found\nLocation: http://169.254.169.254/\nContent-Length: 0\nConnection: close\n",
            [],
            tls: true);
        var transport = new FakeTransport(server).Resolve("files.example.com", PublicAddress);
        using var guarded = new Guarded(Policy("https://files.example.com"), transport);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => guarded.Client.GetAsync("https://files.example.com/report.xml", Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.Redirect);
        refusal.Message.ShouldContain("http://169.254.169.254");
        server.Requests.ShouldBe(["GET /report.xml HTTP/1.1"]);
        transport.Connects.Count.ShouldBe(1, "only the listed host was connected to");
    }

    [Fact]
    public async Task RefusesARedirectToAnotherPublicHttpsHostInsteadOfFollowingIt()
    {
        // Two servers, so a followed redirect would reach the second one and get a 200 back.
        await using var listed = TestServer.Respond(
            "HTTP/1.1 302 Found\nLocation: https://other.example.com/elsewhere\nContent-Length: 0\nConnection: close\n",
            [],
            tls: true);
        await using var unlisted = TestServer.Ok("followed"u8.ToArray(), tls: true);
        var transport = new FakeTransport(listed)
            .Resolve("files.example.com", PublicAddress)
            .Resolve("other.example.com", OtherPublicAddress)
            .Route(OtherPublicAddress, unlisted);
        using var guarded = new Guarded(Policy("https://files.example.com"), transport);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => guarded.Client.GetAsync("https://files.example.com/report.xml", Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.Redirect);
        refusal.Message.ShouldContain("https://other.example.com");
        unlisted.Requests.ShouldBeEmpty();
        transport.Connects.Count.ShouldBe(1);
    }

    [Theory]
    [InlineData("HEAD", "200 OK")]
    [InlineData("GET", "204 No Content")]
    [InlineData("GET", "304 Not Modified")]
    public async Task DoesNotRefuseAResponseWithoutABodyForItsDeclaredLength(string method, string status)
    {
        await using var server = TestServer.Respond(
            $"HTTP/1.1 {status}\nContent-Length: 999999\nConnection: close\n",
            []);
        using var guarded = Http(server, maxResponseBytes: 1_000);

        using var response = await guarded.Client.SendAsync(
            new HttpRequestMessage(new HttpMethod(method), "http://files.example.com/big"),
            Token);

        ((int)response.StatusCode).ShouldBe(int.Parse(status[..3]));
        guarded.Logs.Guard.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("https://other.example.com/file")]
    [InlineData("http://files.example.com/file")]
    [InlineData("https://files.example.com:8443/file")]
    [InlineData("https://sub.files.example.com/file")]
    public async Task RefusesAnUnlistedOriginBeforeSendingAnything(string url)
    {
        var transport = new FakeTransport().Resolve("other.example.com", PublicAddress);
        using var guarded = new Guarded(Policy("https://files.example.com"), transport);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(() => guarded.Client.GetAsync(url, Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.UnlistedOrigin);
        transport.Connects.ShouldBeEmpty();
    }

    [Fact]
    public void RefusesAnUnlistedOriginOnTheSynchronousPathToo()
    {
        var transport = new FakeTransport();
        using var guarded = new Guarded(Policy("https://files.example.com"), transport);

        var refusal = Should.Throw<OutboundRequestRefusedException>(
            () => guarded.Client.Send(new HttpRequestMessage(HttpMethod.Get, "http://169.254.169.254/"), Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.UnlistedOrigin);
        transport.Connects.ShouldBeEmpty();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RefusesABodyOverTheCap(bool declareLength)
    {
        await using var server = TestServer.Ok(new byte[2_000], declareLength);
        using var guarded = Http(server, maxResponseBytes: 1_000);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => guarded.Client.GetByteArrayAsync("http://files.example.com/big", Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.ResponseTooLarge);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RefusesABodyOverTheCapWhenTheCallerStreamsIt(bool declareLength)
    {
        await using var server = TestServer.Ok(new byte[200_000], declareLength);
        using var guarded = Http(server, maxResponseBytes: 1_000);

        await Should.ThrowAsync<OutboundRequestRefusedException>(async () =>
        {
            using var response = await guarded.Client.GetAsync(
                "http://files.example.com/big",
                HttpCompletionOption.ResponseHeadersRead,
                Token);
            await using var body = await response.Content.ReadAsStreamAsync(Token);
            await body.CopyToAsync(Stream.Null, Token);
        });
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ReturnsTheBodyOfAnAllowedFetchUnderTheCap(bool declareLength)
    {
        await using var server = TestServer.Ok("<report>42</report>"u8.ToArray(), declareLength);
        using var guarded = Http(server, maxResponseBytes: 1_000);

        var body = await guarded.Client.GetStringAsync("http://files.example.com/report.xml?sig=secret", Token);

        body.ShouldBe("<report>42</report>");
        server.Requests.ShouldBe(["GET /report.xml?sig=secret HTTP/1.1"]);
    }

    [Fact]
    public async Task ReturnsABodyOfExactlyTheCap()
    {
        await using var server = TestServer.Ok(new byte[1_000], declareLength: false);
        using var guarded = Http(server, maxResponseBytes: 1_000);

        var body = await guarded.Client.GetByteArrayAsync("http://files.example.com/exact", Token);

        body.Length.ShouldBe(1_000);
    }

    [Fact]
    public async Task ReturnsTheBodyOfAnAllowedHttpsFetch()
    {
        await using var server = TestServer.Ok("hello"u8.ToArray(), tls: true);
        var transport = new FakeTransport(server).Resolve("files.example.com", PublicAddress);
        using var guarded = new Guarded(Policy("https://files.example.com"), transport);

        (await guarded.Client.GetStringAsync("https://files.example.com/hello", Token)).ShouldBe("hello");
    }

    [Fact]
    public async Task ARefusalLogsOneWarningWithTheHostAndReasonAndNoError()
    {
        var transport = new FakeTransport().Resolve("internal.example.com", "10.20.30.40");
        using var guarded = new Guarded(Policy("https://internal.example.com"), transport);

        await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => guarded.Client.GetAsync("https://internal.example.com/blob/file.pdf?sig=secret-signature", Token));

        var warning = guarded.Logs.Guard.ShouldHaveSingleItem();
        warning.Level.ShouldBe(LogLevel.Warning);
        warning.Message.ShouldContain("https://internal.example.com");
        warning.Message.ShouldContain(nameof(OutboundRequestRefusalReason.NonPublicAddress));
        warning.Message.ShouldContain(Guarded.ClientName);

        guarded.Logs.Entries.ShouldNotContain(entry => entry.Level >= LogLevel.Error);
        guarded.Logs.Entries.ShouldNotContain(entry => entry.Message.Contains("secret-signature"));

        // The factory's own Information lines name the path, with the query redacted; the guard's do not.
        guarded.Logs.Guard.ShouldNotContain(entry => entry.Message.Contains("/blob/file.pdf"));
    }

    [Theory]
    [InlineData("https://elsewhere.example.com/blob/file.pdf?sig=secret-signature", OutboundRequestRefusalReason.UnlistedOrigin)]
    [InlineData("http://files.example.com/blob/file.pdf?sig=secret-signature", OutboundRequestRefusalReason.ResponseTooLarge)]
    public async Task EveryRefusalLogsOneWarningWithoutThePathOrQuery(string url, OutboundRequestRefusalReason reason)
    {
        await using var server = TestServer.Ok(new byte[2_000], declareLength: false);
        using var guarded = Http(server, maxResponseBytes: 1_000);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(() => guarded.Client.GetAsync(url, Token));

        refusal.Reason.ShouldBe(reason);
        refusal.Message.ShouldNotContain("secret-signature");
        refusal.Message.ShouldNotContain("/blob/file.pdf");

        var warning = guarded.Logs.Guard.ShouldHaveSingleItem();
        warning.Level.ShouldBe(LogLevel.Warning);
        warning.Message.ShouldContain(reason.ToString());
        warning.Message.ShouldContain(new Uri(url).Host);
        warning.Message.ShouldNotContain("/blob/file.pdf");

        guarded.Logs.Entries.ShouldNotContain(entry => entry.Level >= LogLevel.Error);
        guarded.Logs.Entries.ShouldNotContain(entry => entry.Message.Contains("secret-signature"));
    }

    [Fact]
    public async Task DecompressesGzipWhenThePolicyAsksForIt()
    {
        await using var server = TestServer.Ok(Gzip(Encoding.UTF8.GetBytes("<report>42</report>")), extraHeaders: "Content-Encoding: gzip\n");
        using var guarded = Http(server, maxResponseBytes: 1_000, DecompressionMethods.GZip);

        (await guarded.Client.GetStringAsync("http://files.example.com/report.xml", Token)).ShouldBe("<report>42</report>");
    }

    [Fact]
    public async Task AppliesTheCapToTheDecompressedBody()
    {
        // About 1 KB on the wire, 1 MB once decompressed.
        var compressed = Gzip(new byte[1_000_000]);
        compressed.Length.ShouldBeLessThan(10_000);

        await using var server = TestServer.Ok(compressed, extraHeaders: "Content-Encoding: gzip\n");
        using var guarded = Http(server, maxResponseBytes: 100_000, DecompressionMethods.GZip);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => guarded.Client.GetByteArrayAsync("http://files.example.com/bomb", Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.ResponseTooLarge);
    }

    [Fact]
    public async Task AStandardResilienceHandlerAddedByTheCallerDoesNotRetryARefusal()
    {
        var transport = new FakeTransport().Resolve("internal.example.com", "10.20.30.40");
        using var guarded = new Guarded(
            Policy("https://internal.example.com"),
            transport,
            builder => builder.AddStandardResilienceHandler());

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => guarded.Client.GetAsync("https://internal.example.com/", Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.NonPublicAddress);
        guarded.Logs.Guard.Count.ShouldBe(1, "a retried request would be refused, and logged, again");
        guarded.Logs.Entries.ShouldNotContain(entry => entry.Level >= LogLevel.Error);
    }

    [Fact]
    public async Task AStandardResilienceHandlerAddedByTheCallerKeepsWorking()
    {
        await using var server = TestServer.Ok("ok"u8.ToArray());
        using var guarded = Http(server, maxResponseBytes: 1_000, configure: builder => builder.AddStandardResilienceHandler());

        (await guarded.Client.GetStringAsync("http://files.example.com/", Token)).ShouldBe("ok");
    }

    [Fact]
    public async Task KeepsRequestsOffHttp3()
    {
        await using var server = TestServer.Ok("ok"u8.ToArray());
        using var guarded = Http(server, maxResponseBytes: 1_000);
        using var request = new HttpRequestMessage(HttpMethod.Get, "http://files.example.com/")
        {
            Version = HttpVersion.Version30,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrHigher
        };

        using var response = await guarded.Client.SendAsync(request, Token);

        request.Version.ShouldBe(HttpVersion.Version20);
        request.VersionPolicy.ShouldBe(HttpVersionPolicy.RequestVersionOrLower);
        response.Version.ShouldBe(HttpVersion.Version11);
    }

    [Fact]
    public async Task GuardsATypedClient()
    {
        await using var server = TestServer.Ok("ok"u8.ToArray());
        var transport = new FakeTransport(server).Resolve("files.example.com", PublicAddress);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<Internal.OutboundTransport>(transport);
        services.AddGuardedHttpClient<IFetcher, Fetcher>(Policy("http://files.example.com"));
        services.AddGuardedHttpClient<ConcreteFetcher>(_ => Policy("http://files.example.com"));
        await using var provider = services.BuildServiceProvider();

        var fetcher = provider.GetRequiredService<IFetcher>();
        (await fetcher.Client.GetStringAsync("http://files.example.com/", Token)).ShouldBe("ok");
        await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => fetcher.Client.GetAsync("http://169.254.169.254/latest/meta-data/", Token));

        var concrete = provider.GetRequiredService<ConcreteFetcher>();
        await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => concrete.Client.GetAsync("http://169.254.169.254/latest/meta-data/", Token));
    }

    private static OutboundRequestPolicy Policy(params string[] origins) => new(origins, 1_000_000);

    private static Guarded Http(
        TestServer server,
        long maxResponseBytes,
        DecompressionMethods decompression = DecompressionMethods.None,
        Action<IHttpClientBuilder>? configure = null) =>
        new(
            new OutboundRequestPolicy(["http://files.example.com"], maxResponseBytes) { AutomaticDecompression = decompression },
            new FakeTransport(server).Resolve("files.example.com", PublicAddress),
            configure);

    private static byte[] Gzip(byte[] data)
    {
        using var output = new MemoryStream();

        using (var gzip = new GZipStream(output, CompressionLevel.Optimal))
        {
            gzip.Write(data);
        }

        return output.ToArray();
    }

    public interface IFetcher
    {
        HttpClient Client { get; }
    }

    public sealed class Fetcher(HttpClient client) : IFetcher
    {
        public HttpClient Client => client;
    }

    public sealed class ConcreteFetcher(HttpClient client)
    {
        public HttpClient Client => client;
    }
}
