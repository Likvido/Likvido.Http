using Likvido.Http.Tests.Support;
using Microsoft.Extensions.Logging;
using Shouldly;
using Xunit;

namespace Likvido.Http.Tests;

/// <summary>
/// A client whose policy allows any https origin keeps every other check: the public-address check
/// at connect time, no redirects and the size cap. Its URLs come from an outsider, so these are the
/// cases that matter most.
/// </summary>
public class AnyHttpsOriginTests
{
    private const string PublicAddress = "93.184.216.34";

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("https://169.254.169.254/latest/meta-data/")]
    [InlineData("https://127.0.0.1/")]
    [InlineData("https://[::ffff:10.0.0.1]/")]
    [InlineData("https://internal.example.com/client.json")]
    [InlineData("https://mixed.example.com/client.json")]
    [InlineData("https://rebinding.example.com/client.json")]
    public async Task RefusesANonPublicAddressWithoutOpeningAConnection(string url)
    {
        var transport = new FakeTransport()
            .Resolve("internal.example.com", "10.20.30.40")
            .Resolve("mixed.example.com", PublicAddress, "127.0.0.1")
            .Rebind("rebinding.example.com", "192.168.1.1", PublicAddress);
        using var guarded = new Guarded(AnyHttps(), transport);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(() => guarded.Client.GetAsync(url, Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.NonPublicAddress);
        transport.Connects.ShouldBeEmpty();
    }

    [Fact]
    public async Task ConnectsToTheAddressItCheckedWithoutResolvingTheNameAgain()
    {
        await using var server = TestServer.Ok("{}"u8.ToArray(), tls: true);
        var transport = new FakeTransport(server).Rebind("rebinding.example.com", PublicAddress, "127.0.0.1");
        using var guarded = new Guarded(AnyHttps(), transport);

        (await guarded.Client.GetStringAsync("https://rebinding.example.com/client.json", Token)).ShouldBe("{}");

        transport.Lookups.ShouldBe(1);
        transport.Connects.ShouldHaveSingleItem().ShouldBe([System.Net.IPAddress.Parse(PublicAddress)]);
    }

    [Theory]
    [InlineData("http://169.254.169.254/")]
    [InlineData("https://169.254.169.254/")]
    [InlineData("https://files.example.com/")]
    public async Task RefusesARedirectInsteadOfFollowingIt(string location)
    {
        await using var server = TestServer.Respond(
            $"HTTP/1.1 302 Found\nLocation: {location}\nContent-Length: 0\nConnection: close\n",
            [],
            tls: true);
        var transport = new FakeTransport(server).Resolve("client.example.com", PublicAddress);
        using var guarded = new Guarded(AnyHttps(), transport);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => guarded.Client.GetAsync("https://client.example.com/client.json", Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.Redirect);
        server.Requests.ShouldBe(["GET /client.json HTTP/1.1"]);
        transport.Connects.Count.ShouldBe(1, "only the first host was connected to");
    }

    [Theory]
    [InlineData("http://client.example.com/client.json")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("https://client.example.com:8443/client.json")]
    public async Task RefusesHttpAndANonDefaultPortBeforeSendingAnything(string url)
    {
        var transport = new FakeTransport().Resolve("client.example.com", PublicAddress);
        using var guarded = new Guarded(AnyHttps(), transport);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(() => guarded.Client.GetAsync(url, Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.UnlistedOrigin);
        transport.Lookups.ShouldBe(0);
        transport.Connects.ShouldBeEmpty();
    }

    [Fact]
    public async Task ReturnsTheBodyOfAPublicHttpsFetchUnderTheCap()
    {
        await using var server = TestServer.Ok("""{"client_id":"https://client.example.com/client.json"}"""u8.ToArray(), tls: true);
        var transport = new FakeTransport(server).Resolve("client.example.com", PublicAddress);
        using var guarded = new Guarded(AnyHttps(), transport);

        var body = await guarded.Client.GetStringAsync("https://client.example.com/client.json", Token);

        body.ShouldBe("""{"client_id":"https://client.example.com/client.json"}""");
        guarded.Logs.Guard.ShouldBeEmpty();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RefusesABodyOverTheCap(bool declareLength)
    {
        await using var server = TestServer.Ok(new byte[1_001], declareLength, tls: true);
        var transport = new FakeTransport(server).Resolve("client.example.com", PublicAddress);
        using var guarded = new Guarded(AnyHttps(maxResponseBytes: 1_000), transport);

        var refusal = await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => guarded.Client.GetByteArrayAsync("https://client.example.com/client.json", Token));

        refusal.Reason.ShouldBe(OutboundRequestRefusalReason.ResponseTooLarge);
    }

    [Fact]
    public async Task ARefusalLogsOneWarningWithTheSchemeAndHostOnly()
    {
        var transport = new FakeTransport().Resolve("internal.example.com", "10.20.30.40");
        using var guarded = new Guarded(AnyHttps(), transport);

        await Should.ThrowAsync<OutboundRequestRefusedException>(
            () => guarded.Client.GetAsync("https://internal.example.com/oauth/client.json?token=secret", Token));

        var warning = guarded.Logs.Guard.ShouldHaveSingleItem();
        warning.Level.ShouldBe(LogLevel.Warning);
        warning.Message.ShouldContain("https://internal.example.com");
        warning.Message.ShouldNotContain("/oauth/client.json");
        guarded.Logs.Entries.ShouldNotContain(entry => entry.Message.Contains("token=secret"));
        guarded.Logs.Entries.ShouldNotContain(entry => entry.Level >= LogLevel.Error);
    }

    [Fact]
    public void KeepsEveryOtherSettingOfTheSocketHandler()
    {
        using var guarded = new Guarded(AnyHttps(maxConnectionsPerServer: 8), new FakeTransport());

        var socketsHandler = SocketsHandlerOf(guarded);

        socketsHandler.AllowAutoRedirect.ShouldBeFalse();
        socketsHandler.UseProxy.ShouldBeFalse();
        socketsHandler.UseCookies.ShouldBeFalse();
        socketsHandler.ConnectCallback.ShouldNotBeNull();
        socketsHandler.PooledConnectionLifetime.ShouldBe(TimeSpan.FromMinutes(2));
        socketsHandler.MaxConnectionsPerServer.ShouldBe(8);
    }

    [Fact]
    public void LeavesTheConnectionLimitAloneWhenThePolicySetsNone()
    {
        using var guarded = new Guarded(new OutboundRequestPolicy(["https://files.example.com"], 1_000), new FakeTransport());

        SocketsHandlerOf(guarded).MaxConnectionsPerServer.ShouldBe(new SocketsHttpHandler().MaxConnectionsPerServer);
    }

    private static OutboundRequestPolicy AnyHttps(long maxResponseBytes = 1_000_000, int? maxConnectionsPerServer = null) =>
        OutboundRequestPolicy.ForAnyHttpsOrigin(maxResponseBytes, maxConnectionsPerServer);

    private static SocketsHttpHandler SocketsHandlerOf(Guarded guarded)
    {
        HttpMessageHandler? handler = guarded.HandlerFactory.CreateHandler(Guarded.ClientName);

        while (handler is DelegatingHandler delegating)
        {
            if (delegating.InnerHandler is SocketsHttpHandler sockets)
            {
                return sockets;
            }

            handler = delegating.InnerHandler;
        }

        throw new InvalidOperationException("The guarded client has no SocketsHttpHandler.");
    }
}
