using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Likvido.Http.Tests.Support;

/// <summary>Builds a service provider with one guarded named client, the fake transport and captured logs.</summary>
internal sealed class Guarded : IDisposable
{
    internal const string ClientName = "test-client";

    private readonly ServiceProvider _provider;

    internal Guarded(
        OutboundRequestPolicy policy,
        FakeTransport transport,
        Action<IHttpClientBuilder>? configure = null)
    {
        Transport = transport;

        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(Logs).SetMinimumLevel(LogLevel.Trace));
        services.AddSingleton<Internal.OutboundTransport>(transport);

        var builder = services.AddGuardedHttpClient(ClientName, policy);
        configure?.Invoke(builder);

        _provider = services.BuildServiceProvider();
        Client = _provider.GetRequiredService<IHttpClientFactory>().CreateClient(ClientName);
    }

    internal CapturedLogs Logs { get; } = new();

    internal FakeTransport Transport { get; }

    internal HttpClient Client { get; }

    internal IServiceProvider Services => _provider;

    public void Dispose()
    {
        Client.Dispose();
        _provider.Dispose();
    }
}
