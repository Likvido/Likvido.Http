using Likvido.Http.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Likvido.Http;

/// <summary>
/// Registers HTTP clients for server-side fetches of URLs that come from outside data, such as a link
/// in a third party's reply.
/// </summary>
/// <remarks>
/// A guarded client:
/// <list type="bullet">
/// <item>sends a request only to an origin in its <see cref="OutboundRequestPolicy"/>, and refuses any
/// other before anything is sent;</item>
/// <item>opens a connection only to a public IP address, checking every address the host resolves to
/// and connecting to the checked address, which defeats DNS rebinding;</item>
/// <item>follows no redirects, and refuses a redirect response;</item>
/// <item>refuses a response that declares a body over the policy's cap, and stops reading one that
/// passes the cap without declaring its length;</item>
/// <item>uses no proxy and no cookies.</item>
/// </list>
/// A refusal throws <see cref="OutboundRequestRefusedException"/> and logs one Warning with the
/// client's name, the scheme and host, and the reason. The path and query string are never logged.
/// <para>
/// The methods return the client's <see cref="IHttpClientBuilder"/>, so the caller can still set the
/// base address and timeout with <c>ConfigureHttpClient</c> and add handlers, such as
/// <c>AddStandardResilienceHandler</c>. The guard is the client's primary handler, so handlers the
/// caller adds run outside it. Do not call <c>ConfigurePrimaryHttpMessageHandler</c> or
/// <c>UseSocketsHttpHandler</c> on a guarded client outside tests: either replaces the guard.
/// </para>
/// </remarks>
public static class GuardedHttpClientServiceCollectionExtensions
{
    /// <summary>
    /// Adds a typed client, like <c>AddHttpClient&lt;TClient, TImplementation&gt;</c>, guarded by the policy.
    /// </summary>
    public static IHttpClientBuilder AddGuardedHttpClient<TClient, TImplementation>(
        this IServiceCollection services,
        OutboundRequestPolicy policy)
        where TClient : class
        where TImplementation : class, TClient
    {
        ArgumentNullException.ThrowIfNull(policy);

        return services.AddGuardedHttpClient<TClient, TImplementation>(_ => policy);
    }

    /// <summary>
    /// Adds a typed client, like <c>AddHttpClient&lt;TClient, TImplementation&gt;</c>, guarded by a policy
    /// built from the service provider, for example from configuration.
    /// </summary>
    public static IHttpClientBuilder AddGuardedHttpClient<TClient, TImplementation>(
        this IServiceCollection services,
        Func<IServiceProvider, OutboundRequestPolicy> policyFactory)
        where TClient : class
        where TImplementation : class, TClient
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(policyFactory);

        return services.AddHttpClient<TClient, TImplementation>().AddGuard(policyFactory);
    }

    /// <summary>
    /// Adds a typed client, like <c>AddHttpClient&lt;TClient&gt;</c>, guarded by the policy.
    /// </summary>
    public static IHttpClientBuilder AddGuardedHttpClient<TClient>(
        this IServiceCollection services,
        OutboundRequestPolicy policy)
        where TClient : class
    {
        ArgumentNullException.ThrowIfNull(policy);

        return services.AddGuardedHttpClient<TClient>(_ => policy);
    }

    /// <summary>
    /// Adds a typed client, like <c>AddHttpClient&lt;TClient&gt;</c>, guarded by a policy built from the
    /// service provider, for example from configuration.
    /// </summary>
    public static IHttpClientBuilder AddGuardedHttpClient<TClient>(
        this IServiceCollection services,
        Func<IServiceProvider, OutboundRequestPolicy> policyFactory)
        where TClient : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(policyFactory);

        return services.AddHttpClient<TClient>().AddGuard(policyFactory);
    }

    /// <summary>
    /// Adds a named client, like <c>AddHttpClient(name)</c>, guarded by the policy. Create it with
    /// <see cref="IHttpClientFactory.CreateClient(string)"/>.
    /// </summary>
    public static IHttpClientBuilder AddGuardedHttpClient(
        this IServiceCollection services,
        string name,
        OutboundRequestPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        return services.AddGuardedHttpClient(name, _ => policy);
    }

    /// <summary>
    /// Adds a named client, like <c>AddHttpClient(name)</c>, guarded by a policy built from the service
    /// provider, for example from configuration. Create it with
    /// <see cref="IHttpClientFactory.CreateClient(string)"/>.
    /// </summary>
    public static IHttpClientBuilder AddGuardedHttpClient(
        this IServiceCollection services,
        string name,
        Func<IServiceProvider, OutboundRequestPolicy> policyFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(policyFactory);

        return services.AddHttpClient(name).AddGuard(policyFactory);
    }

    private static IHttpClientBuilder AddGuard(
        this IHttpClientBuilder builder,
        Func<IServiceProvider, OutboundRequestPolicy> policyFactory)
    {
        var clientName = builder.Name;

        return builder.ConfigurePrimaryHttpMessageHandler(serviceProvider =>
        {
            var policy = policyFactory(serviceProvider)
                ?? throw new InvalidOperationException(
                    $"The policy factory for the guarded HTTP client '{clientName}' returned null.");

            var loggerFactory = serviceProvider.GetService<ILoggerFactory>() ?? NullLoggerFactory.Instance;
            var reporter = new RefusalReporter(loggerFactory.CreateLogger(RefusalReporter.LoggerCategory), clientName);
            var transport = serviceProvider.GetService<OutboundTransport>() ?? OutboundTransport.Default;

            var socketsHandler = new SocketsHttpHandler
            {
                // ⚠️ A 302 to http://169.254.169.254/ is the textbook way past a check that only
                // looked at the first URL. The guard refuses every redirect instead.
                AllowAutoRedirect = false,

                // ⚠️ Refuses a socket to any non-public address, and connects to the address it
                // approved rather than resolving the name again, which is what defeats DNS rebinding.
                ConnectCallback = new PublicAddressConnectCallback(transport, reporter).ConnectAsync,

                // With a proxy, the connect callback would check the proxy's address, not the host's.
                UseProxy = false,
                UseCookies = false,

                AutomaticDecompression = policy.AutomaticDecompression,

                // Picks up a DNS change instead of keeping a connection to an old address.
                PooledConnectionLifetime = TimeSpan.FromMinutes(2)
            };

            transport.ConfigureHandler(socketsHandler);

            return new OutboundRequestGuardHandler(policy, reporter, socketsHandler);
        });
    }
}
