# Likvido.Http [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/Likvido/Likvido.Http/nuget.yml)](https://github.com/Likvido/Likvido.Http/actions/workflows/nuget.yml) [![Nuget](https://img.shields.io/nuget/v/Likvido.Http)](https://www.nuget.org/packages/Likvido.Http)

HTTP client helpers for Likvido services. It depends only on `Microsoft.Extensions.Http` and
`Microsoft.Extensions.Logging.Abstractions`, so web projects, robots and other libraries can all use it.

## Guarded clients

Use a guarded client for every server-side fetch of a URL that comes from outside data, such as a
download link in a third party's reply. Register it with `AddGuardedHttpClient` instead of
`AddHttpClient`:

```csharp
services.AddGuardedHttpClient<IPdfService, PdfService>(
        new OutboundRequestPolicy(
            ["https://api.pdf.co", "https://pdf-temp-files.s3.us-west-2.amazonaws.com"],
            maxResponseBytes: 20 * 1024 * 1024))
    .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(30))
    .AddStandardResilienceHandler();
```

A guarded client:

- sends a request only to an origin in its policy, and refuses any other before anything is sent;
- opens a connection only to a public IP address. It checks every address the host resolves to and
  connects to the address it checked, so DNS rebinding cannot swap in a private address;
- follows no redirects, and refuses a redirect response;
- refuses a response whose `Content-Length` is over the cap, and stops reading any body once it
  passes the cap. When a response is decompressed, its `Content-Length` is gone, and the
  decompressed bytes read are counted;
- uses no proxy, no cookies and no HTTP/3.

### The policy

- **Origins** are exact: a scheme, a host and, when it is not the default, a port, such as
  `https://api.pdf.co`. There are no wildcards. Listing `https://example.com` does not allow
  `http://example.com`; an http origin is allowed only when it is listed itself.
- **`maxResponseBytes`** caps the response body. With automatic decompression, it caps the
  decompressed body.
- **`AutomaticDecompression`** is off by default. Set it for a host that sends compressed responses:

  ```csharp
  new OutboundRequestPolicy(["http://regnskaber.virk.dk"], maxResponseBytes: 1024 * 1024)
  {
      AutomaticDecompression = DecompressionMethods.GZip
  }
  ```

A policy can also be built from the service provider, for example from configuration:

```csharp
services.AddGuardedHttpClient<IAttachmentDownloader, AttachmentDownloader>(serviceProvider =>
    new OutboundRequestPolicy(
        [serviceProvider.GetRequiredService<IOptions<StorageOptions>>().Value.AccountOrigin],
        maxResponseBytes: 25 * 1024 * 1024));
```

There are overloads for a typed client with an implementation (`AddGuardedHttpClient<TClient, TImplementation>`),
a typed client without one (`AddGuardedHttpClient<TClient>`) and a named client
(`AddGuardedHttpClient(name, policy)`). Each returns the client's `IHttpClientBuilder`.

### Refusals

A refused request throws `OutboundRequestRefusedException`. Its `Reason` is one of `UnlistedOrigin`,
`NonPublicAddress`, `ResponseTooLarge` and `Redirect`, and its `Origin` is the scheme, the host and any non-default port. It
does not derive from `HttpRequestException`, so a resilience handler does not retry it.

The guard logs each refusal once, at Warning, in the category `Likvido.Http.OutboundRequestGuard`,
with the client's name, the origin, and the reason. It never logs the path or query string,
because a signed storage link carries its credential in the query string. Neither does the
exception's message.

### Adding handlers

The guard is the client's primary handler, so it runs inside every handler the caller adds, such as
`AddStandardResilienceHandler`. It sees each request exactly as it is sent.

Do not call `ConfigurePrimaryHttpMessageHandler` or `UseSocketsHttpHandler` on a guarded client
outside tests: either replaces the guard.
