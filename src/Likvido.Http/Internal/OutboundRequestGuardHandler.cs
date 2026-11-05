using System.Net;
using System.Runtime.ExceptionServices;

namespace Likvido.Http.Internal;

/// <summary>
/// The guard around a guarded client's <see cref="SocketsHttpHandler"/>: refuses a request whose
/// origin is not in the policy before anything is sent, refuses a redirect, and caps the response body.
/// <para>
/// It is the client's primary handler, wrapping the socket handler directly, so it is the innermost
/// handler whatever the caller adds to the client. It therefore sees the request exactly as it is
/// sent, after any handler has changed it, and a retry handler the caller adds sees a refusal as an
/// <see cref="OutboundRequestRefusedException"/>, which it does not retry, rather than as an
/// <see cref="HttpRequestException"/>.
/// </para>
/// </summary>
internal sealed class OutboundRequestGuardHandler(
    OutboundRequestPolicy policy,
    RefusalReporter reporter,
    HttpMessageHandler innerHandler) : DelegatingHandler(innerHandler)
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Prepare(request);

        HttpResponseMessage response;

        try
        {
            response = await base.SendAsync(request, cancellationToken);
        }
        catch (HttpRequestException ex) when (FindRefusal(ex) is { } refusal)
        {
            ExceptionDispatchInfo.Throw(refusal);
            throw;
        }

        return Check(request, response);
    }

    // DelegatingHandler.Send would otherwise go straight to the socket handler, past every check here.
    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Prepare(request);

        HttpResponseMessage response;

        try
        {
            response = base.Send(request, cancellationToken);
        }
        catch (HttpRequestException ex) when (FindRefusal(ex) is { } refusal)
        {
            ExceptionDispatchInfo.Throw(refusal);
            throw;
        }

        return Check(request, response);
    }

    private void Prepare(HttpRequestMessage request)
    {
        var uri = request.RequestUri;

        if (uri is null || !policy.Allows(uri))
        {
            throw reporter.Refuse(
                OutboundRequestRefusalReason.UnlistedOrigin,
                RefusalReporter.OriginOf(uri),
                "the origin is not in the client's policy. Nothing was sent.");
        }

        // ⚠️ HTTP/3 runs over QUIC and never calls the connect callback, so it would reach the host
        // without the public-address check. Keep every request on HTTP/2 or lower.
        if (request.Version.Major >= 3)
        {
            request.Version = HttpVersion.Version20;
        }

        if (request.VersionPolicy == HttpVersionPolicy.RequestVersionOrHigher)
        {
            request.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
        }
    }

    private HttpResponseMessage Check(HttpRequestMessage request, HttpResponseMessage response)
    {
        var origin = RefusalReporter.OriginOf(request.RequestUri);
        var status = (int)response.StatusCode;

        // Redirects are not followed (AllowAutoRedirect is off), so a 3xx is refused rather than
        // returned: its target was never checked against the policy. 304 Not Modified is no redirect.
        if (status is >= 300 and < 400 && response.StatusCode != HttpStatusCode.NotModified)
        {
            var location = response.Headers.Location;
            response.Dispose();

            var target = location is null
                ? string.Empty
                : $" to {RefusalReporter.OriginOf(location.IsAbsoluteUri ? location : new Uri(request.RequestUri!, location))}";

            throw reporter.Refuse(
                OutboundRequestRefusalReason.Redirect,
                origin,
                $"the response is a {status} redirect{target}, and redirects are not followed.");
        }

        if (response.Content.Headers.ContentLength is { } declared && declared > policy.MaxResponseBytes)
        {
            response.Dispose();

            throw reporter.Refuse(
                OutboundRequestRefusalReason.ResponseTooLarge,
                origin,
                $"the response declares {declared} bytes, over the {policy.MaxResponseBytes}-byte cap.");
        }

        response.Content = new SizeCappedContent(
            response.Content,
            policy.MaxResponseBytes,
            read => reporter.Refuse(
                OutboundRequestRefusalReason.ResponseTooLarge,
                origin,
                $"the response passed the {policy.MaxResponseBytes}-byte cap after {read} bytes."));

        return response;
    }

    /// <summary>
    /// The socket handler wraps what the connect callback throws in an <see cref="HttpRequestException"/>.
    /// </summary>
    private static OutboundRequestRefusedException? FindRefusal(Exception exception)
    {
        for (var current = exception.InnerException; current is not null; current = current.InnerException)
        {
            if (current is OutboundRequestRefusedException refusal)
            {
                return refusal;
            }
        }

        return null;
    }
}
