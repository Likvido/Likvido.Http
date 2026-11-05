namespace Likvido.Http;

/// <summary>
/// Why a guarded HTTP client refused a request or its response.
/// </summary>
public enum OutboundRequestRefusalReason
{
    /// <summary>The request's scheme, host or port is not in the client's policy. Nothing was sent.</summary>
    UnlistedOrigin,

    /// <summary>The host is, or resolves to, an address that is not on the public internet. No connection was opened.</summary>
    NonPublicAddress,

    /// <summary>The response body is larger than the policy allows.</summary>
    ResponseTooLarge,

    /// <summary>The response is a redirect. Guarded clients do not follow redirects.</summary>
    Redirect
}
