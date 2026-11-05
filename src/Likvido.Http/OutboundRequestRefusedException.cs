namespace Likvido.Http;

/// <summary>
/// Thrown when a guarded HTTP client refuses a request or its response.
/// </summary>
/// <remarks>
/// The guard has already logged the refusal at Warning. The message and <see cref="Origin"/> name the
/// scheme and host only, never the path or query string, so the exception can be logged as it is.
/// <para>
/// It does not derive from <see cref="HttpRequestException"/>, so a retry or circuit-breaker handler
/// that handles transient failures does not retry a refusal.
/// </para>
/// </remarks>
public sealed class OutboundRequestRefusedException : Exception
{
    internal OutboundRequestRefusedException(OutboundRequestRefusalReason reason, string origin, string detail)
        : base($"The guarded HTTP client refused a request to {origin}: {detail}")
    {
        Reason = reason;
        Origin = origin;
    }

    /// <summary>Why the request was refused.</summary>
    public OutboundRequestRefusalReason Reason { get; }

    /// <summary>The scheme and host of the refused request, such as <c>https://example.com</c>.</summary>
    public string Origin { get; }
}
