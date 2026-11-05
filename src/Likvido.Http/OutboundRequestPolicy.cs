using System.Net;

namespace Likvido.Http;

/// <summary>
/// What a guarded HTTP client may fetch: the origins it may send requests to, and how large a
/// response it reads.
/// </summary>
/// <remarks>
/// An origin is an exact scheme, host and port, written as <c>https://api.example.com</c>. There are no
/// wildcards, and the port is the scheme's default unless the origin names one. Listing
/// <c>https://example.com</c> does not allow <c>http://example.com</c>: an http origin is allowed only
/// when it is listed itself.
/// </remarks>
public sealed class OutboundRequestPolicy
{
    private readonly Origin[] _origins;

    /// <summary>
    /// Creates a policy.
    /// </summary>
    /// <param name="allowedOrigins">
    /// The origins the client may send requests to, each an absolute http or https URL with no path,
    /// query, fragment or user information, such as <c>https://api.example.com</c>.
    /// </param>
    /// <param name="maxResponseBytes">
    /// The largest response body the client reads, in bytes, after any automatic decompression.
    /// </param>
    /// <exception cref="ArgumentException">An origin is not a bare http or https origin, or no origin is given.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxResponseBytes"/> is not positive.</exception>
    public OutboundRequestPolicy(IEnumerable<string> allowedOrigins, long maxResponseBytes)
    {
        ArgumentNullException.ThrowIfNull(allowedOrigins);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxResponseBytes);

        _origins = allowedOrigins.Select(Origin.Parse).Distinct().ToArray();

        if (_origins.Length == 0)
        {
            throw new ArgumentException("A policy needs at least one allowed origin.", nameof(allowedOrigins));
        }

        AllowedOrigins = _origins.Select(origin => origin.ToString()).ToArray();
        MaxResponseBytes = maxResponseBytes;
    }

    /// <summary>
    /// The allowed origins, normalised to <c>scheme://host</c>, with the port only when it is not the
    /// scheme's default.
    /// </summary>
    public IReadOnlyList<string> AllowedOrigins { get; }

    /// <summary>
    /// The largest response body the client reads, in bytes, after any automatic decompression.
    /// </summary>
    public long MaxResponseBytes { get; }

    /// <summary>
    /// The content encodings the client decompresses automatically. None by default.
    /// <see cref="MaxResponseBytes"/> applies to the decompressed body.
    /// </summary>
    public DecompressionMethods AutomaticDecompression { get; init; } = DecompressionMethods.None;

    internal bool Allows(Uri uri) => uri.IsAbsoluteUri && _origins.Contains(Origin.Of(uri));

    /// <summary>
    /// A scheme, host and port. The host is compared in its IDN (punycode) form, ignoring case.
    /// </summary>
    private readonly record struct Origin(string Scheme, string Host, int Port, bool IsDefaultPort)
    {
        public static Origin Of(Uri uri) =>
            new(uri.Scheme.ToLowerInvariant(), uri.IdnHost.ToLowerInvariant(), uri.Port, uri.IsDefaultPort);

        public static Origin Parse(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("An allowed origin is empty.", "allowedOrigins");
            }

            if (value.Contains('*'))
            {
                throw new ArgumentException($"The allowed origin '{value}' has a wildcard. List each host.", "allowedOrigins");
            }

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                throw new ArgumentException($"The allowed origin '{value}' is not an absolute http or https URL.", "allowedOrigins");
            }

            if (!string.IsNullOrEmpty(uri.UserInfo)
                || uri.AbsolutePath != "/"
                || !string.IsNullOrEmpty(uri.Query)
                || !string.IsNullOrEmpty(uri.Fragment))
            {
                throw new ArgumentException(
                    $"The allowed origin '{value}' must be a scheme and host only, with no path, query, fragment or user information.",
                    "allowedOrigins");
            }

            return Of(uri);
        }

        public override string ToString() => IsDefaultPort ? $"{Scheme}://{Host}" : $"{Scheme}://{Host}:{Port}";
    }
}
