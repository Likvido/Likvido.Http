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
/// <para>
/// When the origins cannot be listed in advance, <see cref="ForAnyHttpsOrigin"/> allows every https
/// origin on the default port. Every other check of a guarded client still applies.
/// </para>
/// </remarks>
public sealed class OutboundRequestPolicy
{
    private readonly Origin[] _origins;
    private readonly int? _maxConnectionsPerServer;

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

    private OutboundRequestPolicy(long maxResponseBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxResponseBytes);

        _origins = [];
        AllowedOrigins = [];
        AllowsAnyHttpsOrigin = true;
        MaxResponseBytes = maxResponseBytes;
    }

    /// <summary>
    /// Creates a policy that allows any https origin on the default port, for a URL whose host cannot
    /// be known in advance, such as an OAuth client's metadata document.
    /// </summary>
    /// <remarks>
    /// An http URL and an https URL with a port other than 443 are refused as
    /// <see cref="OutboundRequestRefusalReason.UnlistedOrigin"/>, before anything is sent. Every other
    /// check still applies: the connection must go to a public address, redirects are refused, and
    /// the response is capped. Automatic decompression is off.
    /// </remarks>
    /// <param name="maxResponseBytes">The largest response body the client reads, in bytes.</param>
    /// <param name="maxConnectionsPerServer">
    /// The most connections the client opens to one server at a time, as
    /// <see cref="MaxConnectionsPerServer"/>. When it is <see langword="null"/>, there is no limit.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maxResponseBytes"/> or <paramref name="maxConnectionsPerServer"/> is not positive.
    /// </exception>
    public static OutboundRequestPolicy ForAnyHttpsOrigin(long maxResponseBytes, int? maxConnectionsPerServer = null) =>
        new(maxResponseBytes) { MaxConnectionsPerServer = maxConnectionsPerServer };

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

    /// <summary>
    /// Whether the policy allows any https origin on the default port, rather than only
    /// <see cref="AllowedOrigins"/>, which is then empty. See <see cref="ForAnyHttpsOrigin"/>.
    /// </summary>
    public bool AllowsAnyHttpsOrigin { get; }

    /// <summary>
    /// The most connections the client opens to one server at a time. When it is
    /// <see langword="null"/>, the default, there is no limit.
    /// </summary>
    /// <remarks>
    /// Set it for a client whose URLs an outsider chooses, so one slow host cannot tie up an
    /// unbounded number of sockets. A request over the limit waits for a free connection.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">The value is not positive.</exception>
    public int? MaxConnectionsPerServer
    {
        get => _maxConnectionsPerServer;
        init
        {
            if (value is { } max)
            {
                ArgumentOutOfRangeException.ThrowIfNegativeOrZero(max, nameof(MaxConnectionsPerServer));
            }

            _maxConnectionsPerServer = value;
        }
    }

    internal bool Allows(Uri uri) =>
        uri.IsAbsoluteUri
        && (AllowsAnyHttpsOrigin
            ? uri.Scheme == Uri.UriSchemeHttps && uri.IsDefaultPort
            : _origins.Contains(Origin.Of(uri)));

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
