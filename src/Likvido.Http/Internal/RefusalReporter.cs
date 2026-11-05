using Microsoft.Extensions.Logging;

namespace Likvido.Http.Internal;

/// <summary>
/// Logs a refusal once, at Warning, and creates the exception that reports it to the caller.
/// <para>
/// Warning, not Error: an Error line pages the on-call engineer, and a refused fetch is an outsider
/// probing or a provider that moved hosts, neither of which needs someone at night.
/// </para>
/// </summary>
internal sealed partial class RefusalReporter(ILogger logger, string clientName)
{
    internal const string LoggerCategory = "Likvido.Http.OutboundRequestGuard";

    internal OutboundRequestRefusedException Refuse(OutboundRequestRefusalReason reason, string origin, string detail)
    {
        LogRefusal(logger, clientName, origin, reason, detail);

        return new OutboundRequestRefusedException(reason, origin, detail);
    }

    /// <summary>
    /// The scheme and host of a URL, with the port only when it is not the scheme's default.
    /// <para>
    /// ⚠️ Never the path or query string: a signed storage link carries its credential in the query
    /// string, and this text goes into log lines and exception messages.
    /// </para>
    /// </summary>
    internal static string OriginOf(Uri? uri) =>
        uri is null || !uri.IsAbsoluteUri
            ? "(no absolute URL)"
            : uri.IsDefaultPort
                ? $"{uri.Scheme}://{uri.Host}"
                : $"{uri.Scheme}://{uri.Host}:{uri.Port}";

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The guarded HTTP client {ClientName} refused a request to {Origin} ({Reason}): {Detail}")]
    private static partial void LogRefusal(
        ILogger logger,
        string clientName,
        string origin,
        OutboundRequestRefusalReason reason,
        string detail);
}
