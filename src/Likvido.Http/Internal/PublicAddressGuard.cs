using System.Net;
using System.Net.Sockets;

namespace Likvido.Http.Internal;

/// <summary>
/// Decides whether an IP address is on the public internet. Lifted from Likvido.Mcp, which uses the
/// same check for its client metadata document fetch.
/// <para>
/// Enforced at <em>connect</em> time rather than by resolving the hostname first and trusting the
/// answer: see <see cref="PublicAddressConnectCallback"/>. A check before the connect alone is
/// defeated by DNS rebinding, where the name resolves to a public address for the check and to
/// <c>127.0.0.1</c> for the socket a moment later.
/// </para>
/// </summary>
internal static class PublicAddressGuard
{
    /// <summary>
    /// Rejects anything that is not a routable public address, listing the reason for logs.
    /// <para>
    /// Written as an allow-nothing-suspicious check rather than a blocklist of specific
    /// ranges-of-the-week: every branch below is a category, and an address that matches none of
    /// them is public.
    /// </para>
    /// </summary>
    internal static bool IsPublic(IPAddress address, out string reason)
    {
        // An IPv4 address tunnelled through IPv6 must be judged as the IPv4 address it is,
        // otherwise ::ffff:127.0.0.1 walks straight past every IPv4 branch below.
        //
        // ⚠️ IsIPv4MappedToIPv6 covers only ::ffff:0:0/96. Two sibling encodings embed an IPv4
        // address just as effectively and were reaching the final "matches nothing, therefore
        // public" return: the deprecated IPv4-compatible form ::/96 (`::7f00:1`) and the
        // IPv4-translated form ::ffff:0:0:0/96 (`::ffff:0:7f00:1`). An AAAA record of `::7f00:1`
        // was approved by this guard. Whether such an address is routable from a given pod is a
        // property of the cluster's networking, not of this method, and this method is written as a
        // categorical allow-list — so it has to judge them as the IPv4 addresses they encode.
        if (TryGetEmbeddedIPv4(address, out var embedded))
        {
            return IsPublic(embedded, out reason);
        }

        if (IPAddress.IsLoopback(address))
        {
            reason = "loopback";
            return false;
        }

        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            reason = "unspecified";
            return false;
        }

        if (address.IsIPv6LinkLocal)
        {
            reason = "IPv6 link-local";
            return false;
        }

        if (address.IsIPv6SiteLocal)
        {
            reason = "IPv6 site-local";
            return false;
        }

        if (address.IsIPv6Multicast)
        {
            reason = "IPv6 multicast";
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var v6 = address.GetAddressBytes();

            // fc00::/7 — unique local addresses, the IPv6 equivalent of 10/8.
            if ((v6[0] & 0xFE) == 0xFC)
            {
                reason = "IPv6 unique-local (fc00::/7)";
                return false;
            }

            // 64:ff9b::/96 and 2002::/16 embed an IPv4 address that the branches above never
            // see, so a NAT64 or 6to4 form of a private address would otherwise pass.
            if (v6[0] == 0x00 && v6[1] == 0x64 && v6[2] == 0xFF && v6[3] == 0x9B)
            {
                reason = "NAT64 (64:ff9b::/96) embedding an IPv4 address";
                return false;
            }

            if (v6[0] == 0x20 && v6[1] == 0x02)
            {
                reason = "6to4 (2002::/16) embedding an IPv4 address";
                return false;
            }

            reason = string.Empty;
            return true;
        }

        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            // Neither IPv4 nor IPv6 — nothing we know how to reason about, so not public.
            reason = $"unsupported address family {address.AddressFamily}";
            return false;
        }

        var v4 = address.GetAddressBytes();

        // 0.0.0.0/8 — "this network". 0.x is also a well-worn way of writing 127.0.0.1.
        if (v4[0] == 0)
        {
            reason = "0.0.0.0/8";
            return false;
        }

        // 10.0.0.0/8
        if (v4[0] == 10)
        {
            reason = "private 10.0.0.0/8";
            return false;
        }

        // 100.64.0.0/10 — carrier-grade NAT. Not "private" in the RFC 1918 sense, which is
        // exactly why it gets forgotten, and it is routable inside a provider's network.
        if (v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127)
        {
            reason = "CGNAT 100.64.0.0/10";
            return false;
        }

        // 169.254.0.0/16 — link-local, and the home of the cloud instance metadata service.
        if (v4[0] == 169 && v4[1] == 254)
        {
            reason = "link-local 169.254.0.0/16 (instance metadata)";
            return false;
        }

        // 172.16.0.0/12
        if (v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31)
        {
            reason = "private 172.16.0.0/12";
            return false;
        }

        // 192.0.0.0/24 (protocol assignments), 192.0.2.0/24 (documentation),
        // 192.168.0.0/16 (private).
        if (v4[0] == 192 && (v4[1] == 0 || v4[1] == 168))
        {
            reason = "reserved or private 192.x";
            return false;
        }

        // 198.18.0.0/15 (benchmarking) and 198.51.100.0/24 (documentation).
        if (v4[0] == 198 && (v4[1] == 18 || v4[1] == 19 || (v4[1] == 51 && v4[2] == 100)))
        {
            reason = "benchmarking or documentation 198.x";
            return false;
        }

        // 203.0.113.0/24 — documentation.
        if (v4[0] == 203 && v4[1] == 0 && v4[2] == 113)
        {
            reason = "documentation 203.0.113.0/24";
            return false;
        }

        // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved, which together cover everything from
        // 224 up, including the 255.255.255.255 broadcast address.
        if (v4[0] >= 224)
        {
            reason = "multicast, reserved or broadcast (>= 224.0.0.0)";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// Extracts the IPv4 address embedded in any of the three IPv6 forms that carry one, so it can
    /// be judged against the IPv4 categories rather than slipping past all of them.
    /// <para>
    /// <c>::ffff:0:0/96</c> IPv4-mapped (what <see cref="IPAddress.IsIPv4MappedToIPv6"/> knows
    /// about), <c>::/96</c> IPv4-compatible (deprecated by RFC 4291 but still parsed), and
    /// <c>::ffff:0:0:0/96</c> IPv4-translated (RFC 2765). The all-zero and loopback low words are
    /// excluded so <c>::</c> and <c>::1</c> keep being judged by their own dedicated branches.
    /// </para>
    /// </summary>
    private static bool TryGetEmbeddedIPv4(IPAddress address, out IPAddress embedded)
    {
        embedded = IPAddress.None;

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            embedded = address.MapToIPv4();
            return true;
        }

        var bytes = address.GetAddressBytes();

        // The first 8 bytes are zero in all three forms.
        for (var i = 0; i < 8; i++)
        {
            if (bytes[i] != 0)
            {
                return false;
            }
        }

        var isCompatible = bytes[8] == 0x00 && bytes[9] == 0x00 && bytes[10] == 0x00 && bytes[11] == 0x00;
        var isTranslated = bytes[8] == 0xFF && bytes[9] == 0xFF && bytes[10] == 0x00 && bytes[11] == 0x00;

        if (!isCompatible && !isTranslated)
        {
            return false;
        }

        // `::` and `::1` are not embedded IPv4 addresses; leave them to the unspecified and loopback
        // branches, which name them correctly.
        if (bytes[12] == 0 && bytes[13] == 0 && (bytes[14] | bytes[15]) is 0 or 1 && bytes[14] == 0)
        {
            return false;
        }

        embedded = new IPAddress(bytes[12..16]);
        return true;
    }
}
