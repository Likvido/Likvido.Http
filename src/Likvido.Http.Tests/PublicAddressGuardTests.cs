using System.Net;
using Likvido.Http.Internal;
using Shouldly;
using Xunit;

namespace Likvido.Http.Tests;

/// <summary>
/// Lifted from Likvido.Mcp's tests of the same check, with the embedded-IPv4 forms added.
/// </summary>
public class PublicAddressGuardTests
{
    [Theory]
    // Loopback, in both families and in the forms that slip past a naive check.
    [InlineData("127.0.0.1", "loopback")]
    [InlineData("127.1.1.1", "the whole of 127/8 is loopback")]
    [InlineData("::1", "IPv6 loopback")]
    [InlineData("::ffff:127.0.0.1", "IPv4 loopback tunnelled through IPv6")]
    [InlineData("0.0.0.0", "unspecified")]
    [InlineData("0.1.2.3", "0/8, a well-worn way of writing loopback")]
    [InlineData("::", "IPv6 unspecified")]
    // RFC 1918.
    [InlineData("10.0.0.1", "private 10/8")]
    [InlineData("172.16.0.1", "private 172.16/12")]
    [InlineData("172.31.255.255", "top of 172.16/12")]
    [InlineData("192.168.1.1", "private 192.168/16")]
    [InlineData("::ffff:10.0.0.1", "RFC 1918 tunnelled through IPv6")]
    // The ones that get forgotten.
    [InlineData("169.254.169.254", "link-local — the instance metadata service")]
    [InlineData("100.64.0.1", "CGNAT 100.64/10, routable inside a provider network")]
    [InlineData("100.127.255.255", "top of CGNAT")]
    [InlineData("fd00::1", "IPv6 unique-local fc00::/7")]
    [InlineData("fc00::1", "bottom of fc00::/7")]
    [InlineData("fe80::1", "IPv6 link-local")]
    [InlineData("64:ff9b::7f00:1", "NAT64 embedding 127.0.0.1")]
    [InlineData("2002:7f00:0001::", "6to4 embedding 127.0.0.1")]
    [InlineData("224.0.0.1", "multicast")]
    [InlineData("255.255.255.255", "broadcast")]
    [InlineData("240.0.0.1", "reserved 240/4")]
    [InlineData("192.0.2.1", "documentation 192.0.2/24")]
    [InlineData("198.18.0.1", "benchmarking 198.18/15")]
    [InlineData("203.0.113.1", "documentation 203.0.113/24")]
    [InlineData("::ffff:169.254.169.254", "instance metadata tunnelled through IPv6")]
    [InlineData("::a9fe:a9fe", "instance metadata in the IPv4-compatible form")]
    [InlineData("::ffff:0:a9fe:a9fe", "instance metadata in the IPv4-translated form")]
    public void NonPublicAddressesAreRejected(string address, string why)
    {
        PublicAddressGuard.IsPublic(IPAddress.Parse(address), out var reason)
            .ShouldBeFalse($"{address} must be rejected ({why})");

        reason.ShouldNotBeEmpty("the reason is what a log line needs in order to be diagnosable");
    }

    /// <summary>
    /// The guard must not be so broad that no real client can be reached — a blocklist that blocks
    /// everything is indistinguishable from a broken feature.
    /// </summary>
    [Theory]
    [InlineData("160.79.104.1", "Anthropic's outbound range")]
    [InlineData("1.1.1.1", "public")]
    [InlineData("8.8.8.8", "public")]
    [InlineData("172.15.0.1", "just below 172.16/12")]
    [InlineData("172.32.0.1", "just above 172.16/12")]
    [InlineData("100.63.255.255", "just below CGNAT")]
    [InlineData("100.128.0.1", "just above CGNAT")]
    [InlineData("169.253.0.1", "just below link-local")]
    [InlineData("11.0.0.1", "just above 10/8")]
    [InlineData("2606:4700::1111", "public IPv6")]
    [InlineData("223.255.255.255", "just below multicast")]
    public void PublicAddressesAreAccepted(string address, string why)
    {
        PublicAddressGuard.IsPublic(IPAddress.Parse(address), out _)
            .ShouldBeTrue($"{address} must be accepted ({why})");
    }
}
