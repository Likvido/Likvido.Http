using Shouldly;
using Xunit;

namespace Likvido.Http.Tests;

public class OutboundRequestPolicyTests
{
    [Theory]
    [InlineData("https://*.example.com", "a wildcard")]
    [InlineData("https://example.com/files", "a path")]
    [InlineData("https://example.com/?a=b", "a query")]
    [InlineData("https://example.com/#top", "a fragment")]
    [InlineData("https://user:pass@example.com", "user information")]
    [InlineData("ftp://example.com", "a scheme other than http or https")]
    [InlineData("example.com", "no scheme")]
    [InlineData("", "nothing")]
    public void RefusesAnOriginThatIsNotABareSchemeAndHost(string origin, string why)
    {
        Should.Throw<ArgumentException>(() => new OutboundRequestPolicy([origin], 1_000), $"an origin with {why} must be refused");
    }

    [Fact]
    public void NeedsAtLeastOneOrigin()
    {
        Should.Throw<ArgumentException>(() => new OutboundRequestPolicy([], 1_000));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void NeedsAPositiveCap(long maxResponseBytes)
    {
        Should.Throw<ArgumentOutOfRangeException>(() => new OutboundRequestPolicy(["https://example.com"], maxResponseBytes));
    }

    [Fact]
    public void NormalisesTheOrigins()
    {
        var policy = new OutboundRequestPolicy(
            ["HTTPS://Files.Example.com/", "https://files.example.com", "http://regnskaber.virk.dk", "https://example.com:8443"],
            1_000);

        policy.AllowedOrigins.ShouldBe(["https://files.example.com", "http://regnskaber.virk.dk", "https://example.com:8443"]);
    }

    [Theory]
    [InlineData("https://files.example.com/a/b?c=d", true)]
    [InlineData("https://FILES.example.com/", true)]
    [InlineData("https://files.example.com:443/", true)]
    [InlineData("http://files.example.com/", false)]
    [InlineData("https://files.example.com:8443/", false)]
    [InlineData("https://files.example.com.evil.com/", false)]
    [InlineData("https://evil.com/?https://files.example.com", false)]
    public void AllowsOnlyTheListedSchemeHostAndPort(string url, bool allowed)
    {
        new OutboundRequestPolicy(["https://files.example.com"], 1_000).Allows(new Uri(url)).ShouldBe(allowed);
    }
}

public class PackageTests
{
    /// <summary>
    /// Robots and other libraries reference the package, so it must not pull in ASP.NET Core.
    /// </summary>
    [Fact]
    public void DoesNotReferenceAspNetCore()
    {
        typeof(OutboundRequestPolicy).Assembly.GetReferencedAssemblies()
            .ShouldNotContain(name => name.Name!.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal));
    }
}
