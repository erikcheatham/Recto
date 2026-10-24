using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NSubstitute;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

public class CapabilityJwtBuilderTests
{
    [Fact]
    public void Fingerprint_IsSha256OfPublicKeyB64Url()
    {
        // Pin the exact algorithm: SHA-256 of the raw public-key bytes,
        // base64url with no padding. Anyone with the JWT and the phone's
        // public key must be able to recompute this and confirm match.
        var pk = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var expected = Base64Url(SHA256.HashData(pk));

        var actual = CapabilityJwtBuilder.Fingerprint(pk);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Fingerprint_DiffersForDifferentKeys()
    {
        var fp1 = CapabilityJwtBuilder.Fingerprint(new byte[] { 1, 2, 3 });
        var fp2 = CapabilityJwtBuilder.Fingerprint(new byte[] { 1, 2, 4 });
        Assert.NotEqual(fp1, fp2);
    }

    [Fact]
    public void Fingerprint_NoBase64Padding()
    {
        var fp = CapabilityJwtBuilder.Fingerprint(new byte[] { 1, 2, 3 });
        Assert.DoesNotContain("=", fp);
        Assert.DoesNotContain("+", fp);
        Assert.DoesNotContain("/", fp);
    }

    [Fact]
    public async Task BuildAsync_ProducesThreePartJwt()
    {
        var enclave = StubEnclave(V04Protocol.AlgorithmEd25519, returningSignature: new byte[64]);

        var result = await CapabilityJwtBuilder.BuildAsync(
            enclave, "test.alias", SampleClaims(), CancellationToken.None);

        Assert.True(result.IsSuccess);
        var parts = result.Value.Split('.');
        Assert.Equal(3, parts.Length);
        Assert.All(parts, p => Assert.NotEqual(string.Empty, p));
    }

    [Fact]
    public async Task BuildAsync_HeaderUsesEdDsaForEd25519Enclave()
    {
        var enclave = StubEnclave(V04Protocol.AlgorithmEd25519, returningSignature: new byte[64]);

        var result = await CapabilityJwtBuilder.BuildAsync(
            enclave, "x", SampleClaims(), CancellationToken.None);

        var headerJson = DecodePart(result.Value.Split('.')[0]);
        using var doc = JsonDocument.Parse(headerJson);
        Assert.Equal("EdDSA", doc.RootElement.GetProperty("alg").GetString());
        Assert.Equal("JWT", doc.RootElement.GetProperty("typ").GetString());
    }

    [Fact]
    public async Task BuildAsync_HeaderUsesEs256ForEcdsaP256Enclave()
    {
        var enclave = StubEnclave(V04Protocol.AlgorithmEcdsaP256, returningSignature: new byte[64]);

        var result = await CapabilityJwtBuilder.BuildAsync(
            enclave, "x", SampleClaims(), CancellationToken.None);

        var headerJson = DecodePart(result.Value.Split('.')[0]);
        using var doc = JsonDocument.Parse(headerJson);
        Assert.Equal("ES256", doc.RootElement.GetProperty("alg").GetString());
    }

    [Fact]
    public async Task BuildAsync_PreservesAllClaimFields()
    {
        var enclave = StubEnclave(V04Protocol.AlgorithmEd25519, returningSignature: new byte[64]);
        var claims = new CapabilityJwtClaims(
            Iss: "fingerprint-of-phone",
            Sub: "myservice/MY_API_KEY",
            Aud: "bootloader",
            Exp: 1234567890,
            Iat: 1234567000,
            Jti: "unique-id-here",
            Scope: new[] { "sign", "decrypt" },
            MaxUses: 1000,
            Bearer: CapabilityBearer.Bootloader);

        var result = await CapabilityJwtBuilder.BuildAsync(
            enclave, "x", claims, CancellationToken.None);

        var claimsJson = DecodePart(result.Value.Split('.')[1]);
        using var doc = JsonDocument.Parse(claimsJson);
        Assert.Equal("fingerprint-of-phone", doc.RootElement.GetProperty("iss").GetString());
        Assert.Equal("myservice/MY_API_KEY", doc.RootElement.GetProperty("sub").GetString());
        Assert.Equal("bootloader", doc.RootElement.GetProperty("aud").GetString());
        Assert.Equal(1234567890L, doc.RootElement.GetProperty("exp").GetInt64());
        Assert.Equal(1234567000L, doc.RootElement.GetProperty("iat").GetInt64());
        Assert.Equal("unique-id-here", doc.RootElement.GetProperty("jti").GetString());
        Assert.Equal(1000, doc.RootElement.GetProperty("recto:max_uses").GetInt32());
        Assert.Equal("bootloader", doc.RootElement.GetProperty("recto:bearer").GetString());
        var scope = doc.RootElement.GetProperty("recto:scope").EnumerateArray()
            .Select(e => e.GetString()).ToArray();
        Assert.Equal(new[] { "sign", "decrypt" }, scope);
    }

    [Fact]
    public async Task BuildAsync_SignsExactlyTheHeaderDotClaimsBytes()
    {
        // Critical: the signature must cover precisely "{headerB64}.{claimsB64}"
        // as UTF-8 bytes -- not just the claims, not the full JWT, not with a
        // trailing dot. Capture the bytes the enclave receives and verify.
        byte[]? capturedMessage = null;
        var enclave = Substitute.For<IEnclaveKeyService>();
        enclave.Algorithm.Returns(V04Protocol.AlgorithmEd25519);
        enclave.SignAsync(Arg.Any<string>(), Arg.Do<byte[]>(b => capturedMessage = b), Arg.Any<CancellationToken>())
               .Returns(Task.FromResult(Result.Success(new byte[64])));

        var result = await CapabilityJwtBuilder.BuildAsync(
            enclave, "x", SampleClaims(), CancellationToken.None);

        var jwt = result.Value;
        var parts = jwt.Split('.');
        var expectedSigningInput = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");
        Assert.NotNull(capturedMessage);
        Assert.Equal(expectedSigningInput, capturedMessage);
    }

    [Fact]
    public async Task BuildAsync_PassesKeyAliasToEnclave()
    {
        var enclave = Substitute.For<IEnclaveKeyService>();
        enclave.Algorithm.Returns(V04Protocol.AlgorithmEd25519);
        enclave.SignAsync(Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
               .Returns(Task.FromResult(Result.Success(new byte[64])));

        await CapabilityJwtBuilder.BuildAsync(
            enclave, "recto.phone.identity", SampleClaims(), CancellationToken.None);

        await enclave.Received().SignAsync(
            "recto.phone.identity",
            Arg.Any<byte[]>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task BuildAsync_PropagatesSignFailure()
    {
        var enclave = Substitute.For<IEnclaveKeyService>();
        enclave.Algorithm.Returns(V04Protocol.AlgorithmEd25519);
        enclave.SignAsync(Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
               .Returns(Task.FromResult(Result.Failure<byte[]>(Error.Failure("biometric cancelled"))));

        var result = await CapabilityJwtBuilder.BuildAsync(
            enclave, "x", SampleClaims(), CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Contains("biometric cancelled", result.Error.ToString() ?? "");
    }

    [Fact]
    public async Task BuildAsync_FailsForUnknownAlgorithm()
    {
        var enclave = StubEnclave("rsa-2048", returningSignature: new byte[64]);

        var result = await CapabilityJwtBuilder.BuildAsync(
            enclave, "x", SampleClaims(), CancellationToken.None);

        Assert.True(result.IsFailure);
    }

    // --- helpers ---

    private static IEnclaveKeyService StubEnclave(string algorithm, byte[] returningSignature)
    {
        var enclave = Substitute.For<IEnclaveKeyService>();
        enclave.Algorithm.Returns(algorithm);
        enclave.SignAsync(Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
               .Returns(Task.FromResult(Result.Success(returningSignature)));
        return enclave;
    }

    private static CapabilityJwtClaims SampleClaims() => new(
        Iss: "iss-fp",
        Sub: "service/secret",
        Aud: "bootloader",
        Exp: 100,
        Iat: 50,
        Jti: "j",
        Scope: new[] { "sign" },
        MaxUses: 10,
        Bearer: CapabilityBearer.Bootloader);

    private static string Base64Url(byte[] data)
    {
        var b64 = Convert.ToBase64String(data);
        return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string DecodePart(string b64u)
    {
        var padded = b64u.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Encoding.UTF8.GetString(Convert.FromBase64String(padded));
    }
}
