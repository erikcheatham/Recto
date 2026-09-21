using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NSubstitute;
using Recto.Shared.Common;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

public class WebAuthnAssertionBuilderTests
{
    [Fact]
    public void BuildClientDataJson_HasCanonicalShape()
    {
        var bytes = WebAuthnAssertionBuilder.BuildClientDataJson(
            "challenge-b64u-here", "https://demo.recto.example");

        var json = Encoding.UTF8.GetString(bytes);
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("webauthn.get", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal("challenge-b64u-here", doc.RootElement.GetProperty("challenge").GetString());
        Assert.Equal("https://demo.recto.example", doc.RootElement.GetProperty("origin").GetString());
        Assert.False(doc.RootElement.GetProperty("crossOrigin").GetBoolean());
    }

    [Fact]
    public void BuildClientDataJson_PreservesPropertyOrder()
    {
        // Property order matters because the relying party will hash these
        // exact bytes during verification. type first, challenge second,
        // origin third, crossOrigin fourth.
        var bytes = WebAuthnAssertionBuilder.BuildClientDataJson("c", "o");
        var json = Encoding.UTF8.GetString(bytes);
        var typePos = json.IndexOf("\"type\"", StringComparison.Ordinal);
        var challengePos = json.IndexOf("\"challenge\"", StringComparison.Ordinal);
        var originPos = json.IndexOf("\"origin\"", StringComparison.Ordinal);
        var crossOriginPos = json.IndexOf("\"crossOrigin\"", StringComparison.Ordinal);
        Assert.True(typePos < challengePos);
        Assert.True(challengePos < originPos);
        Assert.True(originPos < crossOriginPos);
    }

    [Fact]
    public void BuildAuthenticatorData_Has37Bytes()
    {
        var data = WebAuthnAssertionBuilder.BuildAuthenticatorData("demo.recto.example", counter: 0);
        Assert.Equal(37, data.Length);
    }

    [Fact]
    public void BuildAuthenticatorData_RpIdHashIsSha256OfRpId()
    {
        var rpId = "demo.recto.example";
        var data = WebAuthnAssertionBuilder.BuildAuthenticatorData(rpId, counter: 0);

        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        var actualHash = data.AsSpan(0, 32).ToArray();
        Assert.Equal(expectedHash, actualHash);
    }

    [Fact]
    public void BuildAuthenticatorData_FlagsByteHasUpAndUv()
    {
        var data = WebAuthnAssertionBuilder.BuildAuthenticatorData("rp", counter: 0);
        // UP (0x01) | UV (0x04) = 0x05.
        Assert.Equal(0x05, data[32]);
    }

    [Fact]
    public void BuildAuthenticatorData_CounterIsBigEndian()
    {
        var data = WebAuthnAssertionBuilder.BuildAuthenticatorData("rp", counter: 0xDEADBEEF);
        Assert.Equal(0xDE, data[33]);
        Assert.Equal(0xAD, data[34]);
        Assert.Equal(0xBE, data[35]);
        Assert.Equal(0xEF, data[36]);
    }

    [Fact]
    public async Task BuildAsync_SignsAuthenticatorDataConcatenatedWithClientDataHash()
    {
        // Capture the bytes the enclave is asked to sign and verify they
        // equal: authenticatorData || sha256(clientDataJSON). This is the
        // canonical WebAuthn signing input -- if we get this wrong, no
        // relying party will ever accept our assertions.
        byte[]? capturedSigningInput = null;
        var enclave = Substitute.For<IEnclaveKeyService>();
        enclave.Algorithm.Returns(V04Protocol.AlgorithmEd25519);
        enclave.SignAsync(Arg.Any<string>(), Arg.Do<byte[]>(b => capturedSigningInput = b), Arg.Any<CancellationToken>())
               .Returns(Task.FromResult(Result.Success(new byte[64])));

        await WebAuthnAssertionBuilder.BuildAsync(
            enclave, "alias", "demo.recto.example", "https://demo.recto.example",
            "challenge-x", counter: 0, CancellationToken.None);

        Assert.NotNull(capturedSigningInput);
        Assert.Equal(37 + 32, capturedSigningInput.Length); // authData (37) + sha256 hash (32)

        var expectedAuthData = WebAuthnAssertionBuilder.BuildAuthenticatorData("demo.recto.example", 0);
        var expectedClientData = WebAuthnAssertionBuilder.BuildClientDataJson("challenge-x", "https://demo.recto.example");
        var expectedClientDataHash = SHA256.HashData(expectedClientData);

        Assert.Equal(expectedAuthData, capturedSigningInput.AsSpan(0, 37).ToArray());
        Assert.Equal(expectedClientDataHash, capturedSigningInput.AsSpan(37, 32).ToArray());
    }

    [Fact]
    public async Task BuildAsync_ReturnsAllThreeAssertionPiecesBase64Url()
    {
        var enclave = Substitute.For<IEnclaveKeyService>();
        enclave.Algorithm.Returns(V04Protocol.AlgorithmEd25519);
        enclave.SignAsync(Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
               .Returns(Task.FromResult(Result.Success(new byte[] { 0x01, 0x02, 0x03 })));

        var result = await WebAuthnAssertionBuilder.BuildAsync(
            enclave, "alias", "rp", "origin", "challenge", counter: 0, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.False(string.IsNullOrEmpty(result.Value.ClientDataB64u));
        Assert.False(string.IsNullOrEmpty(result.Value.AuthenticatorDataB64u));
        Assert.False(string.IsNullOrEmpty(result.Value.SignatureB64u));
        // Base64url should never contain padding or +/.
        foreach (var s in new[] { result.Value.ClientDataB64u, result.Value.AuthenticatorDataB64u, result.Value.SignatureB64u })
        {
            Assert.DoesNotContain("=", s);
            Assert.DoesNotContain("+", s);
            Assert.DoesNotContain("/", s);
        }
    }

    [Fact]
    public async Task BuildAsync_PropagatesEnclaveFailure()
    {
        var enclave = Substitute.For<IEnclaveKeyService>();
        enclave.Algorithm.Returns(V04Protocol.AlgorithmEd25519);
        enclave.SignAsync(Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
               .Returns(Task.FromResult(Result.Failure<byte[]>(Error.Failure("user cancelled biometric"))));

        var result = await WebAuthnAssertionBuilder.BuildAsync(
            enclave, "alias", "rp", "origin", "challenge", 0, CancellationToken.None);

        Assert.True(result.IsFailure);
    }
}
