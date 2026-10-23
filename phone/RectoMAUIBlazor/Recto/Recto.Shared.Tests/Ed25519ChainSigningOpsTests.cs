using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// Pins per-chain encoding + message hashing + sign-verify behavior
/// for the ed25519-chain credential family. Sister tests to
/// <see cref="EthSigningOpsTests"/> and <see cref="BtcSigningOpsTests"/>.
///
/// <para>
/// External pins:
/// <list type="bullet">
/// <item>CRC16-XMODEM canonical reference: "123456789" → 0x31C3.</item>
/// <item>Ripple base58 alphabet pinned char-by-char (must be
/// "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz" —
/// distinct from Bitcoin's, position 0 is 'r').</item>
/// <item>SOL System Program pubkey (32 zero bytes) → 32 ones address
/// "11111111111111111111111111111111" — well-known across the
/// Solana ecosystem.</item>
/// <item>Recto's chain-specific message preambles pinned byte-for-byte
/// so phone-side and verifier-side stay in agreement.</item>
/// </list>
/// </para>
/// </summary>
public class Ed25519ChainSigningOpsTests
{
    private const string ZeroEntropyMnemonic12 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    [Fact]
    public void Crc16Xmodem_CanonicalReferenceVector()
    {
        // The "123456789" CRC reference vector is canonical across
        // every CRC implementation. Init 0x0000, poly 0x1021, no
        // reflection, no final XOR → 0x31C3.
        Assert.Equal((ushort)0x31C3,
            Ed25519ChainSigningOps.Crc16Xmodem(Encoding.ASCII.GetBytes("123456789")));
    }

    [Fact]
    public void RippleBase58Alphabet_PinnedCharByChar()
    {
        // Ripple's base58 alphabet is DIFFERENT from Bitcoin's. Pin
        // exact ordering — phone-side and verifier-side MUST agree.
        Assert.Equal(
            "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
            Ed25519ChainSigningOps.RippleBase58Alphabet);
        Assert.Equal('r', Ed25519ChainSigningOps.RippleBase58Alphabet[0]);
        Assert.Equal(58, Ed25519ChainSigningOps.RippleBase58Alphabet.Length);
        Assert.Equal(58,
            Ed25519ChainSigningOps.RippleBase58Alphabet.Distinct().Count());
    }

    [Fact]
    public void SolAddressFromPublicKey_ZeroPubkey_IsSystemProgramAddress()
    {
        // 32 zero bytes pubkey → 32 ones address. Solana System
        // Program ID is at this address; documented across the
        // entire SOL ecosystem.
        var addr = Ed25519ChainSigningOps.SolAddressFromPublicKey(new byte[32]);
        Assert.Equal(new string('1', 32), addr);
    }

    [Fact]
    public void SolAddressFromPublicKey_RoundTripsViaPublicKeyFromAddress()
    {
        var rng = new Random(0xed25519);
        var pubkey = new byte[32];
        rng.NextBytes(pubkey);
        var addr = Ed25519ChainSigningOps.SolAddressFromPublicKey(pubkey);
        var recovered = Ed25519ChainSigningOps.SolPublicKeyFromAddress(addr);
        Assert.True(recovered.SequenceEqual(pubkey));
    }

    [Fact]
    public void XlmAddressFromPublicKey_StartsWithG_AndIs56Chars()
    {
        var rng = new Random(0xed25520);
        var pubkey = new byte[32];
        rng.NextBytes(pubkey);
        var addr = Ed25519ChainSigningOps.XlmAddressFromPublicKey(pubkey);
        Assert.StartsWith("G", addr);
        Assert.Equal(56, addr.Length);
    }

    [Fact]
    public void XlmAddressFromPublicKey_RoundTripsViaPublicKeyFromAddress()
    {
        var rng = new Random(0xed25521);
        var pubkey = new byte[32];
        rng.NextBytes(pubkey);
        var addr = Ed25519ChainSigningOps.XlmAddressFromPublicKey(pubkey);
        var recovered = Ed25519ChainSigningOps.XlmPublicKeyFromAddress(addr);
        Assert.True(recovered.SequenceEqual(pubkey));
    }

    [Fact]
    public void XlmAddress_CorruptedCharFailsCrc()
    {
        var rng = new Random(0xed25522);
        var pubkey = new byte[32];
        rng.NextBytes(pubkey);
        var addr = Ed25519ChainSigningOps.XlmAddressFromPublicKey(pubkey);
        // Flip one body character to a different valid base32 char.
        var chars = addr.ToCharArray();
        chars[5] = chars[5] == 'A' ? 'B' : 'A';
        Assert.Throws<ArgumentException>(() =>
            Ed25519ChainSigningOps.XlmPublicKeyFromAddress(new string(chars)));
    }

    [Fact]
    public void XrpAddressFromPublicKey_StartsWithR()
    {
        var rng = new Random(0xed25523);
        var pubkey = new byte[32];
        rng.NextBytes(pubkey);
        var addr = Ed25519ChainSigningOps.XrpAddressFromPublicKey(pubkey);
        Assert.StartsWith("r", addr);
    }

    [Fact]
    public void XrpAddress_DifferentPubkeys_ProduceDifferentAddresses()
    {
        var rng = new Random(0xed25524);
        var pub1 = new byte[32];
        var pub2 = new byte[32];
        rng.NextBytes(pub1);
        rng.NextBytes(pub2);
        Assert.NotEqual(
            Ed25519ChainSigningOps.XrpAddressFromPublicKey(pub1),
            Ed25519ChainSigningOps.XrpAddressFromPublicKey(pub2));
    }

    [Fact]
    public void XrpAddress_CorruptedCharFailsChecksum()
    {
        var rng = new Random(0xed25525);
        var pubkey = new byte[32];
        rng.NextBytes(pubkey);
        var addr = Ed25519ChainSigningOps.XrpAddressFromPublicKey(pubkey);
        // Flip one body character to a different valid alphabet char.
        var chars = addr.ToCharArray();
        chars[3] = chars[3] == 'r' ? 'p' : 'r';
        Assert.Throws<ArgumentException>(() =>
            Ed25519ChainSigningOps.XrpAccountIdFromAddress(new string(chars)));
    }

    [Fact]
    public void SignedMessageHash_PreambleIsRectoConvention()
    {
        // Pin chain preambles. Phone-side and verifier-side MUST
        // agree on these byte sequences or every signature drops on
        // the floor.
        var solCfg = Ed25519ChainSigningOps.GetChainConfig("sol");
        Assert.Equal(
            Encoding.UTF8.GetBytes("Solana signed message:\n"),
            solCfg.MessagePreamble);
        var xlmCfg = Ed25519ChainSigningOps.GetChainConfig("xlm");
        Assert.Equal(
            Encoding.UTF8.GetBytes("Stellar signed message:\n"),
            xlmCfg.MessagePreamble);
        var xrpCfg = Ed25519ChainSigningOps.GetChainConfig("xrp");
        Assert.Equal(
            Encoding.UTF8.GetBytes("XRP signed message:\n"),
            xrpCfg.MessagePreamble);
    }

    [Fact]
    public void SignedMessageHash_DifferentChains_ProduceDifferentHashes()
    {
        // Same message, different chain → different hash (because
        // the preamble differs). This is the property that lets a
        // SOL signature for "Login" be different from an XLM
        // signature for "Login" — without it, replay across chains
        // would be trivial.
        var sol = Ed25519ChainSigningOps.SignedMessageHash("Login", "sol");
        var xlm = Ed25519ChainSigningOps.SignedMessageHash("Login", "xlm");
        var xrp = Ed25519ChainSigningOps.SignedMessageHash("Login", "xrp");
        Assert.NotEqual(sol, xlm);
        Assert.NotEqual(sol, xrp);
        Assert.NotEqual(xlm, xrp);
    }

    [Fact]
    public void GetChainConfig_UnknownChain_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            Ed25519ChainSigningOps.GetChainConfig("ada"));
    }

    [Fact]
    public void ChainDefaultPaths_AreAllHardened()
    {
        // SLIP-0010 ed25519 hardened-only requirement applies to
        // every chain default path. If a future edit accidentally
        // strips a hardened marker from the config, the failing test
        // here points at the fix.
        foreach (var (key, cfg) in Ed25519ChainSigningOps.ChainConfigs)
        {
            // ParsePath throws on non-hardened; if the path round-trips
            // through ParsePath, every segment is hardened.
            var indices = Slip10.ParsePath(cfg.DefaultPath);
            Assert.NotEmpty(indices);
            foreach (var idx in indices)
            {
                Assert.True(
                    (idx & 0x80000000u) != 0,
                    $"chain {key} default path '{cfg.DefaultPath}' has non-hardened index {idx:X}");
            }
        }
    }

    [Fact]
    public void SignMessage_ProducesValidEd25519Signature()
    {
        // End-to-end: derive the SOL account at the canonical Phantom
        // path, sign a login message, verify the signature against the
        // derived public key. Confirms the BIP-39 → SLIP-0010 →
        // ed25519 sign pipeline produces signatures the standard
        // ed25519 verifier accepts.
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var path = "m/44'/501'/0'/0'";
        var message = "Login to demo.recto.example";
        var sig = Ed25519ChainSigningOps.SignMessage(seed, path, message, "sol");
        Assert.Equal(64, sig.Length);

        var leaf = Slip10.DeriveAtPath(seed, path);
        var pub = Slip10.GetPublicKey(leaf.PrivateKey);
        var msgHash = Ed25519ChainSigningOps.SignedMessageHash(message, "sol");

        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(pub, 0));
        verifier.BlockUpdate(msgHash, 0, msgHash.Length);
        Assert.True(verifier.VerifySignature(sig));
    }

    [Fact]
    public void SignMessage_DifferentChain_ProducesDifferentSignature()
    {
        // Same path + same message + different chain (preamble
        // difference) → different signature.
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        // Use SOL's path for both signs (avoid the chain-distinct path
        // dimension confounding the test); only the chain-specific
        // preamble varies.
        var path = "m/44'/501'/0'/0'";
        var sigSol = Ed25519ChainSigningOps.SignMessage(seed, path, "Login", "sol");
        var sigXlm = Ed25519ChainSigningOps.SignMessage(seed, path, "Login", "xlm");
        Assert.False(sigSol.SequenceEqual(sigXlm));
    }

    [Fact]
    public void Base58CheckEncode_RoundTripsThroughDecode()
    {
        var rng = new Random(0xed25526);
        var payload = new byte[24];
        rng.NextBytes(payload);
        var encoded = Ed25519ChainSigningOps.Base58CheckEncode(
            payload, Encoding.ASCII.GetBytes(Ed25519ChainSigningOps.RippleBase58Alphabet));
        var decoded = Ed25519ChainSigningOps.Base58CheckDecode(
            encoded, Encoding.ASCII.GetBytes(Ed25519ChainSigningOps.RippleBase58Alphabet));
        Assert.True(decoded.SequenceEqual(payload));
    }
}
