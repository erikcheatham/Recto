using System;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Profile;

/// <summary>
/// Phase 2.0.C wave C.3: pins BIP-32 derivation at PROFILE-specific
/// paths against the canonical Trezor "abandon ... about" mnemonic.
///
/// <para>
/// The CRYPTOGRAPHIC primitives (BIP-39 seed derivation + BIP-32
/// HD-key derivation + secp256k1 X||Y pubkey emission) are already
/// cross-validated against the canonical Ethereum reference value
/// in <see cref="Bip32Tests"/> — that test pins m/44'/60'/0'/0/0
/// → 0x9858effd232b4033e47d90003d41ec34ecaeda94 against the
/// published cross-wallet reference. Recto's BIP-32 + BIP-39 stack
/// is byte-for-byte compatible with MetaMask / Ledger / Trezor /
/// every other BIP-39 wallet on the canonical ETH path.
/// </para>
///
/// <para>
/// What's NOT yet externally cross-validated: PROFILE-specific
/// paths of the form <c>m/{PROFILE_BIP32_PURPOSE}'/{coin_type}'/{index}'</c>
/// where PROFILE_BIP32_PURPOSE is <c>0x72656374</c> (1919247220).
/// The same crypto primitives produce these — same Bip32.DeriveAtPath,
/// same EthSigningOps.PublicKeyFromPrivate — so the derivation is
/// correct by construction if the canonical ETH-path test passes.
/// But Recto's "cross-validate any new digest function against an
/// external reference impl" hard rule wants an INDEPENDENT pin too:
/// derive the same path through an external BIP-32 tool (electrum /
/// ian-coleman/bip39 / bitcoinjs) and pin the resulting pubkey here.
/// </para>
///
/// <para>
/// External cross-check is banked as a deferred TODO at the bottom
/// of this file (matches the deferred external-JWT-reference test
/// in <see cref="Capability.CapabilityVerifierTests"/>'s sister
/// pattern). For the operator-facing iPhone smoke that closes
/// Phase 2.0.C wave C.4, the real-hardware end-to-end loop is the
/// stronger validation: bootloader's master-attestation verify
/// path re-canonicalizes the signing input with the phone-supplied
/// child_pubkey_hex and the master signature must recover to the
/// operator's pubkey. If the phone-side derivation is off-by-one,
/// the bootloader rejects with "did not recover."
/// </para>
/// </summary>
public class Bip32ProfileDerivationTests
{
    private const string ZeroEntropyMnemonic12 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// <summary>
    /// PROFILE_BIP32_PURPOSE from recto.profile.manage Python module:
    /// <c>0x72656374</c> = "rect" ASCII bytes interpreted as a
    /// big-endian uint32 = 1919247220 decimal. Reserved per BIP-43.
    /// </summary>
    private const uint ProfileBip32Purpose = 0x72656374u;

    /// <summary>
    /// PROFILE_COIN_TYPES["personal:child"] from recto.profile.manage:
    /// 1. The canonical kind→coin_type assignment for personal-child
    /// profiles.
    /// </summary>
    private const uint PersonalChildCoinType = 1u;

    [Fact]
    public void DeriveAtProfilePath_ZeroEntropyMnemonic_ProducesDeterministicPubkey()
    {
        // Same path that Python's create_child_profile would record
        // for the first personal:child profile under a master:
        // m/1919247220'/1'/0'
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var path = $"m/{ProfileBip32Purpose}'/{PersonalChildCoinType}'/0'";
        var leaf = Bip32.DeriveAtPath(seed, path);
        var pubkeyA = EthSigningOps.PublicKeyFromPrivate(leaf.PrivateKey);

        // Derive twice -- same path + same mnemonic must yield same
        // pubkey (cryptographic determinism).
        var seed2 = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var leaf2 = Bip32.DeriveAtPath(seed2, path);
        var pubkeyB = EthSigningOps.PublicKeyFromPrivate(leaf2.PrivateKey);

        Assert.Equal(64, pubkeyA.Length);
        Assert.Equal(64, pubkeyB.Length);
        Assert.Equal(Convert.ToHexString(pubkeyA), Convert.ToHexString(pubkeyB));
    }

    [Fact]
    public void DeriveAtProfilePath_DifferentIndices_ProduceDifferentPubkeys()
    {
        // The next-index logic in recto.profile.manage advances
        // monotonically per coin_type; index 0 vs index 1 vs index 2
        // must all produce distinct pubkeys (otherwise the bootloader's
        // master attestation would collide across profiles and the
        // signing-input binding would break).
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var pub0 = EthSigningOps.PublicKeyFromPrivate(
            Bip32.DeriveAtPath(seed, $"m/{ProfileBip32Purpose}'/{PersonalChildCoinType}'/0'").PrivateKey);
        var pub1 = EthSigningOps.PublicKeyFromPrivate(
            Bip32.DeriveAtPath(seed, $"m/{ProfileBip32Purpose}'/{PersonalChildCoinType}'/1'").PrivateKey);
        var pub2 = EthSigningOps.PublicKeyFromPrivate(
            Bip32.DeriveAtPath(seed, $"m/{ProfileBip32Purpose}'/{PersonalChildCoinType}'/2'").PrivateKey);

        Assert.NotEqual(Convert.ToHexString(pub0), Convert.ToHexString(pub1));
        Assert.NotEqual(Convert.ToHexString(pub0), Convert.ToHexString(pub2));
        Assert.NotEqual(Convert.ToHexString(pub1), Convert.ToHexString(pub2));
    }

    [Fact]
    public void DeriveAtProfilePath_DifferentCoinTypes_ProduceDifferentPubkeys()
    {
        // PROFILE_COIN_TYPES maps each canonical kind to a distinct
        // coin_type slot (personal:child=1, work=2, school=3,
        // contractor=4). All sharing the same operator master should
        // produce distinct pubkeys at the same index.
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var pubChild = EthSigningOps.PublicKeyFromPrivate(
            Bip32.DeriveAtPath(seed, $"m/{ProfileBip32Purpose}'/1'/0'").PrivateKey);
        var pubWork = EthSigningOps.PublicKeyFromPrivate(
            Bip32.DeriveAtPath(seed, $"m/{ProfileBip32Purpose}'/2'/0'").PrivateKey);
        var pubSchool = EthSigningOps.PublicKeyFromPrivate(
            Bip32.DeriveAtPath(seed, $"m/{ProfileBip32Purpose}'/3'/0'").PrivateKey);

        Assert.NotEqual(Convert.ToHexString(pubChild), Convert.ToHexString(pubWork));
        Assert.NotEqual(Convert.ToHexString(pubChild), Convert.ToHexString(pubSchool));
        Assert.NotEqual(Convert.ToHexString(pubWork), Convert.ToHexString(pubSchool));
    }

    [Fact]
    public void DeriveAtProfilePath_DifferentPurpose_ProducesDifferentPubkey()
    {
        // ETH-path m/44'/60'/0'/0/0 and profile-path
        // m/1919247220'/1'/0' under the SAME mnemonic must produce
        // distinct pubkeys -- they live in different BIP-43 purpose
        // subtrees. Catches a class of bug where the purpose value
        // gets stripped/ignored by accident.
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var ethPub = EthSigningOps.PublicKeyFromPrivate(
            Bip32.DeriveAtPath(seed, "m/44'/60'/0'/0/0").PrivateKey);
        var profilePub = EthSigningOps.PublicKeyFromPrivate(
            Bip32.DeriveAtPath(seed, $"m/{ProfileBip32Purpose}'/1'/0'").PrivateKey);

        Assert.NotEqual(Convert.ToHexString(ethPub), Convert.ToHexString(profilePub));
    }

    [Fact]
    public void DeriveAtProfilePath_HardenedIndicesRequired()
    {
        // All three path segments (purpose, coin_type, index) MUST be
        // hardened. Non-hardened would let a watcher derive child
        // pubkeys from xpub, which is the wrong security posture for
        // profile-tree derivation (profiles are signing identities,
        // not watch-only addresses). Test pins that the canonical
        // path format hardens all segments via the trailing apostrophe.
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var hardenedPath = $"m/{ProfileBip32Purpose}'/1'/0'";
        var leaf = Bip32.DeriveAtPath(seed, hardenedPath);
        Assert.Equal(32, leaf.PrivateKey.Length);

        // Verify that omitting hardened markers produces a DIFFERENT
        // key (proves the apostrophe is load-bearing in our path
        // parser).
        var nonHardenedPath = $"m/{ProfileBip32Purpose}/1/0";
        var nonHardenedLeaf = Bip32.DeriveAtPath(seed, nonHardenedPath);
        Assert.NotEqual(
            Convert.ToHexString(leaf.PrivateKey),
            Convert.ToHexString(nonHardenedLeaf.PrivateKey));
    }

    [Fact(Skip = "Phase 2.0.C wave C.3 continuation: pin profile-path "
        + "child_pubkey_hex against a value derived by an external "
        + "BIP-32 tool (ian-coleman/bip39, electrum, bitcoinjs) using "
        + "the same Trezor 'abandon ... about' mnemonic + canonical "
        + "profile-path. Required by Recto's 'cross-validate any new "
        + "digest function against an external reference impl' hard "
        + "rule before any production use. The cryptographic primitive "
        + "(BIP-32 + secp256k1) is already cross-validated via "
        + "Bip32Tests.DeriveAtPath_TrezorAbandonAboutEthAccount0_MatchesKnownAddress; "
        + "this skipped test is the per-purpose cross-check. Mirrors "
        + "the deferred external-reference pattern in "
        + "tests/test_capability.py::test_verify_external_jwt_TODO.")]
    public void DeriveAtProfilePath_TrezorAbandonAbout_MatchesExternalReference_TODO()
    {
        // Plan:
        //   1. Use ian-coleman/bip39 (or similar) with mnemonic
        //      "abandon ... about" + empty passphrase + path
        //      m/1919247220'/1'/0' to compute a reference child pubkey
        //      (uncompressed X||Y, 128 hex chars).
        //   2. Pin that value as a const here.
        //   3. Run the same derivation through Recto's stack and
        //      assert byte-equality with the external reference.
        //
        // External cross-check is necessary because internal-consistency
        // alone can't catch a class of bug where Recto's BIP-32 impl
        // disagrees with the canonical wallet ecosystem on the profile-
        // purpose subtree specifically. The canonical ETH-path cross-
        // check (Bip32Tests) proves m/44'/60'/0'/0/0 byte-compat, but a
        // future BIP-32 regression scoped to non-ETH purposes would
        // pass the existing tests while silently breaking profile
        // derivation.
    }
}
