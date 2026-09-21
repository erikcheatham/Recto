using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side Bitcoin signing service. Reads the BIP-39 mnemonic from
/// the SAME <c>SecureStorage</c> entry as <c>IEthSignService</c> (one
/// mnemonic per phone, two BIP-44 trees) and derives secp256k1
/// keypairs at native-SegWit BIP-44 paths (<c>m/84'/0'/0'/0/N</c>
/// default), legacy P2PKH paths (<c>m/44'/0'/0'/0/N</c>), or nested
/// SegWit paths (<c>m/49'/0'/0'/0/N</c>). Signs BIP-137 message-signing
/// payloads on operator approval. The Python launcher / bootloader
/// tier never holds a private key.
///
/// <para>
/// Every <c>btc_sign</c> approval through Home.razor flows through
/// <see cref="SignMessageAsync"/> (PSBT signing is reserved for a
/// follow-up). The result is a 65-byte BIP-137 compact signature
/// base64-encoded that the phone returns via
/// <c>RespondRequest.BtcSignatureBase64</c>; the Python bootloader
/// validates structural shape only and forwards the signature opaque
/// to the consumer (smart contract / off-chain verifier / wallet
/// performing on-chain verification).
/// </para>
///
/// <para>
/// Threat model is identical to the ETH service. The BIP-39 mnemonic
/// is the master secret, shared by both ETH and BTC services; loss of
/// the phone (and SecureStorage erased) means both address trees are
/// unrecoverable unless the operator wrote the mnemonic down. Future
/// v0.6+ adds a unified backup ceremony that displays the same 24
/// words covering both coins.
/// </para>
/// </summary>
public interface IBtcSignService
{
    /// <summary>
    /// Returns the account derived at <paramref name="derivationPath"/>
    /// from the mnemonic stored under <paramref name="alias"/>. If no
    /// mnemonic exists yet, generates a fresh 24-word BIP-39 mnemonic
    /// (or reuses one already created by the ETH service since they
    /// share storage), persists it, and returns the freshly-derived
    /// account. <paramref name="network"/> determines the bech32 HRP
    /// (<c>bc</c> for mainnet, <c>tb</c> for testnet/signet,
    /// <c>bcrt</c> for regtest) and the resulting address string.
    /// </summary>
    Task<Result<BtcAccount>> EnsureMnemonicAsync(
        string alias,
        string derivationPath,
        string network,
        string coin,
        CancellationToken ct);

    /// <summary>
    /// Returns the account derived at <paramref name="derivationPath"/>
    /// from the mnemonic stored under <paramref name="alias"/>. Fails
    /// with <c>NotFound</c> if no mnemonic is provisioned.
    /// </summary>
    Task<Result<BtcAccount>> GetAccountAsync(
        string alias,
        string derivationPath,
        string network,
        string coin,
        CancellationToken ct);

    /// <summary>
    /// True if a mnemonic has been provisioned for <paramref name="alias"/>
    /// (either by this BTC service or the sibling ETH service — they
    /// share storage).
    /// </summary>
    Task<Result<bool>> ExistsAsync(string alias, CancellationToken ct);

    /// <summary>
    /// Signs a BIP-137 message-signing payload with the secp256k1 key
    /// derived at <paramref name="derivationPath"/>. Computes
    /// <c>double_sha256("\x18Bitcoin Signed Message:\n" + varint(len(msg)) + msg)</c>
    /// and produces a 65-byte BIP-137 compact signature
    /// (header || r || s) base64-encoded.
    ///
    /// <para>
    /// The header byte encodes the recovery id + the address kind the
    /// signer is asserting authority for, per BIP-137:
    /// <c>27 + 12 + recovery_id</c> = 39..42 for P2WPKH (the default
    /// modern wallets produce). Verifiers parse the header to pick the
    /// expected address kind. We always produce P2WPKH headers when
    /// the derivation path's purpose level is 84'; future support for
    /// 44' / 49' purpose levels would shift to the legacy-P2PKH /
    /// nested-SegWit header ranges respectively.
    /// </para>
    /// </summary>
    Task<Result<string>> SignMessageAsync(
        string alias,
        string derivationPath,
        string network,
        string coin,
        string message,
        CancellationToken ct);

    /// <summary>
    /// Removes the mnemonic stored under <paramref name="alias"/>.
    /// Note: this also affects the sibling ETH service since they
    /// share storage. Intended for the Settings "Unpair all" emergency
    /// wipe and future per-alias revocation. No-op if absent.
    /// </summary>
    Task<Result> ClearAsync(string alias, CancellationToken ct);
}
