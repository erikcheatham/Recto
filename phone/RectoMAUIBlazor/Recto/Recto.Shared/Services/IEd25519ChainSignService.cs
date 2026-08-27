using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side ed25519-chain signing service (Solana / Stellar /
/// XRP-ed25519). Reads the BIP-39 mnemonic from the SAME
/// <c>SecureStorage</c> entry as <c>IEthSignService</c> and
/// <c>IBtcSignService</c> (one mnemonic per phone, multiple curve
/// trees) and derives ed25519 keypairs at chain-specific SLIP-0010
/// paths. Signs chain-specific message-hash payloads on operator
/// approval. The Python launcher / bootloader tier never holds a
/// private key.
///
/// <para>
/// Every <c>ed_sign</c> approval through Home.razor flows through
/// <see cref="SignMessageAsync"/>. The result is a 64-byte raw
/// ed25519 signature that the phone returns via
/// <c>RespondRequest.EdSignatureBase64</c> (base64-encoded), AND
/// the 32-byte ed25519 public key as 64 hex chars via
/// <c>RespondRequest.EdPubkeyHex</c>. The Python bootloader
/// validates structural shape only (64-byte sig decode + 64 hex
/// chars after optional 0x strip) and forwards both fields opaque
/// to the consumer.
/// </para>
///
/// <para>
/// Threat model is identical to the ETH and BTC services. The
/// BIP-39 mnemonic is the master secret, shared across all three
/// signing services; loss of the phone (and SecureStorage erased)
/// means every coin tree is unrecoverable unless the operator wrote
/// the mnemonic down. One backup ceremony covers all eight chain
/// coin families now (ETH + BTC + LTC + DOGE + BCH + SOL + XLM +
/// XRP).
/// </para>
/// </summary>
public interface IEd25519ChainSignService
{
    /// <summary>
    /// Returns the account derived at <paramref name="derivationPath"/>
    /// from the mnemonic stored under <paramref name="alias"/>. If no
    /// mnemonic exists yet, generates a fresh 24-word BIP-39 mnemonic
    /// (or reuses one already created by the ETH / BTC services since
    /// they share storage), persists it, and returns the freshly-
    /// derived account. <paramref name="chain"/> is one of
    /// <c>"sol"</c>, <c>"xlm"</c>, <c>"xrp"</c>.
    /// </summary>
    Task<Result<EdAccount>> EnsureMnemonicAsync(
        string alias,
        string chain,
        string derivationPath,
        CancellationToken ct);

    /// <summary>
    /// Returns the account derived at <paramref name="derivationPath"/>
    /// from the mnemonic stored under <paramref name="alias"/>. Fails
    /// with <c>NotFound</c> if no mnemonic is provisioned.
    /// </summary>
    Task<Result<EdAccount>> GetAccountAsync(
        string alias,
        string chain,
        string derivationPath,
        CancellationToken ct);

    /// <summary>
    /// True if a mnemonic has been provisioned for <paramref name="alias"/>
    /// (either by this service or a sibling — they share storage).
    /// </summary>
    Task<Result<bool>> ExistsAsync(string alias, CancellationToken ct);

    /// <summary>
    /// Signs a chain-specific message-hash payload with the ed25519
    /// key derived at <paramref name="derivationPath"/>. Computes
    /// <c>SHA-256(chain_preamble || message_bytes)</c> (chain-specific
    /// preamble) and produces a 64-byte raw ed25519 signature
    /// base64-encoded.
    ///
    /// <para>
    /// Returns a <see cref="EdSignResult"/> carrying both the base64
    /// signature AND the 32-byte ed25519 public key (hex). Caller
    /// forwards both on the wire.
    /// </para>
    /// </summary>
    Task<Result<EdSignResult>> SignMessageAsync(
        string alias,
        string chain,
        string derivationPath,
        string message,
        CancellationToken ct);

    /// <summary>
    /// Removes the mnemonic stored under <paramref name="alias"/>.
    /// Note: this also affects the sibling ETH / BTC services since
    /// they share storage. Intended for the Settings "Unpair all"
    /// emergency wipe and future per-alias revocation.
    /// </summary>
    Task<Result> ClearAsync(string alias, CancellationToken ct);
}

/// <summary>Result of an ed25519-chain message signing — the
/// 64-byte raw signature base64-encoded plus the 32-byte ed25519
/// public key as 64 hex chars. Both required on the wire because
/// XRP addresses are HASH160s and don't carry the pubkey.</summary>
public sealed record EdSignResult(
    string SignatureBase64,
    string PublicKeyHex);
