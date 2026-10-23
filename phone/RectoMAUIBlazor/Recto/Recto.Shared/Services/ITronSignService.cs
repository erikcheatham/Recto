using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side TRON signing service. Owns a BIP-39 mnemonic in
/// platform <c>SecureStorage</c> (the SAME entry as
/// <c>IEthSignService</c> / <c>IBtcSignService</c> /
/// <c>IEd25519ChainSignService</c> -- one mnemonic, multiple chain
/// trees), derives secp256k1 keypairs at the standard TRON BIP-44
/// path <c>m/44'/195'/0'/0/N</c>, and signs TIP-191 message hashes
/// on operator approval. The Python launcher / bootloader tier
/// never holds a private key; this service is the only code path
/// that ever materializes the secret bytes, and they never leave
/// the phone.
///
/// <para>
/// Every <c>tron_sign</c> approval through Home.razor flows through
/// <see cref="SignMessageAsync"/>. The result is a 65-byte
/// <c>r||s||v</c> hex string that the phone returns via
/// <c>RespondRequest.TronSignatureRsv</c>; the Python bootloader
/// validates structural shape only and forwards the signature
/// opaque to the consumer (TRON node / off-chain verifier /
/// capability-JWT scope enforcer, etc.).
/// </para>
///
/// <para>
/// TIP-191 vs EIP-191: TRON's signed-message standard is
/// structurally identical to Ethereum's EIP-191 with the preamble
/// string swapped (<c>"TRON Signed Message:\n"</c> instead of
/// <c>"Ethereum Signed Message:\n"</c>). The same secp256k1 +
/// Keccak-256 + RFC 6979 deterministic-k pipeline produces a
/// signature TronWeb / TronLink / Tronscan accept verbatim.
/// </para>
///
/// <para>
/// Wave 9 part 2 home: TRON support is message_signing only.
/// TRON transaction signing wraps a protobuf-serialized
/// <c>Transaction</c> message that requires a parser the phone
/// doesn't yet ship; reserved at the protocol layer for a follow-up
/// wave.
/// </para>
/// </summary>
public interface ITronSignService
{
    /// <summary>
    /// Returns the account derived at <paramref name="derivationPath"/>
    /// from the mnemonic stored under <paramref name="alias"/>. If no
    /// mnemonic exists yet, generates a fresh 24-word BIP-39 mnemonic
    /// (or reads the SHARED mnemonic that ETH/BTC/ED already
    /// provisioned), persists it, and returns the freshly-derived
    /// account.
    /// </summary>
    Task<Result<TronAccount>> EnsureMnemonicAsync(
        string alias,
        string derivationPath,
        CancellationToken ct);

    /// <summary>
    /// Returns the account derived at <paramref name="derivationPath"/>
    /// from the mnemonic stored under <paramref name="alias"/>. Fails
    /// with <c>NotFound</c> if no mnemonic is provisioned.
    /// </summary>
    Task<Result<TronAccount>> GetAccountAsync(
        string alias,
        string derivationPath,
        CancellationToken ct);

    /// <summary>
    /// True if a mnemonic has been provisioned for <paramref name="alias"/>.
    /// </summary>
    Task<Result<bool>> ExistsAsync(string alias, CancellationToken ct);

    /// <summary>
    /// Signs a TIP-191 message with the secp256k1 key derived at
    /// <paramref name="derivationPath"/>. Computes
    /// <c>keccak256("\x19TRON Signed Message:\n" + len(msg) + msg)</c>
    /// and produces a 65-byte <c>r||s||v</c> signature, returned as a
    /// 0x-prefixed hex string (132 chars total).
    /// </summary>
    /// <returns>
    /// Hex string with <c>0x</c> prefix, exactly 132 chars including
    /// the prefix. The <c>v</c> byte is <c>27</c> or <c>28</c> --
    /// canonical legacy encoding accepted by TronWeb's
    /// <c>tronWeb.trx.verifyMessageV2</c> verifier.
    /// </returns>
    Task<Result<string>> SignMessageAsync(
        string alias,
        string derivationPath,
        string message,
        CancellationToken ct);

    /// <summary>
    /// Removes the mnemonic stored under <paramref name="alias"/>.
    /// NOTE: because TRON shares the same SecureStorage entry as ETH /
    /// BTC / ED, calling this is equivalent to calling Clear on those
    /// services -- they all reference the same mnemonic. Document
    /// clearly in the operator UI before invoking. Intended for the
    /// Settings "Unpair all" emergency wipe. No-op if absent.
    /// </summary>
    Task<Result> ClearAsync(string alias, CancellationToken ct);
}
