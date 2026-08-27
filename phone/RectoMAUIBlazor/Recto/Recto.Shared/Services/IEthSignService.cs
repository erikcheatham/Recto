using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side Ethereum signing service. Owns a BIP39 mnemonic in
/// platform <c>SecureStorage</c>, derives secp256k1 keypairs at
/// arbitrary BIP32/BIP44 paths, and signs EIP-191 / EIP-712 / RLP
/// digests on operator approval. The Python launcher / bootloader
/// tier never holds a private key &mdash; it only sends signing
/// requests; this service is the only code path that ever
/// materializes the secret bytes, and they never leave the phone.
///
/// <para>
/// Every <c>eth_sign</c> approval through Home.razor flows through
/// <see cref="SignPersonalSignAsync"/> (or the typed_data /
/// transaction siblings, future). The result is a 65-byte
/// <c>r||s||v</c> hex string that the phone returns via
/// <c>RespondRequest.EthSignatureRsv</c>; the Python bootloader
/// validates structural shape only and forwards the signature opaque
/// to the consumer (smart contract on chain, off-chain verifier,
/// capability-JWT scope enforcer, etc.).
/// </para>
///
/// <para>
/// Mnemonic creation is one-shot per <paramref name="alias"/> at the
/// service layer &mdash; <see cref="EnsureMnemonicAsync"/> generates a
/// fresh 24-word BIP39 mnemonic if none exists, otherwise returns the
/// existing account derived at the default path. Operators wanting to
/// import an existing mnemonic from another wallet use
/// <see cref="ImportMnemonicAsync"/> at v0.6+ (not in v0.5+ groundwork).
/// </para>
///
/// <para>
/// Threat model: the BIP39 mnemonic is the master secret. Loss of
/// the phone (and SecureStorage erased) means the keys are
/// unrecoverable unless the operator wrote the mnemonic down at
/// generation time. Future v0.6+ adds an export-mnemonic flow gated
/// on biometric + a destructive-confirmation modal so the operator
/// can back up. The current cut never displays the mnemonic in UI
/// (no accidental shoulder-surf risk during dev iteration).
/// </para>
/// </summary>
public interface IEthSignService
{
    /// <summary>
    /// Returns the account derived at <paramref name="derivationPath"/> from
    /// the mnemonic stored under <paramref name="alias"/>. If no mnemonic
    /// exists yet, generates a fresh 24-word BIP39 mnemonic, persists it
    /// in <c>SecureStorage</c>, and returns the freshly-derived account.
    /// </summary>
    Task<Result<EthAccount>> EnsureMnemonicAsync(
        string alias,
        string derivationPath,
        CancellationToken ct);

    /// <summary>
    /// Returns the account derived at <paramref name="derivationPath"/>
    /// from the mnemonic stored under <paramref name="alias"/>. Fails
    /// with <c>NotFound</c> if no mnemonic is provisioned for the alias.
    /// </summary>
    Task<Result<EthAccount>> GetAccountAsync(
        string alias,
        string derivationPath,
        CancellationToken ct);

    /// <summary>
    /// True if a mnemonic has been provisioned for <paramref name="alias"/>.
    /// </summary>
    Task<Result<bool>> ExistsAsync(string alias, CancellationToken ct);

    /// <summary>
    /// Signs an EIP-191 personal_sign message with the secp256k1 key
    /// derived at <paramref name="derivationPath"/>. Computes
    /// <c>keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)</c>
    /// and produces a 65-byte <c>r||s||v</c> signature, returned as a
    /// 0x-prefixed hex string (132 chars total).
    /// </summary>
    /// <returns>
    /// Hex string with <c>0x</c> prefix, exactly 132 chars including
    /// the prefix. The <c>v</c> byte uses the modern EIP-155 base
    /// (<c>0</c> or <c>1</c>) plus 27, so MetaMask / Trust / Ledger
    /// accept the canonical <c>27</c>/<c>28</c> values.
    /// </returns>
    Task<Result<string>> SignPersonalSignAsync(
        string alias,
        string derivationPath,
        string message,
        CancellationToken ct);

    /// <summary>
    /// Signs an EIP-712 typed-data structure with the secp256k1 key
    /// derived at <paramref name="derivationPath"/>. The
    /// <paramref name="typedDataJson"/> argument is the canonical
    /// EIP-712 JSON envelope: <c>{ "types": {...}, "primaryType": "...",
    /// "domain": {...}, "message": {...} }</c>. Computes the EIP-712
    /// digest <c>keccak256(0x19 || 0x01 || domainSeparator || hashStruct(message))</c>
    /// and produces a 65-byte <c>r||s||v</c> signature returned as a
    /// 0x-prefixed hex string (132 chars total). The <c>v</c> byte
    /// uses the same canonical 27/28 encoding as personal_sign so any
    /// EIP-712 verifier (OpenZeppelin, viem, ethers) accepts it.
    /// </summary>
    Task<Result<string>> SignTypedDataAsync(
        string alias,
        string derivationPath,
        string typedDataJson,
        CancellationToken ct);

    /// <summary>
    /// Signs an EIP-1559 (type-2) transaction with the secp256k1 key
    /// derived at <paramref name="derivationPath"/>. The
    /// <paramref name="transactionJson"/> argument is a JSON object
    /// with the EIP-1559 fields: <c>chainId</c>, <c>nonce</c>,
    /// <c>maxPriorityFeePerGas</c>, <c>maxFeePerGas</c>, <c>gas</c> /
    /// <c>gasLimit</c>, <c>to</c>, <c>value</c>, <c>data</c>, optional
    /// <c>accessList</c>. Computes the transaction hash
    /// <c>keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas,
    /// maxFeePerGas, gasLimit, to, value, data, accessList]))</c> and
    /// produces the signed raw-transaction bytes returned as a
    /// 0x-prefixed hex string (the full RLP-encoded
    /// <c>0x02 || rlp([...all fields..., yParity, r, s])</c>) ready to
    /// hand to <c>eth_sendRawTransaction</c>.
    /// </summary>
    Task<Result<string>> SignTransactionAsync(
        string alias,
        string derivationPath,
        string transactionJson,
        CancellationToken ct);

    /// <summary>
    /// Signs an arbitrary 32-byte digest with the secp256k1 key derived
    /// at <paramref name="derivationPath"/>. Returns the 64-byte raw
    /// <c>r||s</c> signature (no recovery byte) — the format JWS ES256K
    /// (RFC 8812) expects.
    /// <para>
    /// Used by Phase 5 Wave B's <c>capability_request</c> flow: the
    /// bootloader pre-computes <c>SHA-256(f"{cap_header_b64}.{cap_payload_b64}")</c>
    /// and surfaces it as the request's <c>payload_hash_b64u</c>; the
    /// phone reconstructs the same digest from the cap_*_b64 segments
    /// (verifying byte-parity with the bootloader) and calls this method
    /// to produce the JWS signature. Same operator identity as ETH
    /// personal_sign — one BIP-39 mnemonic, one secp256k1 derivation,
    /// two surfaces.
    /// </para>
    /// <para>
    /// Auto-provisions the mnemonic on first call (matching the
    /// existing <see cref="SignPersonalSignAsync"/> behavior) so the
    /// operator's first capability_request just works without a
    /// separate <see cref="EnsureMnemonicAsync"/> bootstrapping step.
    /// </para>
    /// </summary>
    /// <param name="alias">Mnemonic alias in SecureStorage.</param>
    /// <param name="derivationPath">BIP-32/BIP-44 path. Default for
    /// capability signing matches the ETH path
    /// (<c>m/44'/60'/0'/0/0</c>) so one operator identity covers
    /// both surfaces.</param>
    /// <param name="digest">The 32-byte SHA-256 digest the signer is
    /// signing. Throws <c>Validation</c> failure if not exactly 32
    /// bytes.</param>
    /// <returns>64 bytes: <c>r</c> (32) || <c>s</c> (32). NOT the
    /// 65-byte r||s||v form ETH personal_sign returns.</returns>
    Task<Result<byte[]>> SignDigestAsync(
        string alias,
        string derivationPath,
        byte[] digest,
        CancellationToken ct);

    /// <summary>
    /// Phase 2.0.C wave C.3: derive a child pubkey at an arbitrary
    /// BIP-32 path from the operator's mnemonic, WITHOUT signing.
    /// Used by the profile_create approval flow to compute the
    /// <c>child_pubkey_hex</c> that gets bound into the master
    /// attestation's signing input.
    ///
    /// <para>
    /// Returns the 64-byte uncompressed X || Y pubkey (no <c>0x04</c>
    /// prefix, matching what <see cref="EthSigningOps.PublicKeyFromPrivate"/>
    /// emits and what the bootloader's
    /// <c>create_child_profile(derived_pubkey_hex=...)</c> expects
    /// when hex-encoded). Implementations MUST zero-wipe the
    /// intermediate seed + private key material.
    /// </para>
    ///
    /// <para>
    /// Per Hard Rule #9: the mnemonic never leaves the enclave-bound
    /// SecureStorage context; only the derived public key is exposed
    /// to the caller. Same posture as the existing signing methods.
    /// </para>
    /// </summary>
    /// <param name="alias">Mnemonic alias in SecureStorage (same one
    /// the existing signing methods consume).</param>
    /// <param name="derivationPath">BIP-32 path string. For profile
    /// derivation the canonical form is
    /// <c>m/{PROFILE_BIP32_PURPOSE}'/{coin_type}'/{index}'</c> where
    /// PROFILE_BIP32_PURPOSE is <c>0x72656374</c> (1919247220) per
    /// <c>recto.profile.manage</c> and coin_type/index come from
    /// the candidate fields on the PendingRequest.</param>
    /// <returns>64-byte uncompressed pubkey (X || Y).</returns>
    Task<Result<byte[]>> DerivePubkeyAtPathAsync(
        string alias,
        string derivationPath,
        CancellationToken ct);

    /// <summary>
    /// Removes the mnemonic stored under <paramref name="alias"/>.
    /// Intended for the Settings "Unpair all" emergency wipe and
    /// future per-alias revocation. No-op if absent.
    /// </summary>
    Task<Result> ClearAsync(string alias, CancellationToken ct);

    /// <summary>
    /// Build 12 (2026-07-11) mnemonic backup ceremony: returns the raw
    /// 24-word BIP-39 mnemonic for <paramref name="alias"/> so the operator
    /// can write it down. Fails <c>NotFound</c> if none is provisioned.
    ///
    /// <para><b>SECURITY — biometric gate is the CALLER's responsibility and
    /// is NON-NEGOTIABLE.</b> The only sanctioned caller (Settings' backup
    /// ceremony) MUST obtain a fresh biometric proof via
    /// <c>IEnclaveKeyService.SignAsync</c> — which triggers Face ID /
    /// BiometricPrompt through the enclave key's <c>BiometryCurrentSet</c>
    /// ACL — IMMEDIATELY before calling this, and MUST NOT reveal the words
    /// if that sign fails. This method itself performs a bare SecureStorage
    /// read (keychain/keystore-protected at rest) — it does not re-prompt,
    /// so a caller that skips the gate leaks the master secret. Do not add
    /// a second caller without the same gate.</para>
    /// </summary>
    Task<Result<string>> ExportMnemonicAsync(string alias, CancellationToken ct);

    /// <summary>
    /// Build 12 mnemonic restore ceremony: validates <paramref name="mnemonic"/>
    /// (BIP-39 wordlist + checksum) and persists it under
    /// <paramref name="alias"/>, then returns the account derived at
    /// <paramref name="derivationPath"/>. <b>DESTRUCTIVE</b> — overwrites any
    /// existing mnemonic for the alias (the caller shows a confirmation modal
    /// first). Fails <c>Validation</c> on a bad phrase without touching
    /// storage. Also clears the cached derived secp256k1 key entry so the
    /// next sign re-derives from the imported seed.
    /// </summary>
    Task<Result<EthAccount>> ImportMnemonicAsync(
        string alias,
        string mnemonic,
        string derivationPath,
        CancellationToken ct);
}
