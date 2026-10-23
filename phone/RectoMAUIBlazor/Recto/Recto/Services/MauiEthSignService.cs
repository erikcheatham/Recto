using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Maui.Storage;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// MAUI <c>SecureStorage</c>-backed Ethereum signing service. Wave-4
/// upgrade: stores a single 24-word BIP-39 mnemonic per alias and
/// derives infinitely many addresses on demand via BIP-32/BIP-44
/// <c>m/44'/60'/0'/0/N</c> paths. Mnemonics are byte-for-byte
/// interoperable with every other BIP-39 wallet (MetaMask, Ledger,
/// Trezor, Rabby, Coinbase Wallet, etc.) — same words, same
/// derivation, same addresses.
///
/// <para>
/// Storage shape:
/// <list type="bullet">
/// <item><c>recto.phone.eth.mnemonic.{alias}</c> — the 24-word BIP-39
/// mnemonic (canonical English wordlist), space-separated. Single
/// entry per alias, regardless of how many addresses are derived from
/// it.</item>
/// </list>
/// On every sign / GetAccount / EnsureMnemonic call, we read the
/// mnemonic, derive the seed (PBKDF2-HMAC-SHA512), derive the master
/// key + chain code (HMAC-SHA512), walk the BIP-32 path to the leaf,
/// produce the address. The whole derivation chain is in-memory and
/// every intermediate is wiped via <see cref="CryptographicOperations.ZeroMemory"/>
/// before the method returns.
/// </para>
///
/// <para>
/// Wave-4 breaks compatibility with the v0.5+ first-cut single-key
/// storage. Phones that only ever ran the first cut (single random
/// secp256k1 key per alias under <c>recto.phone.eth.{alias}</c>)
/// will, on first wave-4 sign, generate a fresh BIP-39 mnemonic and
/// derive a NEW address tree. The legacy single-key bytes stay in
/// SecureStorage as orphan entries until <see cref="ClearAsync"/> is
/// called; they're not used by any wave-4 code path. There's no
/// production data on the v0.5+ first cut (testnet-only dev
/// iteration), so this is acceptable. Document the migration in the
/// changelog so testers know their address has changed.
/// </para>
///
/// <para>
/// Threat model: the BIP-39 mnemonic IS the master secret. Possession
/// of the 24 words = control of every address derivable from them at
/// any path. The mnemonic lives in MAUI <c>SecureStorage</c> (iOS
/// Keychain on iOS / Android Keystore-encrypted prefs on Android /
/// Windows DPAPI on unpackaged Windows MAUI hosts). v0.6+ adds
/// biometric-gated mnemonic export for backup ceremony + biometric-
/// gated import for Ledger-style mnemonic recovery. v1.0 hardens the
/// per-sign biometric path so even local SecureStorage compromise
/// can't sign without a fresh biometric prompt.
/// </para>
/// </summary>
public sealed class MauiEthSignService : IEthSignService
{
    private const string MnemonicPrefix = "recto.phone.eth.mnemonic.";

    public async Task<Result<EthAccount>> EnsureMnemonicAsync(
        string alias,
        string derivationPath,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<EthAccount>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (string.IsNullOrWhiteSpace(derivationPath))
        {
            return Result.Failure<EthAccount>(Error.Validation([new ValidationErrors("derivationPath", "Derivation path is required.")]));
        }

        try
        {
            // Idempotent: read the existing mnemonic if present, otherwise
            // generate a fresh 24-word BIP-39 mnemonic and persist.
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                mnemonic = Bip39.GenerateMnemonic(wordCount: 24);
                await ResilientStorage
                    .SetAsync(MnemonicPrefix + alias, mnemonic)
                    .ConfigureAwait(false);
            }
            return DeriveAccount(mnemonic, derivationPath);
        }
        catch (Exception ex)
        {
            return Result.Failure<EthAccount>(Error.Failure(
                $"Failed to ensure ETH mnemonic for '{alias}': {ex.GetType().Name}: {ex.Message}"));
        }
    }

    public async Task<Result<EthAccount>> GetAccountAsync(
        string alias,
        string derivationPath,
        CancellationToken ct)
    {
        try
        {
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                return Result.Failure<EthAccount>(Error.NotFound(
                    $"No ETH mnemonic provisioned for '{alias}'."));
            }
            return DeriveAccount(mnemonic, derivationPath);
        }
        catch (Exception ex)
        {
            return Result.Failure<EthAccount>(Error.Failure(
                $"Failed to read ETH mnemonic for '{alias}': {ex.GetType().Name}: {ex.Message}"));
        }
    }

    public async Task<Result<bool>> ExistsAsync(string alias, CancellationToken ct)
    {
        try
        {
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            return Result.Success(!string.IsNullOrEmpty(mnemonic));
        }
        catch (Exception ex)
        {
            return Result.Failure<bool>(Error.Failure(
                $"Failed to check ETH mnemonic existence for '{alias}': {ex.Message}"));
        }
    }

    public async Task<Result<string>> SignPersonalSignAsync(
        string alias,
        string derivationPath,
        string message,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<string>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (message is null)
        {
            return Result.Failure<string>(Error.Validation([new ValidationErrors("message", "Message is required.")]));
        }

        byte[]? seed = null;
        Bip32.ExtendedKey? leaf = null;
        try
        {
            // Auto-provision on first sign so the operator's first ETH
            // request just works (matches the prior single-key behavior).
            // Subsequent calls re-read the persisted mnemonic.
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                var ensure = await EnsureMnemonicAsync(alias, derivationPath, ct).ConfigureAwait(false);
                if (ensure.IsFailure)
                {
                    return Result.Failure<string>(ensure.Error);
                }
                mnemonic = await ResilientStorage
                    .GetAsync(MnemonicPrefix + alias)
                    .ConfigureAwait(false);
                if (string.IsNullOrEmpty(mnemonic))
                {
                    return Result.Failure<string>(Error.Failure(
                        "EnsureMnemonicAsync succeeded but no mnemonic was persisted."));
                }
            }

            // Derive the per-path private key on the fly. No private-key
            // bytes are ever persisted — only the mnemonic is. This keeps
            // the storage surface small (one entry per alias regardless of
            // how many addresses you've derived) and means a SecureStorage
            // dump exposes the master secret cleanly rather than leaking
            // a constellation of addresses + their independent keys.
            seed = Bip39.MnemonicToSeed(mnemonic, passphrase: string.Empty);
            leaf = Bip32.DeriveAtPath(seed, derivationPath);

#if DEBUG
            // Sanity-check breadcrumb in Debug builds only: confirms the
            // BIP-39+BIP-32 derivation path is what's actually running.
            // If a future code change accidentally introduces a regression
            // that bypasses Bip39/Bip32 (e.g. someone adds a fast-path
            // that reads a cached priv key from disk), this line stops
            // appearing in the VS Output window during an ETH sign and
            // the regression is caught at the next dev iteration.
            System.Diagnostics.Debug.WriteLine(
                $"[Recto.MauiEthSignService] BIP-39+BIP-32 path. " +
                $"alias='{alias}' derivationPath='{derivationPath}' message-bytes={System.Text.Encoding.UTF8.GetByteCount(message)}");
#endif

            var msgHash = EthSigningOps.PersonalSignHash(message);
            var rsv = EthSigningOps.SignWithRecovery(msgHash, leaf.PrivateKey);
            return Result.Success("0x" + Convert.ToHexString(rsv).ToLowerInvariant());
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure(
                $"Failed to sign ETH personal_sign for '{alias}' at '{derivationPath}': {ex.GetType().Name}: {ex.Message}"));
        }
        finally
        {
            if (seed is not null) CryptographicOperations.ZeroMemory(seed);
            if (leaf is not null)
            {
                CryptographicOperations.ZeroMemory(leaf.PrivateKey);
                CryptographicOperations.ZeroMemory(leaf.ChainCode);
            }
        }
    }

    public async Task<Result<string>> SignTypedDataAsync(
        string alias,
        string derivationPath,
        string typedDataJson,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<string>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (string.IsNullOrWhiteSpace(typedDataJson))
        {
            return Result.Failure<string>(Error.Validation([new ValidationErrors("typedDataJson", "Typed-data JSON is required.")]));
        }

        byte[]? seed = null;
        Bip32.ExtendedKey? leaf = null;
        try
        {
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                var ensure = await EnsureMnemonicAsync(alias, derivationPath, ct).ConfigureAwait(false);
                if (ensure.IsFailure)
                {
                    return Result.Failure<string>(ensure.Error);
                }
                mnemonic = await ResilientStorage
                    .GetAsync(MnemonicPrefix + alias)
                    .ConfigureAwait(false);
                if (string.IsNullOrEmpty(mnemonic))
                {
                    return Result.Failure<string>(Error.Failure(
                        "EnsureMnemonicAsync succeeded but no mnemonic was persisted."));
                }
            }

            seed = Bip39.MnemonicToSeed(mnemonic, passphrase: string.Empty);
            leaf = Bip32.DeriveAtPath(seed, derivationPath);

            // EIP-712 produces a 32-byte digest. Sign with the same
            // secp256k1 + RFC-6979 + low-s primitive used for personal_sign;
            // the v byte is encoded as 27 + recid (canonical OZ / viem /
            // ethers shape, NOT raw recid like EIP-1559).
            var msgHash = EthSigningOps.TypedDataHash(typedDataJson);
            var rsv = EthSigningOps.SignWithRecovery(msgHash, leaf.PrivateKey);
            return Result.Success("0x" + Convert.ToHexString(rsv).ToLowerInvariant());
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure(
                $"Failed to sign EIP-712 typed-data for '{alias}' at '{derivationPath}': {ex.GetType().Name}: {ex.Message}"));
        }
        finally
        {
            if (seed is not null) CryptographicOperations.ZeroMemory(seed);
            if (leaf is not null)
            {
                CryptographicOperations.ZeroMemory(leaf.PrivateKey);
                CryptographicOperations.ZeroMemory(leaf.ChainCode);
            }
        }
    }

    public async Task<Result<string>> SignTransactionAsync(
        string alias,
        string derivationPath,
        string transactionJson,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<string>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (string.IsNullOrWhiteSpace(transactionJson))
        {
            return Result.Failure<string>(Error.Validation([new ValidationErrors("transactionJson", "Transaction JSON is required.")]));
        }

        byte[]? seed = null;
        Bip32.ExtendedKey? leaf = null;
        try
        {
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                var ensure = await EnsureMnemonicAsync(alias, derivationPath, ct).ConfigureAwait(false);
                if (ensure.IsFailure)
                {
                    return Result.Failure<string>(ensure.Error);
                }
                mnemonic = await ResilientStorage
                    .GetAsync(MnemonicPrefix + alias)
                    .ConfigureAwait(false);
                if (string.IsNullOrEmpty(mnemonic))
                {
                    return Result.Failure<string>(Error.Failure(
                        "EnsureMnemonicAsync succeeded but no mnemonic was persisted."));
                }
            }

            seed = Bip39.MnemonicToSeed(mnemonic, passphrase: string.Empty);
            leaf = Bip32.DeriveAtPath(seed, derivationPath);

            // SignAndEncodeTransactionEip1559 returns the FULL signed
            // raw-transaction bytes (0x02 || rlp([fields..., yParity, r, s]))
            // ready to hand to eth_sendRawTransaction. The consumer / smart
            // contract / RPC node verifies by recovering the signer from
            // the embedded yParity + r + s and checks chainId matches the
            // expected chain.
            var rawSigned = EthSigningOps.SignAndEncodeTransactionEip1559(transactionJson, leaf.PrivateKey);
            return Result.Success("0x" + Convert.ToHexString(rawSigned).ToLowerInvariant());
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure(
                $"Failed to sign EIP-1559 transaction for '{alias}' at '{derivationPath}': {ex.GetType().Name}: {ex.Message}"));
        }
        finally
        {
            if (seed is not null) CryptographicOperations.ZeroMemory(seed);
            if (leaf is not null)
            {
                CryptographicOperations.ZeroMemory(leaf.PrivateKey);
                CryptographicOperations.ZeroMemory(leaf.ChainCode);
            }
        }
    }

    public async Task<Result<byte[]>> SignDigestAsync(
        string alias,
        string derivationPath,
        byte[] digest,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<byte[]>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (digest is null || digest.Length != 32)
        {
            return Result.Failure<byte[]>(Error.Validation([new ValidationErrors(
                "digest",
                $"Digest must be exactly 32 bytes (SHA-256); got {digest?.Length ?? 0}.")]));
        }

        byte[]? seed = null;
        Bip32.ExtendedKey? leaf = null;
        try
        {
            // Auto-provision on first call so the operator's first
            // capability_request just works (matches SignPersonalSignAsync's
            // pattern). Same SecureStorage entry — one operator identity,
            // two surfaces.
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                var ensure = await EnsureMnemonicAsync(alias, derivationPath, ct).ConfigureAwait(false);
                if (ensure.IsFailure)
                {
                    return Result.Failure<byte[]>(ensure.Error);
                }
                mnemonic = await ResilientStorage
                    .GetAsync(MnemonicPrefix + alias)
                    .ConfigureAwait(false);
                if (string.IsNullOrEmpty(mnemonic))
                {
                    return Result.Failure<byte[]>(Error.Failure(
                        "EnsureMnemonicAsync succeeded but no mnemonic was persisted."));
                }
            }

            seed = Bip39.MnemonicToSeed(mnemonic, passphrase: string.Empty);
            leaf = Bip32.DeriveAtPath(seed, derivationPath);

            // SignWithRecovery returns 65 bytes (r||s||v); JWS ES256K
            // uses the 64-byte raw r||s. Slice off the v byte —
            // verifiers don't need the recovery hint because the
            // expected pubkey is known up-front (cfg.capability_operator_pubkey
            // bootloader-side, or pinned via JWT iss claim consumer-side).
            var rsv = EthSigningOps.SignWithRecovery(digest, leaf.PrivateKey);
            var rs = new byte[64];
            System.Buffer.BlockCopy(rsv, 0, rs, 0, 64);
            return Result.Success(rs);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[]>(Error.Failure(
                $"Failed to sign digest for '{alias}' at '{derivationPath}': {ex.GetType().Name}: {ex.Message}"));
        }
        finally
        {
            if (seed is not null) CryptographicOperations.ZeroMemory(seed);
            if (leaf is not null)
            {
                CryptographicOperations.ZeroMemory(leaf.PrivateKey);
                CryptographicOperations.ZeroMemory(leaf.ChainCode);
            }
        }
    }

    public async Task<Result<byte[]>> DerivePubkeyAtPathAsync(
        string alias,
        string derivationPath,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<byte[]>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (string.IsNullOrWhiteSpace(derivationPath))
        {
            return Result.Failure<byte[]>(Error.Validation([new ValidationErrors(
                "derivationPath", "Derivation path is required.")]));
        }

        byte[]? seed = null;
        Bip32.ExtendedKey? leaf = null;
        try
        {
            // Phase 2.0.C wave C.3: read-only public-key derivation. The
            // calling profile_create flow needs the child pubkey for the
            // canonical-JSON binding the master attestation signs over.
            // Same mnemonic-load pattern as SignDigestAsync; refuse to
            // operate if no mnemonic is provisioned (callers should call
            // EnsureMnemonicAsync first OR be called from a flow where
            // EnsureMnemonicAsync has already been invoked transitively
            // via SignDigestAsync's auto-provision path).
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                return Result.Failure<byte[]>(Error.Failure(
                    $"No mnemonic provisioned at alias '{alias}'. "
                    + "Call EnsureMnemonicAsync first, OR invoke any "
                    + "SignDigestAsync / SignPersonalSignAsync path "
                    + "(those auto-provision on first call)."));
            }

            seed = Bip39.MnemonicToSeed(mnemonic, passphrase: string.Empty);
            leaf = Bip32.DeriveAtPath(seed, derivationPath);
            var pubkey = EthSigningOps.PublicKeyFromPrivate(leaf.PrivateKey);
            return Result.Success(pubkey);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[]>(Error.Failure(
                $"Failed to derive pubkey for '{alias}' at "
                + $"'{derivationPath}': {ex.GetType().Name}: {ex.Message}"));
        }
        finally
        {
            if (seed is not null) CryptographicOperations.ZeroMemory(seed);
            if (leaf is not null)
            {
                CryptographicOperations.ZeroMemory(leaf.PrivateKey);
                CryptographicOperations.ZeroMemory(leaf.ChainCode);
            }
        }
    }

    public Task<Result> ClearAsync(string alias, CancellationToken ct)
    {
        try
        {
            ResilientStorage.Remove(MnemonicPrefix + alias);
            // Also clear any orphan v0.5+-first-cut single-key entry under
            // the legacy storage key so a re-pair with `ClearAsync` then
            // `EnsureMnemonicAsync` leaves zero ETH-related state behind.
            ResilientStorage.Remove("recto.phone.eth." + alias);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(Error.Failure(
                $"Failed to clear ETH mnemonic for '{alias}': {ex.Message}")));
        }
    }

    public async Task<Result<string>> ExportMnemonicAsync(string alias, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<string>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        try
        {
            // Bare read — keychain/keystore-protected at rest. The biometric
            // gate is the CALLER's (Settings backup ceremony fires
            // EnclaveKeys.SignAsync immediately before this; see the interface
            // doc's SECURITY note). We do NOT re-prompt here.
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                return Result.Failure<string>(Error.NotFound(
                    $"No mnemonic provisioned for alias '{alias}'."));
            }
            return Result.Success(mnemonic);
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure(
                $"Failed to export mnemonic for '{alias}': {ex.Message}"));
        }
    }

    public async Task<Result<EthAccount>> ImportMnemonicAsync(
        string alias,
        string mnemonic,
        string derivationPath,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<EthAccount>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (string.IsNullOrWhiteSpace(derivationPath))
        {
            return Result.Failure<EthAccount>(Error.Validation([new ValidationErrors("derivationPath", "Derivation path is required.")]));
        }

        // Normalize: BIP-39 phrases are lowercase, single-space-separated. A
        // paste from another wallet often carries newlines / double spaces /
        // stray casing — clean before validating so a valid phrase isn't
        // rejected on formatting alone.
        var normalized = string.Join(' ',
            (mnemonic ?? string.Empty)
                .Trim()
                .ToLowerInvariant()
                .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

        if (!Bip39.ValidateMnemonic(normalized))
        {
            return Result.Failure<EthAccount>(Error.Validation(
                [new ValidationErrors("mnemonic",
                    "That recovery phrase isn't valid — check the words and their order.")]));
        }

        // Derive BEFORE persisting so a derivation failure never clobbers the
        // existing mnemonic (destructive overwrite only after we know the
        // phrase produces a usable account).
        var derived = DeriveAccount(normalized, derivationPath);
        if (derived.IsFailure) return derived;

        try
        {
            await ResilientStorage
                .SetAsync(MnemonicPrefix + alias, normalized)
                .ConfigureAwait(false);
            // Drop any cached first-cut single-key entry so the next sign
            // re-derives from the freshly-imported seed (sister of ClearAsync).
            ResilientStorage.Remove("recto.phone.eth." + alias);
            return derived;
        }
        catch (Exception ex)
        {
            return Result.Failure<EthAccount>(Error.Failure(
                $"Failed to store imported mnemonic for '{alias}': {ex.Message}"));
        }
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    /// <summary>
    /// Derive the public address at <paramref name="derivationPath"/>
    /// from a stored mnemonic. Internal helper shared between
    /// <see cref="EnsureMnemonicAsync"/> and <see cref="GetAccountAsync"/>.
    /// All intermediate secrets (seed, BIP-32 leaf private key) are
    /// wiped before the method returns.
    /// </summary>
    private static Result<EthAccount> DeriveAccount(string mnemonic, string derivationPath)
    {
        byte[]? seed = null;
        Bip32.ExtendedKey? leaf = null;
        try
        {
            seed = Bip39.MnemonicToSeed(mnemonic, passphrase: string.Empty);
            leaf = Bip32.DeriveAtPath(seed, derivationPath);
            var pub = EthSigningOps.PublicKeyFromPrivate(leaf.PrivateKey);
            var address = EthSigningOps.AddressFromPublicKey(pub);
            return Result.Success(new EthAccount(derivationPath, address));
        }
        catch (Exception ex)
        {
            return Result.Failure<EthAccount>(Error.Failure(
                $"BIP-32 derivation failed at '{derivationPath}': {ex.GetType().Name}: {ex.Message}"));
        }
        finally
        {
            if (seed is not null) CryptographicOperations.ZeroMemory(seed);
            if (leaf is not null)
            {
                CryptographicOperations.ZeroMemory(leaf.PrivateKey);
                CryptographicOperations.ZeroMemory(leaf.ChainCode);
            }
        }
    }
}
