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
/// MAUI <c>SecureStorage</c>-backed TRON signing service. Wave 9 part 2.
/// Stores nothing of its own -- reuses the SAME 24-word BIP-39
/// mnemonic that <see cref="MauiEthSignService"/> /
/// <see cref="MauiBtcSignService"/> /
/// <see cref="MauiEd25519ChainSignService"/> already provision under
/// <c>recto.phone.eth.mnemonic.{alias}</c>. One mnemonic, nine chain
/// trees (ETH, BTC, LTC, DOGE, BCH, SOL, XLM, XRP, TRON).
///
/// <para>
/// On every sign / GetAccount / EnsureMnemonic call, we read the
/// mnemonic, derive the seed (PBKDF2-HMAC-SHA512), derive the master
/// key + chain code (HMAC-SHA512), walk the BIP-32 path
/// <c>m/44'/195'/0'/0/N</c> to the leaf, produce the address. The
/// whole derivation chain is in-memory and every intermediate is
/// wiped via <see cref="CryptographicOperations.ZeroMemory"/> before
/// the method returns.
/// </para>
///
/// <para>
/// TRON shares secp256k1 + Keccak-256 with Ethereum byte-for-byte;
/// the signer is literally <see cref="EthSigningOps.SignWithRecovery"/>
/// composed with the TIP-191 hash from
/// <see cref="TronSigningOps.SignedMessageHash"/>. Address derivation
/// reuses <see cref="EthSigningOps.Keccak256"/> on the uncompressed
/// pubkey and slices off the same last 20 bytes Ethereum would --
/// only the version byte (0x41) and encoding (base58check vs EIP-55
/// hex) differ. Output of <see cref="SignMessageAsync"/> is the
/// canonical 65-byte <c>r||s||v</c> with v in {27, 28} that TronWeb's
/// <c>verifyMessageV2</c> accepts.
/// </para>
///
/// <para>
/// Mnemonic lifecycle: <see cref="EnsureMnemonicAsync"/> is the
/// idempotent provision call (creates a fresh mnemonic if absent,
/// reads the existing entry otherwise). <see cref="ClearAsync"/> wipes
/// the SecureStorage entry. NOTE: clearing TRON's alias also clears
/// it for ETH / BTC / ED -- they share the same key. Document
/// clearly in the operator UI before invoking.
/// </para>
/// </summary>
public sealed class MauiTronSignService : ITronSignService
{
    private const string MnemonicPrefix = "recto.phone.eth.mnemonic.";

    public async Task<Result<TronAccount>> EnsureMnemonicAsync(
        string alias,
        string derivationPath,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<TronAccount>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (string.IsNullOrWhiteSpace(derivationPath))
        {
            return Result.Failure<TronAccount>(Error.Validation([new ValidationErrors("derivationPath", "Derivation path is required.")]));
        }

        try
        {
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
            return Result.Failure<TronAccount>(Error.Failure(
                $"Failed to ensure TRON mnemonic for '{alias}': {ex.GetType().Name}: {ex.Message}"));
        }
    }

    public async Task<Result<TronAccount>> GetAccountAsync(
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
                return Result.Failure<TronAccount>(Error.NotFound(
                    $"No mnemonic provisioned for '{alias}'."));
            }
            return DeriveAccount(mnemonic, derivationPath);
        }
        catch (Exception ex)
        {
            return Result.Failure<TronAccount>(Error.Failure(
                $"Failed to read mnemonic for TRON alias '{alias}': {ex.GetType().Name}: {ex.Message}"));
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
                $"Failed to check TRON mnemonic existence for '{alias}': {ex.Message}"));
        }
    }

    public async Task<Result<string>> SignMessageAsync(
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
            // Auto-provision on first sign so the operator's first TRON
            // request just works (matches the prior single-key behavior
            // and the parallel ETH/BTC/ED services).
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

#if DEBUG
            // Sanity-check breadcrumb in Debug builds. Same lane-tagged
            // shape as the ETH/BTC services so the VS Output window
            // shows which derivation path is actually running. If a
            // future regression bypasses Bip39/Bip32 for TRON, this
            // line stops appearing and the test reveals the bug.
            System.Diagnostics.Debug.WriteLine(
                $"[Recto.MauiTronSignService] BIP-39+BIP-32+TIP-191 path. " +
                $"alias='{alias}' derivationPath='{derivationPath}' " +
                $"message-bytes={System.Text.Encoding.UTF8.GetByteCount(message)}");
#endif

            // TIP-191 hash + secp256k1 + RFC 6979 signing. The signer
            // delegates to EthSigningOps.SignWithRecovery -- both chains
            // share the same secp256k1 curve and v-recovery pipeline.
            var msgHash = TronSigningOps.SignedMessageHash(message);
            var rsv = TronSigningOps.SignWithRecovery(msgHash, leaf.PrivateKey);
            return Result.Success("0x" + Convert.ToHexString(rsv).ToLowerInvariant());
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure(
                $"Failed to sign TRON message for '{alias}' at '{derivationPath}': {ex.GetType().Name}: {ex.Message}"));
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

    public async Task<Result> ClearAsync(string alias, CancellationToken ct)
    {
        try
        {
            // Same shared SecureStorage entry as ETH / BTC / ED services.
            // Removing it here removes the mnemonic for all four chain
            // families. Operator-UI should display a confirmation modal
            // before invoking this in any non-emergency context.
            ResilientStorage.Remove(MnemonicPrefix + alias);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(Error.Failure(
                $"Failed to clear mnemonic for TRON alias '{alias}': {ex.Message}"));
        }
    }

    private static Result<TronAccount> DeriveAccount(string mnemonic, string derivationPath)
    {
        byte[]? seed = null;
        Bip32.ExtendedKey? leaf = null;
        try
        {
            seed = Bip39.MnemonicToSeed(mnemonic, passphrase: string.Empty);
            leaf = Bip32.DeriveAtPath(seed, derivationPath);
            // 64-byte uncompressed pubkey (X || Y, no 0x04 prefix) --
            // identical shape to Ethereum's, since both share secp256k1.
            var pub64 = EthSigningOps.PublicKeyFromPrivate(leaf.PrivateKey);
            var address = TronSigningOps.AddressFromPublicKey(pub64);
            return Result.Success(new TronAccount(derivationPath, address));
        }
        catch (Exception ex)
        {
            return Result.Failure<TronAccount>(Error.Failure(
                $"BIP-32 derivation failed for TRON path '{derivationPath}': {ex.Message}"));
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
