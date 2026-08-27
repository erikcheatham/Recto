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
/// MAUI <c>SecureStorage</c>-backed Bitcoin signing service. Reads the
/// SAME BIP-39 mnemonic from <c>SecureStorage</c> as
/// <see cref="MauiEthSignService"/> (one mnemonic per phone, two
/// BIP-44 trees) and derives secp256k1 keypairs at native-SegWit
/// paths (<c>m/84'/0'/0'/0/N</c> default). Signs BIP-137 message-
/// signing payloads with deterministic-k ECDSA + v-recovery, returns
/// 65-byte BIP-137 compact signatures base64-encoded.
///
/// <para>
/// Storage key shape: <c>recto.phone.eth.mnemonic.{alias}</c> — yes,
/// "eth" in the name is misleading post-wave-5 (the mnemonic now
/// powers BOTH credential kinds), but renaming it would be a breaking
/// change for already-paired phones. v0.6+ refactor will introduce a
/// vault-namespaced storage key (<c>recto.phone.vault.mnemonic.*</c>)
/// and migrate the legacy entry transparently. For today, the
/// "eth.mnemonic" prefix is the canonical home; both ETH and BTC
/// services read it, neither owns it exclusively.
/// </para>
///
/// <para>
/// Threat model is identical to <see cref="MauiEthSignService"/>. The
/// mnemonic IS the master secret; possession of the 24 words = control
/// of every address derivable from them at any path under any coin.
/// One backup ceremony covers both coin trees. Per-sign biometric
/// gating + capability-JWT delegation for agent flows applies
/// uniformly.
/// </para>
/// </summary>
public sealed class MauiBtcSignService : IBtcSignService
{
    // SAME storage prefix as MauiEthSignService — both services share
    // the mnemonic. Storage key for alias "default" is
    // "recto.phone.eth.mnemonic.default".
    private const string MnemonicPrefix = "recto.phone.eth.mnemonic.";

    public async Task<Result<BtcAccount>> EnsureMnemonicAsync(
        string alias,
        string derivationPath,
        string network,
        string coin,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<BtcAccount>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (string.IsNullOrWhiteSpace(derivationPath))
        {
            return Result.Failure<BtcAccount>(Error.Validation([new ValidationErrors("derivationPath", "Derivation path is required.")]));
        }
        if (string.IsNullOrWhiteSpace(network))
        {
            return Result.Failure<BtcAccount>(Error.Validation([new ValidationErrors("network", "Network is required.")]));
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
            return DeriveAccount(mnemonic, derivationPath, network, coin);
        }
        catch (Exception ex)
        {
            return Result.Failure<BtcAccount>(Error.Failure(
                $"Failed to ensure BTC mnemonic for '{alias}': {ex.GetType().Name}: {ex.Message}"));
        }
    }

    public async Task<Result<BtcAccount>> GetAccountAsync(
        string alias,
        string derivationPath,
        string network,
        string coin,
        CancellationToken ct)
    {
        try
        {
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                return Result.Failure<BtcAccount>(Error.NotFound(
                    $"No BIP-39 mnemonic provisioned for '{alias}'."));
            }
            return DeriveAccount(mnemonic, derivationPath, network, coin);
        }
        catch (Exception ex)
        {
            return Result.Failure<BtcAccount>(Error.Failure(
                $"Failed to read BTC mnemonic for '{alias}': {ex.GetType().Name}: {ex.Message}"));
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
                $"Failed to check BTC mnemonic existence for '{alias}': {ex.Message}"));
        }
    }

    public async Task<Result<string>> SignMessageAsync(
        string alias,
        string derivationPath,
        string network,
        string coin,
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
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                var ensure = await EnsureMnemonicAsync(alias, derivationPath, network, coin, ct).ConfigureAwait(false);
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

            // Coin-aware on BOTH layers:
            //   (1) preamble -- SignedMessageHash(message, coin) picks
            //       the right "X Signed Message:\n" magic per coin
            //       (BTC/BCH share Bitcoin's; LTC + DOGE have their own).
            //   (2) BIP-137 header byte -- SignCompactBip137(_, _, coin)
            //       picks the right address-kind range. P2WPKH (39..42)
            //       for BTC + LTC; P2PKH compressed (31..34) for DOGE +
            //       BCH because those coins have no bech32 HRP and the
            //       verifier would otherwise refuse to encode the
            //       recovered hash160 as a SegWit address. See the
            //       "BIP-137 header byte must dispatch on coin" gotcha
            //       in CLAUDE.md (banked retroactively after wave-7
            //       smoke on the test device, 2026-04-30).
            var msgHash = BtcSigningOps.SignedMessageHash(message, coin);
            var compactSig = BtcSigningOps.SignCompactBip137(msgHash, leaf.PrivateKey, coin);

#if DEBUG
            // Sanity-check breadcrumb in Debug builds. Same pattern as
            // MauiEthSignService — confirms the BIP-39+BIP-32+BIP-137
            // derivation path is what's actually running. If a future
            // code change accidentally bypasses this path (e.g. a
            // fast-path that reads a cached priv key from disk), this
            // line stops appearing and the regression is caught at the
            // next dev iteration.
            System.Diagnostics.Debug.WriteLine(
                $"[Recto.MauiBtcSignService] BIP-39+BIP-32+BIP-137 path. " +
                $"alias='{alias}' coin='{coin}' derivationPath='{derivationPath}' network='{network}' message-bytes={System.Text.Encoding.UTF8.GetByteCount(message)}");
#endif

            return Result.Success(Convert.ToBase64String(compactSig));
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure(
                $"Failed to sign BTC message for '{alias}' at '{derivationPath}': {ex.GetType().Name}: {ex.Message}"));
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
            // Same key as MauiEthSignService — clears both services'
            // mnemonic in one call. Future v0.6+ vault-namespaced
            // refactor will move this to a unified ClearVaultAsync.
            ResilientStorage.Remove(MnemonicPrefix + alias);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(Error.Failure(
                $"Failed to clear BTC mnemonic for '{alias}': {ex.Message}")));
        }
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    private static Result<BtcAccount> DeriveAccount(string mnemonic, string derivationPath, string network, string coin)
    {
        byte[]? seed = null;
        Bip32.ExtendedKey? leaf = null;
        try
        {
            seed = Bip39.MnemonicToSeed(mnemonic, passphrase: string.Empty);
            leaf = Bip32.DeriveAtPath(seed, derivationPath);
            var pub = EthSigningOps.PublicKeyFromPrivate(leaf.PrivateKey);
            // Coin-aware dispatch. BTC + LTC default to P2WPKH (native
            // SegWit, BIP-84 path). DOGE + BCH default to P2PKH (legacy,
            // BIP-44 path) since neither chain widely adopted SegWit.
            // The coin's BtcCoinConfig.DefaultAddressKind picks which.
            // Operators wanting a non-default kind would set kind
            // explicitly via a future API extension.
            var cfg = BtcSigningOps.GetCoinConfig(coin);
            var address = BtcSigningOps.AddressFromPublicKey(pub, network, kind: null, coin: coin);
            return Result.Success(new BtcAccount(derivationPath, address, network, cfg.DefaultAddressKind));
        }
        catch (Exception ex)
        {
            return Result.Failure<BtcAccount>(Error.Failure(
                $"BIP-32 derivation failed at '{derivationPath}' for coin '{coin}': {ex.GetType().Name}: {ex.Message}"));
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
