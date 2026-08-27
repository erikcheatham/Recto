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
/// MAUI <see cref="SecureStorage"/>-backed ed25519-chain signing
/// service for SOL / XLM / XRP-ed25519. Reads the SAME BIP-39
/// mnemonic from <c>SecureStorage</c> as <see cref="MauiEthSignService"/>
/// and <see cref="MauiBtcSignService"/> (one mnemonic per phone,
/// multiple curve trees) and derives ed25519 keypairs at chain-
/// specific SLIP-0010 paths via <see cref="Slip10"/>.
///
/// <para>
/// Storage key shape: <c>recto.phone.eth.mnemonic.{alias}</c> — same
/// prefix the eth/btc services use. Renaming would be a breaking
/// change for already-paired phones. v0.6+ refactor will namespace
/// it as <c>recto.phone.vault.mnemonic.*</c> with transparent
/// migration. For today, the "eth.mnemonic" prefix is the canonical
/// home; ETH, BTC, and ED chains all read it.
/// </para>
///
/// <para>
/// Threat model identical to <see cref="MauiEthSignService"/> /
/// <see cref="MauiBtcSignService"/>: mnemonic IS the master secret;
/// possession of the 24 words = control of every address derivable
/// from them at any path under any coin family. One backup ceremony
/// covers all eight chain coin families now (ETH + BTC + LTC + DOGE
/// + BCH + SOL + XLM + XRP). Per-sign biometric gating + capability-
/// JWT delegation for agent flows applies uniformly.
/// </para>
///
/// <para>
/// Critical: SLIP-0010 ed25519 derivation is HARDENED-ONLY. The
/// chain-default paths are all-hardened; per-account multi-account
/// flows should override the leaf segment to a different hardened
/// index, not switch to non-hardened.
/// </para>
/// </summary>
public sealed class MauiEd25519ChainSignService : IEd25519ChainSignService
{
    // SAME storage prefix as MauiEthSignService / MauiBtcSignService
    // — all three services share the mnemonic. Storage key for alias
    // "default" is "recto.phone.eth.mnemonic.default".
    private const string MnemonicPrefix = "recto.phone.eth.mnemonic.";

    public async Task<Result<EdAccount>> EnsureMnemonicAsync(
        string alias,
        string chain,
        string derivationPath,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<EdAccount>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (string.IsNullOrWhiteSpace(chain))
        {
            return Result.Failure<EdAccount>(Error.Validation([new ValidationErrors("chain", "Chain is required.")]));
        }
        if (string.IsNullOrWhiteSpace(derivationPath))
        {
            return Result.Failure<EdAccount>(Error.Validation([new ValidationErrors("derivationPath", "Derivation path is required.")]));
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
            return DeriveAccount(mnemonic, chain, derivationPath);
        }
        catch (Exception ex)
        {
            return Result.Failure<EdAccount>(Error.Failure(
                $"Failed to ensure ED mnemonic for '{alias}': {ex.GetType().Name}: {ex.Message}"));
        }
    }

    public async Task<Result<EdAccount>> GetAccountAsync(
        string alias,
        string chain,
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
                return Result.Failure<EdAccount>(Error.NotFound(
                    $"No BIP-39 mnemonic provisioned for '{alias}'."));
            }
            return DeriveAccount(mnemonic, chain, derivationPath);
        }
        catch (Exception ex)
        {
            return Result.Failure<EdAccount>(Error.Failure(
                $"Failed to read ED mnemonic for '{alias}': {ex.GetType().Name}: {ex.Message}"));
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
                $"Failed to check ED mnemonic existence for '{alias}': {ex.Message}"));
        }
    }

    public async Task<Result<EdSignResult>> SignMessageAsync(
        string alias,
        string chain,
        string derivationPath,
        string message,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure<EdSignResult>(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (message is null)
        {
            return Result.Failure<EdSignResult>(Error.Validation([new ValidationErrors("message", "Message is required.")]));
        }

        byte[]? seed = null;
        Slip10.ExtendedKey? leaf = null;
        try
        {
            var mnemonic = await ResilientStorage
                .GetAsync(MnemonicPrefix + alias)
                .ConfigureAwait(false);
            if (string.IsNullOrEmpty(mnemonic))
            {
                var ensure = await EnsureMnemonicAsync(alias, chain, derivationPath, ct).ConfigureAwait(false);
                if (ensure.IsFailure)
                {
                    return Result.Failure<EdSignResult>(ensure.Error);
                }
                mnemonic = await ResilientStorage
                    .GetAsync(MnemonicPrefix + alias)
                    .ConfigureAwait(false);
                if (string.IsNullOrEmpty(mnemonic))
                {
                    return Result.Failure<EdSignResult>(Error.Failure(
                        "EnsureMnemonicAsync succeeded but no mnemonic was persisted."));
                }
            }

            seed = Bip39.MnemonicToSeed(mnemonic, passphrase: string.Empty);
            // SignMessage internally derives + signs + wipes the leaf.
            // We re-derive here so we can also surface the public key
            // (the chain-specific verifier needs it for XRP).
            leaf = Slip10.DeriveAtPath(seed, derivationPath);
            var pub = Slip10.GetPublicKey(leaf.PrivateKey);
            var sig = Ed25519ChainSigningOps.SignMessage(seed, derivationPath, message, chain);

#if DEBUG
            // Sanity-check breadcrumb in Debug builds. If a future code
            // change accidentally bypasses this path (e.g. a fast-path
            // that reads a cached priv key from disk), this line stops
            // appearing and the regression is caught at the next dev
            // iteration.
            System.Diagnostics.Debug.WriteLine(
                $"[Recto.MauiEd25519ChainSignService] BIP-39+SLIP-0010+ed25519 path. " +
                $"alias='{alias}' chain='{chain}' derivationPath='{derivationPath}' " +
                $"message-bytes={System.Text.Encoding.UTF8.GetByteCount(message)}");
#endif

            return Result.Success(new EdSignResult(
                SignatureBase64: Convert.ToBase64String(sig),
                PublicKeyHex: Convert.ToHexString(pub).ToLowerInvariant()));
        }
        catch (Exception ex)
        {
            return Result.Failure<EdSignResult>(Error.Failure(
                $"Failed to sign ED message for '{alias}' at '{derivationPath}' on chain '{chain}': {ex.GetType().Name}: {ex.Message}"));
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
            // Same key as MauiEthSignService / MauiBtcSignService —
            // clears all three services' mnemonic in one call. Future
            // v0.6+ vault-namespaced refactor will move this to a
            // unified ClearVaultAsync.
            ResilientStorage.Remove(MnemonicPrefix + alias);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(Error.Failure(
                $"Failed to clear ED mnemonic for '{alias}': {ex.Message}")));
        }
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    private static Result<EdAccount> DeriveAccount(string mnemonic, string chain, string derivationPath)
    {
        byte[]? seed = null;
        Slip10.ExtendedKey? leaf = null;
        try
        {
            seed = Bip39.MnemonicToSeed(mnemonic, passphrase: string.Empty);
            leaf = Slip10.DeriveAtPath(seed, derivationPath);
            var pub = Slip10.GetPublicKey(leaf.PrivateKey);
            var address = Ed25519ChainSigningOps.AddressFromPublicKey(pub, chain);
            return Result.Success(new EdAccount(
                Chain: chain,
                DerivationPath: derivationPath,
                Address: address,
                PublicKeyHex: Convert.ToHexString(pub).ToLowerInvariant()));
        }
        catch (Exception ex)
        {
            return Result.Failure<EdAccount>(Error.Failure(
                $"SLIP-0010 derivation failed at '{derivationPath}' for chain '{chain}': {ex.GetType().Name}: {ex.Message}"));
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
