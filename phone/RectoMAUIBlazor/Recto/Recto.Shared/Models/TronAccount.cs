namespace Recto.Shared.Models;

/// <summary>
/// One TRON account derived from the phone-resident BIP-39 mnemonic.
/// Lightweight value object surfaced from <c>ITronSignService</c> at
/// mnemonic-create time and address-lookup time. The mnemonic itself
/// never leaves the phone's <c>SecureStorage</c>; only the public
/// derivation (path + address) crosses any service boundary.
/// </summary>
/// <param name="DerivationPath">
/// BIP-32/BIP-44 path the address was derived at, e.g.
/// <c>m/44'/195'/0'/0/0</c> for the default TRON account
/// (SLIP-0044 coin-type 195).
/// </param>
/// <param name="Address">
/// 34-char base58check address starting with <c>T</c> for TRON
/// mainnet (version byte <c>0x41</c>). The address is
/// <c>base58check(0x41 || keccak256(uncompressed_pubkey64)[-20:])</c> --
/// the 20-byte hash160-equivalent is identical to the Ethereum
/// address derivation; only the version byte and encoding differ.
/// TRON's testnets (Shasta, Nile) share the same version byte and
/// produce the same <c>T...</c> visual prefix.
/// </param>
public sealed record TronAccount(
    string DerivationPath,
    string Address);
