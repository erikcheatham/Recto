namespace Recto.Shared.Models;

/// <summary>
/// One Ethereum account derived from the phone-resident BIP39 mnemonic.
/// Lightweight value object surfaced from <c>IEthSignService</c> at
/// mnemonic-create time and address-lookup time. The mnemonic itself
/// never leaves the phone's <c>SecureStorage</c>; only the public
/// derivation (path + address) crosses any service boundary.
/// </summary>
/// <param name="DerivationPath">
/// BIP32/BIP44 path the address was derived at, e.g.
/// <c>m/44'/60'/0'/0/0</c> for the default Ethereum account.
/// </param>
/// <param name="Address">
/// 0x-prefixed lowercase 40-char hex address (no EIP-55 mixed-case
/// checksum &mdash; canonical comparison form). The Ethereum address
/// is the last 20 bytes of <c>keccak256(uncompressed_pubkey64)</c>.
/// </param>
public sealed record EthAccount(
    string DerivationPath,
    string Address);
