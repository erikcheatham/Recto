namespace Recto.Shared.Models;

/// <summary>
/// One Bitcoin account derived from the phone-resident BIP-39
/// mnemonic. Lightweight value object surfaced from
/// <c>IBtcSignService</c> at mnemonic-create time and address-lookup
/// time. The mnemonic itself never leaves the phone's
/// <c>SecureStorage</c>; only the public derivation (path + address +
/// network) crosses any service boundary.
/// </summary>
/// <param name="DerivationPath">
/// BIP32/BIP44 path the address was derived at, e.g.
/// <c>m/84'/0'/0'/0/0</c> for the default native-SegWit Bitcoin
/// account. The purpose level (<c>44'</c> / <c>49'</c> / <c>84'</c>)
/// determines the address kind: 44' for legacy P2PKH, 49' for nested
/// SegWit P2SH-P2WPKH, 84' for native SegWit P2WPKH.
/// </param>
/// <param name="Address">
/// Bitcoin address string. P2WPKH is bech32 (<c>bc1q...</c> on
/// mainnet, <c>tb1q...</c> on testnet). P2PKH is Base58Check
/// (<c>1...</c> / <c>m...</c> / <c>n...</c>). P2SH-P2WPKH is
/// Base58Check (<c>3...</c> / <c>2...</c>).
/// </param>
/// <param name="Network">
/// One of <c>"mainnet"</c>, <c>"testnet"</c>, <c>"signet"</c>,
/// <c>"regtest"</c>. Determines the bech32 HRP / Base58Check version
/// byte, so the same private key produces different address strings
/// per network.
/// </param>
/// <param name="AddressKind">
/// One of <c>"p2wpkh"</c> (default), <c>"p2pkh"</c>,
/// <c>"p2sh-p2wpkh"</c>. Surfaced explicitly so the operator UI can
/// show the address type alongside the value.
/// </param>
public sealed record BtcAccount(
    string DerivationPath,
    string Address,
    string Network,
    string AddressKind);
