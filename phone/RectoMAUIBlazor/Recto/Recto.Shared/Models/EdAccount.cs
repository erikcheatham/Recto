namespace Recto.Shared.Models;

/// <summary>
/// One ed25519-chain account derived from the phone-resident BIP39
/// mnemonic via SLIP-0010. Lightweight value object surfaced from
/// <c>IEd25519ChainSignService</c> at mnemonic-create time and
/// address-lookup time. The mnemonic itself never leaves the phone's
/// <c>SecureStorage</c>; only the public derivation (chain + path +
/// address + pubkey-hex) crosses any service boundary.
/// </summary>
/// <param name="Chain">
/// Chain key — <c>"sol"</c>, <c>"xlm"</c>, or <c>"xrp"</c>. Selects
/// per-chain default path / address encoding / message preamble.
/// </param>
/// <param name="DerivationPath">
/// SLIP-0010 path the address was derived at. Per-chain canonical
/// defaults (all hardened, since SLIP-0010 ed25519 doesn't support
/// non-hardened derivation): SOL <c>m/44'/501'/0'/0'</c>, XLM
/// <c>m/44'/148'/0'</c>, XRP-ed25519 <c>m/44'/144'/0'/0'/0'</c>.
/// </param>
/// <param name="Address">
/// Chain-encoded address. SOL: <c>base58(pubkey32)</c> with no
/// checksum (32–44 chars). XLM: StrKey <c>G…</c> (56 chars). XRP:
/// classic <c>r…</c> address (25–35 chars, Base58Check of HASH160
/// with 0xED ed25519 prefix on pubkey pre-image).
/// </param>
/// <param name="PublicKeyHex">
/// 32-byte ed25519 public key as 64 lowercase hex chars (no 0x
/// prefix). Required because XRP addresses are HASH160s and don't
/// carry the pubkey; SOL and XLM addresses ARE invertible but the
/// pubkey is surfaced here for protocol uniformity across the three
/// chains. The phone returns this on the wire as
/// <c>RespondRequest.EdPubkeyHex</c>.
/// </param>
public sealed record EdAccount(
    string Chain,
    string DerivationPath,
    string Address,
    string PublicKeyHex);
