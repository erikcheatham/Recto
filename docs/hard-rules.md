# Recto — Hard Rules

Non-negotiable constraints on substrate code. Read before authoring.

**This registry is the CONTRACT: what an integrator can rely on the substrate
to do, and what it will never do.** Rules governing how any particular operator
runs their own deployment are not contract, and are not here.

**Numbers are stable anchors and are never renumbered** — source across this
repo cites them, so a gap is deliberate and reusing one would silently
re-point every citation. The gaps are rules that turned out to govern an
operator's own tooling rather than this substrate; they were removed rather
than renumbered.

Every rule cited anywhere in this repository is declared here. A citation to
a number this file does not carry is a bug — it points at a registry the
reader has no access to, which is worse than no citation at all.

---

**1. The YAML schema is additive only.** `apiVersion: recto/v1` is locked. No
renames, no field removals; two minor versions of deprecation before anything
goes. A v2 schema lives *alongside* v1, never in place of it. Deployed config
outlives the release that read it.

**2. Secrets are never logged, serialized, or echoed in stack traces.** A
secret value is consumed immediately and never held in a longer-lived object
than necessary. `SecretMaterial.__repr__` returns `<redacted>`. Any new path
handling secret values follows the same convention.

**3. Apache 2.0, and the substrate stays free.** No commercial-only features in
`recto-core`. Hardware-enclave backends may be a separate paid offering; the
substrate is not.

**4. The launcher path is single-file-runnable.** `python -m recto launch
<yaml>` works after `pip install recto` and nothing else. No daemon, no central
registry, no prerequisite database.

**5. Recto is wrapped by the Windows service registrar, not the reverse.** The
registrar's application parameter points at `python -m recto launch`. Absorbing
registration natively is allowed only with a documented migration path.

**6. The `SecretSource` ABC is the public API contract.** A new backend must not
require changes to `recto.launcher` or to any consumer's `service.yaml` beyond
the `source:` selector. Backends declare themselves; the launcher stays generic.

**9. The phone enclave is the root of trust; agents inherit from humans.** Each
new credential type adds a `PendingRequest.kind` and reuses the operator-gated
phone-side primitive. Agents never get direct phone-side access and never
bypass approval — they act only via operator-issued, scoped, time-bounded
capabilities. **No flow may let an agent act past its capability's expiry,
exceed its scope, or persist after revocation.**

**10. Runtime architecture and packaging architecture are separate concerns.**
Recto ships as `recto-core` (substrate), `recto-client-{py,ts,cs}` (agent
SDKs), and the phone app. Three audiences, three channels. Ask which package a
feature belongs in before shaping the implementation.

**13. The artifact is the canonical record, not a ledger row.** Signed payloads
— capability JWS, pairing JWS, multi-witness contracts — are portable: the
bytes themselves are the record. Transports (HTTP, folder drop, QR) are
interchangeable serializations of the same payload. **Verification must never
require any particular runtime to still be alive.**

**14. The key is the identity.** A phone IS its enclave keypair. Its reference
is `phone_ref` — `"pk_" + sha256(raw public key)[:16]` — derivable by anyone
who holds the public key and usable as a credential by no one. This governs
six things:

1. **`phone_ref` names the phone; nothing else does.** A registration's
   `phone_id` IS its `phone_ref`. The registry mints no other identifier.
2. **Every crossing is a signature by that key over what crossed** — poll,
   pending read, manage reads, approve/deny, pair, unpair, attest
   (`X-Recto-Phone-Sig` / `X-Recto-Phone-Ts`). `signed_poll_mode` moves
   `advisory → required` by the ceremony the substrate names: advisory,
   an evidence window of logged per-poll verdicts, the flip, one redeploy.
   After the flip a bare `?phone_id=` query authenticates nothing. Reads
   (poll, pending, manage) are signed by a **poll key**: a second
   enclave-resident key with no user-presence requirement, delegated at
   registration by the identity key's signature over
   `recto-poll-key-v1|{identity pubkey}|{poll pubkey}`. A registration
   without a delegated poll key does not enroll. The poll key authenticates
   the device; it never signs an approval, and the identity key never signs
   a read. Ahead of the flip, `/v0.4/manage/phones` answers only a read
   whose poll signature verifies, in every `signed_poll_mode`, and an
   owner-slot card is served only to such a read.
3. **Registries key on the key.** The phone registry, the pending queue, the
   push-token map and the consumer webhook map resolve by `phone_ref`.
   Registering a key the registry already holds is the SAME phone: its
   existing id and first-pairing time are kept, its metadata refreshed, and no
   second record exists. Nothing keyed on a phone needs re-pointing when that
   phone pairs again. A key has one spelling: the unpadded base64url of its
   raw bytes (ed25519 32 bytes, ecdsa-p256 64 bytes X||Y), for the identity
   key and the poll key alike; a registration in any other spelling is
   refused, so no key is ever two phones.
4. **Two slots, not a list - and a code is not enough to hold one.** A
   bootloader holds a PRIMARY and a RECOVERY `phone_ref`, the owner's phones.
   A registration challenge has a kind: an OWNER code buys an owner
   challenge, a consumer's MEMBER code a member challenge, and no code a
   plain challenge, which serves revoke and never registers. The challenge's
   kind, the proof and the poll delegation are checked before any slot
   question, and nothing about another phone is said before them. While owner
   genesis is open - a registry started fresh, before its first owner, or one
   the host reset reopened - an owner code alone enrolls the first owner; a
   registry from before the marker that already holds a phone or a session
   starts closed. Once genesis is closed, a new owner key enters a slot only with the
   APPROVAL of an owner phone it does not displace - with no other owner, the
   occupant's approval of its own replacement: the bootloader cards the
   approver with the incoming key's `phone_ref` (the ref the new phone shows),
   the approver signs the card, and the new phone pairs again with a new code.
   The approval binds the key, the slot, the approver and the occupant; two
   keys asking for one slot are both refused. Pairing into an occupied slot
   still names the occupant to the incoming key, whose signed claim says which
   phone it displaces; the displaced key is revoked in the same act, and a
   third key cannot pair without displacing one. The same key re-pairs into
   the slot it holds by its code alone. A member key never enters an owner
   slot. A member phone revokes only itself and lists no other phone; an
   owner phone revokes an owner or a member; the last owner phone is never
   revoked. A lost sole owner phone is the host's act, never the network's:
   `recto bootloader owner-reset` on the bootloader host removes only the
   LAST owner phone and reopens genesis (refused while a server holds a
   file-backend store); a non-sole owner phone is revoked over the network by
   an owner phone in hand. When every owner phone is lost, `owner-reset
   --every-owner-lost`, naming every owner phone held, removes them all and
   reopens genesis. A state directory or schema lost or started fresh is a registry
   that never had an owner. Pairing codes are six digits, so wrong codes
   are counted: a request carrying the edge's client-address header
   (`CF-Connecting-IP` when fronted by Cloudflare) is public, limited per client (an IPv4 address, an
   IPv6 /64), and a code that sat through too many public wrong guesses is
   burned on its next public redemption; a request without the header came
   over a private route and is never counted, so every other
   ingress must sit behind a proxy that sets it. Nothing refuses every
   client at once. The counts are per process and a restart clears them;
   an edge rate rule on the code path is the bound across instances.
5. **A consumer binds to the key, not to the id.** A service that stores a
   phone's id stores a cached display value; its truth is the public key it
   verifies signatures against. "Is this still the phone?" is answered at every
   crossing by the signature, and by nothing else.
6. **The user plane is a vault plane.** A consumer may hold its own automation
   credentials; it holds no opener for any user's vault and no roster of users'
   phones. Absence, not denial: the question cannot be asked of it.

**No compatibility window.** Rule 14 predates launch; there is no earlier
phone or registry to keep working. A registry created before it is wiped at
the deploy that carries it, and its phones pair again on the build that signs.

**15. Fail-closed has named shapes, and a reader that calls one a defect is
read back.** On 2026-09-25 the first whole-tree defensive review of Recto (a
36B reasoner over 140 modules, refuted independently by a second model) raised
24 findings at or above high. Twenty-three were this tree's design, reported as
a fault. Each is a decision Recto stands on, so they are written here, where the
next reader — human or model — looks first, and each is pinned by a test that
fails in the tree before a reader has to find it again
(`tests/test_recurve_acceptances.py` is the map).

- **a. No operator key, no authority.** `capability_operator_pubkey is None`
  is a REFUSAL at every site that reads it — mint, profile create, add
  device — never a skipped check. A defence that silently disables itself
  is not one. Pinned: `test_mint_refuses_when_no_operator_pubkey_is_configured`.
- **b. The pending envelope is a read, never an approval.** `GET /pending`
  is signed as tier 0, one action (`bootloader:pending`), single use, pinned
  to the exact `requests` bytes on the wire. It lets the phone RENDER cards
  that came from the pinned key; each approval is minted separately against
  that record's own fingerprint. Pinned: `test_bootloader_pending_signed.py`.
- **c. Time bounds are upstream; the grant adds the ceiling.** `verify_jws`
  refuses `now < nbf` and `now >= exp`; `verify_pair_grant` is called on
  claims that already passed it and adds the window CEILING on top. Pinned:
  `TestRule15cTimeBoundsAreUpstream`.
- **d. "While children exist" means active children.** A master whose
  children are all revoked has nothing left to orphan; revoking it then is
  the intended end state (children first, then master). Pinned:
  `TestRule15dMasterRevocation`.
- **e. The mnemonic gate is the caller's, and there is one caller.**
  `ExportMnemonicAsync` performs a bare keychain read by design; its ONLY
  caller (Settings' backup ceremony) obtains a fresh biometric proof via
  `IEnclaveKeyService.SignAsync` immediately before, and refuses on failure.
  A second caller without the same gate is a rule violation, not a feature.
- **f. The TOFU window is one host, one pairing operation.** With no pin
  and no system trust, an unknown certificate is accepted only between
  `BeginPairing(host)` and `EndPairing()`, and only for that host. "No pin
  yet" is not a window. (The one finding of the 24 that was REAL: the
  comment promised this scope and the code did not keep it. Fixed the same
  day.) Pinned: `PinningServiceTests`.
- **g. An in-memory challenge store is still a gate.** `ChallengeStore`
  without a state store loses cross-replica persistence, never single-use
  or the TTL. Pinned: `TestRule15gInMemoryChallengeStoreIsStillAGate`.
- **h. The wire names what it carries.** `managed_secrets[].secret_name` is
  a NAME the phone gates, never a value; the field was renamed from `secret`
  the day a reader mistook it. A value-bearing field on this wire is a
  design change, not a rename.
- **i. Dev-host code is compiled out, not configured out.**
  `SoftwareEnclaveKeyService` and its registration exist only under the
  non-iOS/non-Android preprocessor branch; a storefront build cannot reach
  them. Configuration is not the gate; the compiler is.
- **j. Verification is staged, and each stage says what it defers.**
  `verify_jws` documents that jti/replay is the StateStore tracker's;
  `multi_witness` documents that signature verification is its consumer's;
  `evaluate_scope` returning `False` on an unknown group or action is the
  fail-CLOSED answer. A stage is read with its docstring or it is misread.
- **k. A secret's config is the operator's definition, never a caller's
  request.** `SecretSource.fetch(secret_name, config)` takes the registry
  row the OPERATOR wrote; `EnvSource`'s `env_var` override reads the
  operator's own process environment under a name the operator chose. No
  request, header or payload ever reaches `config`; a path that builds one
  from a request is a rule violation. (Second whole-tree review, 09-26:
  the one finding not already named above.) Pinned:
  `TestRule15kSecretConfigIsTheOperators`.
- **l. A heartbeat token is a credential, not a capability.** The cluster
  registry's token is a long-lived per-cluster bearer secret compared in
  constant time over its sha256; its threat is theft, answered by TLS and
  rotation, not by a jti. A reader asking it for a replay guard is asking a
  password for a nonce.
- **m. A subject is a handle, not an identity.** Wherever a consuming
  platform names one of its users - the member code's `member_of`, the user
  vault's `X-Recto-Subject` claim, the device-pairing record - it sends an
  opaque subject handle: exactly 43 base64url characters (32 bytes), minted
  by the platform. Recto checks the grammar and nothing else; a GUID, an
  email or any other shape is refused (400). Storage names use the handle's
  hex form (`subject_storage_id`) so a case-folding filesystem never merges
  two handles. Pinned: `TestRule15mASubjectIsAHandle`.
- **n. A bound subject rebinds only by its bound phone.** A member code
  binds (consumer, subject) to the phone that registers on it - one phone
  per pair, one subject per consumer on a phone. A second key registering
  for a bound pair is refused (409 `member_subject_bound`) unless the bound
  phone's identity key signed the hand-over
  (`recto-member-rebind-v1|consumer|subject|bound ref|incoming key|challenge`);
  with it, the binding moves and the old phone loses it. The challenge is the
  fresh member challenge the incoming phone answers, so each signature admits
  one registration and a replayed one is refused. The operator's host reset
  is the only other way. Pinned: `TestRule15nABoundSubjectRebindsOnlyByItsPhone`.
- **o. The bootloader never stores a platform's user id.** No state field,
  sidecar key or log line carries one - only the subject handle. The platform
  holds the mapping from handle to meaning; nothing in this tree can reverse
  it. Pinned: `TestRule15oTheBootloaderNeverStoresAPlatformUserId`.
- **p. An auth-only agent raises no card.** An agent registered with
  `"capability_requests": false` authenticates to a substrate (the user vault,
  say) and is refused by name (403 `agent_auth_only`) before any capability
  card is raised. An empty request policy stays a config error: "may request
  nothing" is this kind, not an empty list. A user-vault agent's grant
  request (z) is not a capability card and is the one card it may raise.
  Pinned: `TestRule15pAnAuthOnlyAgentRaisesNoCard`.
- **q. The relay log carries the status only.** When a consumer answers a
  relayed device pairing or unpairing with an HTTP error, the bootloader logs
  the status code; the consumer's headers and body can carry its users' data
  and are never printed. Pinned: `test_the_relay_log_carries_the_status_only`.
- **r. A device label is generated, never asked.** A phone that sends no
  label gets `phone-<4 hex>`, derived from its own key's reference; the phone
  may rename itself, and the registry never prompts a person for a name.
  Pinned: `TestRule15rADeviceLabelIsGenerated`.
- **s. A grant verifies against the subject's bound phone, and only that
  phone.** A user-vault grant - one agent (an opaque agent handle) may use one
  of the user's keys until a date - is admitted only under the identity-key
  signature of the phone its (consumer, subject) is bound to, over
  `recto-user-vault-grant-v1|` and the record's canonical bytes. Another
  phone's signature, a subject bound to no phone, or a signature without the
  domain tag is refused by name. The phone submits it; no agent token is the
  authority. Pinned: `TestRule15sAGrantVerifiesOnlyAgainstTheBoundPhone`.
- **t. A grant past its date, or longer than the cap, is refused at
  admission.** The bootloader's clock decides: `not_after` already past, or
  more than `GRANT_MAX_SECONDS` (365 days) ahead, or another bootloader named,
  is refused before anything is stored. Pinned:
  `TestRule15tAGrantPastOrTooLongIsRefused`.
- **u. A revoked grant never grants again.** The bound phone's revoke (signed
  over `recto-user-vault-revoke-v1|` and its record) puts the grant's id on
  the revocation list at once; the same signed grant re-sent is refused. A
  grant REPLACED by a newer one for the same agent and key is revoked in the
  same step, so a superseded grant replayed never displaces the newer one.
  Only the bound phone revokes. Pinned: `TestRule15uARevokedGrantNeverGrantsAgain`.
- **v. A grant names one agent.** The agent is one opaque handle; a wildcard,
  an empty value or a raw id is refused before any signature is read. "All my
  agents" is not a grant. Pinned: `TestRule15vAGrantNamesOneAgent`.
- **w. Admission is not release.** Storing or revoking a grant changes no
  release answer until the release gate is switched on; until then release
  does not read grants at all. One live grant per (consumer, subject, agent,
  key): a newer one replaces the older. Pinned:
  `TestRule15wAdmissionIsNotRelease`; the store in both backends:
  `test_state_postgres.py::test_a_newer_grant_for_the_same_slot_replaces_the_older`.
- **x. A card that cannot render a signed field refuses to sign.** The phone's
  grant and revoke cards show every field of the record it signs: the agent
  handle, key, scope, until, subject, bootloader and consumer, and the nonce
  and grant id. A card missing a field, or holding one it cannot show, offers
  no Approve. The agent's name and the purpose are the service's words,
  labelled that way and never signed. The window chips only shorten what the
  service proposed, and none reaches past the 365-day cap. Pinned (phone):
  `Recto.Shared.Tests/Capability/UserVaultCardTests.cs::Rule15x*`.
- **y. Nothing from a card persists after the tap.** The service's words and
  the proposed record live in the card's model only. Approve, Deny, expiry or
  closing drops them. The phone stores no grant, no history and no
  handle-to-name map; its grants view reads the bootloader each time (aa).
  Pinned (phone): `Recto.Shared.Tests/Capability/UserVaultCardTests.cs::Rule15y*`.
- **z. A grant request rings only the subject's bound phone, and its words
  never touch disk.** A user-vault agent may ask, by
  `POST /v0.4/user-vault/grant-request`, for a grant or a revoke. The card
  rings only the phone its (consumer, subject) is bound to; the consumer comes
  from the operator's platform-to-consumer map, never from the caller. One
  request is open per (agent, key), raises are rate-limited per subject, and a
  request lives five minutes. The purpose (280 characters) and the agent's name
  (64) are held in memory and nowhere else: control and format characters are
  refused, and resolve, deny, expiry or restart drops them. Pinned:
  `TestRule15zAGrantRequestRingsOnlyTheBoundPhone`.
- **aa. A revoke never needs the platform.** The bound phone reads its
  subjects' live grants from the bootloader by its own identity signature
  (`recto-user-vault-grants-v1|`, fresh within two minutes) and revokes one,
  or every grant of one key (`recto-user-vault-revoke-key-v1|`, "stop all"),
  straight to the bootloader. A stop-all lives at most ten minutes and is used
  once, so the same signature re-sent ends nothing granted since. Pinned:
  `TestRule15aaARevokeNeverNeedsThePlatform`.

**The reader's residue.** Findings that name a design here are not re-argued;
they are answered by the rule's letter and the test's name. A finding this
rule does not answer is a real finding until it is fixed or a letter is added
— and adding a letter requires adding the test.

