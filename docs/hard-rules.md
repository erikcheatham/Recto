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
   a read.
3. **Registries key on the key.** The phone registry, the pending queue, the
   push-token map and the consumer webhook map resolve by `phone_ref`.
   Registering a key the registry already holds is the SAME phone: its
   existing id and first-pairing time are kept, its metadata refreshed, and no
   second record exists. Nothing keyed on a phone needs re-pointing when that
   phone pairs again.
4. **Two slots, not a list.** A bootloader holds a PRIMARY and a RECOVERY
   `phone_ref`. Pairing into an occupied slot is a replacement question,
   answered by a signed claim from the incoming key; the outgoing key's slot
   is revoked in the same act. A third key cannot pair without displacing one.
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

**The reader's residue.** Findings that name a design here are not re-argued;
they are answered by the rule's letter and the test's name. A finding this
rule does not answer is a real finding until it is fixed or a letter is added
— and adding a letter requires adding the test.

