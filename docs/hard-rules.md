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

**14. The key is the identity.** A phone IS its enclave keypair, named by its
`phone_ref` - derived from the public key, usable as a credential by no one.

1. **`phone_ref` names the phone;** the registry mints no other identifier.
2. **Every crossing is a signature by the phone's key over what crossed.**
3. **Registries key on the key:** the same key pairing again is the same phone.
4. **A bootloader holds two owner slots, primary and recovery;** after its first
   owner, a new owner key enters one only with an owner phone's approval.
5. **A consumer binds to the key, not to the id.**
6. **The user plane is a vault plane:** a consumer holds no opener for any
   user's vault and no roster of users' phones.
7. **The top plane needs the recovery passphrase AND one owner device, every
   time,** and the bootloader's id is sealed at genesis, never re-derived.

**15. Fail-closed has named shapes.** Each is a decision Recto stands on,
pinned by a test; a finding that names one is answered by its letter.

- **a.** No operator key, no authority.
- **b.** The pending envelope is a read, never an approval.
- **c.** Time bounds are checked upstream; a grant adds its ceiling.
- **d.** A master is revocable once its children are revoked.
- **e.** The recovery phrase is exported only behind a fresh biometric proof.
- **f.** An unpinned certificate is accepted only within one pairing, for one host.
- **g.** A challenge is single use and expires, in every store.
- **h.** The wire names what it carries; a secret's name is never its value.
- **i.** Development-only key code is compiled out of store builds.
- **j.** Verification is staged, and each stage says what it defers.
- **k.** A secret's config is the operator's definition, never a caller's request.
- **l.** A heartbeat token is a credential, not a capability.
- **m.** A subject is an opaque handle, never a platform identity.
- **n.** A bound subject rebinds only by its bound phone.
- **o.** The bootloader stores no platform user id.
- **p.** An auth-only agent raises no card.
- **q.** The relay log carries the status only.
- **r.** A device label is generated, never asked.
- **s.** A grant verifies against the subject's bound phone alone.
- **t.** A grant past its date, or longer than the cap, is refused at admission.
- **u.** A revoked grant never grants again.
- **v.** A grant names one agent.
- **w.** Admission is not release.
- **x.** A card that cannot render a signed field refuses to sign.
- **y.** Nothing from a card persists after the tap.
- **z.** A grant request rings only the subject's bound phone.
- **aa.** A revoke never needs the platform.
