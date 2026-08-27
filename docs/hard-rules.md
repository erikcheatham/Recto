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

