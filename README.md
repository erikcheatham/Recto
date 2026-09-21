# Recto

**Authority lives on a phone.** Recto is a capability substrate: services and
agents hold no standing credentials. Every action that matters is proposed by
software and released by a person, from hardware they carry, one act at a time.

Operated by **Recto LLC**. Licensed Apache 2.0.

---

## What Recto is for

Recto exists so that **any number of independent operators can each hold real
sovereignty over their own platform and their own user base.**

An operator runs a bootloader. Because they run it, they can actually guarantee
what they are claiming to their users — the guarantee is not a policy document,
it is a key they hold on hardware they carry. Recto's job is to make that
guarantee expressible, verifiable, and hard to lose. It is not to decide what
any operator's platform should permit.

That boundary is deliberate and it is the design:

- **Recto extends capability.** It defines how authority originates, what shape
  it travels in, and how a verifier checks it.
- **The operator defines governance.** Who may do what, on what terms, under
  which policies — that lives in the operator's own platform, at their tier,
  designed as their business requires.

**Recto stays simple, straightforward and reliable so that the layer above it
can afford to change.** Anything that varies per platform is a sign it belongs
above this layer, not in here.

## What it does

- **Hardware-held identity.** Keys are generated inside the device secure
  element (iOS Secure Enclave, Android StrongBox) and gated by biometrics. The
  private key is not exportable.
- **Scoped, short-lived grants.** An agent receives a signed capability for one
  action, with an audience, a lifetime and a nonce — not a key.
- **Vault-backed secrets.** Service credentials are stored encrypted at rest and
  fetched at call time. They are never written into deployment config.
- **Wrapped-service supervision.** Declarative YAML config, HTTP liveness probes
  with backoff restart, resource limits, and structured lifecycle events.

## What it deliberately does not do

- **It does not hold your users' keys.** Each operator's users root to that
  operator's bootloader. Recto never becomes a place where many platforms'
  secrets sit together, because that would make one compromise everyone's
  problem.
- **It does not adjudicate between operators.** There is no central registry, no
  Recto-held escrow, no upstream party who can act inside your deployment.
- **It does not offer a removable-media recovery path.** One existed and was
  removed. A backup blob on a stick is passively copyable: an attacker who takes
  it gets unlimited offline attempts, forever, with no rate limit, no detection
  and no revocation. Recovery is two live devices plus a passphrase, or it is
  nothing.
- **It does not implement your policy.** Tiers, quotas, roles, moderation and
  attribution are the operator's platform, not the substrate.

---

## The permission hierarchy

```
1  install the app · biometric   ──▶  PHONE = IDENTITY      (no authority yet)
2  pair with a bootloader        ──▶  OPERATOR *or* USER    (of that bootloader)
3  pair with a service           ──▶  USER + AGENTS         governed by the operator
4  configure an agent domain     ──▶  AGENT DOMAIN          governed by user × operator
```

**Step 2 decides operator or user, and it is not a choice.** A bootloader holds
exactly one operator public key, sealed when the bootloader is created. Pairing
compares your key against it: match makes you the operator, anything else makes
you a user. Nobody *becomes* an operator by pairing.

An operator is an **identity, never a role.** A role can be granted, so
something can be tricked into granting it. There is no grant operation here to
abuse.

Operators and users share one app, one hardware key and one approval card. They
differ only in scope: an operator approves what affects the bootloader and its
agents; a user approves what affects their own vault and data.

**Pair two devices.** A **primary** for routine approvals, replaceable. A
**recovery** device for high-consequence operations only, never replaced. A
single device cannot both survive theft and survive loss; two asymmetric devices
can.

### Strict at the root is what permits flexibility above it

The operator's own vault is held to the tightest posture in the system, and that
is not asceticism — it is what makes a looser, friendlier posture safe for the
users of that operator's platform. Every affordance an operator extends to their
users rests on the operator's root being harder to take than any of them.

If you are running a platform on Recto, hold your own root to a stricter
standard than anything you offer your users. The strictness is the product.

---

## The operator vault

The bootloader's trust root is the operator's public key, sealed at creation.
Beyond it, an operator seals a small set of **genesis members** — the parties who
can together re-establish operator authority after a loss.

**The genesis set is a passphrase and your paired devices.** Restoring operator
authority onto a new phone runs through this set — not through the master key,
which stays in custody and never signs a challenge online. A key that never
signs cannot be phished into signing.

- The **passphrase** is 8+ diceware words, entered only at a no-echo prompt on
  the host — never as a command-line argument, never into an agent. It derives
  a signing key through Argon2id. **Recto does not store it**: only the derived
  public key is written, and the phrase itself exists nowhere in the vault.
- The **devices** sign from their secure elements like any other paired phone.

### Changing the set requires a majority of it

Membership is a signed chain. Each change carries the hash of the entry before
it and the signatures of a majority of the members as they stood:

```
k = (N // 2) + 1        N=1 → 1     N=2 → 2     N=3 → 2
```

**Majority rather than unanimity, and the reason is recovery.** If every member
had to sign, losing one device would be unrecoverable: removing it would
require its own signature, so the roster would freeze — and a frozen roster
cannot admit a replacement either. One loss would permanently degrade the set
to something it could not repair. With three members, any two can drop a lost
device *and* enrol its replacement. One member still cannot alter the roster
alone.

**Two members is the weak point**: a majority of two is two, so that set has no
fault tolerance. It is unavoidable on the way from one member to three, and it
should be brief. Three is the first configuration that survives a loss.

### The chain is detection, not permission

A signature requirement on the writer would be theatre — anyone who can call it
can also open the file in an editor. So each entry is anchored to the one
before it: **edit an entry and its signature stops verifying; edit the genesis
entry and the next entry's hash no longer matches; append or delete and the
sequence breaks.** The file can still be edited. It can no longer be edited
without that being visible.

A chain that fails to verify reports the set as **unreadable**, never as empty.
Those are opposite facts, and confusing them mid-recovery is how someone
concludes the vault is blank and starts over.

**These operations are CLI-only, by design.** Sealing and verifying introduce no
web surface, no external service and no additional party. There is nothing to
compromise remotely because there is nothing listening.

Verify your passphrase cold, from whatever copy you keep, on a day when nothing
is wrong. Entering it twice during a seal catches a slip; only a separate cold
entry later catches a misreading.

---

## Recto Agentic

The phone side — holds the keys, shows the approval card, releases nothing
without a biometric.

[App Store](https://apps.apple.com/us/app/recto-agentic/id6771544174) ·
[Google Play](https://play.google.com/store/apps/details?id=app.recto.phone)

---

## Install

Python 3.10+.

```bash
git clone https://github.com/erikcheatham/Recto.git
cd Recto
python -m venv .venv
. .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[v0_4]"
```

The `[v0_4]` extra pulls the `cryptography` + `pyjwt` dependencies the protocol
needs; without it the verifier paths raise on import.

```bash
python -c "import recto; print(recto.__version__)"
```

A fresh clone never carries a `.venv` — repeat the two steps above after each
one.

---

## Integrating

Six steps. Your app never holds a credential that outlives one action.

### 1. Mint an agent token

Any 64-hex-character string:

```bash
openssl rand -hex 32                      # Linux / macOS
python -c "import secrets; print(secrets.token_hex(32))"
```

Store it in a vault — your platform's keychain, or Recto's own encrypted
backend. **It must never land in plaintext on disk.** The bootloader operator
and your app both need the same value; hand it over through a channel you trust.

### 2. Register your app with the bootloader

The operator declares your agent identity when creating the server:

```python
from recto.bootloader import create_server
from recto.bootloader.state import AppContext

server = create_server(
    port=8765,
    state_dir="~/.recto/bootloader",
    capability_agent_tokens={"your-app-agent": "<the 64-hex token>"},
    principal_apps={
        "your-app-agent": AppContext(
            app_id="your-app",
            app_name="Your App",
            app_description="One-line tagline shown on the phone",
            app_url="https://your-app.example.com",
            app_icon_url="https://your-app.example.com/icon-1024.png",
        ),
    },
)
server.serve_forever()
```

`capability_agent_tokens` authenticates your requests and scopes results back to
you — only the agent that submitted a request can fetch its result.
`principal_apps` supplies what the phone shows at approval time; without it the
phone shows an "unknown app" warning.

**On the icon: serve it from your own origin at a stable per-agent URL.** If
your platform hosts agents acting for businesses with customers of their own,
resolve the icon per request from the approval's *audience* — an agent's owner
recognises the persona avatar, but that owner's customer is a stranger to it and
needs the business mark. The absent-mark fallback must be your platform's
neutral mark, never a user's personal avatar, which would leak one party's
identity into another's approval prompt.

### 3. Configure your app

Point it at the bootloader base URL and supply the agent id and token as the
`X-Recto-Agent-Id` and `X-Recto-Agent-Token` headers on every call.

### 4. Submit a capability request

```http
POST /v0.4/capability/request HTTP/1.1
Host: localhost:8765
Content-Type: application/json
X-Recto-Agent-Id: your-app-agent
X-Recto-Agent-Token: <64-hex>
```

The body carries the claim you want signed (schema below) and a `purpose` string
the operator will read on their phone.

### 5. Poll for the result

```http
GET /v0.4/capability/result/<request-id> HTTP/1.1
X-Recto-Agent-Id: your-app-agent
X-Recto-Agent-Token: <64-hex>
```

`pending` until the operator decides or the TTL elapses. Treat expiry as a
refusal.

### 6. Use the JWS

The returned `capability_jws` is a 3-part JSON Web Signature signed with
`ES256K` (secp256k1 over SHA-256 of the canonical-JSON signing input). Verify it
against the operator's public key, confirm `cap.allow_actions` covers what you
are about to do, then proceed. Persist it on the row representing the action so
a later audit can prove the operator approved that specific invocation.

---

## The capability claim schema

Standard JWT claims plus a `cap` extension.

| Claim | Meaning |
|---|---|
| `iss` | Always `phone:operator:enclave` |
| `sub` | The calling agent and its context, e.g. `agent:<id>@user:<uuid>` |
| `aud` | Audience list — who should accept this |
| `iat` / `nbf` | Issued-at / not-before, Unix seconds |
| `exp` | Expiry. 30–120s for one-shot mutations; longer only for standing roles |
| `jti` | Globally unique. Replay defense and revocation keying |

**`cap` extension**

| Field | Meaning |
|---|---|
| `tier` | 0–3 trust level. The manifest sets a weight ceiling per tier; requests exceeding it are rejected |
| `registry_version` | Manifest version the action identifiers resolve against |
| `groups` | Named groups from the manifest, each expanding to a set of actions |
| `scope` | Narrowing: `env`, `services`, `repos` |
| `allow_actions` | Explicit additions beyond group membership |
| `deny_actions` | Explicit subtractions from group membership |
| `limits` | Numeric rate/count limits for the verifier to enforce |

Tier ceilings: 0 trivial/read-only · 1 autonomous in staging, confirmed in
production · 2 explicit pre-authorisation per capability · 3 fresh approval, no
caching.

**Top-level extensions**

- **`purpose`** — the human-readable string on the approval card. **This is the
  load-bearing UX of the whole system.** The operator reads it at 3 AM and
  decides. `"Delete review d4f9b6a2-… for user 31a5686c-…"` tells them nothing —
  the GUID is the audit handle, not the human label. Never use boilerplate like
  "perform action".
- **`parent_cap`** — the `jti` of the parent, if this is a delegated capability.
- **`max_uses`** — omit for reusable, `1` for single-use.

---

## Production notes

- **Keep expiries short.** A capability that outlives its action is a credential.
- **Treat a timeout as a refusal**, never as an approval you failed to hear.
- **Verify in-process as well as downstream.** Defense in depth costs one call.
- **Never log a signature, a token, or a passphrase** — verdicts and identifiers
  only.
- **Add a new repo or agent to your allowlist before its first call**, not after
  it fails; a 404 from an unauthorised caller is indistinguishable from a missing
  route.

## License

Apache 2.0. See [LICENSE](LICENSE).
