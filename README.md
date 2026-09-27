# sts — an RFC 8693 security token service

A small Go service implementing exactly **one** RFC 8693 token exchange: a
backend-for-frontend (BFF) trades a verified customer or employee token for a
short-lived delegation token naming one agent. That token carries a `garm`
claim — this service's authority claim, not OAuth `scope` — which the
verifying daemon (`garmd`) uses to decide what the agent may do.

This is not a general-purpose STS. There is one exchange, one claim shape,
and one authorization port. What follows describes exactly what exists.

## What this service does

```
customer/employee IdP ──(verify subject_token)──┐
                                                  ▼
BFF ──POST /token (client_assertion)────────▶ ┌───────┐
      grant_type=token-exchange               │  STS  │──▶ mints a delegation token
      subject_token=<human token>             └───────┘     `aud`=garmd, `garm`={...}, `act`={agent}
      agent=<agent name>
```

1. The BFF authenticates itself to `POST /token` with a `client_assertion`
   (`private_key_jwt`, RFC 7523) — a short-lived JWT it signs itself,
   proving it holds a registered private key. The signature and a
   single-use `jti` are checked by `ClientRegistry` (`clients.go`).
2. The BFF's `subject_token` (a customer or employee token) is verified
   against its own issuer's JWKS by `Verifier` (`issuer.go`). Which issuer
   means "customer" and which means "employee" is per-issuer configuration
   (`TrustedIssuer.Kind`), never sniffed from the token.
3. Three yes/no questions are asked of an `Authorizer` (`authz.go`):
   `CanInvoke` (may this principal reach this agent at all), `HandledBy`
   (for an employee acting on a named customer's behalf — the line between
   helping a customer and impersonating one), and `InSegment` (which of the
   policy's declared segments the principal belongs to).
4. A claims policy (`claims.go`, loaded from a YAML file — see
   `deploy/claims.yaml`) turns segment membership into a `GarmClaim`: a
   clearance, a set of compartments, a set of verbs, and optional tool
   sets. Definitions and rules live in that file; *membership* (which of
   potentially millions of customers belongs to which segment) comes from
   the `Authorizer`, never the policy file.
5. A signed token is minted by `Keyring` (`keyring.go`) with ES256 over
   P-256, and its public keys are served as a JWKS at
   `/.well-known/jwks.json` for `garmd` to verify against.

## The token shape

There is no `scope` claim anywhere in a minted token. `garm` replaces it
entirely:

```json
{
  "iss": "https://sts.internal.example.com",
  "aud": "garm://garmd",
  "sub": "customer:C-8123",
  "tenant": "acme",
  "garm": { "clearance": "CONFIDENTIAL", "compartments": ["pii-contact"], "verbs": ["READ"], "kind": "USER" },
  "act": {
    "sub": "agent:order-assistant",
    "garm": { "clearance": "INTERNAL", "verbs": ["READ"], "kind": "AGENT" }
  },
  "exp": 1780000000,
  "iat": 1779999400,
  "jti": "..."
}
```

- **`aud` is always garmd's own identifier** — the verifying daemon this
  service mints tokens for — never the agent. The agent is named at
  `act.sub` (`agent:<name>`). An earlier design sketch put the agent in
  `aud` and used a prefix on it to decide whether an audience meant a
  delegation; that field (`AgentAudPrefix`) does not exist in this
  implementation and should not be reintroduced — once `aud` unconditionally
  names garmd, there is nothing left for such a prefix to decide.
- **`sub`** is a type-prefixed identity (`customer:C-8123`, never a bare
  ID) — see `authz.go`'s doc comment for why every identity crossing the
  `Authorizer` interface is prefixed this way.
- **`act`** is the RFC 8693 §4.1 actor chain. The outermost `act` is
  whoever is *currently* acting (the agent, if one is named); a nested
  `act.act` is a *prior* actor. On the employee-for-customer path the chain
  is `sub`=customer → `act`=agent → `act.act`=employee: the employee
  obtained the token earlier, the agent is exercising it now.
- **`garm.clearance`** is one of `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`,
  `RESTRICTED` (the bare spelling; `garmd` also accepts `CLEARANCE_*`).
  An agent's own authority is minted at `act.garm` **unnarrowed** — this
  service does not intersect the agent's claim against the caller's; that
  narrowing is `garmd`'s job (spec §2.3), not this one's. The one thing
  this service *does* refuse to mint is a chain whose verb intersection is
  empty (a token that would be syntactically valid and useless).

## What is NOT built

- **Exchange 2** (runner + delegation → on-behalf-of, e.g. for a NATS
  callout) does not exist. There is one `POST /token` handler and it
  implements exchange 1 only.
- **The runner / agent-runner broker** is not part of this service.
- **The NATS auth callout integration** is not part of this service.
- **An OpenFGA-backed `Authorizer`** is not built yet. The only
  implementation today is `LoadStaticAuthorizer` (`authz_static.go`): a
  flat YAML file of already-resolved tuples (see `deploy/tuples.yaml`) — it
  does not resolve any graph, so a segment granting an agent entitlement is
  not followed transitively; every relation must be written in its
  already-resolved form. OpenFGA arrives in a later task, wired in through
  the same `Authorizer` interface, chosen by `cmd/sts/main.go`.

## `instanceAuthorization` — and why it exists

Confining a customer to their own records — "this order belongs to this
customer, so only this customer's token may read it" — is enforced by
`garmd`, the daemon that verifies these tokens, not by this service. This
service has no way to *observe* whether that enforcement is actually
running in front of the tools a token will reach; it can only be *told*.

`instanceAuthorization` is that assertion (spec §3.5), and `NewServer`
refuses to start without it:

```yaml
instanceAuthorization:
  status: absent            # "enforced" | "absent" — no default; an operator must say
  unconfinedCeiling: PUBLIC # read only when status is "absent"
```

- `status: enforced` means garmd's record-level confinement is deployed and
  running. This service mints whatever the claims policy grants, unchanged.
- `status: absent` means it is not — record-level confinement does not
  exist yet in this codebase's current state. While absent, **every
  customer-kind mint is capped at `unconfinedCeiling`**, regardless of what
  the claims policy would otherwise grant, so a customer token can never
  carry more authority than that ceiling names. An empty `unconfinedCeiling`
  under `absent` refuses every customer-kind mint outright.

Flipping this to `enforced` is an operational claim about a *different*
system (garmd), not a switch to flip because this service compiles. Get it
wrong in the optimistic direction and a customer token can read further
than garmd actually confines it to.

## Configuration

`LoadConfig` (`config.go`) reads one YAML file (see `deploy/config.yaml`
for a complete, loadable example) and validates it eagerly — every check
below is a hard failure at startup with a message naming the field, not a
mysterious failure discovered at the first request:

- `issuer`, `audience`, `tokenEndpointAudience`, `listen`
- `keys.active` and `keys.keys[]` — at least one signing key; `active` must
  name one of them. **Signing keys are never inlined.** Each key's `pem`
  field is a reference to an environment variable (`$NAME` or `${NAME}`)
  holding the PEM-encoded ECDSA P-256 private key — `LoadConfig` rejects
  literal key material in this field outright. Retired keys can stay listed
  (served for verification, never signed with) during rotation.
- `issuers[]` — at least one trusted upstream issuer, each with a `kind` of
  `customer` or `employee`.
- `clients[]` — BFFs allowed to authenticate with `private_key_jwt`. Client
  keys are *public* keys, not secrets, so they may be a file path or
  inlined PEM directly.
- `policy` — path to the claims policy file (`LoadPolicy`, `claims.go`).
- `authz.static` — path to the static authorizer tuples file
  (`LoadStaticAuthorizer`, `authz_static.go`).
- `instanceAuthorization.status` — must be exactly `enforced` or `absent`.
- `instanceAuthorization.unconfinedCeiling` — if set, must be one of the
  four clearance names.

`(*Config).Build(ctx, authz)` wires a loaded `Config` into a running
`*Server`. It takes the `Authorizer` as a parameter rather than building one
itself: which implementation to use (the static one today) is a decision
`cmd/sts/main.go` makes, not `Config`'s.

## Running it

```bash
go build ./cmd/sts

# Generate an ES256 signing key and a BFF client keypair. Both must be
# ECDSA (or RSA) — EdDSA is deliberately excluded from every algorithm
# allowlist this service accepts, in both directions.
./deploy/keygen.sh
export STS_SIGN_KEY_K1="$(cat sts-sign-k1.pem)"

./sts -config deploy/config.yaml
```

```bash
curl -s localhost:8080/.well-known/jwks.json
# {"keys":[{"use":"sig","kty":"EC","kid":"k1","crv":"P-256","alg":"ES256", ...}]}
```

`deploy/config.yaml` ships with `listen: :8080` and no TLS configured — it
is a local/dev config, and the service loudly warns on startup that it is
serving plaintext. Set `STS_TLS_CERT` and `STS_TLS_KEY` (paths to a
certificate and key) in production, or terminate TLS in front of it at a
proxy or mesh sidecar; `cmd/sts/main.go` refuses to pretend plaintext is
fine, but it does not refuse to run without TLS, since a sidecar is a
legitimate place to terminate it.

Shutdown is signal-aware (`SIGINT`/`SIGTERM`) and graceful, with a 5 second
timeout for in-flight requests to finish.

## Repository layout

| File | What it is |
|---|---|
| `keyring.go` | Signs tokens (ES256), serves the JWKS |
| `issuer.go` | Verifies upstream tokens against their issuer's JWKS |
| `claims.go` | The claims policy: roles, segments, agent authority |
| `authz.go` | The `Authorizer` interface — three yes/no questions |
| `authz_static.go` | A flat, file-backed `Authorizer` (dev/CI) |
| `clients.go` | `private_key_jwt` client authentication + replay protection |
| `exchange.go` | The `POST /token` handler: the whole exchange, in order |
| `config.go` | Loads and validates `deploy/config.yaml`'s shape, wires a `Server` |
| `cmd/sts/main.go` | The binary: flags, logging, TLS, graceful shutdown |
| `deploy/config.yaml` | A complete, loadable example configuration |
| `deploy/claims.yaml` | An example claims policy |
| `deploy/tuples.yaml` | An example static-authorizer tuple file |
| `deploy/keygen.sh` | Generates a signing key and a BFF client keypair |
| `deploy/model.fga`, `deploy/tuples.openfga.yaml` | Sketches for the OpenFGA authorizer — **not built yet**; not currently loaded by anything |

## Security notes

- **Client-assertion replay** protection (`ClientRegistry`) is an
  in-memory, per-process map. With more than one replica of this service
  behind a load balancer, replay protection is per-replica, not global —
  the same assertion can be spent once against each replica before any of
  them has told the others. A shared store would close this gap; none is
  built here.
- **Fail closed.** Every verification error, missing claim, or authorizer
  error denies the exchange. The caller always receives the same opaque
  `{"error":"access_denied"}`, whatever the reason — the reason is written
  to the log, never the response, so this endpoint cannot be used as an
  enumeration oracle.
- **`requested_subject`** (an employee acting for a named customer) is only
  honored after `HandledBy` succeeds. Keep that relation accurate; it is
  the line between an employee helping a customer and one impersonating
  them.
- **Algorithm allowlist.** Both upstream token verification and client
  assertion verification share one allowlist (`permittedAlgorithms`):
  ES256/384/512, RS256/384/512, PS256/384/512. `none` and any HMAC
  algorithm are excluded because there would be nothing to check a
  signature against; EdDSA is excluded to match `garmd`'s own verifier.
