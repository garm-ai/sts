# sts — an RFC 8693 security token service

A small Go service implementing **two** RFC 8693 token exchanges, both
minting the same short-lived delegation token. Ordinarily that token names
one agent at `act`; the direct door also has a narrower mode with **no**
agent at all, for an employee acting directly for a customer (see "The
direct door's request", below). The token carries a `garm` claim — this
service's authority claim, not OAuth `scope` — which the verifying daemon
(`garmd`) uses to decide what whoever is named at `act` may do.

- **The direct door** (exchange 1): a backend-for-frontend (BFF) presents a
  customer or employee token, **verified** against its issuer's JWKS, and
  trades it for a delegation token.
- **The governed door** (exchange 2): a *runner* — a process that executes
  agents, with no human token to present — authenticates as itself and
  **asserts** which subject it is acting for. Nothing verifies that
  assertion, so it is gated on a written `can_run` tuple saying this runner
  may execute this agent at all, and the minted token records which runner
  obtained it in a top-level `exec` claim.

It also mints a second, different credential: a **grant**, the record of a
human's approval of one specific call (`POST /approve`, below). A delegation
token is a session; a grant is a decision.

This is not a general-purpose STS. There are two exchanges, one claim shape,
one minting path shared by both doors, one approval endpoint, and one
authorization port. What follows describes exactly what exists.

## What this service does

```
customer/employee IdP ──(verify subject_token)──┐
                                                ▼
BFF ────POST /token (client_assertion)────▶ ┌───────┐
        grant_type=token-exchange           │       │
        subject_token=<human token>         │       │──▶ mints a delegation token
        agent=<agent name>                  │  STS  │    `aud`=garmd, `garm`={...}, `act`={agent}
                                            │       │    (+ `exec`={runner}, governed door only)
runner ──POST /token (client_assertion)───▶ │       │
         grant_type=token-exchange          └───────┘
         on_behalf_of=<prefixed subject>       ▲
         subject_kind=USER  agent=<name>       │
         tenant=<tenant>                   can_run
```

`subject_token` selects the direct door and `on_behalf_of` selects the
governed one. A request carrying both is refused: there is no exchange that
means both, and quietly preferring one would mint a token from a verified
identity when an asserted one was asked for, or the reverse.

1. The caller — a BFF on the direct door, a runner on the governed one —
   authenticates itself to `POST /token` with a `client_assertion`
   (`private_key_jwt`, RFC 7523): a short-lived JWT it signs itself,
   proving it holds a registered private key. The signature and a
   single-use `jti` are checked by `ClientRegistry` (`clients.go`).
2. **On the direct door**, the `subject_token` (a customer or employee
   token) is verified against its own issuer's JWKS by `Verifier`
   (`issuer.go`). Which issuer means "customer" and which means "employee"
   is per-issuer configuration (`TrustedIssuer.Kind`), never sniffed from
   the token. **On the governed door** there is no subject token at all:
   the runner names a type-prefixed subject in `on_behalf_of`, and the
   prefix it carries decides the kind, into a closed set.
3. Four yes/no questions are asked of an `Authorizer` (`authz.go`):
   `CanRun` (may this runner execute this agent — the governed door only,
   and asked *before* any other authorization question), `CanInvoke` (may this
   principal reach this agent at all), `HandledBy` (for an employee acting
   on a named customer's behalf — the line between helping a customer and
   impersonating one), and `InSegment` (which of the policy's declared
   segments the principal belongs to).
4. A claims policy (`claims.go`, loaded from a YAML file — see
   `deploy/claims.yaml`) turns segment membership into a `GarmClaim`: a
   clearance, a set of compartments, a set of verbs, and optional tool
   sets. Definitions and rules live in that file; *membership* (which of
   potentially millions of customers belongs to which segment) comes from
   the `Authorizer`, never the policy file.
5. A signed token is minted by `Keyring` (`keyring.go`) with ES256 over
   P-256, and its public keys are served as a JWKS at
   `/.well-known/jwks.json` for `garmd` to verify against. Both doors reach
   this through **one** function (`resolveAndMint`), so "the two doors mint
   the same token" is a property of the code rather than of two
   implementations agreeing — a test asserts the two outputs are identical
   apart from `exec`, `jti`, `iat` and `exp`.

### The client assertion

Both `POST /token` and `POST /approve` authenticate the *calling service*
(a BFF, the runner, or whichever service is invoking `/approve`) the same
way: `private_key_jwt` (RFC 7523), checked by `ClientRegistry.Authenticate`
(`clients.go`) before anything else about the request is trusted. The
assertion is itself a short-lived JWT the caller signs, and every one of
these is a hard refusal, not a warning:

| Claim | Requirement |
|---|---|
| `iss` | the calling client's registered id, e.g. `shop-bff` or `agentd` |
| `sub` | must equal `iss` exactly |
| `aud` | must name this service's `tokenEndpointAudience` (see Configuration) |
| `exp` | required; must not already be past, and must be no further than **5 minutes** in the future (fixed; there is no config key for it) |
| `jti` | required; single-use, keyed on **`(client id, jti)`** together, not on the bare `jti` — so two different clients may legitimately reuse the same `jti` value without colliding |
| signature | must verify against one of that client's currently-registered public keys |

`ClientConfig.PEMs` is a **slice**, not a single key, specifically so a
client can rotate: register the new key alongside the old one, cut the
client over to signing with it, then remove the old key in a later
deploy — an assertion signed by *any* currently-registered key is accepted
in the meantime.

### The direct door's request

`POST /token`, `application/x-www-form-urlencoded`:

| Field | Value |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` — **required**; anything else is refused |
| `client_assertion_type` | optional, as below — a present-but-wrong value is refused rather than ignored |
| `client_assertion` | **required** — the BFF's `private_key_jwt`, see "The client assertion" above |
| `subject_token` | the customer or employee token to verify — **required** to select this door (a request carrying this and `on_behalf_of` is refused) |
| `requested_subject` | a customer identity, e.g. `customer:C-8123` — optional, and meaningful only when the caller verified as an **employee**; must open with `customer:` and have a non-empty remainder (a bare `customer:` is refused) |
| `agent` | bare agent name, e.g. `order-assistant` — optional, but **at least one of `agent` or `requested_subject` must be present** |

Refusals beyond the field shapes above: the subject token fails JWKS
verification; its issuer has no usable configured `kind`; its subject
carries a kind prefix its issuer does not assert; it carries no `tenant`
claim at all; `requested_subject` is named by a caller who did not verify
as an employee; `HandledBy` refuses the named employee/customer pair;
`CanInvoke` refuses the acting principal (asked **twice** when delegating —
once for the customer, once for the employee — either miss denies); or
neither `agent` nor `requested_subject` was named, leaving nothing to mint
at `act`.

**A named `requested_subject` with no `agent`** is a real, supported mode,
not an oversight: an employee acting *directly* for a customer, with no
agent in the loop at all. The minted token's `sub` is the customer,
`act.sub` is the employee, and there is no nested `act.act` — because
there is no agent to be the current actor and no prior actor to nest
under it. This is the one shape "the token shape" below does not show.

### The governed door's request

`POST /token`, `application/x-www-form-urlencoded`:

| Field | Value |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` — **required**; anything else is refused |
| `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` — **optional**, but a *different* value is refused rather than ignored (`private_key_jwt` is the only client authentication this service implements, so an absent type is unambiguous; a present one naming something else means the caller and this endpoint have already diverged) |
| `client_assertion` | **required** — the runner's `private_key_jwt`, see "The client assertion" above |
| `on_behalf_of` | type-prefixed subject, e.g. `employee:jdoe` — **required**, and its prefix must be `customer:` or `employee:` |
| `subject_kind` | `USER` — **required**; an absent, empty, or any other value is refused ("subject_kind must be USER or SERVICE"). `SERVICE` is a distinct, named refusal from the same check: the value is recognised but has no claims-policy path in this version. |
| `agent` | bare agent name, e.g. `order-assistant` — **required** |
| `tenant` | the tenant this run belongs to — **required**, for the same reason the direct door refuses a subject token carrying none |

The runner identity is `runner:<client_id>` taken from the **authenticated**
client assertion. There is no form field that names it, which is what keeps
`runner:` out of a caller's control. A presented `act` or `requested_subject`
is refused rather than ignored — the first because the MVP supports a
depth-one chain (the subject at `sub`, the agent at `act`) and a runner
that was itself delegated has nowhere to go in it, the second because
`requested_subject` is only ever honoured behind `HandledBy` against a
verified employee token and this door has no verified anybody.

### The response

Both doors return the same RFC 8693 §2.2.1 shape on success:

```json
{
  "access_token": "eyJ...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 600
}
```

`expires_in` reflects `delegationTTL` (600 seconds is the 10-minute
default). Every failure — from either door — is `400
{"error":"access_denied"}` (the one exception is a non-`POST`, answered
`405` with an `Allow` header), the same opaque body "What is NOT built" and
"Security notes" describe for `/approve`.

## The token shape

Both doors mint this shape when an agent is named; the direct door's
no-agent mode above puts the employee at `act` instead. There is no
`scope` claim anywhere in it —
`garm` replaces it entirely — and the only difference between a direct-door
token and a governed-door one is `exec`, shown here and present **only** on
the governed door's:

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
  "exec": {
    "sub": "runner:agentd",
    "iss": "https://sts.internal.example.com"
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
- **`exec`** is present on **governed-door tokens only** and names the
  runner that obtained the token, plus this service as what attests the
  runner authenticated. A direct-door token has no `exec` key at all — not a
  null, not an empty object — so "was this token obtained by a runner" is
  answerable from the token's shape. It is **provenance, not authority**:
  exactly two fields, outside the `act` chain, never folded. A runner placed
  in `act` instead would have to either assert a `garm` claim it has no
  business asserting or carry an all-permissive one that narrows nothing,
  and both read as authority to anyone who later looks at a token or a
  ledger row.
- **`garm.clearance`** is one of `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`,
  `RESTRICTED` (the bare spelling; `garmd` also accepts `CLEARANCE_*`).
  An agent's own authority is minted at `act.garm` **unnarrowed** — this
  service does not intersect the agent's claim against the caller's; that
  narrowing is `garmd`'s job (spec §2.3), not this one's. Several shapes
  *are* refused before signing, though: a chain whose verb intersection is
  empty (a token that would be syntactically valid and useless); a
  principal, an agent, or (when delegating) the acting employee that
  resolves to no segment roles at all; any resolved claim in the chain
  surfacing an empty `clearance` (an internal invariant — `garmd`'s
  `ParseClaims` would refuse such a token anyway); and a customer-kind mint
  when `instanceAuthorization` is `absent` with no `unconfinedCeiling`
  configured (see below).

## `POST /approve` — minting a human's yes

A second endpoint, and a different credential. `POST /token` mints a
**delegation token**: a session, saying *this agent may act for this
person*. `POST /approve` mints a **grant**: a decision, saying *this person
approved this specific call, over these specific values*. `garmd` requires
one before it will run a tool that declares it needs human approval.

`POST /approve`, `application/json`, plus the approver's own IdP token in
`Authorization: Bearer <token>`:

| Field | Value |
|---|---|
| `client_assertion` | the calling service's `private_key_jwt` — the same registry, the same replay protection, as `POST /token` |
| `client_assertion_type` | optional; if present it must be `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `tool` | the tool's FQN, e.g. `payments.v1.initiate_payment` — shape-checked only, since this service holds no catalogue |
| `subject` | whose call was approved, type-prefixed, e.g. `customer:C-8123` |
| `task_id` | optional; the task the approval was given on, copied verbatim into the grant's `task` claim |
| `material` | a flat map of dotted path → the value's canonical **text** form: the values the human actually saw |

The assertion is in the **body**, not a header: RFC 7523 puts it in the
request itself, and a new header would add a name to the cross-repository
header table that nothing else there needs. An unknown JSON field is
refused, not dropped — a misspelled key is a request that silently approves
something other than what the caller meant.

Response:

```json
{ "grant": "<jws>", "expires_in": 900 }
```

The grant itself:

```json
{
  "iss": "https://sts.internal.example.com",
  "aud": "garm://garmd",
  "jti": "kQ7m...",
  "iat": 1780000000,
  "exp": 1780000900,
  "garm_grant": {
    "tool": "payments.v1.initiate_payment",
    "subject": "customer:C-8123",
    "task": "tsk_d19f4c",
    "material": "sha256:...",
    "approver": "employee:jdoe",
    "approver_clearance": "RESTRICTED",
    "approver_compartments": ["financial"]
  }
}
```

- **There is no `act` key, and the minted struct has no field that could
  produce one.** A delegated identity may not approve — otherwise an agent
  could approve the destructive action it is itself about to take. An
  approver token carrying an `act` claim is refused outright (the *key*,
  not its value: a null `act` is still a token that claimed a chain), and
  `garmd` refuses a grant that carries one. Both ends enforce it, because
  the rule's purpose is to survive a dishonest issuer, and either end alone
  only survives an honest one.
- **The approver must be `employee` kind**, decided by `TrustedIssuer.Kind`
  — per-issuer configuration, never sniffed from the token, exactly as on
  the direct door. A customer cannot approve a payment.
- **The claim is `task`; the request field is `task_id`.** The names differ
  on purpose and neither moves alone: `task_id` is what `studiod` sends, and
  `task` is what the shared reader
  (`github.com/garm-ai/contracts/grants.ParseClaims`) reads and what the
  contract declares. `garmd`'s own copy currently reads either spelling, but
  that is one reader being generous rather than a second permitted name, so
  this service mints `task` alone — the same fact under two keys in one
  signed credential would be two things to keep in step. The value is copied
  in **verbatim**, never looked up: this service holds no tasks, and copying
  is exactly what binds one grant to one task, since two tasks over identical
  material (the same payment asked twice) digest identically.
- **`task_id` is optional, and an absent task means an absent claim.** Not
  every approval is on a task: one spent at `garmd`'s direct door carries
  none, and `garmd` reads no task claim. Such a request mints a grant with
  **no `task` key at all** rather than an empty one, because
  `grants.CheckTask` distinguishes the two — an absent claim is refused with
  "the grant carries no task claim, so it approves the material rather than
  this decision", which is the true reason. A `task_id` that is *present but
  blank* is refused here instead: sending the field says the caller has a
  task in mind, and minting a blank binding would produce a grant
  `tasksd`'s `decide_task` is certain to refuse in front of the person who
  already clicked approve.
- **`approver` is built by the same `identityForKind` the direct door uses**,
  so a persona token already carrying `employee:jdoe` does not become
  `employee:employee:jdoe`, and a subject whose prefix contradicts its
  issuer's kind is refused rather than repaired.
- **`material` is a digest, computed by `grant.Digest` from
  `github.com/garm-ai/contracts/grant`** — the *same function* `garmd`
  recomputes it with, a module dependency rather than a second
  implementation. That package used to live at
  `github.com/garm-ai/garm/contracts/grant`; the contract is now a module of
  its own and `garm` is only the CLI, so this service depends on the
  contract and not on a command-line tool. The function itself is unchanged
  byte for byte across the move, which is why no grant already minted means
  anything different. Two independent derivations of one string is a divergence
  waiting to happen: if the sides ever disagree byte for byte, every
  approval is refused or — worse — one matches a request the approver never
  saw, and neither side can detect that alone. This service digests what it
  is **given** and never resolves a path itself, which is why it needs no
  descriptors and no catalogue; a caller lying about the values is not a
  hole, because `garmd` re-extracts from the real request and compares.
- **`approver_clearance` and `approver_compartments` are *recorded*, not
  judged.** They are read off the approver's own verified token's `garm`
  claim (both spellings — `RESTRICTED` and `CLEARANCE_RESTRICTED` — are
  accepted, and compartments are sorted so one approver's identical
  decision never mints two different grants). Whether that authority meets
  what the tool requires is `garmd`'s question: it has the catalogue, this
  service does not. An approver whose token asserts *no* usable authority
  is refused here, though — a grant recording none is one `garmd` rejects
  with a message about an under-cleared approver, which sends an operator
  looking at the wrong system.
- **There is no `approved_at`.** A separate approval timestamp would be a
  mechanism to re-mint an old decision with a fresh expiry, and `iat` is
  what `garmd` measures a grant's age from against the tool's
  `max_grant_age_seconds`. That limit is a ceiling this service cannot
  raise: `Options.ApproveTTL` (default 15 minutes) only bounds the grant's
  own `exp`, so a tool asking for five minutes gets five however generous
  the default is.
- **Every refusal is the same opaque `400 {"error":"access_denied"}`** that
  `POST /token` returns, with the reason on the log and never in the
  response — otherwise this endpoint is an enumeration oracle for which
  tools exist and who may approve them. The one exception is a wrong HTTP
  method, which is `405` with an `Allow` header: it names no tool and no
  approver, and answering `400` to a `GET` would make the endpoint harder
  to operate for nothing.

### What `/approve` refuses

Every row below is one of those opaque `400`s. In the order they are
checked:

| Refusal | Detail |
|---|---|
| the `Content-Type` media type is not `application/json` | parameters such as `; charset=utf-8` are accepted; only the media type is compared |
| the body exceeds 64 KiB (`maxApproveBody`) | an unauthenticated caller cannot make this service read an unbounded body before anything about it is verified |
| a duplicate top-level JSON key | one legal object where `encoding/json`'s last-wins decode would approve a different request than a reader sees |
| an unknown JSON field | a misspelled key is a request that silently approves something other than what the caller meant |
| more than one JSON value in the body | same reasoning as the unknown-field check above |
| `client_assertion_type` names anything but the one accepted kind | as `POST /token` |
| `client_assertion` fails authentication | see "The client assertion" above — wrong client, bad signature, expired, or replayed `jti` |
| no bearer token, or a non-`Bearer` `Authorization` header | the approver's own credential is missing |
| the approver's bearer token fails JWKS verification | |
| the approver token carries an `act` claim | the *key*, not its value — a delegated identity cannot approve |
| the approver's issuer is not configured `kind: employee` | a customer cannot approve |
| the approver's subject carries a kind prefix its issuer does not assert | the same doubling rule `identityForKind` enforces on the direct door |
| the approver's token asserts no usable `garm` authority | nothing to record |
| `tool` is not a well-formed FQN (`pkg.name`) | shape-only; this service holds no catalogue |
| `subject` is not type-prefixed | e.g. `customer:C-8123` |
| `task_id` is present but blank | omitting it entirely is a different request, and a legitimate one |
| a `material` path is rejected by `grant.ValidPath` | would forge a separator in the digest |

## What is NOT built

- **A runner.** This service mints *for* one (exchange 2 above, gated on a
  `can_run` tuple), but the runner itself is `garm-ai/agentd`, not part of
  this service. It does not execute agents, and it has no view of whether a
  run happened.
- **`subject_kind: SERVICE`.** The field is accepted and validated, and a
  `SERVICE` subject is refused: the claims policy resolves authority from
  segment membership and `ForSegments` always mints `kind: USER`. A service
  principal has no path through it, and inventing one here would be
  inventing policy.
- **The NATS auth callout integration** is not part of this service.
- **Queueing for approvals.** `POST /approve` is stateless: a request
  arrives carrying everything and a grant leaves. Nothing here holds pending
  approvals, notifies an approver, or renders a screen — that is product
  surface above this, and the grant format does not depend on it.
- **Multi-party approval and revocation.** One grant, one approver; a grant
  is valid until it expires or is spent. Short lifetimes are the mitigation
  and a revocation list is not built.
- **Deciding whether an approver is allowed to approve.** This service
  *attests* — it records who approved and what authority their own token
  asserted — and `garmd` *decides*, because the catalogue is what knows
  a tool's `approver_min_clearance`, its required compartments, and its
  `max_grant_age_seconds`. An approver whose clearance does not meet a
  tool's bar receives a grant that `garmd` then refuses: a poor experience,
  deliberately, and not a hole. The one rule neither service holds is the
  four-eyes exclusion — the run's own subject may not approve its own task —
  which the runner enforces at the inbox (`agentd`'s task predicate), where
  the run is known.
- **Single-use enforcement of a grant's `jti`.** Every grant carries a fresh
  one, and spending it at most once is `garmd`'s side of the contract; this
  service keeps no record of the grants it has minted.
- **Any notion of what a tool is.** `/approve` checks that `tool` has the
  shape of an FQN (`pkg.name`, never a `/pkg.Service/Method` route, which
  would match nothing on the far side) and nothing more. Whether it exists,
  whether it requires approval at all, and which of its fields are material
  are all questions for the catalogue this service does not hold.
- **A second `Authorizer` implementation beyond these two.** There are
  two, and which one a binary has is fixed when it is built, not at
  runtime. An **untagged** build uses `LoadStaticAuthorizer`
  (`authz_static.go`): a flat YAML file of already-resolved tuples (see
  `deploy/tuples.yaml`, whose four top-level keys — `can_invoke`,
  `handled_by`, `in_segment`, `can_run` — name the `Authorizer` interface's
  four methods directly) — it resolves no graph, so a segment granting an
  agent entitlement is not followed transitively; every relation must be
  written in its already-resolved form. That is the dev/CI authorizer. A
  build with **`-tags openfga`** uses the OpenFGA-backed one
  (`authz_openfga.go`), against `deploy/model.fga`'s relations — that is
  the production authorizer, and `authz_openfga_parity_test.go` proves the
  two answer the same questions identically. The two build files
  (`cmd/sts/authz_static.go`, `cmd/sts/authz_openfga.go`) carry mutually
  exclusive build tags, so exactly one is ever compiled in.

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

- `issuer`, `audience`, `tokenEndpointAudience`, `listen` (defaults to
  `:8080` if omitted)

  > **`audience` must match garmd's `--audience`.** This service ships
  > `audience: garm://garmd`, and `garmd`'s `--audience` flag **defaults to
  > `garm`**. A garmd started on that default refuses *every* token this
  > service mints, on audience mismatch — correct behaviour, and thoroughly
  > mystifying to debug, since nothing is wrong with the token, the key, or
  > the exchange. Start garmd with `--audience garm://garmd`, or whatever
  > this service's `audience` is set to. The value here is deliberately not
  > changed to garmd's default: `garm://garmd` is the more correct
  > identifier, and garmd's audience is explicitly configurable.
  >
  > **`tokenEndpointAudience` is a *different* audience**, easily confused
  > with the one above: it is the `aud` a `client_assertion` must carry to
  > authenticate to *this* service's own `POST /token` and `POST /approve`
  > (see "The client assertion"), whereas `audience` is what this service
  > mints into every *delegation token it issues*, for `garmd` to check.
  > One is who is allowed to call this service; the other is who this
  > service's own tokens are for. Confuse them and a BFF's otherwise
  > correct client assertion is refused as carrying the wrong audience.
- `delegationTTL` — how long a minted **delegation token** (`POST /token`,
  either door) is valid, as a Go duration string (`10m`). Omitted or `0`, it
  is `NewServer`'s own default (10 minutes) rather than a second default
  living here, for the same reason `approve.ttl_seconds` isn't defaulted in
  `LoadConfig` either. It bounds a different thing than `approve.ttl_seconds`
  below: a delegation token is a session, a grant is a decision, and the two
  are not meant to expire on the same schedule. Unlike `approve.ttl_seconds`
  below, a **negative** value is not rejected at startup — `LoadConfig`
  only checks that the string parses as a duration — it is silently
  replaced by the same 10-minute default at `NewServer`'s `<= 0` check, so a
  misconfigured `-10m` behaves exactly like an omitted key, with no
  diagnostic naming the mistake.
- `keys.active` and `keys.keys[]` — at least one signing key; `active` must
  name one of them. **Signing keys are never inlined.** Each key's `pem`
  field is a reference to an environment variable (`$NAME` or `${NAME}`)
  holding the PEM-encoded ECDSA P-256 private key — `LoadConfig` rejects
  literal key material in this field outright. Retired keys can stay listed
  (served for verification, never signed with) during rotation.
- `issuers[]` — at least one trusted upstream issuer, each requiring a
  non-empty `name` (a label, used only in error messages), `iss`, `jwks`
  (the JWKS URL `Verifier` fetches from), a non-empty `audience`, and a
  `kind` of `customer` or `employee`. Two entries may not share an `iss`:
  the verifier keys on it, so a duplicate would silently keep only the
  last entry's `kind` — and `kind` decides whether
  `instanceAuthorization`'s clearance cap applies.
- `clients[]` — at least one service allowed to authenticate with
  `private_key_jwt` to **both** `POST /token` and `POST /approve` — a BFF,
  and/or the agent runner (`deploy/config.yaml` registers `agentd`, the
  runner, alongside `shop-bff`, the BFF). Client keys are *public* keys,
  not secrets, so they may be a file path or inlined PEM directly, and each
  client may register **more than one** (`ClientConfig.PEMs` is a slice) —
  see "The client assertion" above for why: it is what rotation looks like.
  A client's id matters beyond authentication: it is what makes the
  `runner:<id>` identity the governed door's `CanRun` is asked about
  (`"runner:" + the AUTHENTICATED client id`, never a field a caller
  supplies — see `deploy/tuples.yaml`'s `can_run` tuples: this repository's
  own example ships **two**, one for `agentd`, the real runner, and one for
  `conformance-client`, the id garmd's identity-conformance job
  authenticates with). A config with no clients would serve a JWKS and
  deny every `POST /token` and `POST /approve` as an unknown client, so an
  empty list is a startup failure.
- `policy` — path to the claims policy file (`LoadPolicy`, `claims.go`).
- `authz.static` — path to the static authorizer tuples file
  (`LoadStaticAuthorizer`, `authz_static.go`). Used by an **untagged**
  build. Required in every config, since `LoadConfig` does not know which
  binary will read it.
- `authz.openfga.apiUrl`, `authz.openfga.storeId`, `authz.openfga.modelId`
  — the OpenFGA store the **`-tags openfga`** build checks against.
  `LoadConfig` always parses this block; an untagged binary ignores it
  entirely, and an `-tags openfga` binary refuses to start without
  `apiUrl` and `storeId`. `modelId` is optional but should be set in
  production: an unpinned store silently reinterprets every check the
  moment a new model version is written.
- `instanceAuthorization.status` — must be exactly `enforced` or `absent`.
- `instanceAuthorization.unconfinedCeiling` — if set, must be one of the
  four clearance names.
- `approve.ttl_seconds` — how long a `POST /approve` grant is valid.
  Snake_case where its neighbours are camelCase: the cross-repository
  interface contract names it that way, and renaming it would rename an
  operator's key out from under them. Omitted (or `0`), it is `NewServer`'s
  own default (15 minutes) rather than a second default living here — a
  config that omits the key and a `Server` built directly in Go cannot
  disagree about it. This is only ever a floor on staleness: a tool's own
  `max_grant_age_seconds` is a ceiling `POST /approve` cannot raise, so a
  generous value here still yields whatever a stricter tool asks for. A
  **negative** value is, unlike a negative `delegationTTL` above, a
  **startup failure**: `LoadConfig` rejects it outright — a grant that
  expires before it is minted is refused by every verifier that sees it —
  rather than silently falling back to the default.

`(*Config).Build(ctx, authz)` wires a loaded `Config` into a running
`*Server`. It takes the `Authorizer` as a parameter rather than building one
itself: which implementation a binary has is decided by its build tag —
static when untagged, OpenFGA under `-tags openfga` — in
`cmd/sts/authz_static.go` / `cmd/sts/authz_openfga.go`, not by `Config`.

## Running it

Once started, `stsd.Serve` serves four routes: `POST /token` (both
exchanges), `POST /approve` (the grant-minting endpoint), the JWKS at
`/.well-known/jwks.json`, and the metadata document at
`/.well-known/oauth-authorization-server`.

```bash
# The dev/CI binary: the flat, file-backed authorizer (deploy/tuples.yaml).
go build ./cmd/sts

# The production binary: the OpenFGA-backed authorizer. Same binary name,
# same config file, different Authorizer compiled in — it additionally
# requires authz.openfga.apiUrl and authz.openfga.storeId to be set, and
# refuses to start without them.
go build -tags openfga ./cmd/sts

# Generate an ES256 signing key and a client keypair per registered
# service (shop-bff, agentd). All of them must be ECDSA (or RSA) — EdDSA
# is deliberately excluded from every algorithm allowlist this service
# accepts, in both directions.
./deploy/keygen.sh
export STS_SIGN_KEY_K1="$(cat sts-sign-k1.pem)"

./sts -config deploy/config.yaml
```

Whichever build you run, **start `garmd` with `--audience garm://garmd`**
(or whatever this service's `audience` is configured to mint). `garmd`'s
own default is `garm`, and a garmd left on it rejects every token from this
service on audience mismatch — see the note in the Configuration section
above.

```bash
curl -s localhost:8080/.well-known/jwks.json
# {"keys":[{"use":"sig","kty":"EC","kid":"k1","crv":"P-256","alg":"ES256", ...}]}
```

`deploy/config.yaml` ships with `listen: :8080` and no TLS configured — it
is a local/dev config, and the service loudly warns on startup that it is
serving plaintext. Set `STS_TLS_CERT` and `STS_TLS_KEY` (paths to a
certificate and key) in production, or terminate TLS in front of it at a
proxy or mesh sidecar; `stsd.Serve` refuses to pretend plaintext is
fine, but it does not refuse to run without TLS, since a sidecar is a
legitimate place to terminate it.

Shutdown is signal-aware (`SIGINT`/`SIGTERM`) and graceful, with a 5 second
timeout for in-flight requests to finish. `cmd/sts/main.go` turns the signal
into a cancelled context and `stsd.Serve` drains on it, so there is one
shutdown path rather than one per caller.

### Running it in-process

The binary is the way you run this service. `stsd.Serve(ctx, stsd.Config{…})`
exists so `garm-ai/stack`'s `garmstack` can run garmd, the STS and agentd as
goroutines in one process for local development and demonstration — each
still speaking HTTP and NATS to the others. That single-process mode is
never for production: one process holding this service's signing key,
agentd's client key and garmd's verifier configuration is one compromise
away from all three.

## The metadata document

`GET /.well-known/oauth-authorization-server` (`metadata.go`), unauthenticated
by design — everything in it is already discoverable by anyone who can
obtain one token, and a verifier has to read it *before* it holds any
credential of its own. It follows RFC 8414 where RFC 8414 has a field for
what's meant, plus two extensions this service's one downstream needs:

| Field | Value |
|---|---|
| `issuer` | `cfg.Issuer`, verbatim |
| `jwks_uri` | `<issuer>/.well-known/jwks.json` |
| `token_endpoint` | `<issuer>/token` |
| `grant_types_supported` | `["urn:ietf:params:oauth:grant-type:token-exchange"]` |
| `token_endpoint_auth_signing_alg_values_supported` | `["ES256"]` |
| `garm_audience` | `cfg.Audience` — the field a verifier actually has to agree with; RFC 8414 has no field for the audience an authorization server *mints* |
| `garm_approve_endpoint` | `<issuer>/approve` — RFC 8414 has no field for a second, non-OAuth endpoint either |

**The trap:** `stsd.Serve` builds every URL above by
string-concatenating `cfg.Issuer` with a path
(`cfg.Issuer+"/.well-known/jwks.json"`, and so on) — there is no separate
"public base URL" setting. `issuer` therefore has to be the actual,
externally reachable base URL this service is served at, not merely a
stable *identifier*. An `issuer` that is a fine identity but unreachable
from outside (a cluster-internal DNS name, say, when the service is
actually fronted by a different public hostname) makes this document
advertise a `jwks_uri` and `token_endpoint` that nothing outside the
cluster can fetch — and it will look, to whoever reads it, exactly like a
correctly-configured document, because nothing here checks reachability.

## Repository layout

| File | What it is |
|---|---|
| `keyring.go` | Signs tokens (ES256), serves the JWKS |
| `issuer.go` | Verifies upstream tokens against their issuer's JWKS |
| `claims.go` | The claims policy: roles, segments, agent authority |
| `authz.go` | The `Authorizer` interface — four yes/no questions |
| `authz_static.go` | A flat, file-backed `Authorizer` (dev/CI; untagged builds) |
| `authz_openfga.go` | The OpenFGA-backed `Authorizer` (production; `-tags openfga`) |
| `clients.go` | `private_key_jwt` client authentication + replay protection |
| `exchange.go` | The `POST /token` handler: both doors, in order, and the one minting path they share |
| `approve.go` | The `POST /approve` handler: mints the grant that records a human's yes |
| `metadata.go` | Serves the discovery document at `/.well-known/oauth-authorization-server` |
| `config.go` | Loads and validates `deploy/config.yaml`'s shape, wires a `Server` |
| `cmd/sts/main.go` | The binary: flags, the environment, the signal context |
| `stsd/stsd.go` | `Serve`: the routes, the HTTP server and the drain — what the binary and `garmstack` both run |
| `cmd/sts/authz_static.go`, `cmd/sts/authz_openfga.go` | Which `Authorizer` this build gets — mutually exclusive build tags |
| `deploy/config.yaml` | A complete, loadable example configuration |
| `deploy/claims.yaml` | An example claims policy |
| `deploy/tuples.yaml` | An example static-authorizer tuple file |
| `deploy/keygen.sh` | Generates a signing key and a client keypair per registered service (shop-bff, agentd) |
| `deploy/model.fga` | The OpenFGA authorization model backing the four `Authorizer` checks |
| `deploy/tuples.openfga.yaml` | The same example facts as `deploy/tuples.yaml`, in OpenFGA's derived encoding |

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
- **`on_behalf_of` is asserted, never verified.** The governed door has no
  IdP token to check it against, so `CanRun` is the whole of what makes it
  acceptable: a written tuple saying this runner may execute this agent.
  It is asked **before** `CanInvoke`, deliberately — asking `CanInvoke`
  first would answer "may this subject reach that agent" for anyone holding
  any valid client assertion, turning the refusal into an entitlement
  oracle. Keep `can_run` tuples as tight as `handled_by` ones; remove the
  gate and `on_behalf_of` becomes an impersonation field.
- **Identities are prefixed exactly once.** A subject that already carries
  its issuer's kind (`employee:jdoe`) is used as is, a bare one is prefixed,
  and one whose prefix contradicts its issuer — or which would double into
  `employee:employee:jdoe` — is refused rather than repaired. A doubled
  identity matches no tuple, and the resulting miss is indistinguishable
  from an ordinary denial, which sends an operator to their tuple store
  instead of to their token.
- **Algorithm allowlist.** Both upstream token verification and client
  assertion verification share one allowlist (`permittedAlgorithms`):
  ES256/384/512, RS256/384/512, PS256/384/512. `none` and any HMAC
  algorithm are excluded because there would be nothing to check a
  signature against; EdDSA is excluded to match `garmd`'s own verifier.
- **A delegated identity cannot approve**, and it is enforced twice: this
  service refuses to mint from an approver token carrying `act`, and `garmd`
  refuses a grant that carries one. Either alone suffices for an honest
  issuer; both are required because the rule exists to survive a dishonest
  one.
- **A runner's identity is derived, never supplied.** Exchange 2's
  `runner:<id>` comes from the client id the caller authenticated as. There
  is no form field for it.
- **The approval endpoint holds no state.** No pending approvals, no
  queue — so there is nothing here for an attacker to enumerate or exhaust,
  and the only rate limit that matters is the client-assertion replay cache
  described above.
