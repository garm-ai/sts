# sts — a small RFC 8693 token service backed by OpenFGA

A single-binary Go security token service that sits between your BFFs and the
NATS auth callout. It does the two token exchanges the agent-on-behalf-of flow
needs, verifies every presented token against its issuer's JWKS, and asks
OpenFGA the relationship questions — so authorization lives in one place and the
human IdP (Zitadel for customers, Entra for employees) stays swappable.

```
customer/employee IdP ─┐
   (verify subject)     │        ┌── gate 1: may this human invoke this agent?
                        ▼        │
BFF ──exchange 1──▶  ┌───────┐  ─┤   (OpenFGA)
                     │  STS  │   └── mints delegation token (sub=human, aud=agent, may_act)
runner (k8s/SPIRE) ─▶│       │
   (verify actor)    └───────┘  ─┐  gate 3: may this runner run this agent?
                        │         │  (OpenFGA)
                        └─exchange 2─▶ mints OBO token (sub=human, act={agent, act:{runner}})
                                        │
                                        ▼  verified against the STS's JWKS
                                  NATS auth callout ─▶ NATS user JWT
```

## What each mechanism does (the part that was confusing)

- **SPIRE / k8s** issue *workload* identity. They prove "this is a real runner." They mint nothing about humans or agents.
- **This STS** *transforms* tokens under policy. It is the only thing that mints delegation and OBO tokens.
- **OpenFGA** answers "may X do Y." It issues nothing; the STS calls it mid-exchange.

They are a pipeline, not alternatives. The STS trusts SPIRE/k8s and the IdPs only as **JWKS issuers** it verifies incoming tokens against; it is itself the issuer of the tokens it mints.

## The two exchanges

**Exchange 1 — human → agent (delegation).** The BFF (authenticated as itself with `private_key_jwt`) trades the customer/employee token for a delegation token addressed to one agent, carrying only the task's scopes and a `may_act` naming the agent. Gate 1 (`can_invoke`) is checked here. For an employee acting for a customer, pass `requested_subject=customer:…`; the STS checks `handled_by` and sets `sub`=customer, `act`={employee}.

**Exchange 2 — runner + delegation → on-behalf-of.** The runner presents the delegation as `subject_token` and its own k8s/SPIRE token as `actor_token`, audience `nats`. Gate 3 (`can_run`) is checked here. The STS mints the OBO token: `sub` = the human, `act` = `{sub: agent, act: {sub: runner}}`, scope = delegation ∩ request ∩ the target's ceiling.

### Act chain semantics

Tokens carry typed principals (`customer:C`, `agent:order-assistant`, `runner:agent-runner`) in both `sub` and `act`, so the NATS callout reads them directly without per-issuer subject mapping. The `act` chain is authority-then-execution: the agent is the current actor, an employee link (when staff acts for a customer) nests next, and the runner is the deepest link recording where it ran.

```
customer-direct:        sub=customer:C  act={agent, act:{runner}}
employee-for-customer:  sub=customer:C  act={agent, act:{employee, act:{runner}}}
```

## Run it

```bash
go mod tidy
./deploy/keygen.sh                       # prints a signing seed, writes BFF keys
export STS_SIGN_SEED_K1=<from keygen>
go build ./cmd/sts                       # static authorizer (dev)
./sts -config deploy/config.yaml
```

For production authorization, build with OpenFGA and point it at your store:

```bash
go build -tags openfga ./cmd/sts
export OPENFGA_STORE_ID=… OPENFGA_MODEL_ID=…
# load deploy/model.fga and deploy/tuples.openfga.yaml with the fga CLI first
```

Verify tokens downstream (the NATS callout) against `https://<issuer>/.well-known/jwks.json`.

## How it plugs into what you already have

- **BFF**: terminate the customer/employee IdP session at the BFF; call `POST /token` for exchange 1 with `client_assertion`. The human token never travels past the BFF — only the minted delegation token does.
- **Runner/broker**: the runner obtains its k8s SA token or SPIRE SVID (audience `sts`) and calls `POST /token` for exchange 2. This service *is* the runner→agent broker: it verifies the workload identity and checks `can_run`.
- **NATS callout** (the `natsacl` module): add the STS issuer to its trusted issuers, pointing at the STS JWKS. Map the callout's `principal` from `sub` and expose `act.sub` as the `actor` for manifest rules. The agent reaches only its tenant's subjects because tenant flows from the token.

## What runs vs. what to wire

The core exchange logic (client auth, multi-issuer verification, both gates, scope intersection, act-chain construction, TTL capping) is exercised by `sts/server_test.go` and passes against `golang-jwt`. Two integration edges were written but not compiled here (the sandbox couldn't fetch `gopkg.in`/`golang.org`/the OpenFGA SDK): the `keyfunc/v3` JWKS wiring in `config.go` and the OpenFGA client in `authz_openfga.go`. Run `go mod tidy && go test ./... && go build -tags openfga ./...` and expect only minor SDK-name adjustments (the OpenFGA `client.Check` shape in particular).

## Security notes — read before production

- **TLS**: set `STS_TLS_CERT`/`STS_TLS_KEY` or terminate TLS at a mesh sidecar. The STS refuses to pretend plaintext is fine.
- **Client-assertion replay**: the `jti` single-use cache is in-memory. With multiple replicas, back it with a shared store (NATS KV / Redis) or you lose replay protection across instances.
- **Sender-constraining**: consider DPoP or mTLS-bound tokens so a stolen OBO token can't be replayed from elsewhere. Not implemented here.
- **`requested_subject`**: only honored after a `handled_by` check. Keep that check strict — it's the line between "employee helps a customer" and "employee impersonates a customer."
- **Scope ceilings**: the OBO target ceiling is the last backstop. An agent manifest can narrow further at the callout, but the STS should never mint beyond the ceiling.
- **Fail closed**: any verification error, missing claim, or OpenFGA error denies. The caller always gets an opaque `access_denied`; the reason is in the logs only.
- **RunnerID / HumanKind**: the defaults map `sub` naively. Set `Options.RunnerID` to parse k8s `kubernetes.io` claims into `runner:<ns>/<sa>`, and `Options.HumanKind` to distinguish employees from customers by issuer or a group claim.

## Entra / Zitadel note

Neither IdP calls OpenFGA during token exchange in a way you'd want to depend on — Entra's only outbound seam is a sign-in claims extension (enrichment, not an enforced gate), and Zitadel's token-exchange + external-authz is feature-flagged and limited. That's the reason this STS exists: the IdPs authenticate humans, and this service owns every exchange and every OpenFGA check. Verify whether your IdP can accept a SPIFFE JWT-SVID as `actor_token` before relying on it; if not, this STS is where that gap is closed.
