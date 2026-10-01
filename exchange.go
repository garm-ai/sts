// This file implements the RFC 8693 token exchange handler: the point where
// every other unit in this package (keyring, issuer, claims, authz, clients)
// converges to mint the delegation token garmd verifies.
//
// The order below is fixed and matches spec §3.2 exactly, because it is not
// arbitrary: everything up to and including can_invoke is authentication —
// deciding who is asking — and everything after is authorization — deciding
// what they may have. Reordering these is not a refactor, it is a policy
// change.
package sts

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// grantTypeTokenExchange is the only grant_type this endpoint accepts.
const grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// clientAssertionTypeJWTBearer is the only `client_assertion_type` this
// service accepts, at either endpoint (RFC 7523 §2.2). The field itself is
// OPTIONAL — private_key_jwt is the only client authentication this service
// implements, so an absent type is unambiguous — but a present one that
// names something else is refused rather than ignored: a caller that
// believes it is presenting a different kind of assertion has already
// diverged from what this endpoint will do with it, and silently accepting
// the field while disregarding its value is how that divergence survives to
// production.
const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// issuedTokenType is the `issued_token_type` this endpoint always reports:
// every minted token is a JWT.
const issuedTokenType = "urn:ietf:params:oauth:token-type:jwt"

// defaultDelegationTTL is used when Options.DelegationTTL is left zero.
const defaultDelegationTTL = 10 * time.Minute

// deniedBody is THE single response body for every denial this SERVICE can
// produce, from either endpoint, whatever the reason. An unknown agent, a
// missing handled_by relation, an under-privileged caller, a malformed
// request and an approver who is not an employee all look identical to the
// caller: distinguishing them would make these endpoints an enumeration
// oracle for which tools exist and who may approve them. The reason always
// goes to the log, never the response.
const deniedBody = `{"error":"access_denied"}`

// InstanceAuthzConfig is the required assertion about whether the tool plane
// (garmd) enforces record-level confinement (its FGAChecker, step 4) yet.
// See spec §3.5: this is an assertion, not a measurement — the STS cannot
// observe garmd's configuration, it can only be told.
type InstanceAuthzConfig struct {
	// Status is "enforced" or "absent". Required: there is no default, on
	// purpose. An operator must say which is true.
	Status string

	// UnconfinedCeiling is read ONLY when Status is "absent". Empty means
	// refuse every customer-kind mint outright. Set, it names the clearance
	// (bare spelling, e.g. "PUBLIC") that a customer-kind token is capped
	// at, whatever the claims policy would otherwise grant.
	UnconfinedCeiling string
}

// Options configures a Server. Every field except DelegationTTL and Log is
// required; NewServer fails loudly on a missing one rather than let a nil
// dependency panic on the first request.
//
// There is deliberately no AgentAudPrefix here. An earlier sketch put the
// agent in `aud` and used a prefix to decide whether an audience meant a
// delegation; this design puts garmd's identifier in `aud` unconditionally
// and the agent in `act.sub` (spec §1.2), so there is nothing left for such
// a prefix to decide.
type Options struct {
	// Issuer is this service's own `iss`, minted into every token.
	Issuer string
	// Audience is garmd's identifier, minted into every token's `aud`. It is
	// never the agent — the agent is named at `act.sub`.
	Audience string

	Keyring  *Keyring
	Verifier *Verifier
	Policy   *Policy
	Authz    Authorizer
	Clients  *ClientRegistry

	// DelegationTTL bounds how long a minted token is valid. Defaults to 10
	// minutes if zero or negative.
	DelegationTTL time.Duration

	// ApproveTTL bounds how long a minted GRANT is valid. Defaults to 15
	// minutes if zero or negative.
	//
	// Separate from DelegationTTL because they bound different things: a
	// delegation token is a session and an approval is a decision. And it is
	// only ever a floor on staleness, never a ceiling — the tool's own
	// max_grant_age_seconds is a limit this cannot raise (approval-grants
	// §2.3), so a tool asking for five minutes gets five whatever is set
	// here.
	ApproveTTL time.Duration

	InstanceAuthz InstanceAuthzConfig

	// Log receives every denial reason and every instance-authorization cap.
	// Defaults to slog.Default().
	Log *slog.Logger
}

// Server is the token exchange: POST /token, RFC 8693.
type Server struct {
	issuer   string
	audience string
	keyring  *Keyring
	verifier *Verifier
	policy   *Policy
	authz    Authorizer
	clients  *ClientRegistry
	ttl      time.Duration

	// approveTTL is the grant TTL, separate from ttl for the reason
	// Options.ApproveTTL gives.
	approveTTL time.Duration

	instance InstanceAuthzConfig
	log      *slog.Logger
}

// NewServer validates Options and builds a Server. Every check that can be
// made at construction is made here, not discovered later at the first
// request — the same convention claims.go's LoadPolicy follows.
func NewServer(opts Options) (*Server, error) {
	if opts.Issuer == "" {
		return nil, fmt.Errorf("sts: exchange: Issuer is required")
	}
	if opts.Audience == "" {
		return nil, fmt.Errorf("sts: exchange: Audience is required")
	}
	if opts.Keyring == nil {
		return nil, fmt.Errorf("sts: exchange: Keyring is required")
	}
	if opts.Verifier == nil {
		return nil, fmt.Errorf("sts: exchange: Verifier is required")
	}
	if opts.Policy == nil {
		return nil, fmt.Errorf("sts: exchange: Policy is required")
	}
	if opts.Authz == nil {
		return nil, fmt.Errorf("sts: exchange: Authz is required")
	}
	if opts.Clients == nil {
		return nil, fmt.Errorf("sts: exchange: Clients is required")
	}

	switch opts.InstanceAuthz.Status {
	case "enforced":
		// UnconfinedCeiling is not read in this mode; its presence is not an
		// error, it is simply inert (spec §3.5: "only read when absent").
	case "absent":
		if opts.InstanceAuthz.UnconfinedCeiling != "" {
			if _, ok := clearanceOrder[opts.InstanceAuthz.UnconfinedCeiling]; !ok {
				return nil, fmt.Errorf("sts: exchange: instanceAuthorization.unconfinedCeiling %q is not a known clearance",
					opts.InstanceAuthz.UnconfinedCeiling)
			}
		}
	default:
		return nil, fmt.Errorf("sts: exchange: instanceAuthorization.status must be \"enforced\" or \"absent\", got %q",
			opts.InstanceAuthz.Status)
	}

	ttl := opts.DelegationTTL
	if ttl <= 0 {
		ttl = defaultDelegationTTL
	}

	approveTTL := opts.ApproveTTL
	if approveTTL <= 0 {
		approveTTL = defaultApproveTTL
	}

	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	return &Server{
		issuer:     opts.Issuer,
		audience:   opts.Audience,
		keyring:    opts.Keyring,
		verifier:   opts.Verifier,
		policy:     opts.Policy,
		authz:      opts.Authz,
		clients:    opts.Clients,
		ttl:        ttl,
		approveTTL: approveTTL,
		instance:   opts.InstanceAuthz,
		log:        log,
	}, nil
}

// --- wire shapes ------------------------------------------------------

// garmClaimJSON is the wire shape of one `garm` claim, matching garmd's
// authn.ParseClaims field for field: clearance, compartments, verbs,
// tool_sets, kind.
type garmClaimJSON struct {
	Clearance    string   `json:"clearance"`
	Compartments []string `json:"compartments,omitempty"`
	Verbs        []string `json:"verbs,omitempty"`
	ToolSets     []string `json:"tool_sets,omitempty"`
	Kind         string   `json:"kind"`
}

// actClaimJSON is one `act` level. The OUTER one is never a pointer field on
// mintedToken below: Go always marshals a struct value, which makes it
// impossible for this package to silently omit the first `act` level by
// leaving a pointer nil. A nested Act is a pointer because it is genuinely
// optional: it is present only on the employee-for-customer-to-an-agent
// path, where the chain is customer (sub) -> agent (act) -> employee
// (act.act) — RFC 8693 §4.1: the outermost act is the CURRENT actor, a
// nested act is a PRIOR one, so the agent (who acts now) sits outside the
// employee (who acted earlier, to obtain this token).
type actClaimJSON struct {
	Subject string        `json:"sub"`
	Garm    garmClaimJSON `json:"garm"`
	Act     *actClaimJSON `json:"act,omitempty"`
}

// execClaimJSON is provenance, and deliberately not authority.
//
// sts-design §4.1: a runner placed in the `act` chain must either assert a
// garm claim it has no business asserting, or carry an all-permissive one
// that contributes no narrowing — which reads as authority to everyone who
// later looks at a token or a ledger row, and which a typo turns real. So
// the runner is recorded here instead: a top-level claim, outside the act
// chain, that authn.Fold never touches.
//
// Two fields, no more. garmd refuses an exec that is present but is not an
// object with a non-empty sub (program plan §3.8), and a third field here
// would be authority nobody agreed to carry.
type execClaimJSON struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss"`
}

// mintedToken is the exact shape spec §1.2 mints. There is no `scope` claim
// anywhere in this type: the `garm` claim replaces it entirely.
type mintedToken struct {
	Issuer    string        `json:"iss"`
	Audience  string        `json:"aud"`
	Subject   string        `json:"sub"`
	ExpiresAt int64         `json:"exp"`
	IssuedAt  int64         `json:"iat"`
	ID        string        `json:"jti"`
	Tenant    string        `json:"tenant"`
	Garm      garmClaimJSON `json:"garm"`
	Act       actClaimJSON  `json:"act"`

	// Exec is a POINTER with omitempty so exchange 1 emits no `exec` key at
	// all — not a null, not an empty object. "Was this token obtained by a
	// runner" must be answerable from the token's shape, and an always-
	// present key whose contents happen to be blank does not answer it.
	Exec *execClaimJSON `json:"exec,omitempty"`
}

// tokenResponse is the RFC 8693 §2.2.1 success response.
type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

// Handler returns the POST /token handler. Mounting it, and the Keyring's
// own JWKS handler, at their respective paths is Task 7's job.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveToken)
}

// Keyring returns the Server's Keyring, so a caller (stsd.Serve) can
// mount its JWKS handler alongside Handler() without constructing a second,
// redundant Keyring from the same configuration.
func (s *Server) Keyring() *Keyring {
	return s.keyring
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.deny(r.Context(), "malformed request body", "err", err)
		s.writeDenied(w)
		return
	}

	// Which door. subject_token selects exchange 1; on_behalf_of selects
	// exchange 2 (program plan §3.9: "subject_token must be absent — its
	// presence selects exchange 1"). Both present is ambiguous, and picking
	// one would mint a token the caller did not ask for, so it refuses.
	//
	// Read through firstNonEmpty, not FormValue: FormValue returns only the
	// FIRST value of a repeated field, so "subject_token=&subject_token=
	// <real>&on_behalf_of=<real>" would present an empty subject_token to
	// this guard and a real one to exchange 1 — a request carrying both
	// doors' fields that the both-present refusal below never sees. Every
	// value is examined, the same way a presented `act` is.
	subjectToken, _ := firstNonEmpty(r.Form["subject_token"])
	onBehalfOf, _ := firstNonEmpty(r.Form["on_behalf_of"])

	// RFC 7523 §2.2's assertion type, checked before either door is chosen
	// so both answer it identically. Optional; wrong is refused.
	if t, ok := firstNonEmpty(r.Form["client_assertion_type"]); ok && t != clientAssertionTypeJWTBearer {
		s.deny(r.Context(), "client_assertion_type names an assertion kind this service does not accept",
			"client_assertion_type", t)
		s.writeDenied(w)
		return
	}

	var (
		tok string
		ttl time.Duration
		err error
	)
	switch {
	case subjectToken != "" && onBehalfOf != "":
		s.deny(r.Context(), "request carries both subject_token and on_behalf_of; there is no exchange that means both")
		s.writeDenied(w)
		return
	case onBehalfOf != "":
		tok, ttl, err = s.exchange2(r.Context(), exchange2Request{
			grantType:       r.FormValue("grant_type"),
			clientAssertion: r.FormValue("client_assertion"),
			onBehalfOf:      onBehalfOf,
			subjectKind:     r.FormValue("subject_kind"),
			agent:           r.FormValue("agent"),
			tenant:          r.FormValue("tenant"),

			presentedAct:              r.Form["act"],
			presentedRequestedSubject: r.Form["requested_subject"],
		})
	default:
		tok, ttl, err = s.exchange(r.Context(), exchangeRequest{
			grantType:        r.FormValue("grant_type"),
			clientAssertion:  r.FormValue("client_assertion"),
			subjectToken:     subjectToken,
			requestedSubject: r.FormValue("requested_subject"),
			agent:            r.FormValue("agent"),
		})
	}
	if err != nil {
		// Every failure reason was already logged at its own call site
		// inside the exchange; here there is exactly one response, always.
		s.writeDenied(w)
		return
	}

	resp := tokenResponse{
		AccessToken:     tok,
		IssuedTokenType: issuedTokenType,
		TokenType:       "Bearer",
		ExpiresIn:       int64(ttl.Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) writeDenied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(deniedBody))
}

// deny is the single place a refusal reason is recorded. It always goes to
// the log and never to the HTTP response — see deniedBody's comment.
func (s *Server) deny(_ context.Context, reason string, kv ...any) {
	s.log.Warn("sts: exchange denied: "+reason, kv...)
}

// exchangeRequest is the parsed form body of POST /token.
type exchangeRequest struct {
	grantType        string
	clientAssertion  string
	subjectToken     string
	requestedSubject string // e.g. "customer:C-8123"; present only when an employee acts for a customer
	agent            string // bare agent name, e.g. "order-assistant"
}

// knownKindPrefixes is every identity prefix this service assigns meaning
// to — the claims-policy kinds plus the two it mints itself. It exists so
// identityForKind and segmentKindFromIdentity share ONE notion of "this
// string already names a kind": the two doors disagreeing about that was a
// real defect, where exchange 1 would mint an "employee:customer:C-1" that
// exchange 2 refuses outright.
//
// "service:" is in it for both reasons the others are. It is a kind this
// service mints (the governed door's SERVICE subject), and leaving it out
// made "customer:service:x" a well-formed customer identity to
// segmentKindFromIdentity and "service:x" from an employee IdP mint as
// "employee:service:x" — the doubled identity no tuple names.
var knownKindPrefixes = []string{"customer:", "employee:", "agent:", "runner:", "service:"}

// startsWithKnownKind reports whether identity opens with one of them.
func startsWithKnownKind(identity string) bool {
	for _, p := range knownKindPrefixes {
		if strings.HasPrefix(identity, p) {
			return true
		}
	}
	return false
}

// identityForKind builds the type-prefixed identity for a VERIFIED subject.
//
// An IdP may hand back a bare subject ("jdoe") or one that already carries
// its kind ("employee:jdoe") — devkit's personas do the latter, and both are
// legitimate. Prefixing unconditionally produced "employee:employee:jdoe",
// which no tuple names; every authorizer lookup for it misses, and a miss
// here is indistinguishable from an ordinary, correct-looking denial (see
// authz.go's identity convention comment, which is about exactly this class
// of silent failure).
//
// A subject carrying a DIFFERENT kind's prefix than its issuer's configured
// kind is REFUSED rather than repaired. TrustedIssuer.Kind is the authority
// on what an issuer's tokens mean; a token from the employee IdP whose sub
// says "customer:" is either a misconfigured issuer or a subject claim
// chosen to look like one, and both deserve to be seen rather than turned
// into "employee:customer:C-1".
//
// A subject whose remainder ALSO opens with a known prefix
// ("employee:employee:jdoe", "employee:customer:C-1") is refused for the
// same reason, and so is a bare subject that is itself a prefixed identity
// ("agent:order-assistant" from an employee IdP, which would otherwise be
// prefixed into "employee:agent:order-assistant"). Every one of those is
// the doubled identity program plan §7 item 10 describes; which half the
// caller meant is not this service's call, and segmentKindFromIdentity
// refuses all of them on the other door.
func identityForKind(kind, subject string) (string, bool) {
	if subject == "" {
		// Unreachable: parseUpstreamClaims already refuses a token with no
		// sub. Refused here rather than assumed, so a later change there
		// cannot quietly mint "employee:".
		return "", false
	}
	if !startsWithKnownKind(subject) {
		return kind + ":" + subject, true
	}
	// The prefix is one this service recognises, so it MEANS the kind it
	// spells. It must agree with the issuer's, and it must name somebody
	// who is not themselves a prefixed identity.
	rest, ok := strings.CutPrefix(subject, kind+":")
	if !ok || rest == "" || startsWithKnownKind(rest) {
		return "", false
	}
	return subject, true
}

// exchange2Request is the parsed form body of the GOVERNED door's POST
// /token (program plan §3.9).
//
// It carries no subject token, and that is the whole difference. Exchange 1
// VERIFIES who the subject is against an IdP's JWKS. Here the runner
// ASSERTS it, and the only reason that is acceptable is CanRun: a written
// tuple saying this runner may execute this agent at all. Remove that check
// and on_behalf_of becomes an impersonation field.
type exchange2Request struct {
	grantType       string
	clientAssertion string
	onBehalfOf      string   // type-prefixed, e.g. "employee:jdoe"
	subjectKind     string   // "USER" or "SERVICE", from InvocationContext.principal.kind
	agent           string   // bare agent name, e.g. "support-assistant"
	tenant          string   // from InvocationContext.attribution.tenant (C-1)
	presentedAct    []string // every `act` form value the caller sent, refused below

	// presentedRequestedSubject is every `requested_subject` form value the
	// caller sent, refused below. It is exchange 1's field: it names a
	// customer an EMPLOYEE may act for, and it is honoured only after
	// HandledBy passes against a VERIFIED employee token. There is no
	// verified employee here, so honouring it would be impersonation with
	// no check behind it, and silently ignoring it would mint a token that
	// is not the one the caller asked for.
	presentedRequestedSubject []string
}

// segmentKindFromIdentity reads the claims-policy segment kind off a
// type-prefixed identity.
//
// It is the one place the governed door learns whether it is minting for a
// customer or an employee: there is no verified token to read a
// TrustedIssuer.Kind from, so the prefix the runner presents decides — and
// it decides into a CLOSED set, so an unrecognised prefix (or a bare
// "jdoe") is a refusal rather than a kind that silently matches no segment
// and reads back as an ordinary denial.
func segmentKindFromIdentity(identity string) (string, bool) {
	for _, kind := range []string{"customer", "employee"} {
		rest, ok := strings.CutPrefix(identity, kind+":")
		if !ok || rest == "" {
			continue
		}
		// A remainder that itself carries a known prefix — "employee:
		// employee:jdoe", or "employee:customer:C-1" — is the doubled
		// identity program plan §7 item 10 describes, arriving from a
		// runner rather than from an IdP. Refused for the reason
		// identityForKind refuses it: no tuple names it, and choosing
		// which half the caller meant is not this service's call. Both
		// doors consult the same knownKindPrefixes, so neither can start
		// accepting an identity the other rejects.
		if startsWithKnownKind(rest) {
			return "", false
		}
		return kind, true
	}
	return "", false
}

// firstNonEmpty returns the first non-blank value a repeated form field
// carried, and whether there was one. A bare "act=" is not a delegated
// caller and a bare "requested_subject=" names nobody, so only a value with
// content refuses — but EVERY value is examined, not just the first, so a
// caller cannot hide one behind a leading blank.
func firstNonEmpty(values []string) (string, bool) {
	for _, v := range values {
		if v != "" {
			return v, true
		}
	}
	return "", false
}

// exchange2 is the governed door (program plan §3.9). The order below is
// fixed: authentication, then CanRun, then CanInvoke, then claims. CanRun
// comes first among the authorization checks because on_behalf_of is
// asserted rather than verified — asking CanInvoke of an unauthorised
// runner's chosen subject would turn this endpoint into an entitlement
// oracle for anyone who can reach it.
func (s *Server) exchange2(ctx context.Context, req exchange2Request) (string, time.Duration, error) {
	if req.grantType != grantTypeTokenExchange {
		s.deny(ctx, "unsupported grant_type", "grant_type", req.grantType)
		return "", 0, errDenied
	}

	// A presented act chain is refused outright: the MVP supports a
	// depth-one chain (human at sub, agent at act) and a runner that was
	// itself delegated has nowhere to go in it. An empty `act=` is not a
	// delegated caller, so only a non-empty value refuses.
	if v, ok := firstNonEmpty(req.presentedAct); ok {
		s.deny(ctx, "governed door presented an act chain; the MVP supports a depth-one chain only", "act", v)
		return "", 0, errDenied
	}

	// requested_subject is exchange 1's field and is refused here the same
	// way, for a sharper reason: it is only ever honoured behind HandledBy
	// against a verified employee token, and this door has no verified
	// anybody. See presentedRequestedSubject's comment.
	if v, ok := firstNonEmpty(req.presentedRequestedSubject); ok {
		s.deny(ctx, "governed door presented a requested_subject; it is exchange 1's field and is honoured only behind handled_by",
			"requested_subject", v)
		return "", 0, errDenied
	}

	// Step 1: client assertion + jti replay, exactly as exchange 1. The
	// AUTHENTICATED client id is the runner identity — there is no second
	// credential naming it and no form field a caller could set, which is
	// what keeps "runner:" out of the caller's control.
	clientID, err := s.clients.Authenticate(req.clientAssertion)
	if err != nil {
		s.deny(ctx, "client authentication failed", "err", err)
		return "", 0, errDenied
	}
	runnerIdentity := "runner:" + clientID

	if req.agent == "" {
		s.deny(ctx, "governed door names no agent", "client", clientID)
		return "", 0, errDenied
	}
	agentIdentity := "agent:" + req.agent

	// subject_kind decides what on_behalf_of MEANS, so it is read before the
	// identity is interpreted rather than after: the same field names a
	// segment-matched person under USER and a declared service under
	// SERVICE, and parsing it one way first refuses the other outright —
	// which is exactly how SERVICE used to be unreachable.
	var subKind, serviceName string
	switch req.subjectKind {
	case "USER":
		// ForSegments always mints Kind "USER" (claims.go), and both
		// customers and employees are users to garm.
		k, ok := segmentKindFromIdentity(req.onBehalfOf)
		if !ok {
			s.deny(ctx, "on_behalf_of is not a type-prefixed customer or employee identity",
				"client", clientID, "on_behalf_of", req.onBehalfOf)
			return "", 0, errDenied
		}
		subKind = k
	case "SERVICE":
		// A service calls on its own behalf
		// (decisions/2026-09-30-a-service-calls-on-its-own-behalf.md), and
		// WHICH service is read off the client credential — never off a form
		// field. on_behalf_of must name the service the caller
		// authenticated as, so the policy's `services:` keys ARE client ids.
		//
		// Honouring any other name would hand every declared service's
		// authority to anyone holding ANY registered client key: a BFF could
		// ask for artefactd-writer's RESTRICTED write clearance, and the
		// minted token would look exactly like artefactd asking for it, in
		// the ledger and everywhere else. It is refused rather than quietly
		// replaced with the right name, because a caller that named a
		// different service has already diverged from what this door will do.
		if req.onBehalfOf != "service:"+clientID {
			s.deny(ctx, "a SERVICE subject may only be the client that authenticated as it",
				"client", clientID, "on_behalf_of", req.onBehalfOf)
			return "", 0, errDenied
		}
		serviceName = clientID
	default:
		s.deny(ctx, "subject_kind must be USER or SERVICE", "client", clientID, "subject_kind", req.subjectKind)
		return "", 0, errDenied
	}

	// tenant is REQUIRED here for the same reason exchange 1 refuses a
	// subject token that carries none: confinement to a tenant's own data
	// depends on it, so minting "" is a confinement failure rather than a
	// cosmetic gap. See this plan's C-1.
	if req.tenant == "" {
		s.deny(ctx, "governed door names no tenant", "client", clientID, "on_behalf_of", req.onBehalfOf)
		return "", 0, errDenied
	}

	// Step 2 (program plan §3.9): may this runner execute this agent?
	ok, err := s.authz.CanRun(ctx, runnerIdentity, agentIdentity)
	if err != nil {
		s.deny(ctx, "can_run check failed", "runner", runnerIdentity, "agent", agentIdentity, "err", err)
		return "", 0, errDenied
	}
	if !ok {
		s.deny(ctx, "runner may not execute agent", "runner", runnerIdentity, "agent", agentIdentity)
		return "", 0, errDenied
	}

	// Step 3: can_invoke, the same question exchange 1 asks, asked of the
	// subject the runner named — for a USER subject only.
	//
	// A SERVICE subject is deliberately not asked, and the reason is in
	// deploy/model.fga: can_invoke is DERIVED there from segment membership
	// (`invokable_by: [segment#member]`, and a segment's members are
	// customers and employees), so "service:agentd" is a user no tuple set
	// can answer yes for. Asking it anyway would deny every service mint on
	// the production authorizer while passing in CI against a static file
	// that was simply told to allow it — a path that is green here and dead
	// there. What stands in its place is not weaker: the service is the
	// AUTHENTICATED client, and can_run above already says this runner may
	// execute this agent.
	if serviceName == "" {
		ok, err = s.authz.CanInvoke(ctx, req.onBehalfOf, agentIdentity)
		if err != nil {
			s.deny(ctx, "can_invoke check failed", "principal", req.onBehalfOf, "agent", agentIdentity, "err", err)
			return "", 0, errDenied
		}
		if !ok {
			s.deny(ctx, "principal may not invoke agent", "principal", req.onBehalfOf, "agent", agentIdentity)
			return "", 0, errDenied
		}
	}

	// It never trusts a garm claim the runner presents: there is no field
	// here to present one in, and the chain below is rebuilt from the claims
	// policy exactly as exchange 1 would build it (spec §3.3 item 4).
	return s.resolveAndMint(ctx, mintInputs{
		subIdentity: req.onBehalfOf,
		subKind:     subKind,
		service:     serviceName,
		tenant:      req.tenant,
		agent:       req.agent,
		exec:        &execClaimJSON{Subject: runnerIdentity, Issuer: s.issuer},
	})
}

// mintInputs is everything the claims half of an exchange has resolved to,
// whichever door produced it.
//
// It exists so there is exactly ONE minting path. Two doors with two mint
// implementations is two places the claims policy, the §3.5 clearance gate
// and the §2.4 refusals have to stay in agreement, and the only way to find
// out they had stopped would be a token in production that garmd folds
// differently than anyone expected.
type mintInputs struct {
	// subIdentity is the type-prefixed subject: "customer:C-8123".
	subIdentity string

	// subKind is the CLAIMS-POLICY segment kind, "customer" or "employee" —
	// not garm's PrincipalKind vocabulary, which is always USER for a
	// segment-resolved claim (claims.go's validSegmentKinds). Empty when the
	// sub is a service, which belongs to no segment.
	subKind string

	// service is the BARE service name when sub is a SERVICE principal, ""
	// otherwise. It is the one field that decides which half of
	// resolveAndMint's step 6 runs, because a service's authority is
	// DECLARED and a person's is resolved from membership.
	service string

	tenant string

	// agent is the BARE agent name; "" when the acting employee themself
	// occupies act.
	agent string

	// employeeIdentity is the acting employee, type-prefixed; "" unless
	// delegating.
	employeeIdentity string
	delegating       bool

	// exec is the provenance claim, nil on exchange 1.
	exec *execClaimJSON
}

// exchange runs the whole pipeline and returns a signed token, or an error
// whose text is never shown to the caller (every reason was already logged
// at its call site via s.deny).
func (s *Server) exchange(ctx context.Context, req exchangeRequest) (string, time.Duration, error) {
	// --- authentication -------------------------------------------------

	if req.grantType != grantTypeTokenExchange {
		s.deny(ctx, "unsupported grant_type", "grant_type", req.grantType)
		return "", 0, errDenied
	}

	// Step 1: client assertion + jti replay. ClientRegistry.Authenticate
	// does both: signature verification and single-use jti enforcement.
	clientID, err := s.clients.Authenticate(req.clientAssertion)
	if err != nil {
		s.deny(ctx, "client authentication failed", "err", err)
		return "", 0, errDenied
	}

	// Step 2: the human token verified against its issuer's JWKS.
	upstream, trusted, err := s.verifier.Verify(ctx, req.subjectToken)
	if err != nil {
		s.deny(ctx, "subject token verification failed", "client", clientID, "err", err)
		return "", 0, errDenied
	}

	// Step 3: kind resolved from the issuer's configured Kind field — never
	// sniffed from the token itself. See issuer.go's TrustedIssuer doc.
	callerKind := trusted.Kind
	if callerKind != "customer" && callerKind != "employee" {
		s.deny(ctx, "issuer has no usable kind", "client", clientID, "issuer", trusted.Issuer, "kind", callerKind)
		return "", 0, errDenied
	}
	callerIdentity, ok := identityForKind(callerKind, upstream.Subject)
	if !ok {
		s.deny(ctx, "subject carries a kind prefix its issuer does not assert",
			"client", clientID, "issuer", trusted.Issuer, "kind", callerKind)
		return "", 0, errDenied
	}

	// tenant is REQUIRED, not merely propagated: confinement to a tenant's
	// own data depends on it flowing from the verified token, so a token
	// minted with an empty tenant is a confinement failure, not a cosmetic
	// gap. Refuse rather than mint "".
	tenant, _ := upstream.Raw["tenant"].(string)
	if tenant == "" {
		s.deny(ctx, "subject token carries no tenant claim", "client", clientID)
		return "", 0, errDenied
	}

	// Step 4: handled_by, only when requested_subject is present. This is
	// the line between an employee helping a customer and one impersonating
	// them (spec §3.1).
	var delegating bool
	var employeeIdentity string
	subIdentity := callerIdentity
	subKind := callerKind

	if req.requestedSubject != "" {
		if callerKind != "employee" {
			s.deny(ctx, "requested_subject named by a non-employee", "client", clientID, "caller_kind", callerKind)
			return "", 0, errDenied
		}
		if !strings.HasPrefix(req.requestedSubject, "customer:") || req.requestedSubject == "customer:" {
			s.deny(ctx, "requested_subject is not a well-formed customer identity", "client", clientID)
			return "", 0, errDenied
		}
		ok, err := s.authz.HandledBy(ctx, callerIdentity, req.requestedSubject)
		if err != nil {
			s.deny(ctx, "handled_by check failed", "client", clientID, "err", err)
			return "", 0, errDenied
		}
		if !ok {
			s.deny(ctx, "employee does not handle the requested customer",
				"employee", callerIdentity, "customer", req.requestedSubject)
			return "", 0, errDenied
		}
		delegating = true
		employeeIdentity = callerIdentity
		subIdentity = req.requestedSubject
		subKind = "customer"
	}

	// --- authorization ----------------------------------------------------

	// Step 5: can_invoke, twice when delegating (spec §3.3) — the customer's
	// entitlement and the employee's are different questions, and either one
	// failing must deny. Only asked when an agent is actually being minted.
	mintingForAgent := req.agent != ""
	if !mintingForAgent && !delegating {
		// Neither a named agent nor a delegated customer to act for: there
		// is nothing to put at `act`, and every token this service mints
		// carries one. Refuse rather than guess.
		s.deny(ctx, "request names neither an agent nor a requested_subject", "client", clientID)
		return "", 0, errDenied
	}
	if mintingForAgent {
		agentIdentity := "agent:" + req.agent
		ok, err := s.authz.CanInvoke(ctx, subIdentity, agentIdentity)
		if err != nil {
			s.deny(ctx, "can_invoke check failed", "principal", subIdentity, "agent", agentIdentity, "err", err)
			return "", 0, errDenied
		}
		if !ok {
			s.deny(ctx, "principal may not invoke agent", "principal", subIdentity, "agent", agentIdentity)
			return "", 0, errDenied
		}
		if delegating {
			ok, err := s.authz.CanInvoke(ctx, employeeIdentity, agentIdentity)
			if err != nil {
				s.deny(ctx, "can_invoke check failed (employee)", "employee", employeeIdentity, "agent", agentIdentity, "err", err)
				return "", 0, errDenied
			}
			if !ok {
				s.deny(ctx, "employee may not invoke agent", "employee", employeeIdentity, "agent", agentIdentity)
				return "", 0, errDenied
			}
		}
	}

	// Steps 6 and 7, the §2.4 refusals, the §3.5 gate and the signature are
	// the same for both doors, so they live in one place.
	return s.resolveAndMint(ctx, mintInputs{
		subIdentity:      subIdentity,
		subKind:          subKind,
		tenant:           tenant,
		agent:            req.agent,
		employeeIdentity: employeeIdentity,
		delegating:       delegating,
	})
}

// resolveAndMint runs steps 6 and 7, the spec §2.4 refusals, the §3.5
// instance-authorization gate and the signature. Both doors end here.
func (s *Server) resolveAndMint(ctx context.Context, in mintInputs) (string, time.Duration, error) {
	mintingForAgent := in.agent != ""

	// Step 6: who the sub is allowed to be.
	//
	// Two resolutions, and which one runs is the difference between the two
	// kinds of principal rather than a shortcut. A person's authority comes
	// from MEMBERSHIP — N InSegment questions against a store this service
	// does not own. A service's comes from a DECLARATION: one identity, one
	// authority, written in the deployment's claims policy, with no
	// membership to ask about and nothing to union.
	var subClaim *GarmClaim
	var err error
	if in.service != "" {
		subClaim, err = s.policy.ForService(in.service)
		if err != nil {
			// An undeclared service is refused here, and the caller cannot
			// tell that from any other refusal: deniedBody is the one body
			// this service returns, so this is not an oracle for which
			// services a deployment declares.
			s.deny(ctx, "service resolves to no declared authority", "service", in.service, "err", err)
			return "", 0, errDenied
		}
		if !mintingForAgent {
			// Unreachable: exchange2 refuses a request naming no agent, and
			// exchange 1 never produces a service sub. Refused here anyway,
			// because a service token with no act chain is the one shape
			// tasksd's Create rejects outright (it requires Kind SERVICE
			// *and* HasAgent()), and minting one would look like a tasksd
			// bug rather than a token that was never valid for the call.
			s.deny(ctx, "a service mint names no agent; a service token with no act chain is one the task service refuses", "service", in.service)
			return "", 0, errDenied
		}
	} else {
		subClaim, err = s.resolveSegmentClaim(ctx, in.subIdentity, in.subKind)
		if err != nil {
			s.deny(ctx, "sub principal resolves to no roles", "principal", in.subIdentity, "kind", in.subKind, "err", err)
			return "", 0, errDenied
		}
	}

	// The employee's OWN claim is resolved whenever delegating, whether or
	// not an agent is also named. An employee in no segment has no authority
	// to assert, agent or no agent, and skipping this resolution was a real
	// hole — the customer's full, unnarrowed authority would otherwise mint
	// for staff with no entitlement of their own at all.
	var employeeClaim *GarmClaim
	if in.delegating {
		employeeClaim, err = s.resolveSegmentClaim(ctx, in.employeeIdentity, "employee")
		if err != nil {
			s.deny(ctx, "acting employee resolves to no roles", "employee", in.employeeIdentity, "err", err)
			return "", 0, errDenied
		}
	}

	// Step 7: claims, for whoever is named at `act`. An agent's authority is
	// its own declared claim, never narrowed here — narrowing (intersecting
	// against sub) happens in garmd, not this service (spec §2.3).
	var actClaim *GarmClaim
	if mintingForAgent {
		actClaim, err = s.policy.ForAgent(in.agent)
		if err != nil {
			s.deny(ctx, "agent resolves to no roles", "agent", in.agent, "err", err)
			return "", 0, errDenied
		}
	} else {
		actClaim = employeeClaim
	}

	// --- refusals (spec §2.4) and the instance-authorization gate (§3.5) --
	//
	// This runs for BOTH doors. The governed door reaching a customer
	// subject without passing through here would be a way to obtain an
	// uncapped customer token by asking a runner for it, which is exactly
	// the hole the gate exists to close.
	if in.subKind == "customer" {
		capped, wasCapped, err := s.applyInstanceAuthorization(subClaim.Clearance)
		if err != nil {
			s.deny(ctx, "instance authorization refuses customer mint",
				"principal", in.subIdentity, "status", s.instance.Status)
			return "", 0, errDenied
		}
		if wasCapped {
			s.log.Warn("sts: exchange: customer clearance capped by instanceAuthorization.unconfinedCeiling",
				"principal", in.subIdentity, "granted", subClaim.Clearance, "ceiling", s.instance.UnconfinedCeiling, "effective", capped)
		} else if s.instance.Status == "absent" {
			s.log.Info("sts: exchange: customer mint under instanceAuthorization: absent with a ceiling; no reduction was needed",
				"principal", in.subIdentity, "granted", subClaim.Clearance, "ceiling", s.instance.UnconfinedCeiling)
		}
		subClaim = &GarmClaim{
			Clearance:    capped,
			Compartments: subClaim.Compartments,
			Verbs:        subClaim.Verbs,
			ToolSets:     subClaim.ToolSets,
			Kind:         subClaim.Kind,
		}
	}

	// chain is every level this exchange is about to mint — 2 levels
	// ordinarily, 3 when delegating to a named agent (sub, agent, employee).
	// The runner is NOT in it: exec is provenance and is never folded.
	chain := []*GarmClaim{subClaim, actClaim}
	if mintingForAgent && in.delegating {
		chain = append(chain, employeeClaim)
	}

	if len(intersectAllVerbs(chain)) == 0 {
		s.deny(ctx, "verb intersection over the chain is empty", "principal", in.subIdentity)
		return "", 0, errDenied
	}

	// The invariant the whole design rests on: every level MUST carry a
	// non-empty garm.clearance, or garmd's ParseClaims refuses the whole
	// token.
	for _, c := range chain {
		if c.Clearance == "" {
			s.deny(ctx, "internal: a resolved claim in the chain has an empty clearance")
			return "", 0, errDenied
		}
	}

	// --- mint --------------------------------------------------------

	jti, err := newJTI()
	if err != nil {
		s.deny(ctx, "jti generation failed", "err", err)
		return "", 0, errDenied
	}

	now := time.Now().UTC()
	exp := now.Add(s.ttl)

	actSubject := "agent:" + in.agent
	if !mintingForAgent {
		actSubject = in.employeeIdentity
	}

	act := actClaimJSON{
		Subject: actSubject,
		Garm:    toGarmClaimJSON(actClaim),
	}
	if mintingForAgent && in.delegating {
		// customer (sub) -> agent (act) -> employee (act.act): the agent is
		// the current actor and sits outermost; the employee, who acted
		// earlier to obtain this token, nests inside it (RFC 8693 §4.1).
		act.Act = &actClaimJSON{
			Subject: in.employeeIdentity,
			Garm:    toGarmClaimJSON(employeeClaim),
		}
	}

	claims := mintedToken{
		Issuer:    s.issuer,
		Audience:  s.audience,
		Subject:   in.subIdentity,
		ExpiresAt: exp.Unix(),
		IssuedAt:  now.Unix(),
		ID:        jti,
		Tenant:    in.tenant,
		Garm:      toGarmClaimJSON(subClaim),
		Act:       act,
		Exec:      in.exec,
	}

	tok, err := s.keyring.Sign(claims)
	if err != nil {
		s.deny(ctx, "signing failed", "err", err)
		return "", 0, errDenied
	}
	return tok, s.ttl, nil
}

// errDenied is returned by BOTH doors for every refusal. Its text is never
// surfaced to a caller; deniedBody is what the caller actually sees.
var errDenied = fmt.Errorf("sts: exchange: denied")

// resolveSegmentClaim asks InSegment once per declared segment (a closed,
// bounded set — Policy.Segments()) and folds whichever ones identity
// belongs to into a claim of kind.
func (s *Server) resolveSegmentClaim(ctx context.Context, identity, kind string) (*GarmClaim, error) {
	var matched []string
	for _, name := range s.policy.Segments() {
		ok, err := s.authz.InSegment(ctx, identity, name)
		if err != nil {
			return nil, fmt.Errorf("in_segment(%q, %q): %w", identity, name, err)
		}
		if ok {
			matched = append(matched, name)
		}
	}
	return s.policy.ForSegments(kind, matched)
}

// applyInstanceAuthorization implements spec §3.5's gate for a customer-kind
// sub claim's clearance. It returns the effective clearance to mint, and
// whether it differs from granted (i.e. a cap actually bit).
func (s *Server) applyInstanceAuthorization(granted string) (effective string, capped bool, err error) {
	switch s.instance.Status {
	case "enforced":
		return granted, false, nil
	case "absent":
		if s.instance.UnconfinedCeiling == "" {
			return "", false, fmt.Errorf("instanceAuthorization is absent with no unconfinedCeiling configured")
		}
		if clearanceOrder[granted] > clearanceOrder[s.instance.UnconfinedCeiling] {
			return s.instance.UnconfinedCeiling, true, nil
		}
		return granted, false, nil
	default:
		// NewServer already refuses any other Status; unreachable in
		// practice, refused here rather than assumed.
		return "", false, fmt.Errorf("instanceAuthorization.status %q is not recognised", s.instance.Status)
	}
}

// intersectVerbs returns the verbs common to both, sorted stably by simple
// membership (no map is consulted for the RESULT, only for a lookup — the
// output order follows a's order, which is itself already sorted by
// unionOf, so this never becomes a source of nondeterminism).
// intersectAllVerbs folds intersectVerbs across every claim in chain, in
// order, short-circuiting to nil the moment the running intersection is
// empty. Used only to decide the §2.4 refusal — never to narrow what is
// actually minted (§2.3: this service does not pre-intersect).
func intersectAllVerbs(chain []*GarmClaim) []string {
	if len(chain) == 0 {
		return nil
	}
	result := chain[0].Verbs
	for _, c := range chain[1:] {
		result = intersectVerbs(result, c.Verbs)
		if len(result) == 0 {
			return nil
		}
	}
	return result
}

func intersectVerbs(a, b []string) []string {
	inB := make(map[string]struct{}, len(b))
	for _, v := range b {
		inB[v] = struct{}{}
	}
	var out []string
	for _, v := range a {
		if _, ok := inB[v]; ok {
			out = append(out, v)
		}
	}
	return out
}

func toGarmClaimJSON(c *GarmClaim) garmClaimJSON {
	return garmClaimJSON{
		Clearance:    c.Clearance,
		Compartments: c.Compartments,
		Verbs:        c.Verbs,
		ToolSets:     c.ToolSets,
		Kind:         c.Kind,
	}
}

// newJTI mints a fresh, unguessable token identifier.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sts: exchange: generating jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
