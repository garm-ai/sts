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

// issuedTokenType is the `issued_token_type` this endpoint always reports:
// every minted token is a JWT.
const issuedTokenType = "urn:ietf:params:oauth:token-type:jwt"

// defaultDelegationTTL is used when Options.DelegationTTL is left zero.
const defaultDelegationTTL = 10 * time.Minute

// deniedBody is THE single response body for every denial this handler can
// produce, whatever the reason. An unknown agent, a missing handled_by
// relation, an under-privileged caller and a malformed request all look
// identical to the caller: distinguishing them would make this endpoint an
// enumeration oracle. The reason always goes to the log, never the response.
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

	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	return &Server{
		issuer:   opts.Issuer,
		audience: opts.Audience,
		keyring:  opts.Keyring,
		verifier: opts.Verifier,
		policy:   opts.Policy,
		authz:    opts.Authz,
		clients:  opts.Clients,
		ttl:      ttl,
		instance: opts.InstanceAuthz,
		log:      log,
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

// actClaimJSON is one `act` level. It is never a pointer field on
// mintedToken below: Go always marshals a struct value, which makes it
// impossible for this package to silently omit an `act` level by leaving a
// pointer nil. Chain depth is fixed at 2 for this task — sub, then exactly
// one act — so there is exactly one of these per minted token.
type actClaimJSON struct {
	Subject string        `json:"sub"`
	Garm    garmClaimJSON `json:"garm"`
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

	req := exchangeRequest{
		grantType:        r.FormValue("grant_type"),
		clientAssertion:  r.FormValue("client_assertion"),
		subjectToken:     r.FormValue("subject_token"),
		requestedSubject: r.FormValue("requested_subject"),
		agent:            r.FormValue("agent"),
	}

	tok, ttl, err := s.exchange(r.Context(), req)
	if err != nil {
		// Every failure reason was already logged at its own call site
		// inside exchange(); here there is exactly one response, always.
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
	callerIdentity := callerKind + ":" + upstream.Subject

	tenant, _ := upstream.Raw["tenant"].(string)

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

	var agentIdentity string
	mintingForAgent := req.agent != ""
	if mintingForAgent {
		agentIdentity = "agent:" + req.agent
	} else if !delegating {
		// Neither a named agent nor a delegated customer to act for: there
		// is nothing to put at `act`, and every token this service mints
		// carries one. Refuse rather than guess.
		s.deny(ctx, "request names neither an agent nor a requested_subject", "client", clientID)
		return "", 0, errDenied
	}

	// Step 5: can_invoke, twice when delegating (spec §3.3) — the customer's
	// entitlement and the employee's are different questions, and either one
	// failing must deny. Only asked when an agent is actually being minted.
	if mintingForAgent {
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

	// Step 6: segment membership, feeding step 7's claims resolution.
	subClaim, err := s.resolveSegmentClaim(ctx, subIdentity, subKind)
	if err != nil {
		s.deny(ctx, "sub principal resolves to no roles", "principal", subIdentity, "kind", subKind, "err", err)
		return "", 0, errDenied
	}

	var actClaim *GarmClaim
	if mintingForAgent {
		// Step 7: claims, for the agent — its own declared authority, never
		// narrowed here. Narrowing (intersecting against sub) happens in
		// garmd, not this service (spec §2.3).
		actClaim, err = s.policy.ForAgent(req.agent)
		if err != nil {
			s.deny(ctx, "agent resolves to no roles", "agent", req.agent, "err", err)
			return "", 0, errDenied
		}
	} else {
		actClaim, err = s.resolveSegmentClaim(ctx, employeeIdentity, "employee")
		if err != nil {
			s.deny(ctx, "acting employee resolves to no roles", "employee", employeeIdentity, "err", err)
			return "", 0, errDenied
		}
	}

	// --- refusals (spec §2.4) and the instance-authorization gate (§3.5) --

	if subKind == "customer" {
		capped, wasCapped, err := s.applyInstanceAuthorization(subClaim.Clearance)
		if err != nil {
			s.deny(ctx, "instance authorization refuses customer mint",
				"principal", subIdentity, "status", s.instance.Status)
			return "", 0, errDenied
		}
		if wasCapped {
			s.log.Warn("sts: exchange: customer clearance capped by instanceAuthorization.unconfinedCeiling",
				"principal", subIdentity, "granted", subClaim.Clearance, "ceiling", s.instance.UnconfinedCeiling, "effective", capped)
		} else if s.instance.Status == "absent" {
			// Logged on EVERY exchange under this configuration, capped or
			// not: a cap that only logs when it bites reads, on the quiet
			// calls, as if no cap exists at all.
			s.log.Info("sts: exchange: customer mint under instanceAuthorization: absent with a ceiling; no reduction was needed",
				"principal", subIdentity, "granted", subClaim.Clearance, "ceiling", s.instance.UnconfinedCeiling)
		}
		subClaim = &GarmClaim{
			Clearance:    capped,
			Compartments: subClaim.Compartments,
			Verbs:        subClaim.Verbs,
			ToolSets:     subClaim.ToolSets,
			Kind:         subClaim.Kind,
		}
	}

	if len(intersectVerbs(subClaim.Verbs, actClaim.Verbs)) == 0 {
		s.deny(ctx, "verb intersection over the chain is empty", "principal", subIdentity)
		return "", 0, errDenied
	}

	// The invariant the whole design rests on: every level MUST carry a
	// non-empty garm.clearance, or garmd's ParseClaims refuses the whole
	// token. ForSegments/ForAgent already guarantee this, but a mint-time
	// assertion here is cheap defense in depth for the one property that
	// turns a single miss into a total outage.
	if subClaim.Clearance == "" || actClaim.Clearance == "" {
		s.deny(ctx, "internal: a resolved claim has an empty clearance",
			"sub_clearance", subClaim.Clearance, "act_clearance", actClaim.Clearance)
		return "", 0, errDenied
	}

	// --- mint --------------------------------------------------------

	jti, err := newJTI()
	if err != nil {
		s.deny(ctx, "jti generation failed", "err", err)
		return "", 0, errDenied
	}

	now := time.Now().UTC()
	exp := now.Add(s.ttl)

	actSubject := agentIdentity
	if !mintingForAgent {
		actSubject = employeeIdentity
	}

	claims := mintedToken{
		Issuer:    s.issuer,
		Audience:  s.audience,
		Subject:   subIdentity,
		ExpiresAt: exp.Unix(),
		IssuedAt:  now.Unix(),
		ID:        jti,
		Tenant:    tenant,
		Garm:      toGarmClaimJSON(subClaim),
		Act: actClaimJSON{
			Subject: actSubject,
			Garm:    toGarmClaimJSON(actClaim),
		},
	}

	tok, err := s.keyring.Sign(claims)
	if err != nil {
		s.deny(ctx, "signing failed", "err", err)
		return "", 0, errDenied
	}
	return tok, s.ttl, nil
}

// errDenied is returned by exchange() for every refusal. Its text is never
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
