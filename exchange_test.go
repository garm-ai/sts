package sts_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/garm-ai/sts"
	jose "github.com/go-jose/go-jose/v4"
)

// --- fixture: everything Task 6 consumes, wired together -------------------

const (
	stsIssuer    = "https://sts.internal.example.com"
	garmAudience = "garm://tools" // garmd's identifier, never the agent
	custIssuer   = "https://customer-idp.example"
	empIssuer    = "https://employee-idp.example"
)

// exchangePolicy declares two customer segments (so the invariant property
// test can exercise "several segment combinations"), one employee segment,
// and two agents whose verbs deliberately do NOT overlap with each other —
// write-bot exists purely so a verb-intersection test has an agent to name
// whose authority shares nothing with what any customer holds.
const exchangePolicy = `
roles:
  self-service: { clearance: CONFIDENTIAL, compartments: [pii-contact, financial], verbs: [READ], tool_sets: [self-service] }
  vip-extra:    { clearance: RESTRICTED,   compartments: [vip],                    verbs: [READ] }
  support-desk: { clearance: INTERNAL,     compartments: [support],                verbs: [READ] }
  write-only:   { clearance: INTERNAL,     compartments: [ops],                    verbs: [WRITE] }

segments:
  retail-vip:    { kind: customer, roles: [self-service] }
  sme-basic:     { kind: customer, roles: [self-service, vip-extra] }
  support-staff: { kind: employee, roles: [support-desk] }

agents:
  order-assistant: { roles: [support-desk] }
  write-bot:       { roles: [write-only] }

# The service principal of decisions/2026-09-30-a-service-calls-on-its-own-
# behalf: its authority inline, no tool sets (absent means unscoped, which is
# what reaching a set-less tool takes), and WRITE so the verb intersection
# against write-bot is not empty.
services:
  agentd: { clearance: PUBLIC, verbs: [WRITE] }
`

// fakeAuthz is a hand-rolled Authorizer: the four relations as plain maps,
// set directly by each test rather than round-tripped through a YAML file,
// so every test can build exactly the tuple set its scenario needs.
type fakeAuthz struct {
	canInvoke map[[2]string]bool
	canRun    map[[2]string]bool
	handledBy map[[2]string]bool
	inSegment map[[2]string]bool

	// mu guards calls. The handler answers on the caller's goroutine, so
	// nothing here is concurrent today; the mutex is what keeps that an
	// implementation detail rather than something -race would discover if
	// an exchange ever resolved segments in parallel.
	mu sync.Mutex

	// calls records every question asked of this authorizer, in order, so a
	// test can assert not only WHAT was asked but WHEN and WHETHER. The
	// governed door's CanRun-before-CanInvoke ordering is a security
	// property, not a style choice — see
	// TestExchange2AsksCanRunBeforeCanInvokeAndNeverProbesOnADeniedRun —
	// and ordering is exactly the kind of property that survives a refactor
	// only if something checks it.
	calls []string
}

func newFakeAuthz() *fakeAuthz {
	return &fakeAuthz{
		canInvoke: map[[2]string]bool{},
		canRun:    map[[2]string]bool{},
		handledBy: map[[2]string]bool{},
		inSegment: map[[2]string]bool{},
	}
}

func (a *fakeAuthz) allowInvoke(principal, agent string) {
	a.canInvoke[[2]string{principal, agent}] = true
}
func (a *fakeAuthz) allowRun(runner, agent string) {
	a.canRun[[2]string{runner, agent}] = true
}
func (a *fakeAuthz) allowHandledBy(employee, customer string) {
	a.handledBy[[2]string{employee, customer}] = true
}
func (a *fakeAuthz) allowSegment(principal, segment string) {
	a.inSegment[[2]string{principal, segment}] = true
}

func (a *fakeAuthz) record(format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, fmt.Sprintf(format, args...))
}

// recorded returns a copy of the call log, so a test reading it cannot be
// affected by a later call appending to the original.
func (a *fakeAuthz) recorded() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

func (a *fakeAuthz) CanInvoke(_ context.Context, principal, agent string) (bool, error) {
	a.record("CanInvoke(%s, %s)", principal, agent)
	return a.canInvoke[[2]string{principal, agent}], nil
}
func (a *fakeAuthz) CanRun(_ context.Context, runner, agent string) (bool, error) {
	a.record("CanRun(%s, %s)", runner, agent)
	return a.canRun[[2]string{runner, agent}], nil
}
func (a *fakeAuthz) HandledBy(_ context.Context, employee, customer string) (bool, error) {
	a.record("HandledBy(%s, %s)", employee, customer)
	return a.handledBy[[2]string{employee, customer}], nil
}
func (a *fakeAuthz) InSegment(_ context.Context, principal, segment string) (bool, error) {
	a.record("InSegment(%s, %s)", principal, segment)
	return a.inSegment[[2]string{principal, segment}], nil
}

// firstCallTo returns the index of the first recorded call to name, or -1.
func firstCallTo(calls []string, name string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, name+"(") {
			return i
		}
	}
	return -1
}

var _ sts.Authorizer = (*fakeAuthz)(nil)

// jtiCounter hands out unique client-assertion jtis across a test binary run
// — the replay cache is keyed by (client, jti), so reusing one across calls
// within a test would spuriously trip replay protection.
var jtiCounter atomic.Int64

func nextJTI() string {
	return fmt.Sprintf("exchange-test-%d", jtiCounter.Add(1))
}

// fixture bundles a fully wired Server plus everything needed to mint valid
// subject tokens and client assertions against it.
type fixture struct {
	t         *testing.T
	now       time.Time
	kr        *sts.Keyring
	custKey   *ecdsa.PrivateKey
	empKey    *ecdsa.PrivateKey
	clientKey *ecdsa.PrivateKey
	authz     *fakeAuthz
	srv       *sts.Server
}

// newFixture wires a Server against policyYAML, authz and instance. now is
// fixed so subject tokens, client assertions and the server's own view of
// time never race a real clock during the test.
func newFixture(t *testing.T, policyYAML string, authz *fakeAuthz, instance sts.InstanceAuthzConfig) *fixture {
	t.Helper()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	custKey := genUpstreamKey(t)
	custIdP := newTestIdP(t, upstreamJWK("cust-k1", custKey))
	empKey := genUpstreamKey(t)
	empIdP := newTestIdP(t, upstreamJWK("emp-k1", empKey))

	verifier := sts.NewVerifier([]sts.TrustedIssuer{
		{Name: "customer-idp", Issuer: custIssuer, JWKSURL: custIdP.server.URL, Audience: []string{"shop-bff"}, Kind: "customer"},
		{Name: "employee-idp", Issuer: empIssuer, JWKSURL: empIdP.server.URL, Audience: []string{"internal-app"}, Kind: "employee"},
	}, sts.VerifierOptions{Now: nowFn})

	policy := loadPolicy(t, policyYAML)

	clientKey := genUpstreamKey(t)
	// Two registered clients, one key: "shop-bff" is the BFF every other
	// test authenticates as, and "agentd" is the runner the service-principal
	// tests need — the service identity is derived from the AUTHENTICATED
	// client id, so a test about service:agentd has to actually authenticate
	// as agentd.
	clients := newTestRegistry(t, nowFn,
		sts.ClientConfig{ID: "shop-bff", PEMs: [][]byte{clientPublicKeyPEM(t, clientKey)}},
		sts.ClientConfig{ID: "agentd", PEMs: [][]byte{clientPublicKeyPEM(t, clientKey)}})

	kr, err := sts.NewKeyring([]sts.KeyConfig{{KID: "k1", PEM: testKeyPEM(t)}}, "k1")
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}

	if authz == nil {
		authz = newFakeAuthz()
	}

	srv, err := sts.NewServer(sts.Options{
		Issuer:        stsIssuer,
		Audience:      garmAudience,
		Keyring:       kr,
		Verifier:      verifier,
		Policy:        policy,
		Authz:         authz,
		Clients:       clients,
		DelegationTTL: 5 * time.Minute,
		InstanceAuthz: instance,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	return &fixture{t: t, now: now, kr: kr, custKey: custKey, empKey: empKey, clientKey: clientKey, authz: authz, srv: srv}
}

// enforced is the InstanceAuthzConfig every test that is not specifically
// about §3.5 should use: it mints exactly what the claims policy grants,
// with no capping in the way.
var enforced = sts.InstanceAuthzConfig{Status: "enforced"}

// defaultTestTenant is what customerToken/employeeToken carry unless a test
// overrides it via extra — tenant is now a REQUIRED claim (Important 3), so
// every test that isn't specifically about that requirement needs one.
const defaultTestTenant = "acme"

func (f *fixture) customerToken(sub string, extra map[string]any) string {
	f.t.Helper()
	claims := map[string]any{
		"iss": custIssuer, "sub": sub, "aud": "shop-bff", "tenant": defaultTestTenant,
		"iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return signUpstreamToken(f.t, f.custKey, jose.ES256, "cust-k1", claims)
}

func (f *fixture) employeeToken(sub string, extra map[string]any) string {
	f.t.Helper()
	claims := map[string]any{
		"iss": empIssuer, "sub": sub, "aud": "internal-app", "tenant": defaultTestTenant,
		"iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return signUpstreamToken(f.t, f.empKey, jose.ES256, "emp-k1", claims)
}

// customerTokenNoTenant builds a customer token with NO tenant claim at
// all, for the one test that specifically proves tenant is required.
func (f *fixture) customerTokenNoTenant(sub string) string {
	f.t.Helper()
	claims := map[string]any{
		"iss": custIssuer, "sub": sub, "aud": "shop-bff",
		"iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(),
	}
	return signUpstreamToken(f.t, f.custKey, jose.ES256, "cust-k1", claims)
}

// form builds a valid POST /token body: a fresh client assertion plus the
// given subject token, requestedSubject and agent (either may be "").
func (f *fixture) form(subjectToken, requestedSubject, agent string) url.Values {
	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	v.Set("client_assertion", clientAssertion(f.t, f.clientKey, "shop-bff", testAudience, f.now.Add(time.Minute), nextJTI()))
	v.Set("subject_token", subjectToken)
	if requestedSubject != "" {
		v.Set("requested_subject", requestedSubject)
	}
	if agent != "" {
		v.Set("agent", agent)
	}
	return v
}

// form2 builds a valid exchange-2 POST /token body: a fresh client
// assertion and the governed door's fields, and deliberately NO
// subject_token — its absence is half of what selects this exchange.
func (f *fixture) form2(onBehalfOf, subjectKind, agent, tenant string) url.Values {
	return f.form2As("shop-bff", onBehalfOf, subjectKind, agent, tenant)
}

// form2As is form2 authenticating as a named registered client. Which client
// a request authenticates as is load-bearing on the governed door — it is
// where both "runner:" and, for a SERVICE subject, "service:" come from —
// so a test about either has to be able to choose it.
func (f *fixture) form2As(clientID, onBehalfOf, subjectKind, agent, tenant string) url.Values {
	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	v.Set("client_assertion", clientAssertion(f.t, f.clientKey, clientID, testAudience, f.now.Add(time.Minute), nextJTI()))
	v.Set("on_behalf_of", onBehalfOf)
	v.Set("subject_kind", subjectKind)
	v.Set("agent", agent)
	v.Set("tenant", tenant)
	return v
}

// do POSTs form to the exchange handler and returns the raw response.
func (f *fixture) do(form url.Values) *http.Response {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	return rec.Result()
}

// mint does a full exchange and returns the decoded, SIGNATURE-VERIFIED
// claims of the minted access_token, failing the test on any error or
// non-200 response.
func (f *fixture) mint(form url.Values) map[string]any {
	f.t.Helper()
	resp := f.do(form)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("exchange failed: status %d, body %s", resp.StatusCode, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		f.t.Fatalf("decoding response: %v; body %s", err, body)
	}
	return f.decodeAndVerify(out.AccessToken)
}

// decodeAndVerify checks the minted token against the SERVED JWKS — proving
// the token is not merely well-shaped JSON but a real, verifiable signed
// credential — under the same ES256-only allowlist garmd applies.
func (f *fixture) decodeAndVerify(tok string) map[string]any {
	f.t.Helper()
	sig, err := jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		f.t.Fatalf("minted token does not parse under an ES256-only allowlist: %v", err)
	}
	set := f.kr.JWKS()
	var payload []byte
	for _, k := range set.Keys {
		if p, err := sig.Verify(k.Key); err == nil {
			payload = p
			break
		}
	}
	if payload == nil {
		f.t.Fatalf("minted token did not verify against any key this service serves")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		f.t.Fatalf("minted token body is not valid JSON: %v", err)
	}
	return claims
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func strSlice(m map[string]any, k string) []string {
	v, ok := m[k].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, e := range v {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- Step 1: the happy path -------------------------------------------

func TestExchangeMintsADelegationToken(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("customer:C-8123", "retail-vip")
	authz.allowInvoke("customer:C-8123", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	before := f.now
	claims := f.mint(f.form(f.customerToken("C-8123", map[string]any{"tenant": "acme"}), "", "order-assistant"))

	if got := str(claims, "iss"); got != stsIssuer {
		t.Errorf("iss = %q, want %q", got, stsIssuer)
	}
	if got := str(claims, "aud"); got != garmAudience {
		t.Errorf("aud = %q, want %q (garmd's identifier, never the agent)", got, garmAudience)
	}
	if got := str(claims, "sub"); got != "customer:C-8123" {
		t.Errorf("sub = %q, want %q", got, "customer:C-8123")
	}
	if got := str(claims, "tenant"); got != "acme" {
		t.Errorf("tenant = %q, want %q (propagated from the verified upstream token)", got, "acme")
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if iat < float64(before.Unix()) {
		t.Errorf("iat = %v, want >= %v", iat, before.Unix())
	}
	if exp <= iat {
		t.Errorf("exp (%v) must be after iat (%v)", exp, iat)
	}
	jti := str(claims, "jti")
	if jti == "" {
		t.Error("jti is empty; a minted token must carry a fresh identifier")
	}

	garm, ok := claims["garm"].(map[string]any)
	if !ok {
		t.Fatal("no garm claim at sub level")
	}
	if got := str(garm, "clearance"); got != "CONFIDENTIAL" {
		t.Errorf("garm.clearance = %q, want CONFIDENTIAL", got)
	}
	if got := strSlice(garm, "compartments"); !sliceEqual(got, []string{"financial", "pii-contact"}) {
		t.Errorf("garm.compartments = %v, want [financial pii-contact] (sorted)", got)
	}
	if got := strSlice(garm, "verbs"); !sliceEqual(got, []string{"READ"}) {
		t.Errorf("garm.verbs = %v, want [READ]", got)
	}
	if got := strSlice(garm, "tool_sets"); !sliceEqual(got, []string{"self-service"}) {
		t.Errorf("garm.tool_sets = %v, want [self-service]", got)
	}
	if got := str(garm, "kind"); got != "USER" {
		t.Errorf("garm.kind = %q, want USER", got)
	}
	if _, present := claims["scope"]; present {
		t.Error("minted token carries a `scope` claim; the design says garm replaces it entirely")
	}

	act, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatal("no act level; every minted token in this design carries one")
	}
	if got := str(act, "sub"); got != "agent:order-assistant" {
		t.Errorf("act.sub = %q, want %q", got, "agent:order-assistant")
	}
	actGarm, ok := act["garm"].(map[string]any)
	if !ok {
		t.Fatal("act level carries no garm claim — this is the invariant the whole design rests on")
	}
	if got := str(actGarm, "clearance"); got != "INTERNAL" {
		t.Errorf("act.garm.clearance = %q, want INTERNAL", got)
	}
	if got := strSlice(actGarm, "compartments"); !sliceEqual(got, []string{"support"}) {
		t.Errorf("act.garm.compartments = %v, want [support]", got)
	}
	if got := strSlice(actGarm, "verbs"); !sliceEqual(got, []string{"READ"}) {
		t.Errorf("act.garm.verbs = %v, want [READ]", got)
	}
	if got := str(actGarm, "kind"); got != "AGENT" {
		t.Errorf("act.garm.kind = %q, want AGENT", got)
	}

	// §2.3: the STS does not pre-intersect. sub keeps CONFIDENTIAL/READ even
	// though act's ceiling is only INTERNAL — narrowing is garmd's job.
	if str(garm, "clearance") == str(actGarm, "clearance") {
		t.Fatal("sub and act clearances coincide; this test's fixture is supposed to prove they are minted UNNARROWED — check the fixture, not just this assertion")
	}
}

// --- Review Focus 4: the invariant the entire design rests on ------------

func walkGarmChain(t *testing.T, level map[string]any, depth int) {
	t.Helper()
	garm, ok := level["garm"].(map[string]any)
	if !ok {
		t.Fatalf("level %d of the act chain carries no garm claim at all; garmd's ParseClaims refuses the whole token", depth)
	}
	clearance, _ := garm["clearance"].(string)
	if clearance == "" {
		t.Fatalf("level %d of the act chain has an EMPTY garm.clearance; garmd's ParseClaims refuses the whole token", depth)
	}
	if act, ok := level["act"].(map[string]any); ok {
		walkGarmChain(t, act, depth+1)
	}
}

func TestEveryLevelOfEveryMintedChainCarriesAGarmClaim(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("customer:C-1", "retail-vip")
	authz.allowSegment("customer:C-2", "sme-basic")
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("customer:C-1", "agent:order-assistant")
	authz.allowInvoke("customer:C-2", "agent:order-assistant")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	authz.allowHandledBy("employee:jdoe", "customer:C-1")
	f := newFixture(t, exchangePolicy, authz, enforced)

	matrix := []struct {
		name string
		form url.Values
	}{
		{"direct customer, single segment, to an agent",
			f.form(f.customerToken("C-1", nil), "", "order-assistant")},
		{"direct customer, two-role segment, to an agent",
			f.form(f.customerToken("C-2", nil), "", "order-assistant")},
		{"direct employee, to an agent",
			f.form(f.employeeToken("jdoe", nil), "", "order-assistant")},
		{"employee acting for a customer, to an agent",
			f.form(f.employeeToken("jdoe", nil), "customer:C-1", "order-assistant")},
		{"employee acting for a customer, no agent",
			f.form(f.employeeToken("jdoe", nil), "customer:C-1", "")},
	}

	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			claims := f.mint(tc.form)
			walkGarmChain(t, claims, 0)
		})
	}
}

// --- Review Focus 2: the line between "helps" and "impersonates" --------

func TestRequestedSubjectRequiresHandledBy(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("customer:C-1", "retail-vip")
	// customer:C-2 has real, resolvable roles too — the point of this test is
	// that handled_by ALONE gates it, not an incidental "no roles" refusal
	// from further down the pipeline.
	authz.allowSegment("customer:C-2", "retail-vip")
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowHandledBy("employee:jdoe", "customer:C-1")
	f := newFixture(t, exchangePolicy, authz, enforced)

	t.Run("employee naming a customer they do not handle is refused", func(t *testing.T) {
		resp := f.do(f.form(f.employeeToken("jdoe", nil), "customer:C-2", ""))
		if resp.StatusCode == http.StatusOK {
			t.Fatal("minted a token for a customer this employee does not handle")
		}
	})

	t.Run("employee naming a customer they DO handle: sub is the customer, employee is the act level", func(t *testing.T) {
		claims := f.mint(f.form(f.employeeToken("jdoe", nil), "customer:C-1", ""))

		if got := str(claims, "sub"); got != "customer:C-1" {
			t.Fatalf("sub = %q, want %q — the authority minted is the CUSTOMER's", got, "customer:C-1")
		}
		act, ok := claims["act"].(map[string]any)
		if !ok {
			t.Fatal("no act level")
		}
		if got := str(act, "sub"); got != "employee:jdoe" {
			t.Fatalf("act.sub = %q, want %q — staff exercises the customer's authority, they don't replace it", got, "employee:jdoe")
		}
		actGarm, ok := act["garm"].(map[string]any)
		if !ok || str(actGarm, "clearance") == "" {
			t.Fatal("act level (the employee) carries no usable garm claim")
		}
		if got := str(actGarm, "kind"); got != "USER" {
			t.Errorf("act.garm.kind = %q, want USER (employees are USER, same as customers)", got)
		}
	})
}

// --- spec §3.3: two distinct gates, not one -----------------------------

func TestBothCanInvokeChecksMustPass(t *testing.T) {
	t.Run("customer's segment may not reach the agent", func(t *testing.T) {
		authz := newFakeAuthz()
		authz.allowSegment("customer:C-1", "retail-vip")
		authz.allowSegment("employee:jdoe", "support-staff")
		authz.allowHandledBy("employee:jdoe", "customer:C-1")
		authz.allowInvoke("employee:jdoe", "agent:order-assistant") // employee CAN, customer CANNOT
		f := newFixture(t, exchangePolicy, authz, enforced)

		resp := f.do(f.form(f.employeeToken("jdoe", nil), "customer:C-1", "order-assistant"))
		if resp.StatusCode == http.StatusOK {
			t.Fatal("minted a token though the customer's segment may not reach this agent")
		}
	})

	t.Run("employee may not drive the agent, even though the customer's segment could", func(t *testing.T) {
		authz := newFakeAuthz()
		authz.allowSegment("customer:C-1", "retail-vip")
		authz.allowSegment("employee:jdoe", "support-staff")
		authz.allowHandledBy("employee:jdoe", "customer:C-1")
		authz.allowInvoke("customer:C-1", "agent:order-assistant") // customer CAN, employee CANNOT
		f := newFixture(t, exchangePolicy, authz, enforced)

		resp := f.do(f.form(f.employeeToken("jdoe", nil), "customer:C-1", "order-assistant"))
		if resp.StatusCode == http.StatusOK {
			t.Fatal("minted a token though staff may not drive this agent")
		}
	})

	// Critical 1/2 fix round: when BOTH requested_subject and agent are
	// present, the chain must be THREE levels — customer (sub) -> agent
	// (act) -> employee (act.act), per RFC 8693 §4.1 (the current actor,
	// the agent, sits outermost; the employee, who acted earlier to obtain
	// this token, nests inside it). Asserting only `sub` here (as an
	// earlier draft of this test did) cannot see a level that was never
	// emitted at all — this is exactly the shape Critical 1 fixed.
	t.Run("both permit: mints a THREE-level chain, sub/act/act.act", func(t *testing.T) {
		authz := newFakeAuthz()
		authz.allowSegment("customer:C-1", "retail-vip")
		authz.allowSegment("employee:jdoe", "support-staff")
		authz.allowHandledBy("employee:jdoe", "customer:C-1")
		authz.allowInvoke("customer:C-1", "agent:order-assistant")
		authz.allowInvoke("employee:jdoe", "agent:order-assistant")
		f := newFixture(t, exchangePolicy, authz, enforced)

		claims := f.mint(f.form(f.employeeToken("jdoe", nil), "customer:C-1", "order-assistant"))
		if got := str(claims, "sub"); got != "customer:C-1" {
			t.Fatalf("sub = %q, want customer:C-1", got)
		}
		if got, ok := claims["garm"].(map[string]any); !ok || str(got, "clearance") == "" {
			t.Fatalf("sub carries no usable garm claim: %v", claims["garm"])
		}

		act, ok := claims["act"].(map[string]any)
		if !ok {
			t.Fatal("no act level at all")
		}
		if got := str(act, "sub"); got != "agent:order-assistant" {
			t.Fatalf("act.sub = %q, want agent:order-assistant — the agent is the CURRENT actor, outermost", got)
		}
		actGarm, ok := act["garm"].(map[string]any)
		if !ok || str(actGarm, "clearance") == "" {
			t.Fatalf("act (the agent) carries no usable garm claim: %v", act["garm"])
		}

		inner, ok := act["act"].(map[string]any)
		if !ok {
			t.Fatal("act.act is missing — the employee must be nested inside the agent's act level, not dropped")
		}
		if got := str(inner, "sub"); got != "employee:jdoe" {
			t.Fatalf("act.act.sub = %q, want employee:jdoe — the employee is a PRIOR actor, nested", got)
		}
		innerGarm, ok := inner["garm"].(map[string]any)
		if !ok || str(innerGarm, "clearance") == "" {
			t.Fatalf("act.act (the employee) carries no usable garm claim: %v", inner["garm"])
		}
	})

	// Critical 1/2 fix round: this is the regression this whole fix exists
	// to close. Before it, the employee's own segment membership was never
	// resolved on the delegating-with-agent path, so an employee in NO
	// segment — who the DIRECT path already refuses via
	// TestExchangeRefusesAPrincipalWithNoRoles — minted successfully here at
	// the customer's full, unnarrowed authority. The employee's own
	// entitlement must gate this path exactly as it gates the direct one.
	t.Run("employee in no segment at all is refused, even though the customer is fully entitled", func(t *testing.T) {
		authz := newFakeAuthz()
		authz.allowSegment("customer:C-1", "retail-vip")
		// Deliberately NOT calling authz.allowSegment for employee:jdoe: the
		// employee belongs to no segment, so ForSegments("employee", nil)
		// must refuse.
		authz.allowHandledBy("employee:jdoe", "customer:C-1")
		authz.allowInvoke("customer:C-1", "agent:order-assistant")
		authz.allowInvoke("employee:jdoe", "agent:order-assistant")
		f := newFixture(t, exchangePolicy, authz, enforced)

		resp := f.do(f.form(f.employeeToken("jdoe", nil), "customer:C-1", "order-assistant"))
		if resp.StatusCode == http.StatusOK {
			t.Fatal("minted a token though the acting employee belongs to no segment and has no authority of their own to assert")
		}
	})
}

// --- Important 3: tenant is required, never invented, never blank --------

func TestExchangeRefusesASubjectTokenWithNoTenant(t *testing.T) {
	// A verified upstream token with no `tenant` claim at all must refuse
	// the mint outright rather than propagate an empty string: confinement
	// to a tenant's own data depends on this value flowing from the token,
	// so `"tenant":""` on a minted token is a confinement failure, not a
	// cosmetic gap.
	authz := newFakeAuthz()
	authz.allowSegment("customer:C-1", "retail-vip")
	authz.allowInvoke("customer:C-1", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	resp := f.do(f.form(f.customerTokenNoTenant("C-1"), "", "order-assistant"))
	if resp.StatusCode == http.StatusOK {
		t.Fatal("minted a token for a subject token that carries no tenant claim")
	}
}

// --- Review Focus 1, at the handler --------------------------------------

func TestExchangeRefusesAPrincipalWithNoRoles(t *testing.T) {
	// customer:C-1 belongs to no segment at all — Policy.ForSegments has
	// nothing to resolve, and that refusal must surface all the way to the
	// HTTP handler, not just at the unit tested in claims_test.go.
	authz := newFakeAuthz()
	authz.allowInvoke("customer:C-1", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	resp := f.do(f.form(f.customerToken("C-1", nil), "", "order-assistant"))
	if resp.StatusCode == http.StatusOK {
		t.Fatal("minted a token for a principal with no roles to assert")
	}
}

// --- spec §2.4 ------------------------------------------------------------

func TestExchangeRefusesWhenTheVerbIntersectionIsEmpty(t *testing.T) {
	// customer:C-1 holds only READ (self-service); write-bot holds only
	// WRITE. The chain would be syntactically valid and useless.
	authz := newFakeAuthz()
	authz.allowSegment("customer:C-1", "retail-vip")
	authz.allowInvoke("customer:C-1", "agent:write-bot")
	f := newFixture(t, exchangePolicy, authz, enforced)

	resp := f.do(f.form(f.customerToken("C-1", nil), "", "write-bot"))
	if resp.StatusCode == http.StatusOK {
		t.Fatal("minted a token whose sub/act verb intersection is empty")
	}
}

// --- Review Focus 5: instanceAuthorization is a refusal gate -------------

func TestInstanceAuthorizationAbsentRefusesCustomerTokens(t *testing.T) {
	newAuthzWithBoth := func() *fakeAuthz {
		a := newFakeAuthz()
		a.allowSegment("customer:C-1", "sme-basic") // grants RESTRICTED via vip-extra
		a.allowSegment("employee:jdoe", "support-staff")
		a.allowInvoke("customer:C-1", "agent:order-assistant")
		a.allowInvoke("employee:jdoe", "agent:order-assistant")
		return a
	}

	t.Run("absent, no ceiling: customer refused outright", func(t *testing.T) {
		f := newFixture(t, exchangePolicy, newAuthzWithBoth(), sts.InstanceAuthzConfig{Status: "absent"})
		resp := f.do(f.form(f.customerToken("C-1", nil), "", "order-assistant"))
		if resp.StatusCode == http.StatusOK {
			t.Fatal("minted a customer token with instanceAuthorization absent and no ceiling")
		}
		// An employee token, same configuration, is unaffected.
		claims := f.mint(f.form(f.employeeToken("jdoe", nil), "", "order-assistant"))
		if got := str(claims, "sub"); got != "employee:jdoe" {
			t.Fatalf("employee mint sub = %q, want employee:jdoe", got)
		}
	})

	t.Run("absent with a ceiling: mints, capped, and the cap is logged", func(t *testing.T) {
		var logBuf strings.Builder
		instance := sts.InstanceAuthzConfig{Status: "absent", UnconfinedCeiling: "PUBLIC"}
		f := newFixtureWithLog(t, exchangePolicy, newAuthzWithBoth(), instance, &logBuf)

		claims := f.mint(f.form(f.customerToken("C-1", nil), "", "order-assistant"))
		garm, ok := claims["garm"].(map[string]any)
		if !ok {
			t.Fatal("no garm claim")
		}
		if got := str(garm, "clearance"); got != "PUBLIC" {
			t.Fatalf("garm.clearance = %q, want PUBLIC — the policy grants RESTRICTED, the ceiling must cap it", got)
		}
		if !strings.Contains(logBuf.String(), "capped") {
			t.Fatalf("the cap was applied but not logged; a silent cap is the same failure as no cap.\nlog:\n%s", logBuf.String())
		}

		// An employee, same configuration, is unaffected: no cap applied.
		empClaims := f.mint(f.form(f.employeeToken("jdoe", nil), "", "order-assistant"))
		empGarm, _ := empClaims["garm"].(map[string]any)
		if got := str(empGarm, "clearance"); got != "INTERNAL" {
			t.Fatalf("employee garm.clearance = %q, want INTERNAL (support-desk), unaffected by the customer ceiling", got)
		}
	})

	t.Run("enforced: mints exactly what the policy grants", func(t *testing.T) {
		f := newFixture(t, exchangePolicy, newAuthzWithBoth(), sts.InstanceAuthzConfig{Status: "enforced"})
		claims := f.mint(f.form(f.customerToken("C-1", nil), "", "order-assistant"))
		garm, _ := claims["garm"].(map[string]any)
		if got := str(garm, "clearance"); got != "RESTRICTED" {
			t.Fatalf("garm.clearance = %q, want RESTRICTED — enforced must not cap anything", got)
		}
	})
}

// newFixtureWithLog is newFixture but routes the server's log through a
// buffer the test can inspect.
func newFixtureWithLog(t *testing.T, policyYAML string, authz *fakeAuthz, instance sts.InstanceAuthzConfig, out *strings.Builder) *fixture {
	t.Helper()
	f := newFixture(t, policyYAML, authz, instance)

	// Rebuild the server with the buffering log, reusing every other
	// dependency the first build already validated.
	srv, err := sts.NewServer(sts.Options{
		Issuer:        stsIssuer,
		Audience:      garmAudience,
		Keyring:       f.kr,
		Verifier:      f.verifierOf(t, policyYAML),
		Policy:        loadPolicy(t, policyYAML),
		Authz:         authz,
		Clients:       f.clientsOf(t),
		DelegationTTL: 5 * time.Minute,
		InstanceAuthz: instance,
		Log:           slog.New(slog.NewTextHandler(out, nil)),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	f.srv = srv
	return f
}

// verifierOf and clientsOf rebuild fresh dependencies bound to the SAME
// upstream/client keys and clock the fixture already generated, so the
// re-created server accepts the exact same tokens and assertions the
// original one would have.
func (f *fixture) verifierOf(t *testing.T, _ string) *sts.Verifier {
	t.Helper()
	nowFn := func() time.Time { return f.now }
	custIdP := newTestIdP(t, upstreamJWK("cust-k1", f.custKey))
	empIdP := newTestIdP(t, upstreamJWK("emp-k1", f.empKey))
	return sts.NewVerifier([]sts.TrustedIssuer{
		{Name: "customer-idp", Issuer: custIssuer, JWKSURL: custIdP.server.URL, Audience: []string{"shop-bff"}, Kind: "customer"},
		{Name: "employee-idp", Issuer: empIssuer, JWKSURL: empIdP.server.URL, Audience: []string{"internal-app"}, Kind: "employee"},
	}, sts.VerifierOptions{Now: nowFn})
}

func (f *fixture) clientsOf(t *testing.T) *sts.ClientRegistry {
	t.Helper()
	nowFn := func() time.Time { return f.now }
	return newTestRegistry(t, nowFn,
		sts.ClientConfig{ID: "shop-bff", PEMs: [][]byte{clientPublicKeyPEM(t, f.clientKey)}},
		sts.ClientConfig{ID: "agentd", PEMs: [][]byte{clientPublicKeyPEM(t, f.clientKey)}})
}

// --- fail closed and opaquely ---------------------------------------------

func TestExchangeFailsClosedAndOpaquely(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("customer:C-1", "retail-vip")
	authz.allowSegment("employee:jdoe", "support-staff")
	f := newFixture(t, exchangePolicy, authz, enforced)

	scenarios := map[string]url.Values{
		"unknown agent":                                 f.form(f.customerToken("C-1", nil), "", "no-such-agent"),
		"missing handled_by relation":                   f.form(f.employeeToken("jdoe", nil), "customer:C-1", "order-assistant"),
		"under-privileged caller (no can_invoke tuple)": f.form(f.customerToken("C-1", nil), "", "order-assistant"),
	}

	var status int
	var body string
	first := true
	for name, form := range scenarios {
		resp := f.do(form)
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("%s: unexpectedly minted a token", name)
		}
		if first {
			status, body, first = resp.StatusCode, string(b), false
			continue
		}
		if resp.StatusCode != status {
			t.Errorf("%s: status = %d, want the SAME status every other denial used (%d) — a differing status is an enumeration oracle",
				name, resp.StatusCode, status)
		}
		if string(b) != body {
			t.Errorf("%s: body = %q, want the SAME body every other denial used (%q) — a differing body is an enumeration oracle",
				name, string(b), body)
		}
		if strings.Contains(strings.ToLower(string(b)), "agent") || strings.Contains(strings.ToLower(string(b)), "handled") {
			t.Errorf("%s: response body names the reason: %q", name, string(b))
		}
	}
}

// --- determinism ------------------------------------------------------

func TestMintedTokensAreDeterministic(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("customer:C-1", "sme-basic") // two roles union together — exercises map-fold determinism
	authz.allowInvoke("customer:C-1", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	subjectToken := f.customerToken("C-1", map[string]any{"tenant": "acme"})

	var claimsA, claimsB map[string]any
	for i, dst := range []*map[string]any{&claimsA, &claimsB} {
		*dst = f.mint(f.form(subjectToken, "", "order-assistant"))
		_ = i
	}

	ignore := map[string]bool{"jti": true, "iat": true, "exp": true}
	normalize := func(m map[string]any) map[string]any {
		out := make(map[string]any, len(m))
		for k, v := range m {
			if !ignore[k] {
				out[k] = v
			}
		}
		return out
	}

	a, err := json.Marshal(normalize(claimsA))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(normalize(claimsB))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("two mints of identical inputs produced different claims (modulo jti/iat/exp):\nA: %s\nB: %s", a, b)
	}
	if claimsA["jti"] == claimsB["jti"] {
		t.Fatal("jti did not change between two independent mints")
	}
}

// --- program plan §7 item 10: a subject may already carry its kind --------

// The ONLY tuples written here are for "employee:jdoe". A service that
// prefixed unconditionally would ask the authorizer about
// "employee:employee:jdoe" and be denied — and the denial would name
// nothing, because every refusal from this service is opaque.
func TestExchangeAcceptsASubjectThatAlreadyCarriesItsKindPrefix(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	claims := f.mint(f.form(f.employeeToken("employee:jdoe", nil), "", "order-assistant"))
	if got := str(claims, "sub"); got != "employee:jdoe" {
		t.Fatalf("sub = %q, want employee:jdoe — a subject that already carries its issuer's kind is used as is", got)
	}
}

// The other half, which must keep working: a bare subject IS prefixed.
func TestExchangePrefixesABareSubject(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	claims := f.mint(f.form(f.employeeToken("jdoe", nil), "", "order-assistant"))
	if got := str(claims, "sub"); got != "employee:jdoe" {
		t.Fatalf("sub = %q, want employee:jdoe", got)
	}
}

// A subject carrying a DIFFERENT kind's prefix than its issuer's configured
// kind is refused rather than repaired. TrustedIssuer.Kind is the authority
// on what an issuer's tokens mean (issuer.go: "never vendor-specific claim
// sniffing"), so a token from the employee IdP whose sub says "customer:"
// is either a misconfigured issuer or a subject claim chosen to look like
// one. Rewriting it to "employee:customer:C-1" would hide both.
func TestExchangeRefusesASubjectWhoseKindPrefixContradictsItsIssuer(t *testing.T) {
	authz := newFakeAuthz()
	// Tuples written for BOTH readings, so the refusal below cannot pass
	// merely because nothing happened to match.
	authz.allowSegment("customer:C-1", "retail-vip")
	authz.allowSegment("employee:customer:C-1", "support-staff")
	authz.allowInvoke("customer:C-1", "agent:order-assistant")
	authz.allowInvoke("employee:customer:C-1", "agent:order-assistant")
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowSegment("customer:employee:jdoe", "retail-vip")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	authz.allowInvoke("customer:employee:jdoe", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	// The employee IdP mints it, so the issuer says employee and the
	// subject says customer.
	if resp := f.do(f.form(f.employeeToken("customer:C-1", nil), "", "order-assistant")); resp.StatusCode == http.StatusOK {
		t.Fatal("minted for a subject whose kind prefix contradicts its issuer's configured kind")
	}
	// And the mirror, from the customer IdP.
	if resp := f.do(f.form(f.customerToken("employee:jdoe", nil), "", "order-assistant")); resp.StatusCode == http.StatusOK {
		t.Fatal("minted for a customer-IdP token whose sub claims to be an employee")
	}
	// A prefix with nothing after it names nobody.
	if resp := f.do(f.form(f.employeeToken("employee:", nil), "", "order-assistant")); resp.StatusCode == http.StatusOK {
		t.Fatal("minted for a subject that is nothing but a kind prefix")
	}

	// A subject whose REMAINDER also carries a known prefix is the same
	// doubled identity, reached from the other side. The governed door's
	// segmentKindFromIdentity refuses "employee:employee:jdoe" and
	// "employee:customer:C-1" outright, and the two doors must not disagree
	// about what an identity is — one minting what the other refuses is how
	// a tuple set comes to look correct while half the traffic misses it.
	for _, doubled := range []string{"employee:employee:jdoe", "employee:customer:C-1"} {
		if resp := f.do(f.form(f.employeeToken(doubled, nil), "", "order-assistant")); resp.StatusCode == http.StatusOK {
			t.Fatalf("minted for the doubled identity %q; the governed door refuses exactly this string", doubled)
		}
	}

	// And a bare subject that is itself a prefixed identity would otherwise
	// be prefixed AGAIN, into "employee:agent:order-assistant".
	if resp := f.do(f.form(f.employeeToken("agent:order-assistant", nil), "", "order-assistant")); resp.StatusCode == http.StatusOK {
		t.Fatal("minted for a subject that already names another kind of principal entirely")
	}
}

// --- program plan §3.9: the governed door ---------------------------------

func TestExchange2MintsForAnAssertedSubjectAndCarriesExec(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	authz.allowRun("runner:shop-bff", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	claims := f.mint(f.form2("employee:jdoe", "USER", "order-assistant", "acme"))

	if got := str(claims, "sub"); got != "employee:jdoe" {
		t.Errorf("sub = %q, want employee:jdoe — the subject the runner named", got)
	}
	if got := str(claims, "tenant"); got != "acme" {
		t.Errorf("tenant = %q, want acme", got)
	}
	if got := str(claims, "aud"); got != garmAudience {
		t.Errorf("aud = %q, want %q", got, garmAudience)
	}

	// The exec claim: top-level, outside act, exactly the shape
	// sts-design §4.1 reserved and program plan §3.8 fixes.
	exec, ok := claims["exec"].(map[string]any)
	if !ok {
		t.Fatal("no exec claim; the governed door's whole point is recording WHICH runner obtained this token")
	}
	if got := str(exec, "sub"); got != "runner:shop-bff" {
		t.Errorf("exec.sub = %q, want runner:shop-bff — the AUTHENTICATED client id, prefixed", got)
	}
	if got := str(exec, "iss"); got != stsIssuer {
		t.Errorf("exec.iss = %q, want %q — this service, which is what attests the runner authenticated", got, stsIssuer)
	}
	if len(exec) != 2 {
		t.Errorf("exec has %d fields, want exactly sub and iss; garmd refuses an exec that is not an object with a non-empty sub, and extra fields are authority nobody agreed to", len(exec))
	}

	// And the runner appears NOWHERE in the act chain. Putting it there
	// would make it either assert authority it has no business asserting or
	// carry an all-permissive claim that narrows nothing — the two failures
	// sts-design §4.1 rejected the act-link shape over.
	act, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatal("no act level; every minted token in this design carries one")
	}
	for level, depth := act, 0; level != nil; depth++ {
		if sub := str(level, "sub"); strings.HasPrefix(sub, "runner:") {
			t.Fatalf("act chain level %d names the runner (%q); provenance is exec, never an act link", depth, sub)
		}
		next, _ := level["act"].(map[string]any)
		level = next
	}
	if got := str(act, "sub"); got != "agent:order-assistant" {
		t.Errorf("act.sub = %q, want agent:order-assistant", got)
	}
	// Depth two: human at sub, agent at act, and no runner link — the fold's
	// ceiling of four is not approached (spec §3.3).
	if _, nested := act["act"]; nested {
		t.Error("act carries a nested act; the governed door mints a depth-two chain")
	}
}

// Review Focus 5. subject_token selects exchange 1 and on_behalf_of selects
// exchange 2; there is no reading where both are meant, and silently
// preferring one mints a token the caller did not ask for — from a verified
// identity or an asserted one, which is the whole difference between the
// two doors.
func TestExchange2RefusesWhenSubjectTokenIsAlsoPresent(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	authz.allowRun("runner:shop-bff", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	form := f.form2("employee:jdoe", "USER", "order-assistant", "acme")
	form.Set("subject_token", f.employeeToken("jdoe", nil))

	if resp := f.do(form); resp.StatusCode == http.StatusOK {
		t.Fatal("minted a token for a request naming both a subject_token and an on_behalf_of")
	}
}

// The same refusal, against a caller who REPEATS a door field to hide it.
//
// url.Values.Encode emits every value, and r.FormValue reads only the
// first — so "subject_token=&subject_token=<real>" presents an empty
// subject_token to the door guard and a real one to whatever reads the form
// afterwards. The guard must examine every value, the way a presented `act`
// already does, or the both-present refusal is decorative.
func TestExchangeRefusesBothDoorsEvenWhenAFieldIsRepeated(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	authz.allowRun("runner:shop-bff", "agent:order-assistant")

	cases := map[string]func(f *fixture) url.Values{
		"subject_token hidden behind a leading blank": func(f *fixture) url.Values {
			form := f.form2("employee:jdoe", "USER", "order-assistant", "acme")
			form["subject_token"] = []string{"", f.employeeToken("jdoe", nil)}
			return form
		},
		"on_behalf_of hidden behind a leading blank": func(f *fixture) url.Values {
			form := f.form(f.employeeToken("jdoe", nil), "", "order-assistant")
			form["on_behalf_of"] = []string{"", "employee:jdoe"}
			form.Set("subject_kind", "USER")
			form.Set("tenant", "acme")
			return form
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, exchangePolicy, authz, enforced)
			if resp := f.do(build(f)); resp.StatusCode == http.StatusOK {
				t.Fatal("minted a token for a request that named both doors; repeating a field must not slip past the both-present refusal")
			}
		})
	}
}

// client_assertion_type is in the governed door's documented request table,
// so it must MEAN something. Optional (private_key_jwt is the only client
// authentication this service implements, so an absent type is
// unambiguous), but a present one naming a different kind of assertion is
// refused rather than accepted and disregarded.
func TestExchangeChecksTheClientAssertionType(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	authz.allowRun("runner:shop-bff", "agent:order-assistant")

	t.Run("the jwt-bearer urn is accepted", func(t *testing.T) {
		f := newFixture(t, exchangePolicy, authz, enforced)
		form := f.form2("employee:jdoe", "USER", "order-assistant", "acme")
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		if resp := f.do(form); resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 — the documented assertion type must be accepted", resp.StatusCode)
		}
	})

	t.Run("any other assertion type is refused", func(t *testing.T) {
		f := newFixture(t, exchangePolicy, authz, enforced)
		form := f.form2("employee:jdoe", "USER", "order-assistant", "acme")
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:saml2-bearer")
		if resp := f.do(form); resp.StatusCode == http.StatusOK {
			t.Fatal("minted a token for a caller that said it was presenting a SAML assertion; a documented field that is never read is a field a caller is entitled to believe in")
		}
	})
}

// Review Focus 4. on_behalf_of is asserted, not verified, so its SHAPE is
// the only thing this service can check about it. A bare "jdoe" builds an
// identity no tuple matches, which would read back as an ordinary denial and
// send an operator looking at their tuple store instead of their runner.
func TestExchange2RefusesAnOnBehalfOfWithNoTypePrefix(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("jdoe", "agent:order-assistant")          // deliberately the bare form
	authz.allowInvoke("employee:jdoe", "agent:order-assistant") // and the right one
	authz.allowRun("runner:shop-bff", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	// There is deliberately no "" row here: an empty on_behalf_of means the
	// field is ABSENT, which selects exchange 1 at the dispatch and never
	// reaches this door at all. It is refused (no subject_token verifies),
	// but for an unrelated reason, so asserting it here would have been a
	// row that passes whatever this door does. The bare "jdoe" row below is
	// the case that "" was reaching for, and it does reach exchange 2.
	for _, bad := range []string{
		"jdoe", ":jdoe", "employee:", "vendor:jdoe",
		// Doubled prefixes, the runner-side form of program plan §7
		// item 10. authz.allowInvoke above is written for the bare
		// reading, not these.
		"employee:employee:jdoe", "employee:customer:C-1", "customer:employee:jdoe",
	} {
		t.Run(fmt.Sprintf("on_behalf_of=%q", bad), func(t *testing.T) {
			// The bare-form can_invoke tuple above means a service that
			// skipped this check would actually MINT for "jdoe" — so this
			// case fails loudly rather than passing because nothing matched.
			if resp := f.do(f.form2(bad, "USER", "order-assistant", "acme")); resp.StatusCode == http.StatusOK {
				t.Fatalf("minted a token for on_behalf_of %q", bad)
			}
		})
	}
}

func TestExchange2RefusalsAreOpaqueAndComplete(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	authz.allowRun("runner:shop-bff", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	// Each scenario is one rule from program plan §3.9, mutated off a form
	// that is otherwise known-good — so a case that passes for an unrelated
	// reason is not possible.
	good := func() url.Values { return f.form2("employee:jdoe", "USER", "order-assistant", "acme") }

	noCanRun := good()
	noCanRun.Set("agent", "write-bot") // declared in the policy, but no can_run tuple

	noCanInvoke := good()
	noCanInvoke.Set("on_behalf_of", "employee:stranger")

	presentedAct := good()
	presentedAct.Set("act", "employee:someone-else")

	// requested_subject is exchange 1's field, honoured only behind
	// handled_by against a VERIFIED employee token. This door has no
	// verified anybody, so honouring it would be impersonation with nothing
	// behind it and ignoring it would mint a token nobody asked for.
	presentedRequestedSubject := good()
	presentedRequestedSubject.Set("requested_subject", "customer:C-8123")

	badKind := good()
	badKind.Set("subject_kind", "AGENT")

	// subject_kind SERVICE over a USER's on_behalf_of. A runner must not be
	// able to turn a person into a service principal by relabelling the
	// kind: the service a SERVICE mint is for is the client that
	// authenticated, never a name in the body.
	serviceKindOverAUser := good()
	serviceKindOverAUser.Set("subject_kind", "SERVICE")

	noTenant := good()
	noTenant.Del("tenant")

	noAgent := good()
	noAgent.Del("agent")

	badAssertion := good()
	badAssertion.Set("client_assertion", "not-a-jwt")

	wrongGrantType := good()
	wrongGrantType.Set("grant_type", "authorization_code")

	scenarios := map[string]url.Values{
		"no can_run tuple for this runner and agent":    noCanRun,
		"no can_invoke tuple for the named subject":     noCanInvoke,
		"the runner presented an act chain":             presentedAct,
		"the runner presented a requested_subject":      presentedRequestedSubject,
		"subject_kind is neither USER nor SERVICE":      badKind,
		"subject_kind SERVICE over a user on_behalf_of": serviceKindOverAUser,
		"no tenant":                        noTenant,
		"no agent":                         noAgent,
		"client assertion does not verify": badAssertion,
		"wrong grant_type":                 wrongGrantType,
	}

	for name, form := range scenarios {
		t.Run(name, func(t *testing.T) {
			resp := f.do(form)
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — every refusal from this service is the same status", resp.StatusCode)
			}
			if got := strings.TrimSpace(string(body)); got != `{"error":"access_denied"}` {
				t.Fatalf("body = %q, want the single opaque denial; a body that varies with the reason is an enumeration oracle", got)
			}
		})
	}

	// And the known-good form still mints, so the mutations above are what
	// is being refused rather than the fixture having gone stale.
	if resp := f.do(good()); resp.StatusCode != http.StatusOK {
		t.Fatalf("the unmutated form was refused with %d; every case above proves nothing", resp.StatusCode)
	}
}

// The governed door must not be a way around the §3.5 clearance gate. A
// runner asking on behalf of a customer reaches the same cap a BFF asking
// with that customer's own token would, because both doors mint through
// resolveAndMint.
func TestExchange2AppliesTheInstanceAuthorizationCapToCustomerSubjects(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("customer:C-1", "sme-basic") // grants RESTRICTED via vip-extra
	authz.allowInvoke("customer:C-1", "agent:order-assistant")
	authz.allowRun("runner:shop-bff", "agent:order-assistant")

	t.Run("absent with a ceiling: capped, exactly as the direct door", func(t *testing.T) {
		f := newFixture(t, exchangePolicy, authz, sts.InstanceAuthzConfig{Status: "absent", UnconfinedCeiling: "PUBLIC"})
		claims := f.mint(f.form2("customer:C-1", "USER", "order-assistant", "acme"))
		garm, _ := claims["garm"].(map[string]any)
		if got := str(garm, "clearance"); got != "PUBLIC" {
			t.Fatalf("garm.clearance = %q, want PUBLIC — the governed door must not be a way past the §3.5 cap", got)
		}
	})

	t.Run("absent with no ceiling: refused, exactly as the direct door", func(t *testing.T) {
		f := newFixture(t, exchangePolicy, authz, sts.InstanceAuthzConfig{Status: "absent"})
		if resp := f.do(f.form2("customer:C-1", "USER", "order-assistant", "acme")); resp.StatusCode == http.StatusOK {
			t.Fatal("minted a customer token through the governed door with instanceAuthorization absent and no ceiling")
		}
	})
}

// The two doors mint the same token. Everything that differs is named here
// and nothing else may: exec (present on one, absent on the other by
// design), and jti/iat/exp, which differ between any two mints at all.
//
// It is a property rather than a pair of expectations because the failure it
// guards against is silent: a claims change applied to one door's code path
// and not the other's produces two tokens garmd folds differently, and the
// only place that shows up is a caller who reaches less than they should
// through one door than the other.
func TestBothDoorsMintTheSameTokenApartFromExec(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	authz.allowRun("runner:shop-bff", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	direct := f.mint(f.form(f.employeeToken("jdoe", map[string]any{"tenant": "acme"}), "", "order-assistant"))
	governed := f.mint(f.form2("employee:jdoe", "USER", "order-assistant", "acme"))

	if _, present := direct["exec"]; present {
		t.Error("the DIRECT door minted an exec claim; a token obtained with a human's own credential has no runner to record")
	}
	if _, present := governed["exec"]; !present {
		t.Fatal("the governed door minted no exec claim")
	}

	volatile := map[string]bool{"jti": true, "iat": true, "exp": true, "exec": true}
	normalize := func(m map[string]any) string {
		out := make(map[string]any, len(m))
		for k, v := range m {
			if !volatile[k] {
				out[k] = v
			}
		}
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	if a, b := normalize(direct), normalize(governed); a != b {
		t.Fatalf("the two doors minted different tokens for the same subject and agent.\n direct: %s\ngoverned: %s", a, b)
	}
}

// --- the CanRun gate, made load-bearing -----------------------------------

// Everything here is set up to succeed EXCEPT can_run: the subject is in a
// segment, it may invoke this agent, the tenant is named, the assertion
// verifies, and the verb intersection is non-empty. So the only thing that
// can refuse is the gate, and deleting the gate mints a token.
//
// This is deliberately not the `write-bot` row in
// TestExchange2RefusalsAreOpaqueAndComplete: support-staff holds READ and
// write-only holds WRITE, so that row's verb intersection is empty and
// resolveAndMint would refuse it with the gate gone. It refuses for the
// right reason today and would keep refusing for a wrong one, which is the
// definition of a test that is not load-bearing.
func TestExchange2RefusesARunnerWithNoCanRunTuple(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("employee:jdoe", "agent:order-assistant")
	// and deliberately NO allowRun("runner:shop-bff", "agent:order-assistant")
	f := newFixture(t, exchangePolicy, authz, enforced)

	resp := f.do(f.form2("employee:jdoe", "USER", "order-assistant", "acme"))
	if resp.StatusCode == http.StatusOK {
		t.Fatal("minted for a runner with no can_run tuple, on a request where every other check passes; " +
			"on_behalf_of is asserted and verified against no IdP, so can_run is the only thing standing between this door and impersonation")
	}

	// The same request with the one missing tuple written mints, so the
	// refusal above is that tuple's absence and nothing else.
	authz.allowRun("runner:shop-bff", "agent:order-assistant")
	if resp := f.do(f.form2("employee:jdoe", "USER", "order-assistant", "acme")); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d with the can_run tuple written; the refusal above proves nothing unless this mints", resp.StatusCode)
	}
}

// CanRun is asked BEFORE CanInvoke, and a denied CanRun stops the exchange
// without asking CanInvoke at all.
//
// The order is a security property, not a style choice. on_behalf_of is
// ASSERTED by the runner and verified against no IdP; the only reason to
// look at it is a written tuple saying this runner may execute this agent.
// Asking CanInvoke first would answer "may this subject reach that agent"
// for any caller who can reach the endpoint, whether or not they were ever
// entitled to run it — an entitlement oracle, reachable by anyone holding
// any valid client assertion.
func TestExchange2AsksCanRunBeforeCanInvokeAndNeverProbesOnADeniedRun(t *testing.T) {
	t.Run("granted: can_run is asked, and asked first", func(t *testing.T) {
		authz := newFakeAuthz()
		authz.allowSegment("employee:jdoe", "support-staff")
		authz.allowInvoke("employee:jdoe", "agent:order-assistant")
		authz.allowRun("runner:shop-bff", "agent:order-assistant")
		f := newFixture(t, exchangePolicy, authz, enforced)

		f.mint(f.form2("employee:jdoe", "USER", "order-assistant", "acme"))

		calls := f.authz.recorded()
		run, invoke := firstCallTo(calls, "CanRun"), firstCallTo(calls, "CanInvoke")
		if run < 0 {
			t.Fatalf("CanRun was never asked on the governed door; calls: %v", calls)
		}
		if invoke < 0 {
			t.Fatalf("CanInvoke was never asked; calls: %v", calls)
		}
		if run > invoke {
			t.Fatalf("CanInvoke (index %d) was asked before CanRun (index %d); an unauthorised runner must never get an entitlement answer.\ncalls: %v",
				invoke, run, calls)
		}
	})

	t.Run("denied: can_invoke is never asked at all", func(t *testing.T) {
		authz := newFakeAuthz()
		authz.allowSegment("employee:jdoe", "support-staff")
		// The subject genuinely MAY invoke this agent — so if the door asked,
		// it would get a "yes" it had no business asking for.
		authz.allowInvoke("employee:jdoe", "agent:order-assistant")
		// The runner may not run it.
		f := newFixture(t, exchangePolicy, authz, enforced)

		if resp := f.do(f.form2("employee:jdoe", "USER", "order-assistant", "acme")); resp.StatusCode == http.StatusOK {
			t.Fatal("minted despite no can_run tuple")
		}

		calls := f.authz.recorded()
		if firstCallTo(calls, "CanRun") < 0 {
			t.Fatalf("CanRun was never asked; calls: %v", calls)
		}
		if i := firstCallTo(calls, "CanInvoke"); i >= 0 {
			t.Fatalf("CanInvoke was asked (%q) after CanRun denied; the refusal is now an entitlement oracle — "+
				"a caller who may run nothing still learns who may invoke what.\ncalls: %v", calls[i], calls)
		}
		// Nor did it get as far as resolving anybody's segments.
		if i := firstCallTo(calls, "InSegment"); i >= 0 {
			t.Fatalf("InSegment was asked (%q) after CanRun denied; the exchange should have stopped at the gate.\ncalls: %v", calls[i], calls)
		}
	})
}

// --- the service principal ------------------------------------------------

// TestExchange2ServiceSelfMintCarriesNoActChain is the rewrite of what this
// test asserted before the f21 fix (f21-act-chain-fix-report.md): that a
// SERVICE self-mint's `act` level carried the named agent's own claim. That
// was the bug — folding the agent in is exactly what let garmd's Fold
// intersect the service's `tool_sets` away to nothing (stack-repair-report.md
// §4.2) — so the renamed test now asserts the opposite: no `act` entry at
// all, and the service's OWN declared `tool_sets` surviving untouched.
//
// It uses selfMintPolicy rather than exchangePolicy specifically because
// exchangePolicy's agentd/write-bot pair declares no tool_sets on either
// side, which is why the original version of this test, passing throughout,
// never once observed the defect it was named for: intersectSets' "nil add
// is no constraint" branch made the fold a no-op regardless of whether the
// agent ever reached `act`. selfMintPolicy's agentd is scoped to
// [escalation] and support-assistant to a disjoint [support] — the shape
// that actually broke in production — so this test would have failed
// against the pre-f21 code.
func TestExchange2ServiceSelfMintCarriesNoActChain(t *testing.T) {
	authz := newFakeAuthz()
	// can_run only. No can_invoke tuple is written for the service, and the
	// absence is deliberate — see the assertion on the call log below.
	authz.allowRun("runner:agentd", "agent:support-assistant")
	f := newFixture(t, selfMintPolicy, authz, enforced)

	claims := f.mint(f.form2As("agentd", "service:agentd", "SERVICE", "support-assistant", "acme"))

	if got := str(claims, "sub"); got != "service:agentd" {
		t.Errorf("sub = %q, want service:agentd — the service calls on its own behalf", got)
	}

	garm, ok := claims["garm"].(map[string]any)
	if !ok {
		t.Fatal("no garm claim on the sub level")
	}
	// garmd reads the kind from garm.kind through normaliseKind, which maps
	// anything it does not recognise to the EMPTY STRING with no error. So
	// this asserts the exact spelling: a token minted with "svc" would
	// verify, carry no kind at all, and be refused by tasksd for the one
	// reason that looks like a tasksd bug.
	if got := str(garm, "kind"); got != "SERVICE" {
		t.Errorf("garm.kind = %q, want SERVICE — normaliseKind maps that to PRINCIPAL_KIND_SERVICE; an unrecognised value silently becomes \"\"", got)
	}
	if got := str(garm, "clearance"); got != "PUBLIC" {
		t.Errorf("garm.clearance = %q, want the declared PUBLIC", got)
	}
	if !sliceEqual(strSlice(garm, "verbs"), []string{"READ", "WRITE"}) {
		t.Errorf("garm.verbs = %v, want [READ, WRITE] as declared", strSlice(garm, "verbs"))
	}
	// SCOPED to exactly what agentd declares — [escalation] — and untouched
	// by anything about the named agent. Before f21 this came back EMPTY,
	// non-nil, because Fold intersected it against support-assistant's
	// [support]: this is the one assertion that would have caught the bug
	// directly, had the original fixture given it anything to intersect.
	if !sliceEqual(strSlice(garm, "tool_sets"), []string{"escalation"}) {
		t.Errorf("garm.tool_sets = %v, want [escalation] — the service's own declared scope, which a consumer's Fold must receive unintersected", strSlice(garm, "tool_sets"))
	}

	// THE FIX: no act level at all. The agent named here was authorization
	// input to CanRun (below) and never an actor — there is nothing for a
	// consumer's Fold to narrow this service's claim against.
	if act, present := claims["act"]; present {
		t.Errorf("act = %#v present; a service self-mint names the agent as authorization input to CanRun, "+
			"never as an actor, so there must be no `act` entry for anything to fold against", act)
	}

	// Provenance is still the runner, and still exec rather than an act link.
	exec, ok := claims["exec"].(map[string]any)
	if !ok {
		t.Fatal("no exec claim; the governed door records WHICH runner obtained the token")
	}
	if got := str(exec, "sub"); got != "runner:agentd" {
		t.Errorf("exec.sub = %q, want runner:agentd", got)
	}

	// can_invoke is NOT asked of a service, and that is a design decision
	// rather than an omission: the production model derives can_invoke from
	// segment membership (deploy/model.fga, `invokable_by: [segment#member]`,
	// members being customers and employees), so "service:agentd" is a user
	// no tuple set can answer yes for. Asking it would deny every service
	// mint on the OpenFGA authorizer while passing here against a fake that
	// was told to allow it — green in CI, dead in production.
	for _, c := range authz.recorded() {
		if strings.HasPrefix(c, "CanInvoke(") {
			t.Errorf("asked %s; can_invoke is a person's entitlement and the production model cannot answer it for a service", c)
		}
		if strings.HasPrefix(c, "InSegment(") {
			t.Errorf("asked %s; a service is not segment-matched — it is one identity with one declared authority", c)
		}
	}
	// can_run is still the one relationship standing between a runner and a
	// service mint — see f21-act-chain-fix-report.md's §1: removing the
	// agent from `act` must never have cost this check.
	if firstCallTo(authz.recorded(), "CanRun") < 0 {
		t.Error("never asked CanRun; it is the only relationship standing between a runner and a service mint")
	}
}

// The negative half, without which the positive half proves nothing.
//
// Every row is refused, and every row is refused IDENTICALLY — an undeclared
// service must not be distinguishable from one that is declared but not the
// caller's, or this door becomes an oracle for which services a deployment
// runs.
func TestExchange2RefusesAServiceSubjectItCannotJustify(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowRun("runner:agentd", "agent:write-bot")
	authz.allowRun("runner:shop-bff", "agent:write-bot")
	// Written deliberately: a service that passed can_invoke would still have
	// to be declared AND be the authenticated client, so these tuples must
	// not rescue any row below.
	authz.allowInvoke("service:agentd", "agent:write-bot")
	authz.allowInvoke("service:ghost", "agent:write-bot")
	authz.allowInvoke("service:shop-bff", "agent:write-bot")
	f := newFixture(t, exchangePolicy, authz, enforced)

	cases := map[string]url.Values{
		// Declared in the policy, but the caller authenticated as somebody
		// else. Without this check, any client holding any registered key
		// could mint any declared service's authority.
		"a service the caller did not authenticate as": f.form2As("shop-bff", "service:agentd", "SERVICE", "write-bot", "acme"),
		// The caller IS who it says, and the policy has never heard of it.
		"an undeclared service": f.form2As("shop-bff", "service:shop-bff", "SERVICE", "write-bot", "acme"),
		// Neither declared nor the caller.
		"a service nobody has heard of": f.form2As("agentd", "service:ghost", "SERVICE", "write-bot", "acme"),
		// A service subject on the USER path, and a user subject on the
		// SERVICE path: subject_kind and the prefix must agree.
		"service identity under subject_kind USER": f.form2As("agentd", "service:agentd", "USER", "write-bot", "acme"),
		"bare service name, no prefix":             f.form2As("agentd", "agentd", "SERVICE", "write-bot", "acme"),
		"doubled prefix":                           f.form2As("agentd", "service:service:agentd", "SERVICE", "write-bot", "acme"),
		"empty service name":                       f.form2As("agentd", "service:", "SERVICE", "write-bot", "acme"),
	}

	for name, form := range cases {
		t.Run(name, func(t *testing.T) {
			resp := f.do(form)
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if got := strings.TrimSpace(string(body)); got != `{"error":"access_denied"}` {
				t.Fatalf("body = %q, want the single opaque denial; a body that varies with the reason tells a caller which services exist", got)
			}
		})
	}

	// And the one request that SHOULD mint still does, so the rows above are
	// refused for their own reason rather than because the service path never
	// worked.
	if resp := f.do(f.form2As("agentd", "service:agentd", "SERVICE", "write-bot", "acme")); resp.StatusCode != http.StatusOK {
		t.Fatalf("the justified service mint was refused with %d; every row above proves nothing", resp.StatusCode)
	}
}

// TestExchange2ServiceSelfMintSucceedsDespiteDisjointAgentVerbsAndToolSets is
// the rewrite of what this test asserted before the f21 fix: that a service
// whose verbs shared nothing with the named agent's minted nothing, on the
// theory that the agent's claim was the other half of a fold this exchange
// was computing. It was not — the agent is authorization input to CanRun,
// never a party this mint's chain includes — so there is nothing left to
// intersect and nothing left to refuse on that basis: this now asserts the
// mint SUCCEEDS, carries no `act`, and the service's own verbs and tool_sets
// are exactly what it declared, regardless of what the agent happens to
// hold.
//
// destructive-bot is deliberately the sharpest case selfMintPolicy has: its
// verb (DESTRUCTIVE) and its set (danger) share NOTHING with agentd's
// declared [READ, WRITE] / [escalation] — not one axis in common — so this
// is not a near miss, and it would have failed outright, on the old
// assertion, against the pre-f21 code.
func TestExchange2ServiceSelfMintSucceedsDespiteDisjointAgentVerbsAndToolSets(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowRun("runner:agentd", "agent:destructive-bot")
	f := newFixture(t, selfMintPolicy, authz, enforced)

	claims := f.mint(f.form2As("agentd", "service:agentd", "SERVICE", "destructive-bot", "acme"))

	if _, present := claims["act"]; present {
		t.Error("act present; the named agent's own verbs/tool_sets must not matter to a service self-mint")
	}
	garm, ok := claims["garm"].(map[string]any)
	if !ok {
		t.Fatal("no garm claim on the sub level")
	}
	if !sliceEqual(strSlice(garm, "verbs"), []string{"READ", "WRITE"}) {
		t.Errorf("garm.verbs = %v, want [READ, WRITE] as agentd declared, untouched by destructive-bot's [DESTRUCTIVE]", strSlice(garm, "verbs"))
	}
	if !sliceEqual(strSlice(garm, "tool_sets"), []string{"escalation"}) {
		t.Errorf("garm.tool_sets = %v, want [escalation] as agentd declared, untouched by destructive-bot's [danger]", strSlice(garm, "tool_sets"))
	}
}

// --- the self-mint act-chain fix (f21) --------------------------------------
//
// stack-repair-report.md §4.2: ExchangeService is Exchange2 with on_behalf_of
// == "service:"+clientID, so the agent it names used to land at `act` — an
// actor in the delegation chain — and garmd's Fold intersects tool_sets
// UNCONDITIONALLY at every chain level, before the first-level shortcut
// clearance/compartments/verbs get. A service scoped to tool_sets:
// [escalation] folded against ANY agent (none of which declare escalation,
// nor should they — that is the set's entire purpose) always intersected to
// the empty, non-nil scope, and garmd's inScope treats a non-nil empty scope
// as reaching nothing. create_task was one of the zero tools reachable.
//
// selfMintPolicy mirrors examples/bank/auth/claims.yaml closely enough to
// reproduce that exactly: agentd is scoped to [escalation] and
// support-assistant is scoped to a disjoint set, [support]. exchangePolicy's
// write-bot and order-assistant never exercise this, because neither one
// declares any tool_sets at all — intersectSets' "nil add is no constraint"
// branch makes the bug invisible to every existing test in this file, which
// is exactly how it reached production.
//
// destructive-bot exists for the same reason, one dimension over: its verb
// (DESTRUCTIVE) and its set (danger) share NOTHING with agentd's declared
// [READ, WRITE] / [escalation] — neither a verb nor a set in common — so a
// test that names it is the sharpest possible demonstration that a service
// self-mint's own authority stands alone, un-intersected against the
// agent's, on every axis Fold narrows.
const selfMintPolicy = `
roles:
  support-desk:     { clearance: INTERNAL, compartments: [], verbs: [READ],       tool_sets: [support] }
  destructive-only: { clearance: INTERNAL, compartments: [], verbs: [DESTRUCTIVE], tool_sets: [danger] }

segments:
  support-staff: { kind: employee, roles: [support-desk] }

agents:
  support-assistant: { roles: [support-desk] }
  destructive-bot:   { roles: [destructive-only] }

services:
  agentd: { clearance: PUBLIC, verbs: [READ, WRITE], tool_sets: [escalation] }
`

// TestExchange2ServiceSelfMintStillRequiresCanRun pins the check that must
// not regress alongside the act-chain fix: the agent no longer appears in
// the minted token, but it is still asked of CanRun before anything mints. A
// fix that stopped asking would trade this bug for a worse one — a service
// minting for ANY agent at all, approved or not.
func TestExchange2ServiceSelfMintStillRequiresCanRun(t *testing.T) {
	authz := newFakeAuthz() // no can_run tuple written at all
	f := newFixture(t, selfMintPolicy, authz, enforced)

	resp := f.do(f.form2As("agentd", "service:agentd", "SERVICE", "support-assistant", "acme"))
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400 (denied); minted without a can_run tuple at all: %s", resp.StatusCode, body)
	}
	if i := firstCallTo(authz.recorded(), "CanRun"); i < 0 {
		t.Fatalf("CanRun was never asked; calls: %v", authz.recorded())
	}
}

// TestExchange2HumanDelegationStillCarriesTheAgentActChain is the regression
// this fix must not cause: a REAL on-behalf-of exchange — a human subject,
// an agent acting for them — is untouched. Its act chain still names the
// agent and still carries the agent's own declared claim, tool_sets
// included: unlike the service's self-mint, this agent genuinely IS the
// actor, and a consumer's Fold narrowing against it is the whole point of
// delegation (spec §2.3) — not the bug fixed above.
func TestExchange2HumanDelegationStillCarriesTheAgentActChain(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowInvoke("employee:jdoe", "agent:support-assistant")
	authz.allowRun("runner:shop-bff", "agent:support-assistant")
	f := newFixture(t, selfMintPolicy, authz, enforced)

	claims := f.mint(f.form2("employee:jdoe", "USER", "support-assistant", "acme"))

	act, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatal("no act level; a genuine on-behalf-of exchange must still carry one")
	}
	if got := str(act, "sub"); got != "agent:support-assistant" {
		t.Errorf("act.sub = %q, want agent:support-assistant", got)
	}
	actGarm, ok := act["garm"].(map[string]any)
	if !ok {
		t.Fatal("act carries no garm claim; garmd's ParseClaims refuses the whole token")
	}
	if !sliceEqual(strSlice(actGarm, "tool_sets"), []string{"support"}) {
		t.Errorf("act.garm.tool_sets = %v, want [support] — the agent's own declared scope, unchanged by this fix", strSlice(actGarm, "tool_sets"))
	}
}

// --- the agent attribution claim (contracts v0.12.0, InvocationContext.agent,
// field 12) ------------------------------------------------------------------
//
// The act-chain fix above correctly stopped a SERVICE self-mint's agent from
// folding authority, but it also stopped attributing the run to that agent at
// all — garmd's Agent: p.Actor (core.go:1023) is sourced from the delegation
// chain, which the fix emptied for exactly this case. contracts v0.12.0 gave
// attribution a home that is NOT the chain: InvocationContext.agent, field
// 12, whose own doc states the rule this section exists to satisfy: "`act`
// answers 'whose authority is this'; this answers 'whose run was it'."
//
// These three tests mint carries that claim, that it is absent where there is
// genuinely nothing to attribute, and — the one that matters — that its mere
// presence changes nothing Fold narrows.

// TestExchange2ServiceSelfMintCarriesAnAgentAttributionClaim is the positive
// case: the agent named for CanRun now also reaches the token, as a
// standalone claim, so garmd has something to forward.
func TestExchange2ServiceSelfMintCarriesAnAgentAttributionClaim(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowRun("runner:agentd", "agent:support-assistant")
	f := newFixture(t, selfMintPolicy, authz, enforced)

	claims := f.mint(f.form2As("agentd", "service:agentd", "SERVICE", "support-assistant", "acme"))

	if got := str(claims, "agent"); got != "agent:support-assistant" {
		t.Errorf(`agent = %q, want "agent:support-assistant" — type-prefixed, the same shape every other identity on this token uses`, got)
	}
	// Still no act — this claim is how attribution travels NOW that act no
	// longer carries it, not a second place agent-as-actor could sneak back
	// in.
	if _, present := claims["act"]; present {
		t.Error("act present; the agent attribution claim exists precisely so act does not have to carry the agent")
	}
}

// TestExchangeWithNoAgentNamedCarriesNoAgentAttributionClaim is the "exec"
// precedent applied here too: a mint that genuinely has no agent to
// attribute — an employee exercising a handled-by customer's authority
// directly, no agent in the call at all — carries no `agent` claim, honestly,
// rather than an empty value nothing attested.
func TestExchangeWithNoAgentNamedCarriesNoAgentAttributionClaim(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowSegment("customer:C-1", "retail-vip")
	authz.allowSegment("employee:jdoe", "support-staff")
	authz.allowHandledBy("employee:jdoe", "customer:C-1")
	f := newFixture(t, exchangePolicy, authz, enforced)

	claims := f.mint(f.form(f.employeeToken("jdoe", nil), "customer:C-1", ""))

	if _, present := claims["agent"]; present {
		t.Errorf(`agent = %#v present; no agent was named at all, so there is nothing to attribute`, claims["agent"])
	}
}

// TestExchange2ServiceSelfMintAgentAttributionClaimDoesNotTouchToolSets is
// the regression guard F21 earned: the whole reason the agent left `act` was
// that Fold intersects tool_sets unconditionally at every chain level, and
// this claim exists to carry the SAME piece of information (which agent)
// back onto the token. If it ever ended up anywhere Fold's chain walk
// reaches — inside `garm`, inside `act`, or as a second `act`-like level —
// this would be F21 again, in a new field.
//
// What structurally prevents that: `agent` is a sibling of `exec` and
// `tenant` on mintedToken, read once, outside the `Garm`/`Act` recursion.
// Fold's chain walk (`for cur := c; cur != nil; cur = cur.Act`) only ever
// dereferences `cur.Garm` and advances via `cur.Act` — it has no reference to
// this field, or to `Exec`, at all. That is a fact about Fold's loop body,
// not a convention this claim merely happens to respect, which is why this
// test asserts the OUTCOME (tool_sets unaffected) rather than the field's
// mere existence: a claim that sat in the right place but somehow still got
// folded would still be the bug.
func TestExchange2ServiceSelfMintAgentAttributionClaimDoesNotTouchToolSets(t *testing.T) {
	authz := newFakeAuthz()
	authz.allowRun("runner:agentd", "agent:support-assistant")
	f := newFixture(t, selfMintPolicy, authz, enforced)

	claims := f.mint(f.form2As("agentd", "service:agentd", "SERVICE", "support-assistant", "acme"))

	if got := str(claims, "agent"); got != "agent:support-assistant" {
		t.Fatalf(`agent = %q, want "agent:support-assistant"`, got)
	}
	garm, ok := claims["garm"].(map[string]any)
	if !ok {
		t.Fatal("no garm claim on the sub level")
	}
	// support-assistant declares tool_sets: [support] — disjoint from
	// agentd's [escalation]. Before F21 this intersected to empty; the agent
	// attribution claim re-adds the agent's NAME to the token, and if that
	// name carried its claim along with it the way `act` used to, this would
	// be empty again.
	if !sliceEqual(strSlice(garm, "tool_sets"), []string{"escalation"}) {
		t.Errorf("garm.tool_sets = %v, want [escalation] unchanged — the agent attribution claim must narrow nothing", strSlice(garm, "tool_sets"))
	}
}
