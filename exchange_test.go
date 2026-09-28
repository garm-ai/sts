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
`

// fakeAuthz is a hand-rolled Authorizer: the three relations as plain maps,
// set directly by each test rather than round-tripped through a YAML file,
// so every test can build exactly the tuple set its scenario needs.
type fakeAuthz struct {
	canInvoke map[[2]string]bool
	canRun    map[[2]string]bool
	handledBy map[[2]string]bool
	inSegment map[[2]string]bool
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

func (a *fakeAuthz) CanInvoke(_ context.Context, principal, agent string) (bool, error) {
	return a.canInvoke[[2]string{principal, agent}], nil
}
func (a *fakeAuthz) CanRun(_ context.Context, runner, agent string) (bool, error) {
	return a.canRun[[2]string{runner, agent}], nil
}
func (a *fakeAuthz) HandledBy(_ context.Context, employee, customer string) (bool, error) {
	return a.handledBy[[2]string{employee, customer}], nil
}
func (a *fakeAuthz) InSegment(_ context.Context, principal, segment string) (bool, error) {
	return a.inSegment[[2]string{principal, segment}], nil
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
	clients := newTestRegistry(t, nowFn, sts.ClientConfig{ID: "shop-bff", PEMs: [][]byte{clientPublicKeyPEM(t, clientKey)}})

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
	return newTestRegistry(t, nowFn, sts.ClientConfig{ID: "shop-bff", PEMs: [][]byte{clientPublicKeyPEM(t, f.clientKey)}})
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
