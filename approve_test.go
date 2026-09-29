package sts_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/garm-ai/contracts/grant"
	"github.com/garm-ai/contracts/grants"
	"github.com/garm-ai/sts"
	jose "github.com/go-jose/go-jose/v4"
)

// approverGarm is the `garm` claim an approver's own IdP token carries. The
// approval path READS this rather than resolving it from the claims policy
// (approval-grants §2.4), so every approve test builds one explicitly.
func approverGarm(clearance string, compartments ...string) map[string]any {
	c := map[string]any{"clearance": clearance, "verbs": []any{"READ"}, "kind": "USER"}
	if len(compartments) > 0 {
		list := make([]any, 0, len(compartments))
		for _, s := range compartments {
			list = append(list, s)
		}
		c["compartments"] = list
	}
	return c
}

// bankMaterial is the worked example from approval-grants §1.1, verbatim.
// Using the document's own values means a reader can check this test against
// it without translating.
func bankMaterial() map[string]string {
	return map[string]string{
		"amount_minor_units": "25000",
		"beneficiary_iban":   "GB29NWBK60161331926819",
		"currency_code":      "GBP",
	}
}

// approve posts one /approve request and returns the raw response. bearer
// is the approver's token; body is marshalled as-is so a test can send a
// malformed one.
func (f *fixture) approve(bearer string, body any) *http.Response {
	f.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.srv.ApproveHandler().ServeHTTP(rec, req)
	return rec.Result()
}

// approveBody builds a well-formed request body with a fresh client
// assertion. Callers mutate the returned map to build a bad one.
func (f *fixture) approveBody(tool, subject string, material map[string]string) map[string]any {
	f.t.Helper()
	return map[string]any{
		"client_assertion": clientAssertion(f.t, f.clientKey, "shop-bff", testAudience, f.now.Add(time.Minute), nextJTI()),
		"tool":             tool,
		"subject":          subject,
		"material":         material,
	}
}

// grantClaims posts an approval that is expected to SUCCEED and returns the
// grant's signature-verified claims.
func (f *fixture) grantClaims(bearer string, body any) map[string]any {
	f.t.Helper()
	resp := f.approve(bearer, body)
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("approve failed: status %d, body %s", resp.StatusCode, raw)
	}
	var out struct {
		Grant     string `json:"grant"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		f.t.Fatalf("decoding response: %v; body %s", err, raw)
	}
	if out.ExpiresIn != 900 {
		f.t.Errorf("expires_in = %d, want 900 (program plan §3.10's default)", out.ExpiresIn)
	}
	return f.decodeAndVerify(out.Grant)
}

// TestApproveMintsAGrantGarmdCanRead asserts the claim NAMES, not just the
// values. Every string checked here is one the shared reader in
// github.com/garm-ai/contracts/grants pulls out of a map (ParseClaims), and
// one garmd's own copy pulls out too (parseGrantClaims) — and a name that
// drifts decodes to "" over there and is refused with a message about the
// wrong thing entirely.
func TestApproveMintsAGrantGarmdCanRead(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	bearer := f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})

	claims := f.grantClaims(bearer, f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))

	// The registered claims, read by parseGrantClaims as iss/aud/jti/iat/exp.
	if got := str(claims, "iss"); got != stsIssuer {
		t.Errorf("iss = %q, want %q", got, stsIssuer)
	}
	if got := str(claims, "aud"); got != garmAudience {
		t.Errorf("aud = %q, want %q — the grant's audience is garmd, the same identifier a delegation token names", got, garmAudience)
	}
	if str(claims, "jti") == "" {
		t.Error("jti is empty; §2.2 makes it mandatory and single-use, and garmd refuses a grant with none rather than treating it as unlimited")
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if iat == 0 {
		t.Error("iat is absent; §2.3 makes it load-bearing — garmd measures the grant's AGE from it against the tool's max_grant_age_seconds")
	}
	if int64(exp-iat) != 900 {
		t.Errorf("exp - iat = %d, want 900", int64(exp-iat))
	}
	if _, present := claims["approved_at"]; present {
		t.Error("the grant carries approved_at; §2.3 rules it out deliberately — a separate approval timestamp is a mechanism to re-mint an old decision with a fresh expiry")
	}

	// §2.1, by shape: there is nowhere in the minted struct to put an act
	// chain, and garmd refuses a grant carrying the KEY at all.
	if _, present := claims["act"]; present {
		t.Fatal("the grant carries an act key; garmd refuses any grant that has one, and a delegated identity must not be launderable into a clean approval")
	}

	g, ok := claims["garm_grant"].(map[string]any)
	if !ok {
		t.Fatal(`no garm_grant claim; without it garmd says "the token carries no garm_grant claim, so it is not an approval"`)
	}
	for field, want := range map[string]string{
		"tool":               "payments.v1.initiate_payment",
		"subject":            "customer:C-8123",
		"material":           grant.Digest(bankMaterial()),
		"approver":           "employee:jdoe",
		"approver_clearance": "RESTRICTED",
	} {
		if got := str(g, field); got != want {
			t.Errorf("garm_grant.%s = %q, want %q", field, got, want)
		}
	}
	if got := strSlice(g, "approver_compartments"); !sliceEqual(got, []string{"financial"}) {
		t.Errorf("garm_grant.approver_compartments = %v, want [financial]", got)
	}

	// The digest's own prefix, checked here rather than only through
	// grant.Digest, so a future change to that function's output format
	// fails a test in BOTH repositories instead of silently in neither.
	if !strings.HasPrefix(str(g, "material"), "sha256:") {
		t.Errorf("garm_grant.material = %q, want a sha256: digest", str(g, "material"))
	}
}

// The grant is a real, verifiable ES256 credential signed by the same
// keyring that signs delegation tokens, not merely well-shaped JSON.
func TestApproveSignsWithTheServedKeyring(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	bearer := f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})

	resp := f.approve(bearer, f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Grant string `json:"grant"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	sig, err := jose.ParseSigned(out.Grant, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("the grant does not parse under an ES256-only allowlist: %v", err)
	}
	if kid := sig.Signatures[0].Header.KeyID; kid != "k1" {
		t.Errorf("kid = %q, want k1 — without it a verifier cannot pick the right key after rotation", kid)
	}
}

// Review Focus 2 (§4, frame 12). A customer cannot approve a payment. The
// kind is per-issuer configuration, so this fixture's customer IdP is what
// makes the token a customer's — nothing in the token itself says so.
func TestApproveRefusesANonEmployeeApprover(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	bearer := f.customerToken("C-8123", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})

	resp := f.approve(bearer, f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — a customer cannot approve a payment", resp.StatusCode)
	}
	if got := strings.TrimSpace(string(body)); got != `{"error":"access_denied"}` {
		t.Fatalf("body = %q, want the single opaque denial", got)
	}
}

// Review Focus 3 (§2.1, frame 10). This is what structurally prevents an
// agent approving the destructive action it is itself about to take. Not a
// policy an operator sets: a shape the token may not have.
func TestApproveRefusesADelegatedApprover(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)

	for _, act := range []map[string]any{
		{"sub": "agent:order-assistant", "garm": approverGarm("INTERNAL", "support")},
		{}, // an act with nothing in it is still a token that claimed a chain
	} {
		bearer := f.employeeToken("jdoe", map[string]any{
			"garm": approverGarm("RESTRICTED", "financial"),
			"act":  act,
		})
		resp := f.approve(bearer, f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (act %v); a delegated identity may not approve, and minting one launders a delegated identity through a clean grant", resp.StatusCode, act)
		}
		if got := strings.TrimSpace(string(body)); got != `{"error":"access_denied"}` {
			t.Fatalf("body = %q, want the single opaque denial (act %v)", got, act)
		}
	}
}

// Review Focus 1 (program plan §4 line 2). The STS digests what it is
// GIVEN. A caller can lie about the values, and it does not work — garmd
// re-extracts from the real request and compares — but the property this
// side owns is that the digest is over the presented values ONLY: changing
// one value changes the digest, and no two distinct material sets share
// one.
func TestApproveDigestsOnlyTheValuesItWasGiven(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	bearer := func() string {
		return f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})
	}

	shown := bankMaterial()
	tampered := bankMaterial()
	tampered["amount_minor_units"] = "2500000" // two extra zeros

	shownDigest := str(f.grantClaims(bearer(), f.approveBody("payments.v1.initiate_payment", "customer:C-8123", shown))["garm_grant"].(map[string]any), "material")
	tamperedDigest := str(f.grantClaims(bearer(), f.approveBody("payments.v1.initiate_payment", "customer:C-8123", tampered))["garm_grant"].(map[string]any), "material")

	if shownDigest == tamperedDigest {
		t.Fatal("one changed material value produced the same digest; the grant would then authorise a payment the approver never saw")
	}
	// The digest is exactly what garmd will recompute from the same values.
	if want := grant.Digest(shown); shownDigest != want {
		t.Errorf("material = %q, want %q — the shared grant.Digest over the presented values and nothing else", shownDigest, want)
	}
	if want := grant.Digest(tampered); tamperedDigest != want {
		t.Errorf("material = %q, want %q", tamperedDigest, want)
	}

	// And a value the caller did NOT present contributes nothing. The
	// approver saw three fields; the grant binds those three. If this
	// service ever started resolving a fourth from somewhere, the digest
	// would stop matching what garmd extracts.
	fewer := bankMaterial()
	delete(fewer, "currency_code")
	fewerDigest := str(f.grantClaims(bearer(), f.approveBody("payments.v1.initiate_payment", "customer:C-8123", fewer))["garm_grant"].(map[string]any), "material")
	if fewerDigest == shownDigest {
		t.Fatal("dropping a material field did not change the digest")
	}
	if want := grant.Digest(fewer); fewerDigest != want {
		t.Errorf("material = %q, want %q; the STS must digest what it was GIVEN and never fill in a path itself", fewerDigest, want)
	}
}

// One case per remaining refusal in approval-grants §4, plus the frame-2
// checks. Every one must produce the identical opaque body: this endpoint
// must not be usable as an oracle for which tools exist or who may approve
// them.
func TestApproveRefusalsAreOpaqueAndComplete(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	good := func() string {
		return f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})
	}
	goodBody := func() map[string]any {
		return f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial())
	}

	type scenario struct {
		bearer string
		body   map[string]any
	}
	mutate := func(fn func(map[string]any)) scenario {
		b := goodBody()
		fn(b)
		return scenario{bearer: good(), body: b}
	}

	// Frame 3: a replayed client assertion. The registry is single-use per
	// (client, jti), so presenting one twice must fail the second time.
	replayed := clientAssertion(t, f.clientKey, "shop-bff", testAudience, f.now.Add(time.Minute), "approve-replay-fixed")
	first := goodBody()
	first["client_assertion"] = replayed
	if resp := f.approve(good(), first); resp.StatusCode != http.StatusOK {
		t.Fatalf("the first presentation of a fresh assertion was refused with %d; the replay case below would then prove nothing", resp.StatusCode)
	}
	replayedBody := goodBody()
	replayedBody["client_assertion"] = replayed

	scenarios := map[string]scenario{
		// Frames 3-4.
		"no client assertion":       mutate(func(b map[string]any) { delete(b, "client_assertion") }),
		"client assertion is junk":  mutate(func(b map[string]any) { b["client_assertion"] = "not-a-jwt" }),
		"client assertion replayed": {bearer: good(), body: replayedBody},
		"client assertion type names something else": mutate(func(b map[string]any) {
			b["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"
		}),

		// Frames 5-9.
		"no bearer at all":               {bearer: "", body: goodBody()},
		"bearer is junk":                 {bearer: "not-a-jwt", body: goodBody()},
		"bearer from no issuer":          {bearer: signUpstreamToken(t, f.custKey, jose.ES256, "cust-k1", map[string]any{"iss": "https://elsewhere.example", "sub": "jdoe", "aud": "shop-bff", "exp": f.now.Add(time.Minute).Unix()}), body: goodBody()},
		"approver asserts no garm claim": {bearer: f.employeeToken("jdoe", nil), body: goodBody()},

		// Frames 15-17.
		"tool is empty":            mutate(func(b map[string]any) { b["tool"] = "" }),
		"tool is a method route":   mutate(func(b map[string]any) { b["tool"] = "/payments.v1.PaymentsService/InitiatePayment" }),
		"tool has no package part": mutate(func(b map[string]any) { b["tool"] = "initiate_payment" }),
		"subject is not prefixed":  mutate(func(b map[string]any) { b["subject"] = "C-8123" }),
		"subject is empty":         mutate(func(b map[string]any) { b["subject"] = "" }),
		// Sending the field says the caller has a task in mind; sending it
		// blank says the value was lost on the way. Omitting it entirely is
		// a different request and a legitimate one — see
		// TestApproveWithNoTaskMintsNoTaskClaimAtAll.
		"task_id is present but empty":      mutate(func(b map[string]any) { b["task_id"] = "" }),
		"task_id is present but whitespace": mutate(func(b map[string]any) { b["task_id"] = "   " }),
		"material path is empty":            mutate(func(b map[string]any) { b["material"] = map[string]string{"": "25000"} }),
		"material path has a newline": mutate(func(b map[string]any) {
			b["material"] = map[string]string{"amount\nbeneficiary_iban": "25000"}
		}),
		"material path has an equals sign": mutate(func(b map[string]any) {
			b["material"] = map[string]string{"amount=1": "25000"}
		}),
		"material path has an empty segment": mutate(func(b map[string]any) {
			b["material"] = map[string]string{"payment..amount": "25000"}
		}),

		// Frame 2 and the decoder.
		"unknown body field": mutate(func(b map[string]any) { b["approved_at"] = 1780000000 }),
	}

	for name, sc := range scenarios {
		t.Run(name, func(t *testing.T) {
			resp := f.approve(sc.bearer, sc.body)
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if got := strings.TrimSpace(string(body)); got != `{"error":"access_denied"}` {
				t.Fatalf("body = %q, want the single opaque denial", got)
			}
			lower := strings.ToLower(string(body))
			for _, leak := range []string{"tool", "approver", "material", "employee", "customer"} {
				if strings.Contains(lower, leak) {
					t.Errorf("response body names %q: %q", leak, string(body))
				}
			}
		})
	}
}

// The RFC 7523 assertion type is OPTIONAL but not ignored: the correct URN
// is accepted, and the refusal of a wrong one lives in the table above.
// Accepting the field while disregarding its value is exactly the state
// this pair of tests exists to prevent.
func TestApproveAcceptsTheJWTBearerAssertionType(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	bearer := f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})

	body := f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial())
	body["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	if resp := f.approve(bearer, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the documented assertion type must be accepted, not refused as an unknown field", resp.StatusCode)
	}
}

// Frame 2's own three checks, which do not go through a JSON body at all.
func TestApproveRefusesTheWrongMethodTypeAndSize(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	h := f.srv.ApproveHandler()

	t.Run("GET is 405, not a denial", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/approve", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET got %d, want 405", rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodPost {
			t.Errorf("Allow = %q, want POST", got)
		}
	})

	t.Run("form encoding is refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader("tool=payments.v1.initiate_payment"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("form-encoded POST got %d, want 400", rec.Code)
		}
	})

	t.Run("application/json with a charset parameter is accepted", func(t *testing.T) {
		bearer := f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})
		b, _ := json.Marshal(f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))
		req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("got %d, want 200 — a charset parameter is a legitimate part of the media type", rec.Code)
		}
	})

	t.Run("a body carrying a second JSON value is refused", func(t *testing.T) {
		// Only the first object would be honoured, which is the same fault
		// DisallowUnknownFields exists to prevent: a request that approves
		// something other than what the caller sent.
		bearer := f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})
		b, _ := json.Marshal(f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))
		req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(string(b)+`{"tool":"other.v1.thing"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("got %d, want 400", rec.Code)
		}
	})

	t.Run("an oversized body is refused before anything is verified", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(strings.Repeat("x", (64<<10)+1)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("oversized POST got %d, want 400", rec.Code)
		}
	})
}

// An approver may hold no compartments at all. That is not a refusal — the
// tool decides whether it needs any — but the claim must still be a list
// rather than a null, so a decoded grant says "this approver held none".
func TestApproveMintsAnEmptyCompartmentListRatherThanNull(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	bearer := f.employeeToken("jdoe", map[string]any{"garm": approverGarm("INTERNAL")})

	claims := f.grantClaims(bearer, f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))
	g := claims["garm_grant"].(map[string]any)
	list, ok := g["approver_compartments"].([]any)
	if !ok {
		t.Fatalf("approver_compartments is %T, want a JSON array", g["approver_compartments"])
	}
	if len(list) != 0 {
		t.Errorf("approver_compartments = %v, want []", list)
	}
}

// Program plan §7 item 10, at the approval endpoint. Three cases, one per
// shape a subject can arrive in.
func TestApproveBuildsTheApproverIdentityFromTheIssuersKind(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	garm := map[string]any{"garm": approverGarm("RESTRICTED", "financial")}

	t.Run("a subject already carrying its kind is used as is", func(t *testing.T) {
		claims := f.grantClaims(f.employeeToken("employee:jdoe", garm),
			f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))
		g := claims["garm_grant"].(map[string]any)
		if got := str(g, "approver"); got != "employee:jdoe" {
			t.Fatalf("approver = %q, want employee:jdoe — devkit's persona tokens carry the prefix already, and doubling it records an approver nobody is", got)
		}
	})

	t.Run("a bare subject is prefixed", func(t *testing.T) {
		claims := f.grantClaims(f.employeeToken("jdoe", garm),
			f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))
		g := claims["garm_grant"].(map[string]any)
		if got := str(g, "approver"); got != "employee:jdoe" {
			t.Fatalf("approver = %q, want employee:jdoe", got)
		}
	})

	t.Run("a contradicting prefix is refused, not repaired", func(t *testing.T) {
		// The employee IdP mints it, so the issuer says employee and the
		// subject says customer. Repairing it into
		// "employee:customer:C-1" would mint a grant recording an
		// approver that exists in no directory.
		for _, sub := range []string{"customer:C-1", "employee:"} {
			resp := f.approve(f.employeeToken(sub, garm),
				f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("minted a grant for an approver whose sub is %q", sub)
			}
		}
	})
}

// newFixtureWithApproveTTL is newFixture but rebuilds the server with a
// non-default Options.ApproveTTL, reusing every other dependency the first
// build already validated (the same pattern as newFixtureWithLog in
// exchange_test.go).
func newFixtureWithApproveTTL(t *testing.T, policyYAML string, authz *fakeAuthz, instance sts.InstanceAuthzConfig, ttl time.Duration) *fixture {
	t.Helper()
	f := newFixture(t, policyYAML, authz, instance)

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
		ApproveTTL:    ttl,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	f.srv = srv
	return f
}

// Task 4 wires config.go's approve.ttl_seconds into Options.ApproveTTL
// (TestLoadConfigReadsTheApproveTTL proves that half); this proves the other
// half, that a non-default Options.ApproveTTL actually reaches the minted
// grant — end to end, an operator's ttl_seconds is what a runner sees.
func TestApproveHonoursANonDefaultApproveTTL(t *testing.T) {
	const ttl = 300 * time.Second
	f := newFixtureWithApproveTTL(t, exchangePolicy, newFakeAuthz(), enforced, ttl)
	bearer := f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})

	resp := f.approve(bearer, f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve failed: status %d, body %s", resp.StatusCode, raw)
	}
	var out struct {
		Grant     string `json:"grant"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decoding response: %v; body %s", err, raw)
	}
	if out.ExpiresIn != int64(ttl.Seconds()) {
		t.Errorf("expires_in = %d, want %d", out.ExpiresIn, int64(ttl.Seconds()))
	}

	claims := f.decodeAndVerify(out.Grant)
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if int64(exp-iat) != int64(ttl.Seconds()) {
		t.Errorf("exp - iat = %d, want %d", int64(exp-iat), int64(ttl.Seconds()))
	}
}

// Carried from Task 3's review: a duplicate top-level key is the same class
// of smuggle DisallowUnknownFields exists to prevent, but it does not catch
// this one. `{"tool":"a.b","tool":"c.d",...}` is one legal JSON object, so
// json.Decoder happily decodes it last-wins — the request that is approved
// is not the one whose fields a reader sees first.
func TestApproveRefusesADuplicateTopLevelKey(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	bearer := f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})
	body := f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial())

	materialJSON, err := json.Marshal(body["material"])
	if err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{"tool":"a.b","tool":"c.d","subject":%q,"material":%s,"client_assertion":%q}`,
		body["subject"], materialJSON, body["client_assertion"])

	req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	f.srv.ApproveHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — a duplicate top-level key must be refused, not decoded last-wins", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"access_denied"}` {
		t.Fatalf("body = %q, want the single opaque denial", got)
	}
}

// theTask is the id a tasks service hands the page, and what every approval
// below is given on. Any opaque string will do — this service resolves no
// task and never looks one up.
const theTask = "tsk_d19f4c"

// approveToken posts an approval expected to SUCCEED and returns the grant
// exactly as the wire carries it, for the tests that hand the string to the
// SHARED reader instead of to this package's own decoder.
func (f *fixture) approveToken(bearer string, body any) string {
	f.t.Helper()
	resp := f.approve(bearer, body)
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("approve failed: status %d, body %s", resp.StatusCode, raw)
	}
	var out struct {
		Grant string `json:"grant"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		f.t.Fatalf("decoding response: %v; body %s", err, raw)
	}
	if out.Grant == "" {
		f.t.Fatal("approve answered 200 with no grant")
	}
	return out.Grant
}

// grantKeys is this service's published JWKS read back through the shared
// key reader, which is how a consumer gets it: fetch the document, parse it
// with grants.ParseJWKS. A test that verifies through this is exercising the
// real path rather than a private handle on the signing key.
func (f *fixture) grantKeys() grants.KeySource {
	f.t.Helper()
	doc, err := json.Marshal(f.kr.JWKS())
	if err != nil {
		f.t.Fatal(err)
	}
	ks, err := grants.ParseJWKS(doc)
	if err != nil {
		f.t.Fatalf("this service's own JWKS did not parse with the shared reader: %v", err)
	}
	return ks
}

// The claim the tasks service turns on, proved with the reader that service
// actually uses: contracts/grants.Verify — ParseClaims behind a signature
// check — and then CheckTask. Parsing the token by hand here would only
// prove that this file agrees with itself, and the whole point of the claim
// is that two repositories agree about it.
func TestApproveMintsTheTaskClaimTheTasksServiceChecks(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	bearer := f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})

	// `task_id` on the wire, because that is the field studiod sends
	// (studio/internal/sts/client.go).
	body := f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial())
	body["task_id"] = theTask

	tok := f.approveToken(bearer, body)

	c, err := grants.Verify(tok, f.grantKeys())
	if err != nil {
		t.Fatalf("the shared reader could not verify a grant this service minted: %v", err)
	}
	if c.Task != theTask {
		t.Fatalf("Claims.Task = %q, want %q — decide_task reads this field and nothing else", c.Task, theTask)
	}
	if err := c.CheckTask(theTask); err != nil {
		t.Fatalf("CheckTask refused a grant minted for that very task: %v", err)
	}
	// And the binding is a binding: the same values approved on one task do
	// not authorise the decision on another, which is the reason the claim
	// exists at all.
	if err := c.CheckTask("tsk_someone_else"); err == nil {
		t.Error("a grant given on one task was accepted for another")
	}
	// Every other check decide_task makes still passes, so the task claim
	// is the only thing this test changed.
	for name, err := range map[string]error{
		"no act":   c.CheckNoAct(),
		"tool":     c.CheckTool("payments.v1.initiate_payment"),
		"subject":  c.CheckSubject("customer:C-8123"),
		"material": c.CheckMaterial(bankMaterial()),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The spelling, asserted here rather than left to a consumer: garmd's
	// own copy reads firstOf(g, "task", "task_id") and would accept either,
	// so its tolerance cannot tell us whether this service minted the name
	// the contract declares. And exactly once — the same fact under two
	// keys in one signed credential is two things to keep in step.
	g := f.decodeAndVerify(tok)["garm_grant"].(map[string]any)
	if got := str(g, "task"); got != theTask {
		t.Errorf(`garm_grant.task = %q, want %q — contracts/grants.ParseClaims reads "task"`, got, theTask)
	}
	if _, present := g["task_id"]; present {
		t.Error("the grant carries task_id as well as task; the request field's name must not travel into the claim")
	}
}

// An approval need not be on a task. agentd approves calls that are spent at
// garmd's direct door and sends no task_id at all, and garmd reads no task
// claim — so a request that names none is minted rather than refused.
//
// What matters is that the claim is then ABSENT, not empty: CheckTask reads
// an absent claim as "this approves the material rather than a decision" and
// says so, while an empty string would be a value somebody appears to have
// set. The two are different states and only one of them is true here.
func TestApproveWithNoTaskMintsNoTaskClaimAtAll(t *testing.T) {
	f := newFixture(t, exchangePolicy, newFakeAuthz(), enforced)
	bearer := f.employeeToken("jdoe", map[string]any{"garm": approverGarm("RESTRICTED", "financial")})

	tok := f.approveToken(bearer, f.approveBody("payments.v1.initiate_payment", "customer:C-8123", bankMaterial()))

	g := f.decodeAndVerify(tok)["garm_grant"].(map[string]any)
	if v, present := g["task"]; present {
		t.Errorf("garm_grant.task is present (%#v) on an approval that named no task; absent and empty are different claims to the reader", v)
	}

	c, err := grants.Verify(tok, f.grantKeys())
	if err != nil {
		t.Fatalf("the shared reader could not verify a grant this service minted: %v", err)
	}
	// Still a perfectly good grant at the door that does not read tasks.
	for name, err := range map[string]error{
		"no act":   c.CheckNoAct(),
		"tool":     c.CheckTool("payments.v1.initiate_payment"),
		"subject":  c.CheckSubject("customer:C-8123"),
		"material": c.CheckMaterial(bankMaterial()),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// And refused by the door that does, with the refusal naming the real
	// reason rather than a task mismatch against "".
	err = c.CheckTask(theTask)
	if err == nil {
		t.Fatal("a grant carrying no task claim was accepted for a task decision")
	}
	if !strings.Contains(err.Error(), "no task claim") {
		t.Errorf("the refusal does not say the grant carries no task: %v", err)
	}
}
