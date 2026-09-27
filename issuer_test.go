package sts_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/garm-ai/sts"
	jose "github.com/go-jose/go-jose/v4"
)

// --- helpers: a fake upstream IdP -----------------------------------------

// genUpstreamKey generates a fresh ECDSA P-256 key, standing in for one of
// an upstream IdP's signing keys.
func genUpstreamKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// upstreamJWK wraps a private key as a named JWK, the shape a JWKS document
// carries.
func upstreamJWK(kid string, key *ecdsa.PrivateKey) jose.JSONWebKey {
	return jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: "ES256", Use: "sig"}
}

// testIdP is a fake upstream identity provider: an httptest server serving a
// JWKS document, with the ability to count fetches and simulate an outage.
// Using a fake IdP is correct here — this package tests ITS OWN verification
// logic against an issuer's JWKS, not any particular real IdP.
type testIdP struct {
	server *httptest.Server

	mu   sync.Mutex
	keys jose.JSONWebKeySet
	fail bool

	fetches int32
}

func newTestIdP(t *testing.T, keys ...jose.JSONWebKey) *testIdP {
	t.Helper()
	idp := &testIdP{}
	pub := make([]jose.JSONWebKey, len(keys))
	for i, k := range keys {
		pub[i] = k.Public()
	}
	idp.keys = jose.JSONWebKeySet{Keys: pub}

	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&idp.fetches, 1)

		idp.mu.Lock()
		fail := idp.fail
		keys := idp.keys
		idp.mu.Unlock()

		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys)
	}))
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *testIdP) setFail(fail bool) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.fail = fail
}

func (idp *testIdP) fetchCount() int {
	return int(atomic.LoadInt32(&idp.fetches))
}

// --- helpers: signing upstream tokens --------------------------------------

// signUpstreamToken signs claims as a compact JWS, the shape an upstream IdP
// hands back to a human.
func signUpstreamToken(t *testing.T, key *ecdsa.PrivateKey, alg jose.SignatureAlgorithm, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// noneAlgToken hand-builds a compact JWS-shaped string with alg "none" and an
// empty signature. go-jose's signer will not produce one (there is no key for
// "no signature"), and that refusal is itself part of what proves alg:none is
// unreachable through the ordinary signing path — so the attack token has to
// be built by hand, the way an attacker would.
func noneAlgToken(kid string, claims map[string]any) string {
	header := map[string]any{"alg": "none", "typ": "JWT", "kid": kid}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc(h) + "." + enc(p) + "."
}

// claimsAt builds a registered claim set at explicit times. nbf is omitted
// when nil.
func claimsAt(iss string, iat, exp time.Time, nbf *time.Time) map[string]any {
	c := map[string]any{
		"iss": iss,
		"sub": "user-1",
		"aud": "sts",
		"iat": iat.Unix(),
		"exp": exp.Unix(),
	}
	if nbf != nil {
		c["nbf"] = nbf.Unix()
	}
	return c
}

// claimsWithAud builds a registered claim set with an explicit aud value,
// which may be a string or a []string — the two wire shapes RFC 7519 allows.
func claimsWithAud(iss string, now time.Time, aud any) map[string]any {
	return map[string]any{
		"iss": iss,
		"sub": "user-1",
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

func timePtr(t time.Time) *time.Time { return &t }

// --- tests ------------------------------------------------------------------

func TestVerifyAcceptsAGoodUpstreamToken(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))

	trusted := sts.TrustedIssuer{
		Name:     "customer-idp",
		Issuer:   "https://idp.example/customer",
		JWKSURL:  idp.server.URL,
		Audience: []string{"sts"},
		Kind:     "customer",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{
		Now: func() time.Time { return now },
	})

	tok := signUpstreamToken(t, key, jose.ES256, "k1", claimsAt(trusted.Issuer, now, now.Add(time.Hour), nil))

	claims, iss, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify() error = %v, want a good upstream token accepted", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", claims.Subject)
	}
	if claims.Issuer != trusted.Issuer {
		t.Fatalf("Issuer = %q, want %q", claims.Issuer, trusted.Issuer)
	}
	if iss == nil || iss.Kind != "customer" {
		t.Fatalf("returned issuer Kind = %+v, want Kind == customer", iss)
	}
}

func TestVerifyRejectsAnUnknownIssuer(t *testing.T) {
	now := time.Now()
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))

	trusted := sts.TrustedIssuer{
		Issuer: "https://trusted.example", JWKSURL: idp.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{Now: func() time.Time { return now }})

	// Signed by a key the trusted issuer's JWKS DOES serve, but claiming an
	// iss that was never configured. A verifier that only checks the
	// signature and ignores which issuer is trusted would wrongly accept
	// this.
	tok := signUpstreamToken(t, key, jose.ES256, "k1", claimsAt("https://untrusted.example", now, now.Add(time.Hour), nil))

	if _, _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() accepted a token from an issuer that was never configured as trusted")
	}
}

func TestVerifyRejectsAWrongAudience(t *testing.T) {
	now := time.Now()
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))

	trusted := sts.TrustedIssuer{
		Issuer: "https://idp.example", JWKSURL: idp.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{Now: func() time.Time { return now }})

	tok := signUpstreamToken(t, key, jose.ES256, "k1", claimsWithAud(trusted.Issuer, now, "some-other-service"))

	if _, _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() accepted a token whose aud is not among the issuer's configured audiences")
	}
}

func TestVerifyAcceptsAnyConfiguredAudience(t *testing.T) {
	now := time.Now()
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))

	trusted := sts.TrustedIssuer{
		Issuer:   "https://idp.example",
		JWKSURL:  idp.server.URL,
		Audience: []string{"sts-primary", "sts-secondary"},
		Kind:     "employee",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{Now: func() time.Time { return now }})

	// The token carries only the SECOND configured audience.
	tok := signUpstreamToken(t, key, jose.ES256, "k1", claimsWithAud(trusted.Issuer, now, []string{"sts-secondary"}))

	if _, _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("Verify() error = %v, want the second configured audience accepted (containment, not equality)", err)
	}
}

func TestVerifyRejectsExpiredAndNotYetValid(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))
	trusted := sts.TrustedIssuer{
		Issuer: "https://idp.example", JWKSURL: idp.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	skew := 30 * time.Second

	for name, tc := range map[string]struct {
		claims  map[string]any
		wantErr bool
	}{
		"expired well outside skew": {
			claims:  claimsAt(trusted.Issuer, now.Add(-2*time.Hour), now.Add(-time.Hour), nil),
			wantErr: true,
		},
		"not yet valid well outside skew": {
			claims:  claimsAt(trusted.Issuer, now, now.Add(2*time.Hour), timePtr(now.Add(time.Hour))),
			wantErr: true,
		},
		"expired but inside skew": {
			claims:  claimsAt(trusted.Issuer, now.Add(-time.Hour), now.Add(-10*time.Second), nil),
			wantErr: false,
		},
		"not yet valid but inside skew": {
			claims:  claimsAt(trusted.Issuer, now, now.Add(time.Hour), timePtr(now.Add(10*time.Second))),
			wantErr: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{
				Skew: skew,
				Now:  func() time.Time { return now },
			})
			tok := signUpstreamToken(t, key, jose.ES256, "k1", tc.claims)
			_, _, err := v.Verify(context.Background(), tok)
			if tc.wantErr && err == nil {
				t.Fatal("Verify() accepted a token outside its validity window")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Verify() error = %v, want acceptance: within skew tolerance", err)
			}
		})
	}
}

func TestVerifyRejectsNoneAlgorithm(t *testing.T) {
	now := time.Now()
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))
	trusted := sts.TrustedIssuer{
		Issuer: "https://idp.example", JWKSURL: idp.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{Now: func() time.Time { return now }})

	// The attack token names a real kid the JWKS actually serves and
	// otherwise-legitimate claims. This matters: with no kid at all, an
	// implementation that forgot the algorithm allowlist entirely would
	// still be caught by a separate "token has no kid" check, making that
	// case a false positive for THIS test. Naming a real kid removes that
	// safety net, so a fetchCount of 0 below can only be explained by the
	// allowlist itself refusing "none" during parsing.
	tok := noneAlgToken("k1", claimsAt(trusted.Issuer, now, now.Add(time.Hour), nil))

	if _, _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() accepted an alg:none token — it must be refused during parsing, before any key lookup")
	}
	// The JWKS must never even be consulted for an alg:none token: parsing
	// itself must refuse it, before the kid is ever used to look anything up.
	if got := idp.fetchCount(); got != 0 {
		t.Fatalf("JWKS fetches = %d, want 0 — an alg:none token must never reach key lookup", got)
	}
}

func TestVerifyRejectsAKeyNotInTheIssuersJWKS(t *testing.T) {
	now := time.Now()
	servedKey := genUpstreamKey(t)
	attackerKey := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", servedKey))
	trusted := sts.TrustedIssuer{
		Issuer: "https://idp.example", JWKSURL: idp.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{Now: func() time.Time { return now }})

	// Signed under the SAME kid the JWKS serves, but with a DIFFERENT key.
	// A verifier that only checks "is this kid present" without actually
	// verifying the signature against that key's bytes would wrongly accept
	// this.
	tok := signUpstreamToken(t, attackerKey, jose.ES256, "k1", claimsAt(trusted.Issuer, now, now.Add(time.Hour), nil))

	if _, _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() accepted a token signed by a key the issuer's JWKS does not serve")
	}
}

func TestVerifyRejectsATokenWithNoExpiry(t *testing.T) {
	now := time.Now()
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))
	trusted := sts.TrustedIssuer{
		Issuer: "https://idp.example", JWKSURL: idp.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{Now: func() time.Time { return now }})

	claims := map[string]any{
		"iss": trusted.Issuer,
		"sub": "user-1",
		"aud": "sts",
		"iat": now.Unix(),
		// deliberately no "exp"
	}
	tok := signUpstreamToken(t, key, jose.ES256, "k1", claims)

	if _, _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() accepted a token with no exp — with no expiry it can never be revoked")
	}
}

func TestVerifyTolerationOfAudAsStringAndArray(t *testing.T) {
	now := time.Now()
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))
	trusted := sts.TrustedIssuer{
		Issuer: "https://idp.example", JWKSURL: idp.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}

	cases := map[string]any{
		"string form": "sts",
		"array form":  []string{"sts"},
	}
	for name, aud := range cases {
		t.Run(name, func(t *testing.T) {
			v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{Now: func() time.Time { return now }})
			tok := signUpstreamToken(t, key, jose.ES256, "k1", claimsWithAud(trusted.Issuer, now, aud))

			claims, _, err := v.Verify(context.Background(), tok)
			if err != nil {
				// This is the exact bug fixed in garmd: a bare aud.(string)
				// assertion returns "" for the array form and fails here
				// with a misleading error.
				t.Fatalf("Verify() error = %v, want the %s of aud accepted (RFC 7519 permits both)", err, name)
			}
			if len(claims.Audience) != 1 || claims.Audience[0] != "sts" {
				t.Fatalf("Audience = %v, want [sts] regardless of wire shape", claims.Audience)
			}
		})
	}
}

// --- JWKS caching behaviour --------------------------------------------------
//
// These are not in the brief's named list, but the brief's caching
// requirements (cache by issuer+kid; unknown kid rate-limited; a valid cache
// survives an outage; an expired cache with a failed refresh is a hard
// failure) are each a genuine way for the verifier to become either an IdP
// hammer or a fail-open hole, so each gets its own regression test.

func TestVerifyKeyCacheServesThroughATransientIdPOutage(t *testing.T) {
	now := time.Now()
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))
	trusted := sts.TrustedIssuer{
		Issuer: "https://idp.example", JWKSURL: idp.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{Now: func() time.Time { return now }})

	tok := signUpstreamToken(t, key, jose.ES256, "k1", claimsAt(trusted.Issuer, now, now.Add(time.Hour), nil))

	if _, _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("initial Verify() error = %v", err)
	}
	if got := idp.fetchCount(); got != 1 {
		t.Fatalf("fetches after first verification = %d, want 1", got)
	}

	// The IdP now fails every request. A second verification of a token
	// whose key is already cached and not yet expired must still succeed,
	// and must not touch the network at all.
	idp.setFail(true)
	if _, _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("Verify() during an IdP outage error = %v, want the cached key to keep serving", err)
	}
	if got := idp.fetchCount(); got != 1 {
		t.Fatalf("fetches after the outage verification = %d, want still 1 — "+
			"a cached, unexpired key must never touch a downed IdP", got)
	}
}

func TestVerifyRateLimitsRefetchForAnUnknownKid(t *testing.T) {
	now := time.Now()
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))
	trusted := sts.TrustedIssuer{
		Issuer: "https://idp.example", JWKSURL: idp.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{Now: func() time.Time { return now }})

	// A kid the JWKS has never served.
	tok := signUpstreamToken(t, key, jose.ES256, "garbage-kid", claimsAt(trusted.Issuer, now, now.Add(time.Hour), nil))

	if _, _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() accepted a token with an unknown kid")
	}
	if got := idp.fetchCount(); got != 1 {
		t.Fatalf("fetches after the first unknown-kid lookup = %d, want 1", got)
	}

	// Immediately retrying with the same garbage kid must NOT cause a second
	// fetch — that is exactly the hammering an unknown kid must not be able
	// to cause.
	for i := 0; i < 3; i++ {
		if _, _, err := v.Verify(context.Background(), tok); err == nil {
			t.Fatal("Verify() accepted a token with an unknown kid on retry")
		}
	}
	if got := idp.fetchCount(); got != 1 {
		t.Fatalf("fetches after retries = %d, want still 1 — refetch on an unknown kid must be rate-limited", got)
	}
}

func TestVerifyFailsClosedWhenCacheExpiresAndRefreshFails(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	key := genUpstreamKey(t)
	idp := newTestIdP(t, upstreamJWK("k1", key))
	trusted := sts.TrustedIssuer{
		Issuer: "https://idp.example", JWKSURL: idp.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{Now: clock})

	tok := signUpstreamToken(t, key, jose.ES256, "k1", claimsAt(trusted.Issuer, now, now.Add(24*time.Hour), nil))

	// Populate the cache while the IdP is healthy.
	if _, _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("initial Verify() error = %v", err)
	}

	// Move well past the JWKS cache TTL (and the refetch rate-limit window),
	// then take the IdP down.
	now = now.Add(10 * time.Minute)
	idp.setFail(true)

	if _, _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("Verify() accepted a token whose cache had expired and whose refresh failed — " +
			"this must be a hard failure, never a fallback to the stale key")
	}
}

// TestVerifyReturnsPromptlyWhenTheIdPHangs is the availability gap the other
// direction from an unknown kid: a garbage kid must not let anyone hammer the
// IdP with requests, but an IdP that accepts a connection and never responds
// must also not be able to block verification forever. http.DefaultClient has
// no timeout, so this only works if NewVerifier gives its default client one.
func TestVerifyReturnsPromptlyWhenTheIdPHangs(t *testing.T) {
	now := time.Now()
	key := genUpstreamKey(t)

	release := make(chan struct{})
	hangingIdP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // never responds until the test says so
	}))
	t.Cleanup(func() {
		close(release)
		hangingIdP.Close()
	})

	trusted := sts.TrustedIssuer{
		Issuer: "https://hanging.example", JWKSURL: hangingIdP.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	// A short client timeout stands in for the production default so this
	// test doesn't have to wait out the real default to prove the point.
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{
		Now:        func() time.Time { return now },
		HTTPClient: &http.Client{Timeout: 200 * time.Millisecond},
	})

	tok := signUpstreamToken(t, key, jose.ES256, "k1", claimsAt(trusted.Issuer, now, now.Add(time.Hour), nil))

	start := time.Now()
	result := make(chan error, 1)
	go func() {
		_, _, err := v.Verify(context.Background(), tok)
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("Verify() against a hanging IdP returned no error")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Verify() took %s to fail, want it bounded by the client timeout, not the test's own safety net", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Verify() did not return within 2s against a hanging IdP — it must be bounded by a timeout, never block indefinitely")
	}
}

// TestVerifyOfADifferentIssuerIsUnaffectedByAHangingIdP proves the mutex
// covering an issuer's JWKS cache is released for the duration of the network
// fetch: a hang on one issuer must not stall a concurrent verification for a
// completely unrelated, healthy issuer.
func TestVerifyOfADifferentIssuerIsUnaffectedByAHangingIdP(t *testing.T) {
	now := time.Now()
	hangingKey := genUpstreamKey(t)
	healthyKey := genUpstreamKey(t)

	release := make(chan struct{})
	hangingIdP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		hangingIdP.Close()
	})
	healthyIdP := newTestIdP(t, upstreamJWK("k1", healthyKey))

	hangingIssuer := sts.TrustedIssuer{
		Issuer: "https://hanging.example", JWKSURL: hangingIdP.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	healthyIssuer := sts.TrustedIssuer{
		Issuer: "https://healthy.example", JWKSURL: healthyIdP.server.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}

	// A client timeout much longer than this test's own patience, so a
	// regression that serializes the two issuers behind one lock shows up as
	// this test timing out, not as the client timeout quietly saving it.
	v := sts.NewVerifier([]sts.TrustedIssuer{hangingIssuer, healthyIssuer}, sts.VerifierOptions{
		Now:        func() time.Time { return now },
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	})

	hangingTok := signUpstreamToken(t, hangingKey, jose.ES256, "k1", claimsAt(hangingIssuer.Issuer, now, now.Add(time.Hour), nil))
	healthyTok := signUpstreamToken(t, healthyKey, jose.ES256, "k1", claimsAt(healthyIssuer.Issuer, now, now.Add(time.Hour), nil))

	go func() {
		_, _, _ = v.Verify(context.Background(), hangingTok)
	}()
	time.Sleep(50 * time.Millisecond) // give it time to actually start the request

	result := make(chan error, 1)
	go func() {
		_, _, err := v.Verify(context.Background(), healthyTok)
		result <- err
	}()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Verify() of an unrelated, healthy issuer error = %v, want success", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Verify() of a different issuer blocked behind a hanging issuer's in-flight fetch")
	}
}

// TestVerifyOfAnAlreadyCachedKidIsUnaffectedByAConcurrentSlowFetchOnTheSameIssuer
// is the test that actually distinguishes "the mutex is released during the
// fetch" from "the mutex is held across it": TestVerifyOfADifferentIssuerIsUn-
// affectedByAHangingIdP above passes even if the lock were held across the
// fetch, because each issuer already has its own jwksCache and mutex. Holding
// the lock across the fetch only matters WITHIN one issuer's cache: a lookup
// for a kid already cached and fresh must not wait behind a concurrent,
// slow-or-hanging fetch for a different (unknown) kid on that SAME issuer.
func TestVerifyOfAnAlreadyCachedKidIsUnaffectedByAConcurrentSlowFetchOnTheSameIssuer(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	knownKey := genUpstreamKey(t)

	var hang int32 // 0 = respond normally, 1 = hang until released
	release := make(chan struct{})
	knownJWK := upstreamJWK("known-kid", knownKey)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{knownJWK.Public()}}
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&hang) == 1 {
			<-release
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(func() {
		close(release)
		idp.Close()
	})

	trusted := sts.TrustedIssuer{
		Issuer: "https://idp.example", JWKSURL: idp.URL,
		Audience: []string{"sts"}, Kind: "customer",
	}
	v := sts.NewVerifier([]sts.TrustedIssuer{trusted}, sts.VerifierOptions{
		Now:        clock,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	})

	knownTok := signUpstreamToken(t, knownKey, jose.ES256, "known-kid", claimsAt(trusted.Issuer, now, now.Add(time.Hour), nil))

	// Populate the cache with known-kid while the IdP responds normally.
	if _, _, err := v.Verify(context.Background(), knownTok); err != nil {
		t.Fatalf("initial Verify() error = %v", err)
	}

	// Advance the fake clock past the unknown-kid refetch rate-limit window
	// (so the garbage-kid lookup below actually reaches the network instead
	// of being rejected outright by the rate limiter) but stay within the
	// JWKS cache TTL (so known-kid stays servable straight from cache).
	now = now.Add(35 * time.Second)

	atomic.StoreInt32(&hang, 1)
	garbageTok := signUpstreamToken(t, knownKey, jose.ES256, "garbage-kid", claimsAt(trusted.Issuer, now, now.Add(time.Hour), nil))
	go func() {
		_, _, _ = v.Verify(context.Background(), garbageTok)
	}()
	time.Sleep(100 * time.Millisecond) // let it actually start the hanging request

	result := make(chan error, 1)
	go func() {
		_, _, err := v.Verify(context.Background(), knownTok)
		result <- err
	}()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Verify() of an already-cached kid error = %v, want success", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Verify() of an already-cached kid blocked behind a concurrent slow fetch " +
			"for a different kid on the same issuer — the cache mutex must not be held across the network call")
	}
}
