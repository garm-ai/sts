package sts_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/garm-ai/sts"
	jose "github.com/go-jose/go-jose/v4"
)

// testAudience stands in for this service's own token endpoint identifier —
// the aud a valid client assertion must name.
const testAudience = "https://sts.example/token"

// clientPublicKeyPEM PEM-encodes priv's public half as PKIX, the shape
// ClientConfig.PEMs expects. It is the public-key counterpart to
// keyring_test.go's testKeyPEM, which PEM-encodes a PRIVATE key for the
// keyring's own signing use — a client's registered material is the other
// half of a key pair from what the keyring signs with.
func clientPublicKeyPEM(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// clientAssertion signs a private_key_jwt-shaped assertion for clientID with
// key. It reuses signUpstreamToken (issuer_test.go) and genUpstreamKey
// (also issuer_test.go): a client assertion and an upstream token are both,
// structurally, nothing more than a signed JWT carrying registered claims —
// signing one needs no client-specific machinery.
func clientAssertion(t *testing.T, key *ecdsa.PrivateKey, clientID string, aud any, exp time.Time, jti string) string {
	t.Helper()
	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": aud,
		"exp": exp.Unix(),
		"jti": jti,
	}
	return signUpstreamToken(t, key, jose.ES256, "irrelevant-kid", claims)
}

// newTestRegistry builds a ClientRegistry against testAudience with the
// given clock and clients, failing the test immediately on a construction
// error so every test below can go straight to exercising Authenticate.
func newTestRegistry(t *testing.T, now func() time.Time, clients ...sts.ClientConfig) *sts.ClientRegistry {
	t.Helper()
	r, err := sts.NewClientRegistry(clients, sts.ClientOptions{
		Audience: testAudience,
		Now:      now,
	})
	if err != nil {
		t.Fatalf("NewClientRegistry: %v", err)
	}
	return r
}

func TestAuthenticateAcceptsAValidClientAssertion(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := genUpstreamKey(t)
	r := newTestRegistry(t, func() time.Time { return now }, sts.ClientConfig{
		ID:   "shop-bff",
		PEMs: [][]byte{clientPublicKeyPEM(t, key)},
	})

	assertion := clientAssertion(t, key, "shop-bff", testAudience, now.Add(time.Minute), "jti-1")

	id, err := r.Authenticate(assertion)
	if err != nil {
		t.Fatalf("Authenticate() error = %v, want a valid assertion accepted", err)
	}
	if id != "shop-bff" {
		t.Fatalf("Authenticate() = %q, want %q", id, "shop-bff")
	}
}

func TestAuthenticateRejectsAnUnknownClient(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := genUpstreamKey(t)
	// The registry knows about "shop-bff" only; the assertion below claims
	// to be from a client that was never registered at all.
	r := newTestRegistry(t, func() time.Time { return now }, sts.ClientConfig{
		ID:   "shop-bff",
		PEMs: [][]byte{clientPublicKeyPEM(t, key)},
	})

	assertion := clientAssertion(t, key, "never-registered", testAudience, now.Add(time.Minute), "jti-1")

	if _, err := r.Authenticate(assertion); err == nil {
		t.Fatal("Authenticate() accepted an assertion from a client that was never registered")
	}
}

func TestAuthenticateRejectsAWrongKey(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	registeredKey := genUpstreamKey(t)
	attackerKey := genUpstreamKey(t)
	r := newTestRegistry(t, func() time.Time { return now }, sts.ClientConfig{
		ID:   "shop-bff",
		PEMs: [][]byte{clientPublicKeyPEM(t, registeredKey)},
	})

	// Correct client id, but signed with a key the client never registered.
	// This proves Authenticate actually verifies the signature against a
	// registered key rather than trusting iss/sub because they name a known
	// client.
	assertion := clientAssertion(t, attackerKey, "shop-bff", testAudience, now.Add(time.Minute), "jti-1")

	if _, err := r.Authenticate(assertion); err == nil {
		t.Fatal("Authenticate() accepted an assertion signed by a key the client never registered")
	}
}

func TestAuthenticateRejectsAWrongAudience(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := genUpstreamKey(t)
	r := newTestRegistry(t, func() time.Time { return now }, sts.ClientConfig{
		ID:   "shop-bff",
		PEMs: [][]byte{clientPublicKeyPEM(t, key)},
	})

	// An otherwise-valid assertion, but minted for a DIFFERENT STS's token
	// endpoint.
	assertion := clientAssertion(t, key, "shop-bff", "https://some-other-sts.example/token", now.Add(time.Minute), "jti-1")

	if _, err := r.Authenticate(assertion); err == nil {
		t.Fatal("Authenticate() accepted an assertion whose aud names a different service's token endpoint")
	}
}

func TestAuthenticateRejectsAnExpiredAssertion(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := genUpstreamKey(t)
	r := newTestRegistry(t, func() time.Time { return now }, sts.ClientConfig{
		ID:   "shop-bff",
		PEMs: [][]byte{clientPublicKeyPEM(t, key)},
	})

	assertion := clientAssertion(t, key, "shop-bff", testAudience, now.Add(-time.Second), "jti-1")

	if _, err := r.Authenticate(assertion); err == nil {
		t.Fatal("Authenticate() accepted an assertion whose exp is already in the past")
	}
}

// TestAuthenticateRejectsAReplayedJTI is the whole point of private_key_jwt
// over a shared secret: an assertion captured in a log or a proxy must not
// become a reusable credential. The same assertion is accepted the first
// time and refused the second.
func TestAuthenticateRejectsAReplayedJTI(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := genUpstreamKey(t)
	r := newTestRegistry(t, func() time.Time { return now }, sts.ClientConfig{
		ID:   "shop-bff",
		PEMs: [][]byte{clientPublicKeyPEM(t, key)},
	})

	assertion := clientAssertion(t, key, "shop-bff", testAudience, now.Add(time.Minute), "jti-once")

	if _, err := r.Authenticate(assertion); err != nil {
		t.Fatalf("first Authenticate() error = %v, want the first presentation accepted", err)
	}
	if _, err := r.Authenticate(assertion); err == nil {
		t.Fatal("Authenticate() accepted the same assertion a second time — jti replay was not refused")
	}
}

// TestAuthenticateAcceptsAssertionSignedByTheSecondRegisteredKey exercises
// ClientConfig.PEMs's whole reason for being a slice: a client can register
// a new key ALONGSIDE an old one to rotate without an outage, and an
// assertion signed by either must be accepted. An implementation that only
// ever checked PEMs[0] would pass every other test in this file yet reject
// every client mid-rotation.
func TestAuthenticateAcceptsAssertionSignedByTheSecondRegisteredKey(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	firstKey := genUpstreamKey(t)
	secondKey := genUpstreamKey(t)
	r := newTestRegistry(t, func() time.Time { return now }, sts.ClientConfig{
		ID:   "shop-bff",
		PEMs: [][]byte{clientPublicKeyPEM(t, firstKey), clientPublicKeyPEM(t, secondKey)},
	})

	assertion := clientAssertion(t, secondKey, "shop-bff", testAudience, now.Add(time.Minute), "jti-second-key")

	id, err := r.Authenticate(assertion)
	if err != nil {
		t.Fatalf("Authenticate() error = %v, want an assertion signed by the SECOND registered key accepted", err)
	}
	if id != "shop-bff" {
		t.Fatalf("Authenticate() = %q, want %q", id, "shop-bff")
	}
}

func TestAuthenticateRejectsAnAssertionWhoseSubDoesNotMatchIss(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := genUpstreamKey(t)
	r := newTestRegistry(t, func() time.Time { return now }, sts.ClientConfig{
		ID:   "shop-bff",
		PEMs: [][]byte{clientPublicKeyPEM(t, key)},
	})

	claims := map[string]any{
		"iss": "shop-bff",
		"sub": "someone-else", // deliberately different from iss
		"aud": testAudience,
		"exp": now.Add(time.Minute).Unix(),
		"jti": "jti-1",
	}
	assertion := signUpstreamToken(t, key, jose.ES256, "kid", claims)

	if _, err := r.Authenticate(assertion); err == nil {
		t.Fatal("Authenticate() accepted an assertion whose sub does not equal its iss")
	}
}

func TestAuthenticateRejectsAnAssertionWithNoJTI(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := genUpstreamKey(t)
	r := newTestRegistry(t, func() time.Time { return now }, sts.ClientConfig{
		ID:   "shop-bff",
		PEMs: [][]byte{clientPublicKeyPEM(t, key)},
	})

	claims := map[string]any{
		"iss": "shop-bff",
		"sub": "shop-bff",
		"aud": testAudience,
		"exp": now.Add(time.Minute).Unix(),
		// deliberately no "jti"
	}
	assertion := signUpstreamToken(t, key, jose.ES256, "kid", claims)

	if _, err := r.Authenticate(assertion); err == nil {
		t.Fatal("Authenticate() accepted an assertion with no jti — replay could never be detected without one")
	}
}

// TestAuthenticateRejectsAnAssertionWithAnExpFurtherThanTheBoundedWindow
// proves exp is bounded, not just present and in the future: an
// assertion — and thus the reusable-until-then jti slot it would occupy —
// must not be able to live indefinitely just because a client set a very
// distant exp.
func TestAuthenticateRejectsAnAssertionWithAnExpFurtherThanTheBoundedWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := genUpstreamKey(t)
	r, err := sts.NewClientRegistry([]sts.ClientConfig{{
		ID:   "shop-bff",
		PEMs: [][]byte{clientPublicKeyPEM(t, key)},
	}}, sts.ClientOptions{
		Audience: testAudience,
		Now:      func() time.Time { return now },
		JTITTL:   time.Minute,
	})
	if err != nil {
		t.Fatalf("NewClientRegistry: %v", err)
	}

	// exp is in the future, but far beyond the configured window.
	assertion := clientAssertion(t, key, "shop-bff", testAudience, now.Add(time.Hour), "jti-1")

	if _, err := r.Authenticate(assertion); err == nil {
		t.Fatal("Authenticate() accepted an assertion whose exp is far beyond the configured bounded window")
	}
}

func TestNewClientRegistryRejectsAClientWithNoRegisteredKeys(t *testing.T) {
	_, err := sts.NewClientRegistry([]sts.ClientConfig{{ID: "shop-bff", PEMs: nil}}, sts.ClientOptions{
		Audience: testAudience,
	})
	if err == nil {
		t.Fatal("NewClientRegistry accepted a client with no registered keys — it could never authenticate")
	}
}
