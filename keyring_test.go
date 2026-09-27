package sts_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"testing"

	"github.com/garm-ai/sts"
	jose "github.com/go-jose/go-jose/v4"
)

func testKeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestKeyringSignsES256AndVerifiesAgainstItsJWKS(t *testing.T) {
	kr, err := sts.NewKeyring([]sts.KeyConfig{{KID: "k1", PEM: testKeyPEM(t)}}, "k1")
	if err != nil {
		t.Fatal(err)
	}

	tok, err := kr.Sign(map[string]any{"sub": "customer:C-1"})
	if err != nil {
		t.Fatal(err)
	}

	// garmd parses with an algorithm allowlist that contains ES256 and NOT
	// EdDSA. Parsing here with the same constraint is what proves the token
	// is acceptable to the verifier it is minted for.
	sig, err := jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("a minted token must parse under an ES256-only allowlist: %v", err)
	}
	if got := sig.Signatures[0].Header.KeyID; got != "k1" {
		t.Fatalf("kid = %q, want k1 — a token with no kid cannot be verified after rotation", got)
	}

	set := kr.JWKS()
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "k1" {
		t.Fatalf("JWKS = %+v, want one key with kid k1", set.Keys)
	}
	if set.Keys[0].IsPublic() == false {
		t.Fatal("the JWKS contains a PRIVATE key; it is served to the world")
	}
	if _, err := sig.Verify(set.Keys[0].Key); err != nil {
		t.Fatalf("a token did not verify against the key set we serve: %v", err)
	}
}

func TestKeyringServesEveryKeyButSignsOnlyWithTheActiveOne(t *testing.T) {
	// During rotation the previous key must still be SERVED, so tokens it
	// signed keep verifying, while new tokens use the active key.
	k0PEM := testKeyPEM(t)
	k1PEM := testKeyPEM(t)

	// Sign a token before rotating, while k0 is active.
	preRotation, err := sts.NewKeyring([]sts.KeyConfig{{KID: "k0", PEM: k0PEM}}, "k0")
	if err != nil {
		t.Fatal(err)
	}
	oldTok, err := preRotation.Sign(map[string]any{"sub": "x"})
	if err != nil {
		t.Fatal(err)
	}

	// Rotate: k1 becomes active, k0 stays configured (retired but served).
	kr, err := sts.NewKeyring([]sts.KeyConfig{
		{KID: "k0", PEM: k0PEM},
		{KID: "k1", PEM: k1PEM},
	}, "k1")
	if err != nil {
		t.Fatal(err)
	}

	set := kr.JWKS()
	if n := len(set.Keys); n != 2 {
		t.Fatalf("JWKS has %d keys, want 2 — the retired key must stay served", n)
	}
	gotKIDs := map[string]bool{}
	for _, k := range set.Keys {
		gotKIDs[k.KeyID] = true
	}
	if !gotKIDs["k0"] || !gotKIDs["k1"] {
		t.Fatalf("JWKS kids = %v, want both k0 (retired) and k1 (active) — a bug that "+
			"drops k0 and serves k1 twice would pass a bare length check", gotKIDs)
	}

	// The property that actually matters: a token signed under k0 before
	// rotation must still verify against the post-rotation keyring's JWKS.
	oldSig, err := jose.ParseSigned(oldTok, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("pre-rotation token must still parse under ES256: %v", err)
	}
	if got := oldSig.Signatures[0].Header.KeyID; got != "k0" {
		t.Fatalf("pre-rotation token kid = %q, want k0", got)
	}
	var k0Pub *jose.JSONWebKey
	for i := range set.Keys {
		if set.Keys[i].KeyID == "k0" {
			k0Pub = &set.Keys[i]
		}
	}
	if k0Pub == nil {
		t.Fatal("k0 not found in post-rotation JWKS")
	}
	if _, err := oldSig.Verify(k0Pub.Key); err != nil {
		t.Fatalf("a token signed by the retired key no longer verifies after rotation: %v", err)
	}

	// New tokens must be signed with the ACTIVE key, k1.
	tok, err := kr.Sign(map[string]any{"sub": "x"})
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if got := sig.Signatures[0].Header.KeyID; got != "k1" {
		t.Fatalf("signed with %q, want the ACTIVE key k1", got)
	}
}

func TestNewKeyringRejectsUnusableConfigurations(t *testing.T) {
	good := testKeyPEM(t)
	for name, tc := range map[string]struct {
		keys   []sts.KeyConfig
		active string
	}{
		"no keys":            {nil, "k1"},
		"active not present": {[]sts.KeyConfig{{KID: "k0", PEM: good}}, "k1"},
		"no active named":    {[]sts.KeyConfig{{KID: "k0", PEM: good}}, ""},
		"duplicate kid":      {[]sts.KeyConfig{{KID: "k1", PEM: good}, {KID: "k1", PEM: good}}, "k1"},
		"empty kid":          {[]sts.KeyConfig{{KID: "", PEM: good}}, "nonexistent"},
		"garbage pem":        {[]sts.KeyConfig{{KID: "k1", PEM: []byte("not a key")}}, "k1"},
	} {
		if _, err := sts.NewKeyring(tc.keys, tc.active); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestJWKSHandlerServesPublicKeysOnly(t *testing.T) {
	kr, _ := sts.NewKeyring([]sts.KeyConfig{{KID: "k1", PEM: testKeyPEM(t)}}, "k1")
	rec := httptest.NewRecorder()
	kr.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{`"d"`, "PRIVATE"} {
		if bytesContains(body, forbidden) {
			t.Fatalf("the served JWKS contains %s — that is the private key", forbidden)
		}
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(body), &set); err != nil {
		t.Fatalf("served JWKS is not valid JSON: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("served %d keys, want 1", len(set.Keys))
	}
}

func bytesContains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
