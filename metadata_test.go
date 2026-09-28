package sts

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The document exists so a verifier can refuse at startup instead of refusing
// every token at runtime. So what matters is that the two fields a verifier
// compares against are present and carry what this service actually mints —
// a document that omitted either would be worse than none, because it would
// let a check pass while the disagreement stood.
func TestMetadataPublishesWhatAVerifierMustAgreeWith(t *testing.T) {
	s := &Server{issuer: "https://sts.example", audience: "garm://garmd"}
	h := s.MetadataHandler("https://sts.example/.well-known/jwks.json",
		"https://sts.example/token")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}

	var got Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if got.Issuer != "https://sts.example" {
		t.Errorf("issuer = %q — a verifier compares its own --issuer with this", got.Issuer)
	}
	if got.GarmAudience != "garm://garmd" {
		t.Errorf("garm_audience = %q — this is the field the audience trap turns on, "+
			"and the one RFC 8414 has no place for", got.GarmAudience)
	}
	if got.JWKSURI == "" {
		t.Error("no jwks_uri")
	}
}

// The wire names, pinned. A verifier in another repository reads these
// strings, and renaming one is a silent break: the field decodes to its zero
// value and the check passes against nothing.
func TestTheWireNamesAreStable(t *testing.T) {
	s := &Server{issuer: "i", audience: "a"}
	rec := httptest.NewRecorder()
	s.MetadataHandler("j", "t").ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/", nil))

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"issuer", "jwks_uri", "garm_audience"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("%q absent; a verifier reading it would compare against an "+
				"empty string and pass", k)
		}
	}
}

// Read-only. A metadata endpoint that accepted a POST would be a
// configuration surface nobody meant to expose.
func TestMetadataRefusesAnythingButARead(t *testing.T) {
	s := &Server{issuer: "i", audience: "a"}
	rec := httptest.NewRecorder()
	s.MetadataHandler("j", "t").ServeHTTP(rec,
		httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST got %d, want 405", rec.Code)
	}
}
