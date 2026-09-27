package sts

import (
	"net/http"
	"testing"
)

// TestNewVerifierDefaultHTTPClientHasATimeout is a white-box companion to
// TestVerifyReturnsPromptlyWhenTheIdPHangs (issuer_test.go): that test proves
// a client WITH a timeout bounds a hanging IdP, but it supplies its own
// client, so it never exercises NewVerifier's defaulting logic. This test
// exercises exactly that: opts.HTTPClient left nil must not resolve to
// http.DefaultClient, which has no timeout at all.
func TestNewVerifierDefaultHTTPClientHasATimeout(t *testing.T) {
	v := NewVerifier(nil, VerifierOptions{})
	if v.client == http.DefaultClient {
		t.Fatal("NewVerifier used http.DefaultClient, which has no Timeout — a hanging IdP would block forever")
	}
	if v.client.Timeout <= 0 {
		t.Fatalf("default HTTPClient.Timeout = %v, want > 0", v.client.Timeout)
	}
}
