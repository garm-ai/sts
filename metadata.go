package sts

import (
	"encoding/json"
	"net/http"
)

// Metadata is what this service publishes about itself, so a verifier can
// check it was configured to expect the right thing.
//
// The problem it solves is dull and expensive: garmd is told an issuer and an
// audience by flag, this service mints an issuer and an audience from its own
// config, and nothing compares them. Get either wrong and every token is
// refused — correctly, and with a message about audience mismatch that reads
// like a bug in the token rather than a typo in a deployment. It is the sort
// of thing that costs an afternoon and teaches nothing.
//
// Publishing it lets the verifier refuse at STARTUP instead, naming the
// disagreement. That is the same move garm already makes with the descriptor
// hash: the far side advertises what it is serving, the near side compares,
// and a mismatch is a refusal rather than a mystery.
//
// The shape follows RFC 8414 (OAuth 2.0 Authorization Server Metadata) where
// it has a field for what we mean, which is most of it. `garm_audience` and
// `garm_approve_endpoint` are extensions because RFC 8414 describes what an
// authorization server IS and has no field for the audience it MINTS, nor for
// a second, non-OAuth endpoint this one happens to serve — both are peculiar
// to a service with exactly one downstream, which is peculiar to this one.
type Metadata struct {
	Issuer string `json:"issuer"`

	// JWKSURI is where the verifying side fetches keys. Advertised rather
	// than assumed so this can move without every verifier being reconfigured.
	JWKSURI string `json:"jwks_uri"`

	// TokenEndpoint is for the BFF, not for garmd. Included because a reader
	// looking at this document wants the whole picture.
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// SigningAlgValuesSupported is what this service signs with, so a verifier
	// can refuse at startup if its own allowlist would reject every token.
	// EdDSA is absent from both sides on purpose.
	SigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// GarmAudience is the `aud` this service mints into every token — garmd's
	// identifier. The field a verifier actually has to agree with, and the one
	// RFC 8414 has no place for.
	GarmAudience string `json:"garm_audience"`

	// GarmApproveEndpoint is where a caller obtains an approval grant. Like
	// GarmAudience it is an extension: RFC 8414 describes what an
	// authorization server IS and has no field for a second, non-OAuth
	// endpoint this one happens to serve.
	//
	// Advertised rather than assumed for the same reason JWKSURI is: the
	// runner is configured with one base URL and reads the rest, so the two
	// sides cannot be told two paths that disagree.
	GarmApproveEndpoint string `json:"garm_approve_endpoint"`
}

// MetadataHandler serves the document at
// /.well-known/oauth-authorization-server.
//
// Unauthenticated, and it should be: everything in it is already discoverable
// by anyone who can obtain one token, and a verifier has to read it before it
// holds any credential of its own.
func (s *Server) MetadataHandler(jwksURI, tokenEndpoint, approveEndpoint string) http.Handler {
	doc := Metadata{
		Issuer:                    s.issuer,
		JWKSURI:                   jwksURI,
		TokenEndpoint:             tokenEndpoint,
		GrantTypesSupported:       []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		SigningAlgValuesSupported: []string{"ES256"},
		GarmAudience:              s.audience,
		GarmApproveEndpoint:       approveEndpoint,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		// Unreachable: every field is a string or a string slice. Serving a
		// 500 forever would be worse than failing to build the handler, but
		// there is nothing to return an error to from here.
		panic("sts: encoding metadata: " + err.Error())
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		_, _ = w.Write(body)
	})
}
