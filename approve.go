// This file implements POST /approve: the endpoint that turns an
// authenticated human's decision into a grant garmd will accept
// (2026-09-28-approval-grants-design.md).
//
// The frame numbers below are that document's §3 call stack, and the order
// is the design's rather than a convenience. Frames 2-13 establish WHO
// approved; frames 14-18 establish WHAT they approved; frame 19 is the line
// the whole design turns on — the claims are assembled with no act field,
// because a delegated identity that could approve is an agent approving the
// destructive action it is itself about to take.
//
// What this file deliberately does NOT do: read a catalogue, know what a
// tool is, resolve a material path, or refuse an under-cleared approver.
// The STS attests and garmd decides (design "Decided" item 3). An approver
// whose clearance does not meet the tool's bar gets a grant that is
// refused, which is a poor experience and not a hole.
package sts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/garm-ai/garm/contracts/grant"
)

// defaultApproveTTL is how long a minted grant is valid when
// Options.ApproveTTL is left zero. Fifteen minutes, per design §2.3: the
// tool's own max_grant_age_seconds is a ceiling this cannot raise, so a
// generous default here still yields five minutes for a tool asking for
// five.
const defaultApproveTTL = 15 * time.Minute

// maxApproveBody bounds the request body (frame 2). The largest legitimate
// request is a client assertion plus a handful of short scalar values, so
// 64 KiB is generous by two orders of magnitude — the point is that an
// unauthenticated caller cannot make this service read an unbounded body
// before it has verified anything about them.
const maxApproveBody = 64 << 10

// approveRequest is the JSON body of POST /approve.
//
// client_assertion is in the BODY rather than in a header: the design's
// §1.1 shows a JSON body and its frame 3 requires the calling service to
// authenticate, RFC 7523 puts the assertion in the request itself, and a
// new header would put a name in the cross-repository header table that
// nothing else there needs. See the plan's C-2.
type approveRequest struct {
	ClientAssertion string `json:"client_assertion"`

	// ClientAssertionType is the RFC 7521 §4.2 field naming what kind of
	// assertion the one above is. Optional — the only kind this service
	// ever accepts is a private_key_jwt, so its absence is unambiguous —
	// but when it IS sent it must name that kind, because a caller
	// believing it is presenting something else is a caller whose
	// expectations and this endpoint's behaviour have already diverged.
	// Accepting the field while ignoring its value is the failure mode
	// this avoids.
	ClientAssertionType string `json:"client_assertion_type"`

	// Tool is the FQN the approval is for. Without it an approval for
	// get_balance is spendable on initiate_payment.
	Tool string `json:"tool"`

	// Subject is whose call was approved. Without it, one person's approval
	// authorises another's payment.
	Subject string `json:"subject"`

	// Material is a flat map of dotted path to the value's canonical text
	// form — the values the human actually saw. This service digests what
	// it is GIVEN and never resolves a path itself, which is why it needs
	// no descriptors and no catalogue (§1.1). A caller lying is not a hole:
	// garmd re-extracts from the real request and compares (§1.2).
	Material map[string]string `json:"material"`
}

// approveResponse is the §1.1 success body.
type approveResponse struct {
	Grant     string `json:"grant"`
	ExpiresIn int64  `json:"expires_in"`
}

// grantClaimJSON is the `garm_grant` claim, field for field as
// garmd/internal/grants/claims.go's parseGrantClaims reads it.
//
// Renaming a key here is not a refactor. The far side pulls these exact
// strings out of a decoded map, so a drifted name yields "" over there and
// is refused with a message about the wrong thing — an approver who "held
// %q" when the real fault is a misspelled JSON key.
type grantClaimJSON struct {
	Tool                 string   `json:"tool"`
	Subject              string   `json:"subject"`
	Material             string   `json:"material"`
	Approver             string   `json:"approver"`
	ApproverClearance    string   `json:"approver_clearance"`
	ApproverCompartments []string `json:"approver_compartments"`
}

// mintedGrant is a grant on the wire.
//
// It has NO act field and must never gain one. garmd refuses a grant whose
// body carries an `act` key at all, and §2.1 makes that a rule enforced at
// both ends precisely because its purpose is to survive a dishonest issuer.
// A struct with nowhere to put a delegation chain is the mint-side half of
// that rule expressed as a shape rather than as a check somebody can
// forget to run.
//
// There is no `approved_at` either, for the reason §2.3 gives: a separate
// approval timestamp would be a mechanism to re-mint an old decision with a
// fresh expiry, and the age limit exists precisely because approvals go
// stale.
type mintedGrant struct {
	Issuer    string         `json:"iss"`
	Audience  string         `json:"aud"`
	ID        string         `json:"jti"`
	IssuedAt  int64          `json:"iat"`
	ExpiresAt int64          `json:"exp"`
	Grant     grantClaimJSON `json:"garm_grant"`
}

// ApproveHandler returns the POST /approve handler. Mounting it is
// cmd/sts/main.go's job, as it is for Handler and the JWKS.
func (s *Server) ApproveHandler() http.Handler {
	return http.HandlerFunc(s.serveApprove)
}

func (s *Server) serveApprove(w http.ResponseWriter, r *http.Request) {
	// Frame 2, first part. A wrong method is 405 rather than the opaque
	// denial: it says nothing about tools or approvers, and answering 400
	// to a GET would make the endpoint harder to operate for no gain.
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tok, ttl, err := s.approve(r)
	if err != nil {
		// Every failure reason was already logged at its own call site
		// inside approve(); here there is exactly one response, always.
		s.writeDenied(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(approveResponse{Grant: tok, ExpiresIn: int64(ttl.Seconds())})
}

// denyApprove is the single place an approval refusal reason is recorded.
// It always goes to the log and never to the HTTP response — see
// deniedBody's comment.
func (s *Server) denyApprove(_ context.Context, reason string, kv ...any) {
	s.log.Warn("sts: approve denied: "+reason, kv...)
}

// approve runs frames 2 through 20 and returns a signed grant, or an error
// whose text is never shown to the caller.
func (s *Server) approve(r *http.Request) (string, time.Duration, error) {
	ctx := r.Context()

	// Frame 2, rest: content type and body size.
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		s.denyApprove(ctx, "content type is not application/json", "content_type", r.Header.Get("Content-Type"))
		return "", 0, errDenied
	}
	// One byte past the limit, so a body exactly at it still succeeds and
	// one over is detectable rather than silently truncated into a parse
	// error that names the wrong problem.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxApproveBody+1))
	if err != nil {
		s.denyApprove(ctx, "reading the request body failed", "err", err)
		return "", 0, errDenied
	}
	if len(body) > maxApproveBody {
		s.denyApprove(ctx, "request body exceeds the limit", "limit_bytes", maxApproveBody)
		return "", 0, errDenied
	}

	var req approveRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	// A misspelled key is a request that silently approves something other
	// than what the caller meant — the same reasoning LoadConfig and
	// LoadPolicy use for KnownFields(true).
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.denyApprove(ctx, "malformed request body", "err", err)
		return "", 0, errDenied
	}
	// Exactly one JSON value, for DisallowUnknownFields' own reason: a body
	// carrying a second object would have only its first honoured, which is
	// again a request that approves something other than what the caller
	// sent.
	if dec.More() {
		s.denyApprove(ctx, "request body carries more than one JSON value")
		return "", 0, errDenied
	}

	// Frames 3-4: the calling service authenticates with private_key_jwt,
	// jti replay included. The same registry the token endpoint uses — a
	// second one would be a second set of credentials to rotate.
	if req.ClientAssertionType != "" && req.ClientAssertionType != clientAssertionTypeJWTBearer {
		s.denyApprove(ctx, "client_assertion_type names an assertion kind this service does not accept",
			"client_assertion_type", req.ClientAssertionType)
		return "", 0, errDenied
	}
	clientID, err := s.clients.Authenticate(req.ClientAssertion)
	if err != nil {
		s.denyApprove(ctx, "client authentication failed", "err", err)
		return "", 0, errDenied
	}

	// Frames 5-9: the approver's own bearer, verified against its issuer's
	// JWKS under the same algorithm allowlist everything else here uses.
	bearer, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		s.denyApprove(ctx, "no bearer token presented", "client", clientID)
		return "", 0, errDenied
	}
	upstream, trusted, err := s.verifier.Verify(ctx, bearer)
	if err != nil {
		s.denyApprove(ctx, "approver token verification failed", "client", clientID, "err", err)
		return "", 0, errDenied
	}

	// Frame 10 (§2.1). A delegated identity cannot approve. Refusing at
	// MINT as well as at verify is not redundant: either alone suffices for
	// an honest issuer, and both are required because the rule's purpose is
	// to survive a dishonest one. Presence of the KEY, not its value — a
	// null act is still a token that claimed a chain.
	if _, delegated := upstream.Raw["act"]; delegated {
		s.denyApprove(ctx, "approver token carries an act chain", "client", clientID, "approver", upstream.Subject)
		return "", 0, errDenied
	}

	// Frames 11-12: kind from the ISSUER'S configuration, never sniffed
	// from the token. A customer cannot approve a payment.
	if trusted.Kind != "employee" {
		s.denyApprove(ctx, "approver is not an employee kind",
			"client", clientID, "issuer", trusted.Issuer, "kind", trusted.Kind)
		return "", 0, errDenied
	}
	// The identity, built the same way exchange 1 builds one (Task 2's
	// identityForKind): devkit's persona tokens already carry
	// "employee:jdoe" at sub, and prefixing that again would record an
	// approver garmd then compares against a caller identity nobody holds.
	approver, ok := identityForKind(trusted.Kind, upstream.Subject)
	if !ok {
		s.denyApprove(ctx, "approver subject carries a kind prefix its issuer does not assert",
			"client", clientID, "issuer", trusted.Issuer, "kind", trusted.Kind)
		return "", 0, errDenied
	}

	// Frame 13: the approver's authority, recorded rather than judged.
	authority, err := ApproverAuthorityFromClaims(upstream.Raw)
	if err != nil {
		s.denyApprove(ctx, "approver token asserts no usable authority", "client", clientID, "approver", approver, "err", err)
		return "", 0, errDenied
	}

	// Frames 14-17: the body, shape only.
	if err := validToolFQN(req.Tool); err != nil {
		s.denyApprove(ctx, "tool is malformed", "client", clientID, "err", err)
		return "", 0, errDenied
	}
	if !typePrefixed(req.Subject) {
		s.denyApprove(ctx, "subject is not a type-prefixed identity", "client", clientID, "subject", req.Subject)
		return "", 0, errDenied
	}
	for path := range req.Material {
		if err := grant.ValidPath(path); err != nil {
			s.denyApprove(ctx, "material path is malformed", "client", clientID, "err", err)
			return "", 0, errDenied
		}
	}

	// Frame 18. grant.Digest, shared with the verifier rather than
	// reimplemented: if the two sides ever disagree byte for byte, every
	// approval is refused or — worse — one matches a request the approver
	// never saw, and neither side can detect that alone.
	digest := grant.Digest(req.Material)

	// Frames 19-20.
	jti, err := newJTI()
	if err != nil {
		s.denyApprove(ctx, "jti generation failed", "err", err)
		return "", 0, errDenied
	}
	now := time.Now().UTC()

	// Never nil. A nil slice marshals to `null`, which garmd reads back as
	// no compartments — the same answer, but a decoded grant that a human
	// reads should say "this approver held none" rather than say nothing.
	compartments := authority.Compartments
	if compartments == nil {
		compartments = []string{}
	}

	claims := mintedGrant{
		Issuer:    s.issuer,
		Audience:  s.audience,
		ID:        jti,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.approveTTL).Unix(),
		Grant: grantClaimJSON{
			Tool:                 req.Tool,
			Subject:              req.Subject,
			Material:             digest,
			Approver:             approver,
			ApproverClearance:    authority.Clearance,
			ApproverCompartments: compartments,
		},
	}

	tok, err := s.keyring.Sign(claims)
	if err != nil {
		s.denyApprove(ctx, "signing failed", "err", err)
		return "", 0, errDenied
	}
	return tok, s.approveTTL, nil
}

// bearerToken pulls the credential out of an Authorization header. The
// scheme is matched case-insensitively per RFC 7235 §2.1; the credential
// itself is not.
func bearerToken(h string) (string, bool) {
	const scheme = "bearer "
	if len(h) < len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(scheme):])
	return tok, tok != ""
}

// validToolFQN checks the SHAPE of a tool name and only the shape: this
// service holds no catalogue, so whether the tool exists is garmd's
// question (frame 15, and "Decided" item 3).
//
// A method path ("/pkg.Service/Method") is refused explicitly because garmd
// compares the grant's tool against tool.Def.FQN, which is "pkg.name" — a
// grant naming a route would match nothing, and the refusal a caller
// eventually saw would be about the wrong thing.
func validToolFQN(s string) error {
	if s == "" {
		return fmt.Errorf("tool is empty")
	}
	if strings.ContainsAny(s, "/ \t\r\n") {
		return fmt.Errorf("tool %q is not an FQN; garmd compares against \"pkg.name\", not a method route", s)
	}
	if !strings.Contains(s, ".") {
		return fmt.Errorf("tool %q has no package part", s)
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return fmt.Errorf("tool %q has an empty package or name segment", s)
	}
	return nil
}

// typePrefixed is the identity convention every Authorizer call already
// obeys (authz.go): "customer:C-8123", never a bare id. It matters here for
// a different reason — garmd compares the grant's subject against the
// CALLER'S folded Principal.Subject, which is always prefixed, so a bare id
// produces a grant that can never be spent by anybody.
func typePrefixed(s string) bool {
	i := strings.Index(s, ":")
	return i > 0 && i < len(s)-1
}
