package sts

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// defaultJTITTL is the JTITTL a ClientRegistry uses when ClientOptions.JTITTL
// is left zero. It bounds both how far in the future a client assertion's
// exp may be set, and — because a spent jti is evicted at the assertion's
// own exp, never later — the maximum time any single jti is retained in the
// replay cache.
const defaultJTITTL = 5 * time.Minute

// ClientConfig registers one calling service — a backend-for-frontend,
// typically — allowed to authenticate to this service's token endpoint with
// private_key_jwt (RFC 7523).
//
// ID is a plain, un-prefixed client identifier ("shop-bff"), deliberately
// NOT the type-prefixed identity convention Authorizer's identities carry
// (see authz.go): a calling service authenticating itself is not a
// principal in the authorization model, so there is nothing here for a
// prefix to disambiguate.
//
// PEMs holds every public key currently registered for this client,
// PEM-encoded PKIX ("PUBLIC KEY"). It is a slice, not a single key, so a
// client can rotate: register the new key alongside the old one, cut the
// client over to signing with it, then remove the old key in a later
// deploy — an assertion signed by ANY currently-registered key is accepted.
type ClientConfig struct {
	ID   string
	PEMs [][]byte
}

// ClientOptions configures a ClientRegistry.
type ClientOptions struct {
	// Audience is this service's token endpoint identifier — the aud a
	// valid client assertion must name. Required.
	Audience string

	// Now returns the current time. Defaults to time.Now; tests override it
	// to advance a fake clock past a jti's TTL without a real sleep.
	Now func() time.Time

	// JTITTL bounds how far in the future an assertion's exp may be set. A
	// spent jti's cache entry is evicted at that same exp (never later), so
	// this doubles as the upper bound on how long any single jti is
	// retained. Defaults to defaultJTITTL if zero or negative.
	JTITTL time.Duration
}

// ClientRegistry authenticates a calling service against a registered set of
// public keys using private_key_jwt: the caller signs a short-lived JWT (a
// "client assertion") with a private key whose public half is registered
// here, proving it holds that key without any shared secret ever crossing
// the wire.
//
// Replay protection — refusing a jti that has been presented before — is
// held in an in-memory, per-process map, guarded by mu. THIS IS A REAL
// DEPLOYMENT LIMITATION, not an oversight: with more than one replica of
// this service behind a load balancer, replay protection is per-replica,
// not global. The same assertion can be spent once against EACH replica
// before that replica's own cache has recorded it, since no replica knows
// what any other has seen. A shared store (Redis or similar) would close
// this gap, but building one is out of scope here — this type only ever
// guards a single process's memory, and says so, so the limitation is
// discovered by reading this comment, not by an incident in production.
type ClientRegistry struct {
	audience string
	now      func() time.Time
	jtiTTL   time.Duration

	byID map[string][]any // client id -> parsed, registered public keys

	mu sync.Mutex
	// seen is keyed by (client id, jti), not by jti alone: jti uniqueness is
	// only ever guaranteed PER CLIENT (RFC 7523 leaves it to the issuer to
	// pick, exactly as RFC 7519's jti does for any issuer), never globally.
	// Keying on the bare jti would make one client's assertion fail as
	// "already used" whenever its jti happened to collide with a completely
	// unrelated client's — fail-closed, not a bypass, but an unspecified and
	// unnecessary cross-client interaction.
	seen map[[2]string]time.Time // (client id, jti) -> the expiry it was recorded with
}

// NewClientRegistry parses every client's registered PEM-encoded public keys
// eagerly and fails loudly on a bad one: this runs at startup, and an
// operator should see a malformed key as a startup error, never as a
// mysterious per-request authentication failure discovered later.
func NewClientRegistry(clients []ClientConfig, opts ClientOptions) (*ClientRegistry, error) {
	if opts.Audience == "" {
		return nil, fmt.Errorf("clients: audience is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.JTITTL <= 0 {
		opts.JTITTL = defaultJTITTL
	}

	byID := make(map[string][]any, len(clients))
	for _, c := range clients {
		if c.ID == "" {
			return nil, fmt.Errorf("clients: a client has an empty id")
		}
		if _, dup := byID[c.ID]; dup {
			return nil, fmt.Errorf("clients: duplicate client id %q", c.ID)
		}
		if len(c.PEMs) == 0 {
			return nil, fmt.Errorf("clients: client %q has no registered keys", c.ID)
		}

		keys := make([]any, 0, len(c.PEMs))
		for i, p := range c.PEMs {
			pub, err := parsePublicKeyPEM(p)
			if err != nil {
				return nil, fmt.Errorf("clients: client %q: key %d: %w", c.ID, i, err)
			}
			keys = append(keys, pub)
		}
		byID[c.ID] = keys
	}

	return &ClientRegistry{
		audience: opts.Audience,
		now:      opts.Now,
		jtiTTL:   opts.JTITTL,
		byID:     byID,
		seen:     make(map[[2]string]time.Time),
	}, nil
}

// parsePublicKeyPEM decodes a PEM-encoded PKIX public key. PKIX covers every
// key type permittedAlgorithms allows (EC and RSA), so one parser suffices.
func parsePublicKeyPEM(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("not a valid PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return pub, nil
}

// Authenticate verifies assertion as a private_key_jwt client assertion and
// returns the authenticated client's id.
//
// A valid assertion:
//   - parses under permittedAlgorithms — the SAME allowlist issuer.go
//     enforces for upstream tokens (see its comment for why: no "none", no
//     HMAC, no EdDSA), passed to jose.ParseSigned so an out-of-list alg is
//     refused during parsing, before any key lookup;
//   - is signed by one of the claimed client's currently registered keys;
//   - carries iss == sub == that client's own id;
//   - carries an aud equal to this service's token endpoint;
//   - carries an exp that is neither already past nor further in the future
//     than the configured JTITTL bound;
//   - carries a jti that has not been presented before.
//
// Every check is fail-closed: a parse failure, a missing or mismatched
// field, or a signature that does not verify against a registered key is
// refused with an error and no client id.
func (r *ClientRegistry) Authenticate(assertion string) (string, error) {
	sig, err := jose.ParseSigned(assertion, permittedAlgorithms)
	if err != nil {
		return "", fmt.Errorf("clients: %w", err)
	}
	if len(sig.Signatures) != 1 {
		return "", fmt.Errorf("clients: assertion carries %d signatures, want 1", len(sig.Signatures))
	}

	// iss must be read before the signature can be checked, since which
	// client's keys to try against depends on it. As in issuer.go's
	// Verify, this value is used ONLY to select candidate keys, never
	// trusted as fact: if it names a real client but the assertion was not
	// actually signed by one of THAT client's keys, verification below
	// fails regardless of what iss claims.
	var unverified map[string]any
	if err := json.Unmarshal(sig.UnsafePayloadWithoutVerification(), &unverified); err != nil {
		return "", fmt.Errorf("clients: assertion body: %w", err)
	}
	claimedID, _ := unverified["iss"].(string)
	if claimedID == "" {
		return "", fmt.Errorf("clients: assertion has no iss")
	}
	keys, ok := r.byID[claimedID]
	if !ok {
		return "", fmt.Errorf("clients: unknown client %q", claimedID)
	}

	var payload []byte
	var verifyErr error
	for _, key := range keys {
		if payload, verifyErr = sig.Verify(key); verifyErr == nil {
			break
		}
	}
	if verifyErr != nil {
		return "", fmt.Errorf("clients: signature: %w", verifyErr)
	}

	// Everything below this line is verified content.
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return "", fmt.Errorf("clients: assertion body: %w", err)
	}

	iss, _ := raw["iss"].(string)
	if iss == "" || iss != claimedID {
		// Should be unreachable — the verified payload is byte-identical to
		// the one iss was read from above — but refuse rather than assume,
		// matching issuer.go's equivalent belt-and-braces check.
		return "", fmt.Errorf("clients: verified iss %q does not match %q", iss, claimedID)
	}
	sub, _ := raw["sub"].(string)
	if sub != iss {
		return "", fmt.Errorf("clients: sub %q must equal iss %q", sub, iss)
	}

	aud, err := parseAudience(raw["aud"])
	if err != nil {
		return "", fmt.Errorf("clients: aud: %w", err)
	}
	if !containsAny(aud, []string{r.audience}) {
		return "", fmt.Errorf("clients: assertion audience %v does not name this service's token endpoint (%q)", aud, r.audience)
	}

	expF, ok := raw["exp"].(float64)
	if !ok {
		return "", fmt.Errorf("clients: assertion has no exp")
	}
	exp := time.Unix(int64(expF), 0)
	now := r.now()
	if !now.Before(exp) {
		return "", fmt.Errorf("clients: assertion expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if exp.Sub(now) > r.jtiTTL {
		return "", fmt.Errorf("clients: assertion exp %s is further than %s in the future, want a bounded window",
			exp.UTC().Format(time.RFC3339), r.jtiTTL)
	}

	jti, _ := raw["jti"].(string)
	if jti == "" {
		return "", fmt.Errorf("clients: assertion has no jti")
	}

	if err := r.spend(iss, jti, exp); err != nil {
		return "", err
	}

	return iss, nil
}

// spend records (clientID, jti) as used, refusing a replay, and evicts every
// entry whose own recorded expiry has already passed.
//
// The "have I seen this" check and the "record it" write happen inside one
// uninterrupted critical section (a single held r.mu), which is what makes
// this race-free by construction: two concurrent presentations of the same
// assertion cannot both observe an empty slot and both proceed to record
// it — one always executes its lookup-and-set before the other's lookup can
// begin, so a genuine race between them still yields exactly one success.
//
// Eviction runs inline, on every call, rather than on a timer: this cache is
// reachable by anyone who can reach the token endpoint, so bounding its size
// cannot depend on a background goroutine that might not be running, or
// might not run often enough. An entry is removed at its OWN exp, which is
// itself bounded by JTITTL — never retained "just in case" beyond the
// window the assertion itself claimed to be valid for.
func (r *ClientRegistry) spend(clientID, jti string, exp time.Time) error {
	now := r.now()
	key := [2]string{clientID, jti}

	r.mu.Lock()
	defer r.mu.Unlock()

	for k, e := range r.seen {
		if !now.Before(e) {
			delete(r.seen, k)
		}
	}

	if _, alreadyUsed := r.seen[key]; alreadyUsed {
		return fmt.Errorf("clients: jti %q for client %q has already been used", jti, clientID)
	}
	r.seen[key] = exp
	return nil
}
