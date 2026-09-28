package sts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// permittedAlgorithms is the allowlist of signature algorithms this service
// accepts from an upstream IdP. It lives here, as a package-level var, and
// nowhere in TrustedIssuer or VerifierOptions, on purpose: an operator cannot
// widen it through configuration. Adding an algorithm is a source change,
// reviewed like anything else.
//
// This is the same list garmd's verifier accepts (garmd/internal/authn/
// verify.go), and for the same reasoning: it excludes `none` (there would be
// no signature to check), any HMAC algorithm (the "key" would be a public
// key an attacker already has), and EdDSA — deliberately absent, matching
// the verifier this service mints tokens for.
var permittedAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
}

// jwksCacheTTL is how long a fetched JWKS is trusted before a key lookup
// forces a refetch, even for a kid the cache already has.
const jwksCacheTTL = 5 * time.Minute

// unknownKidRefetchWindow bounds how often a single issuer's JWKS can be
// refetched in response to a key lookup that the current cache cannot
// satisfy (an unknown kid, or an expired cache). Without this, a token
// bearing a garbage kid could be replayed to force one HTTP request to the
// IdP per verification attempt.
const unknownKidRefetchWindow = 30 * time.Second

// defaultJWKSFetchTimeout bounds a single JWKS fetch when the caller does not
// supply their own HTTPClient. A JWKS fetch is allowed to be slow — it is
// off the hot path of any individual request, cached, and rate-limited — but
// it must never be unbounded: http.DefaultClient has no timeout, and an IdP
// that accepts a connection and never responds would otherwise hang every
// verification for that issuer indefinitely, which is exactly the
// availability problem the unknown-kid rate limit exists to prevent from the
// other direction.
const defaultJWKSFetchTimeout = 8 * time.Second

// TrustedIssuer is one upstream identity provider this service accepts
// tokens from.
//
// Kind is how a verified token becomes "customer" or "employee": both real
// IdPs in this design are placeholders, so this is plain per-issuer
// configuration, never vendor-specific claim sniffing.
type TrustedIssuer struct {
	Name     string
	Issuer   string
	JWKSURL  string
	Audience []string
	Kind     string
}

// VerifierOptions configures a Verifier. Every field is optional.
type VerifierOptions struct {
	// Skew tolerated on exp/nbf. Clocks disagree; without it a token minted
	// a second in the future by a fast IdP is refused for no reason.
	Skew time.Duration

	// Now returns the current time. Defaults to time.Now; tests override it.
	Now func() time.Time

	// HTTPClient fetches JWKS documents. Defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// UpstreamClaims is the verified content of an upstream token, plus the
// decoded claim map (Raw) so a later stage can read issuer-specific claims
// (such as "tenant") that have no dedicated field here.
type UpstreamClaims struct {
	Subject   string
	Issuer    string
	Audience  []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Raw       map[string]any
}

// jwksCache holds one issuer's fetched JWKS and the bookkeeping needed to
// rate-limit refetches.
//
// mu guards only the fields below, never the network call itself: a fetch
// runs with the lock released (see key), so a slow or hanging IdP for this
// issuer cannot block unrelated lookups against the same cache that would
// otherwise be answerable from a still-fresh copy, and cannot wedge the
// per-issuer bookkeeping for other goroutines. fetchDone implements the
// single-flight join: while non-nil, a fetch is already in progress and a
// concurrent caller waits on it instead of starting a second one, then reads
// fetchErr/keys once it closes.
//
// Known limitation, not addressed here: the shared fetch runs on the
// LEADER's context (see fetchAndStore's caller in key), so a joiner whose
// own context is still live can still fail if the leader's context is
// cancelled first. Fine for now — every joiner still gets a prompt answer,
// just occasionally the wrong reason — but worth revisiting if leaders and
// joiners start carrying meaningfully different deadlines.
type jwksCache struct {
	mu          sync.Mutex
	keys        map[string]jose.JSONWebKey
	fetchedAt   time.Time
	lastAttempt time.Time
	fetchDone   chan struct{}
	fetchErr    error
}

// Verifier checks upstream tokens against their issuer's configured JWKS.
type Verifier struct {
	issuers map[string]TrustedIssuer // by Issuer (the `iss` value)
	skew    time.Duration
	now     func() time.Time
	client  *http.Client

	mu   sync.Mutex
	sets map[string]*jwksCache // by issuer
}

// NewVerifier builds a Verifier that accepts tokens from exactly the given
// issuers.
func NewVerifier(issuers []TrustedIssuer, opts VerifierOptions) *Verifier {
	if opts.Skew <= 0 {
		opts.Skew = 60 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: defaultJWKSFetchTimeout}
	}

	byIssuer := make(map[string]TrustedIssuer, len(issuers))
	for _, iss := range issuers {
		byIssuer[iss.Issuer] = iss
	}

	return &Verifier{
		issuers: byIssuer,
		skew:    opts.Skew,
		now:     opts.Now,
		client:  opts.HTTPClient,
		sets:    make(map[string]*jwksCache),
	}
}

// Verify checks a token's signature and registered claims against its
// issuer's JWKS. Nothing in the payload is trusted until the signature
// verifies against a key that issuer's JWKS actually serves.
func (v *Verifier) Verify(ctx context.Context, token string) (*UpstreamClaims, *TrustedIssuer, error) {
	// ParseSigned takes the allowlist, so an `alg` outside it — including
	// "none" — is refused during parsing, before any key lookup and before
	// any claim is read.
	sig, err := jose.ParseSigned(token, permittedAlgorithms)
	if err != nil {
		return nil, nil, fmt.Errorf("sts: %w", err)
	}
	if len(sig.Signatures) != 1 {
		return nil, nil, fmt.Errorf("sts: token carries %d signatures, want 1", len(sig.Signatures))
	}
	kid := sig.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, nil, fmt.Errorf("sts: token has no kid")
	}

	// The issuer must be read from the payload before the signature can be
	// checked, because which issuer's JWKS to check against depends on it.
	// This is safe: the value is used only to select a candidate key set,
	// never trusted as fact. If it names a real trusted issuer but the token
	// was not actually signed by one of that issuer's keys, signature
	// verification below fails and the token is denied either way.
	var unverified map[string]any
	if err := json.Unmarshal(sig.UnsafePayloadWithoutVerification(), &unverified); err != nil {
		return nil, nil, fmt.Errorf("sts: token body: %w", err)
	}
	claimedIssuer, _ := unverified["iss"].(string)
	if claimedIssuer == "" {
		return nil, nil, fmt.Errorf("sts: token has no iss")
	}
	trusted, ok := v.issuers[claimedIssuer]
	if !ok {
		return nil, nil, fmt.Errorf("sts: issuer %q is not trusted", claimedIssuer)
	}

	key, err := v.keyFor(ctx, trusted, kid)
	if err != nil {
		return nil, nil, fmt.Errorf("sts: %w", err)
	}

	payload, err := sig.Verify(key)
	if err != nil {
		return nil, nil, fmt.Errorf("sts: signature: %w", err)
	}

	// Everything below this line is verified content.
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, nil, fmt.Errorf("sts: token body: %w", err)
	}

	claims, err := parseUpstreamClaims(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("sts: %w", err)
	}
	if claims.Issuer != trusted.Issuer {
		// The verified iss disagrees with the one used to pick the key set.
		// This should be unreachable (the key set is keyed by issuer), but
		// refuse rather than assume.
		return nil, nil, fmt.Errorf("sts: verified issuer %q does not match %q", claims.Issuer, trusted.Issuer)
	}

	if err := v.checkRegistered(claims, &trusted); err != nil {
		return nil, nil, err
	}

	return claims, &trusted, nil
}

// checkRegistered validates aud and the time window on already-verified
// claims.
func (v *Verifier) checkRegistered(c *UpstreamClaims, trusted *TrustedIssuer) error {
	if !containsAny(c.Audience, trusted.Audience) {
		return fmt.Errorf("sts: token audience %v does not include any of %v configured for issuer %q",
			c.Audience, trusted.Audience, trusted.Issuer)
	}

	if c.ExpiresAt.IsZero() {
		// A token with no expiry never stops being valid, which makes
		// revocation impossible. Refuse rather than pick a default.
		return fmt.Errorf("sts: token has no exp")
	}
	now := v.now()
	if now.After(c.ExpiresAt.Add(v.skew)) {
		return fmt.Errorf("sts: token expired at %s", c.ExpiresAt.UTC().Format(time.RFC3339))
	}

	// nbf is optional and has no dedicated field on UpstreamClaims, so it is
	// read here from the verified raw claims.
	if nbf, ok := c.Raw["nbf"]; ok {
		if f, ok := nbf.(float64); ok {
			start := time.Unix(int64(f), 0)
			if now.Add(v.skew).Before(start) {
				return fmt.Errorf("sts: token is not valid until %s", start.UTC().Format(time.RFC3339))
			}
		}
	}
	return nil
}

// parseUpstreamClaims decodes the registered claims this package understands
// out of an already-verified claim map, keeping the map itself as Raw.
func parseUpstreamClaims(raw map[string]any) (*UpstreamClaims, error) {
	// sub is required, not merely read. Every identity this service asks
	// the Authorizer about, and every `sub` it mints, is built as
	// callerKind + ":" + Subject (see exchange.go) — so a token with no
	// sub, or a sub that is not a string, yields the identity "customer:"
	// and proceeds. That fails closed today only because every authorizer
	// lookup for it happens to miss, which is a property of the data in a
	// store, not a check. Refuse it here, where iss and exp are refused.
	sub, ok := raw["sub"].(string)
	if !ok || sub == "" {
		return nil, fmt.Errorf("token has no sub")
	}
	iss, _ := raw["iss"].(string)
	if iss == "" {
		return nil, fmt.Errorf("token has no iss")
	}

	aud, err := parseAudience(raw["aud"])
	if err != nil {
		return nil, fmt.Errorf("aud: %w", err)
	}

	var exp time.Time
	if v, ok := raw["exp"]; ok {
		f, ok := v.(float64)
		if !ok {
			return nil, fmt.Errorf("exp is not a number")
		}
		exp = time.Unix(int64(f), 0)
	}

	var iat time.Time
	if v, ok := raw["iat"]; ok {
		if f, ok := v.(float64); ok {
			iat = time.Unix(int64(f), 0)
		}
	}

	return &UpstreamClaims{
		Subject:   sub,
		Issuer:    iss,
		Audience:  aud,
		ExpiresAt: exp,
		IssuedAt:  iat,
		Raw:       raw,
	}, nil
}

// parseAudience decodes `aud` per RFC 7519: it may be a single string or an
// array of strings. A bare `.(string)` type assertion silently yields "" for
// the array form — which most JWT libraries emit by default — and this bug
// was just fixed in the companion daemon for exactly that reason.
func parseAudience(v any) ([]string, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case string:
		if t == "" {
			return nil, nil
		}
		return []string{t}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("array element %T is not a string", item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", v)
	}
}

// containsAny reports whether have and want share at least one element.
// Containment, not equality, is the correct check for aud: an issuer may be
// configured with several acceptable audiences.
func containsAny(have, want []string) bool {
	for _, w := range want {
		if slices.Contains(have, w) {
			return true
		}
	}
	return false
}

// keyFor resolves the verification key for (issuer, kid), fetching and
// caching the issuer's JWKS as needed.
func (v *Verifier) keyFor(ctx context.Context, trusted TrustedIssuer, kid string) (any, error) {
	v.mu.Lock()
	cache, ok := v.sets[trusted.Issuer]
	if !ok {
		cache = &jwksCache{}
		v.sets[trusted.Issuer] = cache
	}
	v.mu.Unlock()

	return cache.key(ctx, v, trusted, kid)
}

// key returns the key for kid, refetching the issuer's JWKS if the cache
// cannot answer.
//
// Cache behaviour, all four required properties:
//  1. Cached by (issuer, kid): each jwksCache belongs to one issuer and
//     indexes its keys by kid.
//  2. An unknown kid triggers at most one refetch per unknownKidRefetchWindow
//     — checked below before any network call.
//  3. A cached-and-valid (not yet expired) key set serves known kids without
//     touching the network at all, so a transient IdP outage does not affect
//     tokens whose key is already cached.
//  4. An expired cache plus a failed refresh is a hard failure: this method
//     never returns a key from c.keys after a failed fetch. There is no
//     fallback path to stale keys.
//
// A fifth property, not in the original list but load-bearing for
// availability: the mutex is never held across the network call. A fetch
// runs unlocked; concurrent callers for the same issuer join it (single
// flight) rather than each starting — and each blocking on — their own.
// Combined with the caller-supplied or default-timeout http.Client, a
// hanging IdP delays callers by at most that timeout, not forever.
func (c *jwksCache) key(ctx context.Context, v *Verifier, trusted TrustedIssuer, kid string) (any, error) {
	c.mu.Lock()

	now := v.now()
	fresh := !c.fetchedAt.IsZero() && now.Sub(c.fetchedAt) < jwksCacheTTL

	if fresh {
		if key, ok := c.keys[kid]; ok {
			c.mu.Unlock()
			return key.Key, nil
		}
	}

	// A fetch is already in flight (for a garbage kid, an expired cache, or
	// simply a concurrent caller that got here first): join it instead of
	// starting a second request against the same IdP.
	if c.fetchDone != nil {
		done := c.fetchDone
		c.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, fmt.Errorf("jwks: %w", ctx.Err())
		}
		return c.lookupAfterFetch(trusted, kid)
	}

	// No fetch in flight. The cache is either stale or missing this kid.
	// Either way a fetch is needed, but it is rate-limited: without this, a
	// token carrying a garbage kid could force one HTTP request per
	// verification attempt.
	if !c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < unknownKidRefetchWindow {
		c.mu.Unlock()
		return nil, fmt.Errorf("jwks: issuer %q kid %q unavailable, refresh rate-limited until %s",
			trusted.Issuer, kid, c.lastAttempt.Add(unknownKidRefetchWindow).UTC().Format(time.RFC3339))
	}
	c.lastAttempt = now
	done := make(chan struct{})
	c.fetchDone = done
	c.mu.Unlock()

	// The network call itself runs with the lock released. fetchAndStore
	// guarantees fetchDone is cleared and done is closed on every exit path,
	// a panic from fetchJWKS included — see its doc comment for why that
	// matters.
	c.fetchAndStore(ctx, v, trusted, done)

	return c.lookupAfterFetch(trusted, kid)
}

// fetchAndStore runs the network fetch and records its outcome, then wakes
// every goroutine waiting on done.
//
// The cleanup (recording fetchErr/keys, clearing fetchDone, closing done) is
// entirely inside a deferred func, so it runs even if fetchJWKS panics —
// without that, a leader that panics mid-fetch would leave fetchDone set
// forever and every joiner blocked on <-done with no deadline, reintroducing
// the exact indefinite-hang class the single-flight design was built to
// close, just from a different cause. The panic itself is deliberately not
// swallowed: recover() only lets the cleanup run, then the same value is
// re-panicked so it still surfaces to the leader's own caller as a bug, not
// as a quietly-failed fetch.
func (c *jwksCache) fetchAndStore(ctx context.Context, v *Verifier, trusted TrustedIssuer, done chan struct{}) {
	var keys map[string]jose.JSONWebKey
	var err error

	defer func() {
		r := recover()
		if r != nil {
			// The fetch never completed normally; a joiner must see a
			// failure for THIS round, never a stale result left over from
			// some earlier fetch.
			err = fmt.Errorf("jwks: fetch panicked: %v", r)
		}

		c.mu.Lock()
		if err == nil {
			// Never fall back to the old (expired, or kid-incomplete) key
			// set: c.keys is replaced only on success.
			c.keys = keys
			c.fetchedAt = v.now()
		}
		c.fetchErr = err
		c.fetchDone = nil
		c.mu.Unlock()
		close(done) // wake every goroutine that joined this fetch

		if r != nil {
			panic(r)
		}
	}()

	keys, err = fetchJWKS(ctx, v.client, trusted.JWKSURL)
}

// lookupAfterFetch reads the outcome of the most recently completed fetch
// (this goroutine's own, or one it joined) and resolves kid against it.
func (c *jwksCache) lookupAfterFetch(trusted TrustedIssuer, kid string) (any, error) {
	c.mu.Lock()
	err := c.fetchErr
	key, ok := c.keys[kid]
	c.mu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("jwks: refreshing issuer %q failed: %w", trusted.Issuer, err)
	}
	if !ok {
		return nil, fmt.Errorf("jwks: issuer %q has no key for kid %q", trusted.Issuer, kid)
	}
	return key.Key, nil
}

// fetchJWKS retrieves and decodes a JWKS document, indexed by kid.
func fetchJWKS(ctx context.Context, client *http.Client, url string) (map[string]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s returned %d: %s", url, resp.StatusCode, string(body))
	}

	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("decoding jwks from %s: %w", url, err)
	}

	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	for _, k := range set.Keys {
		keys[k.KeyID] = k
	}
	return keys, nil
}
