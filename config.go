// This file loads the on-disk configuration for the sts binary and wires it
// into a running Server. It is deliberately the only place in this package
// that reads a YAML file describing the whole service (LoadPolicy and
// LoadStaticAuthorizer each read their own, narrower files); everything
// else in this package is a library, wired together here and in cmd/sts.
//
// Config errors are startup failures, read once by an operator, so every
// validation in LoadConfig names the field and says what was wrong with it
// rather than surfacing a bare "invalid" or a stdlib parse error.
package sts

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// defaultListen is used when the config file omits listen entirely.
const defaultListen = ":8080"

// Config is a fully loaded, validated STS configuration, ready to Build a
// Server. LoadConfig performs every check that can be made from the file's
// shape alone; Build performs the few checks that can only be made once the
// pieces it names are actually assembled (see NewServer).
type Config struct {
	// Issuer is this service's own `iss`, minted into every token.
	Issuer string
	// Audience is garmd's identifier, minted into every token's `aud`.
	Audience string
	// Listen is the address the HTTP server binds, e.g. ":8443".
	Listen string

	// TokenEndpointAudience is the audience a client_assertion
	// (private_key_jwt, RFC 7523) must name to authenticate to THIS
	// service's own POST /token endpoint. It is unrelated to Audience
	// above, which names garmd in every token this service mints — the two
	// are different audiences for different tokens.
	TokenEndpointAudience string

	// DelegationTTL bounds how long a minted token is valid. Zero means
	// "use NewServer's default" (10 minutes).
	DelegationTTL time.Duration

	// Keys are every configured signing key, PEM already resolved from its
	// named environment variable (see resolveSecretPEM). ActiveKey names
	// which one signs new tokens; the rest stay served for verification
	// during rotation.
	Keys      []KeyConfig
	ActiveKey string

	// Issuers are the upstream identity providers this service accepts
	// subject tokens from.
	Issuers []TrustedIssuer

	// Clients are the calling services (BFFs) allowed to authenticate to
	// POST /token with private_key_jwt.
	Clients []ClientConfig

	// PolicyPath is the claims policy file (see LoadPolicy).
	PolicyPath string
	// StaticAuthzPath is the static authorizer tuples file (see
	// LoadStaticAuthorizer). Config does not load it itself — which
	// Authorizer implementation a binary builds is chosen by its build tag,
	// not at runtime (see cmd/sts/authz_static.go and
	// cmd/sts/authz_openfga.go), and the result is passed to Build.
	StaticAuthzPath string

	// OpenFGA carries the OpenFGA store connection details. LoadConfig
	// always parses these fields, whether or not the running binary can use
	// them — an untagged build ignores them entirely, and only a binary
	// built with -tags openfga (cmd/sts/authz_openfga.go) requires ApiURL
	// and StoreID to be set. See deploy/config.yaml's authz.openfga block.
	OpenFGA OpenFGAConfig

	InstanceAuthorization InstanceAuthzConfig
}

// OpenFGAConfig is the connection configuration for the OpenFGA-backed
// Authorizer (authz_openfga.go, built only under -tags openfga).
// AuthorizationModelID is optional — leave it empty only for local
// development; production should pin it, since an unpinned store silently
// reinterprets every check the moment a new model version is written.
type OpenFGAConfig struct {
	ApiURL               string
	StoreID              string
	AuthorizationModelID string
}

// --- on-disk shape -------------------------------------------------------

type configFile struct {
	Issuer                string `yaml:"issuer"`
	Audience              string `yaml:"audience"`
	Listen                string `yaml:"listen"`
	TokenEndpointAudience string `yaml:"tokenEndpointAudience"`
	DelegationTTL         string `yaml:"delegationTTL"`

	Keys struct {
		Active string          `yaml:"active"`
		Keys   []keyConfigFile `yaml:"keys"`
	} `yaml:"keys"`

	Issuers []issuerConfigFile `yaml:"issuers"`
	Clients []clientConfigFile `yaml:"clients"`

	Policy string `yaml:"policy"`
	Authz  struct {
		Static  string `yaml:"static"`
		OpenFGA struct {
			ApiURL               string `yaml:"apiUrl"`
			StoreID              string `yaml:"storeId"`
			AuthorizationModelID string `yaml:"modelId"`
		} `yaml:"openfga"`
	} `yaml:"authz"`

	InstanceAuthorization struct {
		Status            string `yaml:"status"`
		UnconfinedCeiling string `yaml:"unconfinedCeiling"`
	} `yaml:"instanceAuthorization"`
}

// keyConfigFile is one signing key. PEM is NEVER the key material itself —
// it names the environment variable holding it, as an env-var reference
// ("$NAME" or "${NAME}"). A config file that could carry a private key is a
// config file that ends up in a bug report, a wiki, or a screenshot; this
// shape makes inlining one a rejected value, not merely a discouraged one.
type keyConfigFile struct {
	KID string `yaml:"kid"`
	PEM string `yaml:"pem"`
}

type issuerConfigFile struct {
	Name     string   `yaml:"name"`
	Issuer   string   `yaml:"iss"`
	JWKS     string   `yaml:"jwks"`
	Audience []string `yaml:"audience"`
	Kind     string   `yaml:"kind"`
}

// clientConfigFile registers one calling service's public key(s). These are
// public keys, not secrets, so — unlike signing keys — they may be inlined
// directly (a literal PEM block) or given as a path to a PEM file.
type clientConfigFile struct {
	ID   string   `yaml:"id"`
	Keys []string `yaml:"keys"`
}

// envRefPattern matches a whole-value reference to an environment variable:
// "$NAME" or "${NAME}". Anything else is rejected as inline material for a
// secret-bearing field.
var envRefPattern = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$`)

// resolveSecretEnvRef expands field's value as a reference to an
// environment variable and returns the variable's contents. It is called
// ONLY for secret-bearing fields (today: a signing key's pem). Every other
// field in this loader is used verbatim — env expansion does not apply
// arbitrarily across the whole file, only to the values that would
// otherwise require a secret to sit in the config file.
func resolveSecretEnvRef(field, raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%s is empty; it must reference an environment variable holding the secret, e.g. $STS_SIGN_KEY_K1", field)
	}
	m := envRefPattern.FindStringSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("%s must be an environment variable reference ($NAME or ${NAME}), not inline material; got %q", field, raw)
	}
	name := m[1]
	val, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("%s references environment variable %s, which is not set", field, name)
	}
	if val == "" {
		return "", fmt.Errorf("%s references environment variable %s, which is set but empty", field, name)
	}
	return val, nil
}

// resolveClientKey returns the PEM bytes for one registered client key. A
// client key is a public key, not a secret, so it may be given either as a
// literal inline PEM block or as a path to a PEM file — no environment
// variable required or expanded.
func resolveClientKey(field, raw string) ([]byte, error) {
	if raw == "" {
		return nil, fmt.Errorf("%s is empty", field)
	}
	if len(raw) >= 10 && raw[:10] == "-----BEGIN" {
		return []byte(raw), nil
	}
	data, err := os.ReadFile(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: reading %s: %w", field, raw, err)
	}
	return data, nil
}

// LoadConfig reads and validates path as an STS configuration file. Every
// check it makes is a startup failure with an operator-legible message: an
// operator reads this error exactly once, so it names the field and what
// was wrong with it rather than surfacing a bare parse error.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sts: config: reading %s: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cf configFile
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("sts: config: parsing %s: %w", path, err)
	}

	cfg := &Config{
		Issuer:                cf.Issuer,
		Audience:              cf.Audience,
		Listen:                cf.Listen,
		TokenEndpointAudience: cf.TokenEndpointAudience,
		PolicyPath:            cf.Policy,
		StaticAuthzPath:       cf.Authz.Static,
		OpenFGA: OpenFGAConfig{
			ApiURL:               cf.Authz.OpenFGA.ApiURL,
			StoreID:              cf.Authz.OpenFGA.StoreID,
			AuthorizationModelID: cf.Authz.OpenFGA.AuthorizationModelID,
		},
	}
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}

	if cfg.Issuer == "" {
		return nil, fmt.Errorf("sts: config: issuer is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("sts: config: audience is required")
	}
	if cfg.TokenEndpointAudience == "" {
		return nil, fmt.Errorf("sts: config: tokenEndpointAudience is required")
	}
	if cfg.PolicyPath == "" {
		return nil, fmt.Errorf("sts: config: policy is required (path to the claims policy file)")
	}
	if cfg.StaticAuthzPath == "" {
		return nil, fmt.Errorf("sts: config: authz.static is required (path to the static authorizer tuples file)")
	}

	if cf.DelegationTTL != "" {
		ttl, err := time.ParseDuration(cf.DelegationTTL)
		if err != nil {
			return nil, fmt.Errorf("sts: config: delegationTTL %q is not a valid duration: %w", cf.DelegationTTL, err)
		}
		cfg.DelegationTTL = ttl
	}

	// --- keys -------------------------------------------------------------

	if len(cf.Keys.Keys) == 0 {
		return nil, fmt.Errorf("sts: config: keys.keys is empty; at least one signing key is required")
	}
	if cf.Keys.Active == "" {
		return nil, fmt.Errorf("sts: config: keys.active is empty; it must name one of keys.keys[].kid")
	}
	var sawActive bool
	keys := make([]KeyConfig, 0, len(cf.Keys.Keys))
	for i, kf := range cf.Keys.Keys {
		if kf.KID == "" {
			return nil, fmt.Errorf("sts: config: keys.keys[%d].kid is empty", i)
		}
		pem, err := resolveSecretEnvRef(fmt.Sprintf("keys.keys[%d] (kid %q) pem", i, kf.KID), kf.PEM)
		if err != nil {
			return nil, fmt.Errorf("sts: config: %w", err)
		}
		keys = append(keys, KeyConfig{KID: kf.KID, PEM: []byte(pem)})
		if kf.KID == cf.Keys.Active {
			sawActive = true
		}
	}
	if !sawActive {
		return nil, fmt.Errorf("sts: config: keys.active %q names no key in keys.keys", cf.Keys.Active)
	}
	cfg.Keys = keys
	cfg.ActiveKey = cf.Keys.Active

	// --- trusted issuers ----------------------------------------------------

	if len(cf.Issuers) == 0 {
		return nil, fmt.Errorf("sts: config: issuers is empty; at least one trusted issuer is required")
	}
	issuers := make([]TrustedIssuer, 0, len(cf.Issuers))
	for i, isf := range cf.Issuers {
		if isf.Name == "" {
			return nil, fmt.Errorf("sts: config: issuers[%d].name is empty", i)
		}
		if isf.Issuer == "" {
			return nil, fmt.Errorf("sts: config: issuers[%d] (%s): iss is empty", i, isf.Name)
		}
		if isf.JWKS == "" {
			return nil, fmt.Errorf("sts: config: issuers[%d] (%s): jwks is empty", i, isf.Name)
		}
		if isf.Kind != "customer" && isf.Kind != "employee" {
			return nil, fmt.Errorf("sts: config: issuers[%d] (%s): kind %q must be \"customer\" or \"employee\"", i, isf.Name, isf.Kind)
		}
		issuers = append(issuers, TrustedIssuer{
			Name:     isf.Name,
			Issuer:   isf.Issuer,
			JWKSURL:  isf.JWKS,
			Audience: isf.Audience,
			Kind:     isf.Kind,
		})
	}
	cfg.Issuers = issuers

	// --- clients ------------------------------------------------------------

	clients := make([]ClientConfig, 0, len(cf.Clients))
	for i, cl := range cf.Clients {
		if cl.ID == "" {
			return nil, fmt.Errorf("sts: config: clients[%d].id is empty", i)
		}
		if len(cl.Keys) == 0 {
			return nil, fmt.Errorf("sts: config: clients[%d] (%s): keys is empty", i, cl.ID)
		}
		pems := make([][]byte, 0, len(cl.Keys))
		for j, k := range cl.Keys {
			pem, err := resolveClientKey(fmt.Sprintf("clients[%d] (%s) keys[%d]", i, cl.ID, j), k)
			if err != nil {
				return nil, fmt.Errorf("sts: config: %w", err)
			}
			pems = append(pems, pem)
		}
		clients = append(clients, ClientConfig{ID: cl.ID, PEMs: pems})
	}
	cfg.Clients = clients

	// --- instance authorization (spec §3.5) ----------------------------

	switch cf.InstanceAuthorization.Status {
	case "enforced", "absent":
		cfg.InstanceAuthorization.Status = cf.InstanceAuthorization.Status
	default:
		return nil, fmt.Errorf("sts: config: instanceAuthorization.status must be \"enforced\" or \"absent\", got %q", cf.InstanceAuthorization.Status)
	}
	if ceiling := cf.InstanceAuthorization.UnconfinedCeiling; ceiling != "" {
		if _, ok := clearanceOrder[ceiling]; !ok {
			return nil, fmt.Errorf("sts: config: instanceAuthorization.unconfinedCeiling %q is not a known clearance (want one of PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)", ceiling)
		}
		cfg.InstanceAuthorization.UnconfinedCeiling = ceiling
	}

	return cfg, nil
}

// Build wires a loaded Config's pieces — keyring, verifier, claims policy
// and client registry — into a running Server. authz is supplied by the
// caller rather than built here, because which Authorizer implementation a
// binary has is decided by its build tag (see cmd/sts/authz_static.go and
// cmd/sts/authz_openfga.go), not something this file needs to know about.
//
// ctx is accepted for symmetry with the rest of this package's
// context-aware constructors and to leave room for a future step here that
// needs one (fetching a JWKS eagerly, say); nothing currently in Build
// blocks on it.
func (c *Config) Build(ctx context.Context, authz Authorizer) (*Server, error) {
	_ = ctx
	if authz == nil {
		return nil, fmt.Errorf("sts: config: build: an Authorizer is required")
	}

	kr, err := NewKeyring(c.Keys, c.ActiveKey)
	if err != nil {
		return nil, fmt.Errorf("sts: config: %w", err)
	}

	verifier := NewVerifier(c.Issuers, VerifierOptions{})

	policy, err := LoadPolicy(c.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("sts: config: %w", err)
	}

	clients, err := NewClientRegistry(c.Clients, ClientOptions{Audience: c.TokenEndpointAudience})
	if err != nil {
		return nil, fmt.Errorf("sts: config: %w", err)
	}

	srv, err := NewServer(Options{
		Issuer:        c.Issuer,
		Audience:      c.Audience,
		Keyring:       kr,
		Verifier:      verifier,
		Policy:        policy,
		Authz:         authz,
		Clients:       clients,
		DelegationTTL: c.DelegationTTL,
		InstanceAuthz: c.InstanceAuthorization,
	})
	if err != nil {
		return nil, fmt.Errorf("sts: config: %w", err)
	}
	return srv, nil
}
