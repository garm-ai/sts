package sts_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garm-ai/sts"
)

// validPolicyYAML is a minimal claims policy, just enough for LoadPolicy to
// accept it, written to disk for tests that exercise Config.Build.
const validPolicyYAML = `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
segments:
  seg1: { kind: customer, roles: [r1] }
agents:
  a1: { roles: [r1] }
`

// validStaticAuthzYAML is a minimal (empty) static authorizer file: every
// relation is absent, which is a perfectly valid, if useless, configuration.
const validStaticAuthzYAML = `
can_invoke: []
handled_by: []
in_segment: []
`

// writeFile writes content to name inside dir and returns the full path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// baseConfigYAML returns a complete, valid config file referencing policy
// and static-authz files already written to dir, and a signing key named by
// the given env var. Fields can be overridden by the caller via override,
// which receives the rendered YAML and returns a modified version.
func baseConfigYAML(dir, keyEnvVar string) string {
	policyPath := filepath.Join(dir, "claims.yaml")
	authzPath := filepath.Join(dir, "tuples.yaml")
	return `
issuer: https://sts.internal.example.com
audience: garm://tools
listen: :8443
tokenEndpointAudience: https://sts.internal.example.com/token

keys:
  active: k1
  keys:
    - kid: k1
      pem: $` + keyEnvVar + `

issuers:
  - name: customer
    iss: https://auth.example.com
    jwks: https://auth.example.com/keys
    audience: [shop-bff]
    kind: customer

clients:
  - id: shop-bff
    keys:
      - ` + `"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest\n-----END PUBLIC KEY-----\n"` + `

policy: ` + policyPath + `
authz:
  static: ` + authzPath + `

instanceAuthorization:
  status: absent
  unconfinedCeiling: PUBLIC
`
}

func TestLoadConfigExpandsEnvForSecretsOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "claims.yaml", validPolicyYAML)
	writeFile(t, dir, "tuples.yaml", validStaticAuthzYAML)

	pemContent := string(testKeyPEM(t))
	t.Setenv("STS_TEST_SIGN_KEY", pemContent)

	// The issuer field deliberately contains a literal '$' followed by
	// something that LOOKS like a var reference. If expansion were applied
	// arbitrarily (rather than only to secret-bearing fields), this would
	// either be mangled or fail to resolve; it must instead survive
	// byte-for-byte.
	cfgYAML := baseConfigYAML(dir, "STS_TEST_SIGN_KEY")
	cfgYAML = strings.Replace(cfgYAML,
		"issuer: https://sts.internal.example.com",
		"issuer: https://sts.internal.example.com/$NOT_AN_ENV_VAR_EXPANSION",
		1)
	path := writeFile(t, dir, "config.yaml", cfgYAML)

	cfg, err := sts.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if len(cfg.Keys) != 1 {
		t.Fatalf("Keys = %d entries, want 1", len(cfg.Keys))
	}
	if got := string(cfg.Keys[0].PEM); got != pemContent {
		t.Fatalf("the signing key's pem was not expanded from its named env var:\ngot:  %q\nwant: %q", got, pemContent)
	}
	if cfg.Keys[0].KID != "k1" {
		t.Fatalf("KID = %q, want k1", cfg.Keys[0].KID)
	}

	// The non-secret field must NOT have been expanded: it still contains
	// the literal, unresolved "$NOT_AN_ENV_VAR_EXPANSION" text.
	want := "https://sts.internal.example.com/$NOT_AN_ENV_VAR_EXPANSION"
	if cfg.Issuer != want {
		t.Fatalf("issuer = %q, want %q (env expansion must apply only to secret-bearing fields)", cfg.Issuer, want)
	}
}

func TestLoadConfigRejectsInlineKeyMaterial(t *testing.T) {
	// A config file that could hold a private key is exactly what this
	// design refuses to allow: the pem field must be an env-var reference,
	// never the key itself, even if an operator pastes it in directly.
	dir := t.TempDir()
	writeFile(t, dir, "claims.yaml", validPolicyYAML)
	writeFile(t, dir, "tuples.yaml", validStaticAuthzYAML)

	cfgYAML := baseConfigYAML(dir, "IRRELEVANT")
	cfgYAML = strings.Replace(cfgYAML, "pem: $IRRELEVANT", "pem: |\n        -----BEGIN EC PRIVATE KEY-----\n        not-really-a-key\n        -----END EC PRIVATE KEY-----", 1)
	path := writeFile(t, dir, "config.yaml", cfgYAML)

	if _, err := sts.LoadConfig(path); err == nil {
		t.Fatal("LoadConfig accepted inline key material in keys.keys[].pem")
	}
}

func TestLoadConfigRejectsAnIncompleteConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "claims.yaml", validPolicyYAML)
	writeFile(t, dir, "tuples.yaml", validStaticAuthzYAML)
	t.Setenv("STS_TEST_SIGN_KEY_2", string(testKeyPEM(t)))

	render := func(mutate func(string) string) string {
		y := baseConfigYAML(dir, "STS_TEST_SIGN_KEY_2")
		if mutate != nil {
			y = mutate(y)
		}
		return y
	}

	for name, mutate := range map[string]func(string) string{
		"missing issuer": func(y string) string {
			return strings.Replace(y, "issuer: https://sts.internal.example.com\n", "", 1)
		},
		"missing audience": func(y string) string {
			return strings.Replace(y, "audience: garm://tools\n", "", 1)
		},
		"no keys": func(y string) string {
			return strings.Replace(y, "keys:\n  active: k1\n  keys:\n    - kid: k1\n      pem: $STS_TEST_SIGN_KEY_2\n",
				"keys:\n  active: k1\n  keys: []\n", 1)
		},
		"active key naming nothing": func(y string) string {
			return strings.Replace(y, "active: k1", "active: k9", 1)
		},
		"no trusted issuers": func(y string) string {
			return strings.Replace(y,
				"issuers:\n  - name: customer\n    iss: https://auth.example.com\n    jwks: https://auth.example.com/keys\n    audience: [shop-bff]\n    kind: customer\n",
				"issuers: []\n", 1)
		},
		"instanceAuthorization status neither value": func(y string) string {
			return strings.Replace(y, "status: absent", "status: sometimes", 1)
		},
		"unconfinedCeiling not a known clearance": func(y string) string {
			return strings.Replace(y, "unconfinedCeiling: PUBLIC", "unconfinedCeiling: SUPER_SECRET", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			y := render(mutate)
			path := writeFile(t, dir, "config-"+strings.ReplaceAll(name, " ", "_")+".yaml", y)
			if _, err := sts.LoadConfig(path); err == nil {
				t.Fatalf("%s: LoadConfig accepted an incomplete config", name)
			}
		})
	}
}

func TestBuildRefusesAnUnknownInstanceAuthorizationStatus(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeFile(t, dir, "claims.yaml", validPolicyYAML)

	cfg := &sts.Config{
		Issuer:                "https://sts.internal.example.com",
		Audience:              "garm://tools",
		Listen:                ":8443",
		TokenEndpointAudience: "https://sts.internal.example.com/token",
		Keys:                  []sts.KeyConfig{{KID: "k1", PEM: testKeyPEM(t)}},
		ActiveKey:             "k1",
		Issuers: []sts.TrustedIssuer{
			{Name: "customer", Issuer: "https://auth.example.com", JWKSURL: "https://auth.example.com/keys", Kind: "customer"},
		},
		PolicyPath: policyPath,
		InstanceAuthorization: sts.InstanceAuthzConfig{
			Status: "sometimes", // neither "enforced" nor "absent"
		},
	}

	authz := &nullAuthorizer{}
	if _, err := cfg.Build(context.Background(), authz); err == nil {
		t.Fatal("Build accepted an unknown instanceAuthorization.status")
	}
}

// nullAuthorizer answers every question with a denial. It exists purely so
// TestBuildRefusesAnUnknownInstanceAuthorizationStatus has a non-nil
// Authorizer to pass — the test never reaches a call to it, since NewServer
// refuses the bad InstanceAuthz status before any request is served.
type nullAuthorizer struct{}

func (nullAuthorizer) CanInvoke(context.Context, string, string) (bool, error) { return false, nil }
func (nullAuthorizer) HandledBy(context.Context, string, string) (bool, error) { return false, nil }
func (nullAuthorizer) InSegment(context.Context, string, string) (bool, error) { return false, nil }

var _ sts.Authorizer = nullAuthorizer{}
