package sts_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

approve:
  ttl_seconds: 900
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
	//
	// The second half of this test is the point of the first: the error
	// this rejection produces is written to stdout by cmd/sts/main.go, so
	// it must not carry the material it just refused. The body line is a
	// distinctive sentinel rather than a plausible-looking key precisely so
	// the "does not appear in the error" assertion is checking something —
	// a generic "not-really-a-key" could be absent from the message by
	// accident.
	const secretSentinel = "SUPERSECRET-DO-NOT-LOG-a7f3c1e9"

	dir := t.TempDir()
	writeFile(t, dir, "claims.yaml", validPolicyYAML)
	writeFile(t, dir, "tuples.yaml", validStaticAuthzYAML)

	cfgYAML := baseConfigYAML(dir, "IRRELEVANT")
	cfgYAML = strings.Replace(cfgYAML, "pem: $IRRELEVANT", "pem: |\n        -----BEGIN EC PRIVATE KEY-----\n        "+secretSentinel+"\n        -----END EC PRIVATE KEY-----", 1)
	path := writeFile(t, dir, "config.yaml", cfgYAML)

	_, err := sts.LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig accepted inline key material in keys.keys[].pem")
	}
	if strings.Contains(err.Error(), secretSentinel) {
		t.Fatalf("LoadConfig's rejection of inline key material reproduced the key material in its error, "+
			"which cmd/sts/main.go writes to stdout; error was: %v", err)
	}
	// The message still has to be actionable: it must name the field the
	// operator got wrong, even though it may not quote its value.
	if !strings.Contains(err.Error(), "keys.keys[0]") {
		t.Fatalf("LoadConfig's rejection does not name the offending field; error was: %v", err)
	}
}

// TestLoadConfigRejectsADuplicateIssuer pins the one config mistake whose
// consequence is a silently weaker gate rather than a startup failure.
// NewVerifier keys its issuer table by `iss`, so two entries sharing one
// would keep only the last — and TrustedIssuer.Kind is the sole input to the
// caller's kind, which decides whether instanceAuthorization's clearance cap
// runs at all. A second entry saying kind: employee would therefore turn the
// customer cap off for that IdP, silently, from a clean start.
func TestLoadConfigRejectsADuplicateIssuer(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "claims.yaml", validPolicyYAML)
	writeFile(t, dir, "tuples.yaml", validStaticAuthzYAML)
	t.Setenv("STS_TEST_SIGN_KEY_3", string(testKeyPEM(t)))

	y := baseConfigYAML(dir, "STS_TEST_SIGN_KEY_3")
	y = strings.Replace(y,
		"    kind: customer\n",
		"    kind: customer\n\n  - name: employee-shadow\n    iss: https://auth.example.com\n"+
			"    jwks: https://auth.example.com/keys\n    audience: [shop-bff]\n    kind: employee\n",
		1)
	path := writeFile(t, dir, "config-duplicate-iss.yaml", y)

	_, err := sts.LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig accepted two issuers sharing one iss; the second would silently replace the first, kind and all")
	}
	// The operator has to be able to find BOTH entries, not just the one
	// that happened to be reported.
	for _, want := range []string{"issuers[0]", "issuers[1]", "https://auth.example.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the duplicate-iss error does not mention %q; error was: %v", want, err)
		}
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
		// An issuer with no audience can never verify a token: every one
		// of them fails containment against an empty list.
		"issuer with an empty audience": func(y string) string {
			return strings.Replace(y, "    audience: [shop-bff]\n", "", 1)
		},
		// No clients means every POST /token is denied as an unknown
		// client — the service binds and serves a JWKS but cannot perform
		// the one exchange it exists for.
		"no clients block at all": func(y string) string {
			return strings.Replace(y,
				"clients:\n  - id: shop-bff\n    keys:\n      - "+
					`"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest\n-----END PUBLIC KEY-----\n"`+"\n",
				"", 1)
		},
		"an empty clients list": func(y string) string {
			return strings.Replace(y,
				"clients:\n  - id: shop-bff\n    keys:\n      - "+
					`"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest\n-----END PUBLIC KEY-----\n"`+"\n",
				"clients: []\n", 1)
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
func (nullAuthorizer) CanRun(context.Context, string, string) (bool, error)    { return false, nil }
func (nullAuthorizer) HandledBy(context.Context, string, string) (bool, error) { return false, nil }
func (nullAuthorizer) InSegment(context.Context, string, string) (bool, error) { return false, nil }

var _ sts.Authorizer = nullAuthorizer{}

func TestLoadConfigReadsTheApproveTTL(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "claims.yaml", validPolicyYAML)
	writeFile(t, dir, "tuples.yaml", validStaticAuthzYAML)
	t.Setenv("STS_TEST_KEY_APPROVE", string(testKeyPEM(t)))

	t.Run("read from the file", func(t *testing.T) {
		path := writeFile(t, dir, "config.yaml", baseConfigYAML(dir, "STS_TEST_KEY_APPROVE"))
		cfg, err := sts.LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.ApproveTTL != 900*time.Second {
			t.Errorf("ApproveTTL = %v, want 15m0s", cfg.ApproveTTL)
		}
	})

	t.Run("omitted is zero, and NewServer supplies the default", func(t *testing.T) {
		// Zero here rather than 900 in the loader, so there is exactly one
		// place the default lives (NewServer) and a config that omits the
		// key and a Server built directly in Go get the same answer.
		yaml := strings.Replace(baseConfigYAML(dir, "STS_TEST_KEY_APPROVE"), "approve:\n  ttl_seconds: 900\n", "", 1)
		// baseConfigYAML's shop-bff key is a shape-only placeholder — real
		// enough for LoadConfig's own checks, but not valid ASN.1, and every
		// other test that renders it only ever calls LoadConfig. This is the
		// first to call Build, which parses it as a real PKIX public key
		// (NewClientRegistry), so it is swapped here for a real one.
		realKey := `"` + strings.ReplaceAll(string(clientPublicKeyPEM(t, genUpstreamKey(t))), "\n", `\n`) + `"`
		yaml = strings.Replace(yaml,
			`"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest\n-----END PUBLIC KEY-----\n"`,
			realKey, 1)
		path := writeFile(t, dir, "config-no-approve.yaml", yaml)
		cfg, err := sts.LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.ApproveTTL != 0 {
			t.Errorf("ApproveTTL = %v, want 0 when the key is absent", cfg.ApproveTTL)
		}
		srv, err := cfg.Build(context.Background(), nullAuthorizer{})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if srv == nil {
			t.Fatal("Build returned no Server")
		}
	})

	t.Run("a negative ttl is a startup failure", func(t *testing.T) {
		yaml := strings.Replace(baseConfigYAML(dir, "STS_TEST_KEY_APPROVE"), "ttl_seconds: 900", "ttl_seconds: -1", 1)
		path := writeFile(t, dir, "config-bad-approve.yaml", yaml)
		if _, err := sts.LoadConfig(path); err == nil {
			t.Fatal("LoadConfig accepted a negative approve.ttl_seconds; a grant that expires before it is minted is a startup failure, not a per-request mystery")
		}
	})
}

// The shipped example must load and must register the runner whose client
// id deploy/tuples.yaml's can_run tuple names. A tuple naming a client the
// config does not register is a can_run check that can never pass, and the
// operator sees only an opaque denial.
func TestDeployConfigYAMLRegistersTheRunnerItsTuplesName(t *testing.T) {
	// The example references ./clients/*.pub.pem, which are not committed
	// (they are generated by deploy/keygen.sh), so this reads the file's
	// declared client ids rather than calling LoadConfig.
	data, err := os.ReadFile("deploy/config.yaml")
	if err != nil {
		t.Fatalf("read deploy/config.yaml: %v", err)
	}
	if !strings.Contains(string(data), "id: agentd") {
		t.Error("deploy/config.yaml registers no client `agentd`; deploy/tuples.yaml's can_run tuple names runner:agentd, and exchange 2 derives that identity from the AUTHENTICATED client id")
	}
	if !strings.Contains(string(data), "ttl_seconds:") {
		t.Error("deploy/config.yaml documents no approve.ttl_seconds; the example is what an operator copies")
	}
}
