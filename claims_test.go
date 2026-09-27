package sts_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/garm-ai/sts"
)

// minimalPolicy is the smallest well-formed policy: one role, one customer
// segment granting it, one agent granted it directly. Tests that only need
// *some* loadable policy to probe refusal behavior on use this.
const minimalPolicy = `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
segments:
  cust: { kind: customer, roles: [r1] }
agents:
  a1: { roles: [r1] }
`

// loadPolicy writes yamlContent to a temp file and loads it, failing the
// test immediately if the policy does not load — it is for tests that need
// a *working* policy, not for TestLoadPolicyRejectsUnusableFiles, which
// expects LoadPolicy to fail.
func loadPolicy(t *testing.T, yamlContent string) *sts.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "claims.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := sts.LoadPolicy(path)
	if err != nil {
		t.Fatalf("loadPolicy: %v", err)
	}
	return p
}

// sameSet reports whether got and want contain the same elements,
// irrespective of order — claim slices are sorted by contract, but these
// tests assert on set membership, not on the exact order.
func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

func TestRolesUnion(t *testing.T) {
	// The devkit precedent: holding two roles gives the HIGHER clearance and
	// the UNION of compartments and verbs. Delegation intersects; roles do not.
	p := loadPolicy(t, `
roles:
  support-desk:  { clearance: INTERNAL,   compartments: [support],   verbs: [READ] }
  payments-desk: { clearance: RESTRICTED, compartments: [financial], verbs: [READ, WRITE] }
segments:
  staff: { kind: employee, roles: [support-desk, payments-desk] }
agents:
  order-assistant: { roles: [support-desk] }
`)
	c, err := p.ForSegments("employee", []string{"staff"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Clearance != "RESTRICTED" {
		t.Fatalf("clearance = %q, want the HIGHEST over the union", c.Clearance)
	}
	if !sameSet(c.Compartments, []string{"support", "financial"}) {
		t.Fatalf("compartments = %v, want the union", c.Compartments)
	}
	if !sameSet(c.Verbs, []string{"READ", "WRITE"}) {
		t.Fatalf("verbs = %v, want the union", c.Verbs)
	}
	if c.Kind != "USER" {
		t.Fatalf("kind = %q; an employee is a USER to garm — it has no employee kind", c.Kind)
	}
}

// Review Focus 1. This is the case that actually occurs in production: a
// tuple never written, or a segment renamed in the policy but not in the store.
func TestForSegmentsRefusesAPrincipalInNoSegment(t *testing.T) {
	p := loadPolicy(t, minimalPolicy)
	if _, err := p.ForSegments("customer", nil); err == nil {
		t.Fatal("a principal in no segment resolved to claims; there are none to mint")
	}
	if _, err := p.ForSegments("customer", []string{"not-a-segment"}); err == nil {
		t.Fatal("an unknown segment resolved to claims")
	}
}

func TestForSegmentsIgnoresSegmentsOfTheWrongKind(t *testing.T) {
	// A customer who somehow holds an employee segment must not get its roles.
	// Membership comes from a tuple store that garm does not own.
	p := loadPolicy(t, `
roles:
  retail-role:   { clearance: INTERNAL,   compartments: [retail], verbs: [READ] }
  hr-role:       { clearance: RESTRICTED, compartments: [hr],     verbs: [WRITE] }
segments:
  retail-vip: { kind: customer, roles: [retail-role] }
  hr-staff:   { kind: employee, roles: [hr-role] }
`)
	// A customer principal that (incorrectly, per some stale tuple) is also
	// listed as a member of the employee-only "hr-staff" segment.
	c, err := p.ForSegments("customer", []string{"retail-vip", "hr-staff"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Clearance != "INTERNAL" {
		t.Fatalf("clearance = %q, want INTERNAL — the wrong-kind (employee) segment's RESTRICTED role must not leak into a customer's claim", c.Clearance)
	}
	if !sameSet(c.Compartments, []string{"retail"}) {
		t.Fatalf("compartments = %v, want only [retail] — the wrong-kind segment's compartment must be ignored", c.Compartments)
	}
	if !sameSet(c.Verbs, []string{"READ"}) {
		t.Fatalf("verbs = %v, want only [READ] — the wrong-kind segment's verb must be ignored", c.Verbs)
	}
}

func TestForAgentRefusesAnUndeclaredAgent(t *testing.T) {
	// An agent absent from the policy has no authority to assert. Refuse
	// rather than mint an empty act level.
	p := loadPolicy(t, minimalPolicy)
	if _, err := p.ForAgent("ghost-agent"); err == nil {
		t.Fatal("an undeclared agent resolved to claims; there is no authority to mint")
	}
}

func TestLoadPolicyRejectsUnusableFiles(t *testing.T) {
	// no roles; a segment naming an undeclared role; an agent naming an
	// undeclared role; a role with no clearance; a role with an unknown
	// clearance name; a segment with no kind; a kind that is neither
	// customer nor employee. Each must fail at LOAD, not at mint — the
	// policy is configuration and an operator reads the error at startup.
	cases := map[string]string{
		"no roles at all": `
segments:
  s1: { kind: customer, roles: [] }
`,
		"segment names an undeclared role": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
segments:
  s1: { kind: customer, roles: [nope] }
`,
		"agent names an undeclared role": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
agents:
  a1: { roles: [nope] }
`,
		"role with no clearance": `
roles:
  r1: { verbs: [READ] }
`,
		"role with an unknown clearance name": `
roles:
  r1: { clearance: TOP_SECRET, verbs: [READ] }
`,
		"segment with no kind": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
segments:
  s1: { roles: [r1] }
`,
		"kind neither customer nor employee": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
segments:
  s1: { kind: robot, roles: [r1] }
`,
	}

	for name, yamlContent := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "claims.yaml")
			if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := sts.LoadPolicy(path); err == nil {
				t.Fatalf("LoadPolicy accepted an unusable policy (%s); it must fail at load, not at mint", name)
			}
		})
	}
}

func TestAgentClaimKindIsAgent(t *testing.T) {
	// ForAgent produces kind AGENT; ForSegments produces kind USER.
	p := loadPolicy(t, minimalPolicy)

	agentClaim, err := p.ForAgent("a1")
	if err != nil {
		t.Fatal(err)
	}
	if agentClaim.Kind != "AGENT" {
		t.Fatalf("ForAgent kind = %q, want AGENT", agentClaim.Kind)
	}

	userClaim, err := p.ForSegments("customer", []string{"cust"})
	if err != nil {
		t.Fatal(err)
	}
	if userClaim.Kind != "USER" {
		t.Fatalf("ForSegments kind = %q, want USER", userClaim.Kind)
	}
}

func TestSegmentsReturnsDeclaredSegmentsSorted(t *testing.T) {
	p := loadPolicy(t, `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
segments:
  zeta:  { kind: customer, roles: [r1] }
  alpha: { kind: employee, roles: [r1] }
  mid:   { kind: customer, roles: [r1] }
`)
	got := p.Segments()
	want := []string{"alpha", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("Segments() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Segments() = %v, want sorted %v", got, want)
		}
	}
}
