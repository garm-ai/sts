package sts_test

import (
	"os"
	"path/filepath"
	"reflect"
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
		"agent with an empty roles list": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
agents:
  a1: { roles: [] }
`,
		"agent with roles omitted entirely": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
agents:
  a1: {}
`,
		"segment with an empty roles list": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
segments:
  s1: { kind: customer, roles: [] }
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

// TestLoadPolicyRejectsUnknownFieldInRole guards against exactly the gap
// that let deploy/claims.yaml ship broken: a typo'd key inside `roles:` (say
// `compartment:`, singular) that a permissive decoder silently drops. A
// dropped field is never referenced anywhere afterward, so `garm claims
// check` cannot flag it as unmatched either — the role loads looking
// intentional, holding fewer claims than whoever wrote it meant to grant.
// KnownFields(true) turns that into a load-time error instead, matching
// devkit's LoadPersonas.
func TestLoadPolicyRejectsUnknownFieldInRole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claims.yaml")
	yamlContent := `
roles:
  r1: { clearance: PUBLIC, compartment: [oops], verbs: [READ] }
segments:
  s1: { kind: customer, roles: [r1] }
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sts.LoadPolicy(path); err == nil {
		t.Fatal("LoadPolicy accepted a role with an unknown field (compartment, singular); a typo'd key is a misconfigured identity, not a warning")
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

// TestGarmClaimSlicesAreSortedNotJustEqualAsSets guards the sort inside
// unionOf/sortedKeys, a code path distinct from Segments()'s own inline
// sort. Every other assertion in this file goes through sameSet, which is
// order-independent by design, so deleting the slices.Sort call inside
// sortedKeys would pass the rest of this suite in silence. This test
// declares compartments and verbs out of alphabetical order across two
// roles and checks exact slice order with reflect.DeepEqual, so it fails
// the moment that sort is removed.
func TestGarmClaimSlicesAreSortedNotJustEqualAsSets(t *testing.T) {
	p := loadPolicy(t, `
roles:
  zebra-role: { clearance: PUBLIC, compartments: [zeta, alpha], verbs: [WRITE, READ] }
  mid-role:   { clearance: PUBLIC, compartments: [mid],         verbs: [DELETE] }
segments:
  s1: { kind: customer, roles: [zebra-role, mid-role] }
`)
	c, err := p.ForSegments("customer", []string{"s1"})
	if err != nil {
		t.Fatal(err)
	}
	wantCompartments := []string{"alpha", "mid", "zeta"}
	if !reflect.DeepEqual(c.Compartments, wantCompartments) {
		t.Fatalf("Compartments = %v, want %v in sorted order — a minted token must be byte-identical for the same inputs", c.Compartments, wantCompartments)
	}
	wantVerbs := []string{"DELETE", "READ", "WRITE"}
	if !reflect.DeepEqual(c.Verbs, wantVerbs) {
		t.Fatalf("Verbs = %v, want %v in sorted order", c.Verbs, wantVerbs)
	}
}

// TestDeployClaimsYAMLExampleLoadsAndStaysInSync loads the worked example
// committed at deploy/claims.yaml, exactly as the dev IdP's personas file is
// loaded by its own test "so it cannot rot". A schema change to claims.go
// (a renamed field, a stricter validation, a changed union rule) that
// breaks this file, or a hand-edit that drifts the file from its documented
// shape, fails this test rather than being discovered later.
func TestDeployClaimsYAMLExampleLoadsAndStaysInSync(t *testing.T) {
	p, err := sts.LoadPolicy("deploy/claims.yaml")
	if err != nil {
		t.Fatalf("deploy/claims.yaml failed to load: %v", err)
	}
	if got := p.Segments(); !sameSet(got, []string{"retail-vip", "sme-basic", "support-staff"}) {
		t.Fatalf("Segments() = %v, want [retail-vip sme-basic support-staff]", got)
	}
	c, err := p.ForSegments("customer", []string{"retail-vip"})
	if err != nil {
		t.Fatalf("ForSegments(retail-vip): %v", err)
	}
	if c.Clearance != "CONFIDENTIAL" {
		t.Fatalf("retail-vip clearance = %q, want CONFIDENTIAL — deploy/claims.yaml has drifted from its documented self-service role", c.Clearance)
	}
	if !sameSet(c.Compartments, []string{"pii-contact", "financial"}) {
		t.Fatalf("retail-vip compartments = %v, want [pii-contact financial]", c.Compartments)
	}

	// The worked `services:` entry. It is the only declaration in the
	// repository that lets a runner open a task at all, so a hand-edit that
	// widens it — a compartment, a higher clearance, a verb beyond WRITE —
	// fails here rather than shipping. The whole platform's runner holds
	// this, and every run can reach whatever it holds.
	svc, err := p.ForService("agentd")
	if err != nil {
		t.Fatalf("deploy/claims.yaml declares no agentd service: %v", err)
	}
	if svc.Kind != "SERVICE" {
		t.Fatalf("agentd kind = %q, want SERVICE", svc.Kind)
	}
	if svc.Clearance != "PUBLIC" {
		t.Fatalf("agentd clearance = %q, want PUBLIC — create_task declares min_clearance CLEARANCE_PUBLIC and nothing higher is warranted", svc.Clearance)
	}
	if !sameSet(svc.Verbs, []string{"WRITE"}) {
		t.Fatalf("agentd verbs = %v, want exactly [WRITE]", svc.Verbs)
	}
	if len(svc.Compartments) != 0 {
		t.Fatalf("agentd compartments = %v, want none — create_task requires none, and a compartment here is one every run can reach", svc.Compartments)
	}
	if svc.ToolSets != nil {
		t.Fatalf("agentd tool_sets = %v, want absent until create_task's own set exists; a scoped caller cannot reach a set-less tool", svc.ToolSets)
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

// The approver's authority is RECORDED, not judged (approval-grants §2.4):
// the STS copies what the approver's own verified token says they hold, and
// garmd compares it with what the tool requires. So the only thing to get
// right here is reading it faithfully — including both spellings of a
// clearance, since garmd accepts both and an IdP may emit either.
func TestApproverAuthorityFromClaims(t *testing.T) {
	cases := []struct {
		name             string
		raw              map[string]any
		wantClearance    string
		wantCompartments []string
	}{
		{
			name: "bare spelling",
			raw: map[string]any{"garm": map[string]any{
				"clearance":    "RESTRICTED",
				"compartments": []any{"financial", "pii-contact"},
			}},
			wantClearance:    "RESTRICTED",
			wantCompartments: []string{"financial", "pii-contact"},
		},
		{
			name: "CLEARANCE_ spelling, which devkit and garmd both emit",
			raw: map[string]any{"garm": map[string]any{
				"clearance": "CLEARANCE_INTERNAL",
			}},
			wantClearance:    "INTERNAL",
			wantCompartments: nil,
		},
		{
			name: "compartments sorted, so one approver never mints two different grants",
			raw: map[string]any{"garm": map[string]any{
				"clearance":    "PUBLIC",
				"compartments": []any{"pii-contact", "financial"},
			}},
			wantClearance:    "PUBLIC",
			wantCompartments: []string{"financial", "pii-contact"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := sts.ApproverAuthorityFromClaims(c.raw)
			if err != nil {
				t.Fatalf("ApproverAuthorityFromClaims: %v", err)
			}
			if got.Clearance != c.wantClearance {
				t.Errorf("Clearance = %q, want %q", got.Clearance, c.wantClearance)
			}
			if !reflect.DeepEqual(got.Compartments, c.wantCompartments) {
				t.Errorf("Compartments = %v, want %v", got.Compartments, c.wantCompartments)
			}
		})
	}
}

// An approver whose token asserts no authority is refused at MINT rather
// than handed a grant garmd will refuse at call time. The grant would carry
// approver_clearance "" and fail checkShape's approver_min_clearance test
// with a message about the approver being under-cleared, which sends an
// operator looking at the wrong system entirely.
func TestApproverAuthorityFromClaimsRefusesAnEmptyOrUnknownClearance(t *testing.T) {
	cases := map[string]map[string]any{
		"no garm claim at all":  {"sub": "jdoe"},
		"garm is not an object": {"garm": "RESTRICTED"},
		"empty clearance":       {"garm": map[string]any{"clearance": ""}},
		"absent clearance":      {"garm": map[string]any{"compartments": []any{"financial"}}},
		"unknown clearance":     {"garm": map[string]any{"clearance": "TOP_SECRET"}},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := sts.ApproverAuthorityFromClaims(raw); err == nil {
				t.Fatal("got nil error; an approver asserting no usable authority must be refused here")
			}
		})
	}
}

// --- services ------------------------------------------------------------

// servicePolicy declares one service beside the agents, with the shape the
// `services:` block is meant to have: its authority written INLINE, and no
// tool_sets — absent means unscoped, which is what reaching a set-less tool
// (garm.tasks.v1.create_task declares no sets) requires.
const servicePolicy = `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
segments:
  cust: { kind: customer, roles: [r1] }
agents:
  a1: { roles: [r1] }
services:
  agentd: { clearance: PUBLIC, verbs: [WRITE] }
  artefactd-writer: { clearance: RESTRICTED, compartments: [card-data, generated-artefacts], verbs: [WRITE], tool_sets: [artefacts] }
`

func TestForServiceMintsTheDeclaredAuthorityAsKindService(t *testing.T) {
	p := loadPolicy(t, servicePolicy)

	c, err := p.ForService("artefactd-writer")
	if err != nil {
		t.Fatalf("ForService: %v", err)
	}
	// "SERVICE" and not "service" or "PRINCIPAL_KIND_SERVICE": garmd's
	// normaliseKind accepts all three, but it maps anything it does NOT
	// recognise to the empty string SILENTLY, so what this mints has to be
	// a value that round-trips rather than one that reads plausibly.
	if c.Kind != "SERVICE" {
		t.Errorf("kind = %q, want SERVICE — garmd's normaliseKind maps it to PRINCIPAL_KIND_SERVICE, and an unrecognised kind becomes \"\" with no error", c.Kind)
	}
	if c.Clearance != "RESTRICTED" {
		t.Errorf("clearance = %q, want RESTRICTED as declared", c.Clearance)
	}
	if !sameSet(c.Compartments, []string{"card-data", "generated-artefacts"}) {
		t.Errorf("compartments = %v, want the declared pair", c.Compartments)
	}
	if !sameSet(c.Verbs, []string{"WRITE"}) {
		t.Errorf("verbs = %v, want [WRITE]", c.Verbs)
	}
	if !sameSet(c.ToolSets, []string{"artefacts"}) {
		t.Errorf("tool_sets = %v, want [artefacts]", c.ToolSets)
	}

	// A service that names no tool sets is UNSCOPED, and that must arrive as
	// nil rather than an empty slice: garmd reads nil ToolSets as "every
	// set" and an empty one as "no set at all", so the difference decides
	// whether a set-less tool is reachable.
	unscoped, err := p.ForService("agentd")
	if err != nil {
		t.Fatalf("ForService(agentd): %v", err)
	}
	if unscoped.ToolSets != nil {
		t.Errorf("tool_sets = %#v, want nil — absent means unscoped, and only nil says that", unscoped.ToolSets)
	}
}

// An undeclared service has no authority to mint, exactly as an undeclared
// agent has none. It must fail here rather than mint an empty claim: a claim
// with no clearance is one garmd's ParseClaims refuses, and the operator
// would read that as a verifier problem rather than a missing policy entry.
func TestForServiceRefusesAnUndeclaredService(t *testing.T) {
	p := loadPolicy(t, servicePolicy)
	if _, err := p.ForService("ghost"); err == nil {
		t.Fatal("ForService accepted a service the policy never declares")
	}
}

func TestLoadPolicyRejectsUnusableServiceBlocks(t *testing.T) {
	cases := map[string]string{
		// A typo'd key inside a service entry is the same failure
		// TestLoadPolicyRejectsUnknownFieldInRole guards in a role, and it
		// is WORSE here: `garm claims check` reads only `roles:`, so
		// nothing downstream looks at a service's names at all.
		"unknown field in a service": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
services:
  s: { clerance: PUBLIC, verbs: [WRITE] }
`,
		"service with no clearance": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
services:
  s: { verbs: [WRITE] }
`,
		"service with an unknown clearance name": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
services:
  s: { clearance: TOP_SECRET, verbs: [WRITE] }
`,
		// A service with no verbs reaches no tool: the exchange refuses an
		// empty verb intersection over the chain, so this would load and
		// then deny every mint, which is a policy bug an operator should
		// read at startup.
		"service with no verbs": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
services:
  s: { clearance: PUBLIC }
`,
		// A service's NAME is bare. The exchange looks it up by the
		// authenticated client id and mints "service:" + that, so a key
		// written with the prefix already on it is the doubled identity
		// ("service:service:agentd") nothing matches — and it would read
		// back as an undeclared service, which is a long way from the
		// mistake.
		"service key carrying a kind prefix": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
services:
  service:agentd: { clearance: PUBLIC, verbs: [WRITE] }
`,
		// A service names its authority inline; it does not name roles. A
		// `roles:` key here is somebody writing the other shape, and
		// accepting it silently would grant nothing at all.
		"service naming roles": `
roles:
  r1: { clearance: PUBLIC, verbs: [READ] }
services:
  s: { roles: [r1] }
`,
	}

	for name, yamlContent := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "claims.yaml")
			if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := sts.LoadPolicy(path); err == nil {
				t.Fatalf("LoadPolicy accepted an unusable service block (%s); it must fail at load, not at mint", name)
			}
		})
	}
}
