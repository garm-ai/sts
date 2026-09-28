package sts

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// clearanceOrder ranks the clearance vocabulary from lowest to highest. The
// bare spelling ("INTERNAL", not "CLEARANCE_INTERNAL") is what an operator
// writes in the policy file; garmd's verifier accepts both spellings, but
// this is the one a human reads and writes here. The union of two roles
// takes the HIGHEST clearance among them, which is why this is a rank and
// not merely a validity set.
var clearanceOrder = map[string]int{
	"PUBLIC":       0,
	"INTERNAL":     1,
	"CONFIDENTIAL": 2,
	"RESTRICTED":   3,
}

// validSegmentKinds is the vocabulary a segment's `kind:` field may declare
// in the policy file. It is deliberately narrower than GarmClaim.Kind (the
// verifier's USER/AGENT/SERVICE vocabulary): both a "customer" and an
// "employee" segment mint a claim of Kind "USER" — the distinction between
// them lives in the subject string and the authorization store, never in
// the minted claim.
var validSegmentKinds = map[string]bool{
	"customer": true,
	"employee": true,
}

// Role is a bundle of claims: a clearance, a set of compartments, a set of
// verbs, and optionally a set of tool sets. A segment or an agent carries a
// role's authority by naming it.
type Role struct {
	Clearance    string
	Compartments []string
	Verbs        []string
	ToolSets     []string
}

// GarmClaim is the authority claim this service mints into a token — the
// garm claim of the design's §2. Kind is the verifier's principal-kind
// vocabulary (USER, AGENT, SERVICE): ForSegments always produces USER
// (customers and employees are both users to garm), ForAgent always
// produces AGENT.
type GarmClaim struct {
	Clearance    string
	Compartments []string
	Verbs        []string
	ToolSets     []string
	Kind         string
}

// policySegment is the validated, internal form of a declared segment: the
// kind of principal it applies to, and the roles it grants. It is NOT
// membership — which principals belong to a segment is a question for the
// authorization store, never for this file.
type policySegment struct {
	kind  string
	roles []string
}

// policyAgent is the validated, internal form of an agent's own declared
// authority.
type policyAgent struct {
	roles []string
}

// Policy is a loaded, validated claims policy: role definitions, which
// segments grant which roles, and each agent's own authority. It holds
// definitions and rules ONLY. Per-principal membership — which segments a
// given customer or employee actually belongs to — comes from an
// authorization store built elsewhere; there are potentially millions of
// customers, and that cannot live in a file reviewed by a pull request.
type Policy struct {
	roles    map[string]Role
	segments map[string]policySegment
	agents   map[string]policyAgent
}

// --- on-disk shape -----------------------------------------------------

type policyFile struct {
	Roles    map[string]roleFile    `yaml:"roles"`
	Segments map[string]segmentFile `yaml:"segments"`
	Agents   map[string]agentFile   `yaml:"agents"`
}

type roleFile struct {
	Clearance    string   `yaml:"clearance"`
	Compartments []string `yaml:"compartments"`
	Verbs        []string `yaml:"verbs"`
	ToolSets     []string `yaml:"tool_sets"`
}

type segmentFile struct {
	Kind  string   `yaml:"kind"`
	Roles []string `yaml:"roles"`
}

type agentFile struct {
	Roles []string `yaml:"roles"`
}

// LoadPolicy reads and validates a claims policy file. Every validation that
// can be caught here IS caught here, not left for mint time: the policy is
// configuration, and an operator should see a bad role reference or an
// unknown clearance name as a startup error, never as a silently short
// claim discovered later in production.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("claims: reading %s: %w", path, err)
	}

	var pf policyFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a typo'd key is a misconfigured identity, not a warning
	if err := dec.Decode(&pf); err != nil {
		return nil, fmt.Errorf("claims: parsing %s: %w", path, err)
	}

	if len(pf.Roles) == 0 {
		return nil, fmt.Errorf("claims: %s defines no roles", path)
	}

	roles := make(map[string]Role, len(pf.Roles))
	for name, rf := range pf.Roles {
		if _, ok := clearanceOrder[rf.Clearance]; !ok {
			return nil, fmt.Errorf("claims: role %q has clearance %q, want one of PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED", name, rf.Clearance)
		}
		roles[name] = Role{
			Clearance:    rf.Clearance,
			Compartments: dedupeSorted(rf.Compartments),
			Verbs:        dedupeSorted(rf.Verbs),
			ToolSets:     dedupeSorted(rf.ToolSets),
		}
	}

	segments := make(map[string]policySegment, len(pf.Segments))
	for name, sf := range pf.Segments {
		if !validSegmentKinds[sf.Kind] {
			return nil, fmt.Errorf("claims: segment %q has kind %q, want \"customer\" or \"employee\"", name, sf.Kind)
		}
		if len(sf.Roles) == 0 {
			return nil, fmt.Errorf("claims: segment %q names no roles; it would grant nothing", name)
		}
		for _, roleName := range sf.Roles {
			if _, ok := roles[roleName]; !ok {
				return nil, fmt.Errorf("claims: segment %q names undeclared role %q", name, roleName)
			}
		}
		segments[name] = policySegment{kind: sf.Kind, roles: dedupeSorted(sf.Roles)}
	}

	agents := make(map[string]policyAgent, len(pf.Agents))
	for name, af := range pf.Agents {
		if len(af.Roles) == 0 {
			return nil, fmt.Errorf("claims: agent %q names no roles; it would have no authority to assert", name)
		}
		for _, roleName := range af.Roles {
			if _, ok := roles[roleName]; !ok {
				return nil, fmt.Errorf("claims: agent %q names undeclared role %q", name, roleName)
			}
		}
		agents[name] = policyAgent{roles: dedupeSorted(af.Roles)}
	}

	return &Policy{roles: roles, segments: segments, agents: agents}, nil
}

// Segments returns the declared segment names, sorted. This is a closed,
// declared set on purpose: it bounds a later task's work, letting the
// exchange ask the authorization store N membership questions with N small
// and known, rather than an open-ended "list everything this principal
// belongs to".
func (p *Policy) Segments() []string {
	names := make([]string, 0, len(p.segments))
	for name := range p.segments {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// ForSegments resolves the claim for a USER principal — customer or
// employee — known (by the caller, via the authorization store) to belong
// to the given segments. kind is the segment-kind vocabulary the policy
// file declares ("customer" or "employee"), used to filter membership, not
// the claim's own Kind (always "USER" here).
//
// Roles UNION: holding roles granted by more than one segment produces the
// HIGHEST clearance among them and the UNION of compartments and verbs.
// Delegation intersects — that happens in the verifying daemon, never here.
//
// A segment declared with a different kind than the one asserted is
// ignored, not unioned in: membership comes from a tuple store this service
// does not own, and a customer must never inherit an employee segment's
// roles because of a stale or mismatched tuple. If, after filtering,
// nothing is left to grant, this refuses — a principal with no claims to
// mint should fail loudly at exchange, not mint an empty, useless token.
func (p *Policy) ForSegments(kind string, segmentNames []string) (*GarmClaim, error) {
	roleSet := make(map[string]struct{})
	for _, name := range segmentNames {
		seg, ok := p.segments[name]
		if !ok {
			return nil, fmt.Errorf("claims: unknown segment %q", name)
		}
		if seg.kind != kind {
			// Membership comes from a store this service does not own. A
			// principal asserting a kind that doesn't match a segment it
			// supposedly belongs to is either a bug in that store or an
			// attempt to widen authority; dropping it is correct, but it
			// must not vanish silently, or nobody ever learns it happened.
			slog.Default().Warn("claims: dropping segment of mismatched kind",
				"segment", name, "kind_expected", kind, "kind_found", seg.kind)
			continue
		}
		for _, r := range seg.roles {
			roleSet[r] = struct{}{}
		}
	}
	if len(roleSet) == 0 {
		return nil, fmt.Errorf("claims: principal (kind %q, segments %v) resolves to no roles; there are no claims to mint", kind, segmentNames)
	}
	claim := p.unionOf(roleSet)
	claim.Kind = "USER"
	return &claim, nil
}

// ForAgent resolves the claim for an agent's own declared authority — the
// act-level ceiling a delegation chain folds against. An agent absent from
// the policy has no authority to assert, so this refuses rather than mint
// an empty act level.
func (p *Policy) ForAgent(name string) (*GarmClaim, error) {
	a, ok := p.agents[name]
	if !ok {
		return nil, fmt.Errorf("claims: agent %q is not declared in the policy", name)
	}
	roleSet := make(map[string]struct{}, len(a.roles))
	for _, r := range a.roles {
		roleSet[r] = struct{}{}
	}
	if len(roleSet) == 0 {
		// LoadPolicy already refuses an agent declared with no roles, so
		// this should be unreachable. It is here anyway, matching
		// ForSegments's equivalent guard, as a belt-and-braces refusal
		// against ever minting a claim with an empty, invalid clearance.
		return nil, fmt.Errorf("claims: agent %q resolves to no roles; there is no authority to mint", name)
	}
	claim := p.unionOf(roleSet)
	claim.Kind = "AGENT"
	return &claim, nil
}

// unionOf folds a set of role names into a single claim: the highest
// clearance among them, and the union of compartments, verbs and tool
// sets. Every output slice is sorted — map iteration order must never leak
// into a signed credential, or the same inputs could mint two different
// tokens.
func (p *Policy) unionOf(roleNames map[string]struct{}) GarmClaim {
	compartments := make(map[string]struct{})
	verbs := make(map[string]struct{})
	toolSets := make(map[string]struct{})
	rank := -1
	var clearance string
	for name := range roleNames {
		r := p.roles[name]
		if cr := clearanceOrder[r.Clearance]; cr > rank {
			rank = cr
			clearance = r.Clearance
		}
		for _, c := range r.Compartments {
			compartments[c] = struct{}{}
		}
		for _, v := range r.Verbs {
			verbs[v] = struct{}{}
		}
		for _, ts := range r.ToolSets {
			toolSets[ts] = struct{}{}
		}
	}
	return GarmClaim{
		Clearance:    clearance,
		Compartments: sortedKeys(compartments),
		Verbs:        sortedKeys(verbs),
		ToolSets:     sortedKeys(toolSets),
	}
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func dedupeSorted(vals []string) []string {
	if len(vals) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		set[v] = struct{}{}
	}
	return sortedKeys(set)
}
