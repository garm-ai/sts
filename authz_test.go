package sts_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/garm-ai/sts"
)

// authzFixture is deliberately written so every subject that appears at all
// appears in more than one relation but not in every combination — that lets
// TestStaticAuthorizerDeniesWhatIsNotWritten exercise "subject present, but
// this particular pairing absent" as well as "subject absent entirely",
// without inventing throwaway names for each case.
//
// Every principal/agent/employee/customer string is type-prefixed
// ("customer:C1", not bare "C1"), per the Authorizer identity convention —
// segment names ("retail-vip") are the one exception, since they are policy
// labels, not identities.
const authzFixture = `
can_invoke:
  - principal: customer:C1
    agent: agent:order-assistant

handled_by:
  - employee: employee:jdoe
    customer: customer:C1

in_segment:
  - principal: customer:C1
    segment: retail-vip
  - principal: customer:C2
    segment: sme-basic

can_run:
  - runner: runner:agentd
    agent: agent:order-assistant
`

// writeAuthzFile writes content to a temp file and returns its path. It
// does not load it — callers that need a loaded Authorizer call
// sts.LoadStaticAuthorizer themselves, since some tests (the malformed-file
// one) need to inspect the error LoadStaticAuthorizer itself returns.
func writeAuthzFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tuples.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
	return path
}

func TestStaticAuthorizerAnswersTheThreeQuestions(t *testing.T) {
	authz, err := sts.LoadStaticAuthorizer(writeAuthzFile(t, authzFixture))
	if err != nil {
		t.Fatalf("LoadStaticAuthorizer: %v", err)
	}
	ctx := context.Background()

	if ok, err := authz.CanInvoke(ctx, "customer:C1", "agent:order-assistant"); err != nil || !ok {
		t.Fatalf("CanInvoke(written tuple) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := authz.HandledBy(ctx, "employee:jdoe", "customer:C1"); err != nil || !ok {
		t.Fatalf("HandledBy(written tuple) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := authz.InSegment(ctx, "customer:C1", "retail-vip"); err != nil || !ok {
		t.Fatalf("InSegment(written tuple) = %v, %v; want true, nil", ok, err)
	}

	// Argument order must matter: HandledBy(employee, customer) draws the
	// line between an employee helping a customer and impersonating one, so
	// swapping the two arguments must not also read as authorized.
	if ok, err := authz.HandledBy(ctx, "customer:C1", "employee:jdoe"); err != nil || ok {
		t.Fatalf("HandledBy(customer, employee) swapped = %v, %v; want false, nil", ok, err)
	}
}

// TestStaticAuthorizerUsesTheSameIdentityStringAcrossMethods pins the
// Authorizer identity convention (sts/authz.go): every principal/agent/
// employee/customer string is type-prefixed, and a caller that derives an
// identity once must be able to reuse that exact string across every
// method. The shipped deploy/tuples.yaml originally violated this
// silently — can_invoke and in_segment wrote "customer:C" while handled_by
// wrote bare "C" for what was evidently the same customer — and every
// lookup being an exact-string map index meant the mismatch would never
// surface as anything louder than an ordinary-looking denial. This test
// takes ONE canonical customer identity and asserts it matches across all
// three methods, so that kind of drift fails a test instead of hiding.
func TestStaticAuthorizerUsesTheSameIdentityStringAcrossMethods(t *testing.T) {
	const customer = "customer:C1"

	authz, err := sts.LoadStaticAuthorizer(writeAuthzFile(t, authzFixture))
	if err != nil {
		t.Fatalf("LoadStaticAuthorizer: %v", err)
	}
	ctx := context.Background()

	if ok, err := authz.CanInvoke(ctx, customer, "agent:order-assistant"); err != nil || !ok {
		t.Fatalf("CanInvoke(%s, agent:order-assistant) = %v, %v; want true, nil", customer, ok, err)
	}
	if ok, err := authz.HandledBy(ctx, "employee:jdoe", customer); err != nil || !ok {
		t.Fatalf("HandledBy(employee:jdoe, %s) = %v, %v; want true, nil — the same customer identity string used with CanInvoke must also match HandledBy", customer, ok, err)
	}
	if ok, err := authz.InSegment(ctx, customer, "retail-vip"); err != nil || !ok {
		t.Fatalf("InSegment(%s, retail-vip) = %v, %v; want true, nil — the same customer identity string used with CanInvoke must also match InSegment", customer, ok, err)
	}
}

func TestStaticAuthorizerDeniesWhatIsNotWritten(t *testing.T) {
	// Every unwritten relation must answer false with no error. This is the
	// property that keeps a missing tuple an ordinary denial instead of
	// turning it into a 500 for a caller who names a principal, agent,
	// employee, customer or segment the store has simply never heard of.
	authz, err := sts.LoadStaticAuthorizer(writeAuthzFile(t, authzFixture))
	if err != nil {
		t.Fatalf("LoadStaticAuthorizer: %v", err)
	}
	ctx := context.Background()

	cases := []struct {
		name string
		call func() (bool, error)
	}{
		// Subject not mentioned anywhere in the file at all.
		{"CanInvoke: unknown principal", func() (bool, error) { return authz.CanInvoke(ctx, "customer:ghost", "agent:order-assistant") }},
		{"CanInvoke: unknown agent", func() (bool, error) { return authz.CanInvoke(ctx, "customer:C1", "agent:ghost") }},
		{"HandledBy: unknown employee", func() (bool, error) { return authz.HandledBy(ctx, "employee:ghost", "customer:C1") }},
		{"HandledBy: unknown customer", func() (bool, error) { return authz.HandledBy(ctx, "employee:jdoe", "customer:ghost") }},
		{"InSegment: unknown principal", func() (bool, error) { return authz.InSegment(ctx, "customer:ghost", "retail-vip") }},
		{"InSegment: unknown segment", func() (bool, error) { return authz.InSegment(ctx, "customer:C1", "ghost-segment") }},

		// Both sides of the pair are known subjects from elsewhere in the
		// file, but this exact pairing was never written.
		{"CanInvoke: principal and agent both known, pairing absent", func() (bool, error) {
			return authz.CanInvoke(ctx, "customer:C2", "agent:order-assistant") // C2 only has a segment tuple
		}},
		{"HandledBy: employee and customer both known, pairing absent", func() (bool, error) {
			return authz.HandledBy(ctx, "employee:jdoe", "customer:C2") // jdoe only handles C1
		}},
		{"InSegment: principal and segment both known, pairing absent", func() (bool, error) {
			return authz.InSegment(ctx, "customer:C1", "sme-basic") // C1 is retail-vip, not sme-basic
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := c.call()
			if err != nil {
				t.Fatalf("got error %v; an unwritten relation must be a denial, never an error", err)
			}
			if ok {
				t.Fatalf("got true; want false for a relation that was never written")
			}
		})
	}
}

func TestLoadStaticAuthorizerRejectsAMalformedFile(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"invalid YAML syntax", "can_invoke: [this is not closed\n"},
		{"wrong shape for a relation", "can_invoke: \"not a list of tuples\"\n"},
		{"unknown top-level field", "cannot_invoke:\n  - principal: customer:C1\n    agent: agent:order-assistant\n"},

		// A tuple entry missing a required field decodes cleanly (the field
		// zero-values to "") unless LoadStaticAuthorizer explicitly rejects
		// it. Left unchecked, such a tuple loads silently and matches
		// nothing — the same silent-miss failure shape as an identity
		// convention mismatch, just caused by a fat-fingered edit instead.
		// One case per relation per missing field, so all three relations
		// and both of each relation's required fields are covered.
		{"can_invoke missing principal", "can_invoke:\n  - agent: agent:order-assistant\n"},
		{"can_invoke missing agent", "can_invoke:\n  - principal: customer:C1\n"},
		{"handled_by missing employee", "handled_by:\n  - customer: customer:C1\n"},
		{"handled_by missing customer", "handled_by:\n  - employee: employee:jdoe\n"},
		{"in_segment missing principal", "in_segment:\n  - segment: retail-vip\n"},
		{"in_segment missing segment", "in_segment:\n  - principal: customer:C1\n"},
		{"can_run missing runner", "can_run:\n  - agent: agent:order-assistant\n"},
		{"can_run missing agent", "can_run:\n  - runner: runner:agentd\n"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := sts.LoadStaticAuthorizer(writeAuthzFile(t, c.content))
			if err == nil {
				t.Fatalf("LoadStaticAuthorizer(%q) = nil error; want an error for a malformed file", c.name)
			}
		})
	}

	t.Run("file does not exist", func(t *testing.T) {
		_, err := sts.LoadStaticAuthorizer(filepath.Join(t.TempDir(), "missing.yaml"))
		if err == nil {
			t.Fatalf("LoadStaticAuthorizer(missing file) = nil error; want an error")
		}
	})
}

// TestDeployTuplesYAMLExampleLoadsAndAnswersItsDocumentedFacts guards the
// shipped deploy/tuples.yaml against silently drifting from what its own
// comments claim — a renamed field or a hand-edit that no longer matches
// the documented tuples fails here rather than being discovered later, by a
// developer whose local dev/test setup quietly stops authorizing what the
// file says it authorizes.
func TestDeployTuplesYAMLExampleLoadsAndAnswersItsDocumentedFacts(t *testing.T) {
	authz, err := sts.LoadStaticAuthorizer("deploy/tuples.yaml")
	if err != nil {
		t.Fatalf("deploy/tuples.yaml failed to load: %v", err)
	}
	ctx := context.Background()

	if ok, err := authz.CanInvoke(ctx, "customer:C", "agent:order-assistant"); err != nil || !ok {
		t.Fatalf("CanInvoke(customer:C, agent:order-assistant) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := authz.HandledBy(ctx, "employee:jdoe", "customer:C"); err != nil || !ok {
		t.Fatalf("HandledBy(employee:jdoe, customer:C) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := authz.InSegment(ctx, "customer:C", "retail-vip"); err != nil || !ok {
		t.Fatalf("InSegment(customer:C, retail-vip) = %v, %v; want true, nil", ok, err)
	}

	// The delegating path — an employee acting for a customer they handle —
	// needs more than the handled_by tuple above. exchange.go asks
	// can_invoke twice there (once for the customer, once for the
	// employee), and resolves the employee's own claim from their own
	// segment. Both were missing, which made the shipped handled_by tuple
	// unreachable: the example could not serve the requested_subject path
	// the README describes, and the operator saw only an opaque denial.
	// These two assertions pin the example to serving every path the README
	// documents, not only the direct one.
	if ok, err := authz.CanInvoke(ctx, "employee:jdoe", "agent:order-assistant"); err != nil || !ok {
		t.Fatalf("CanInvoke(employee:jdoe, agent:order-assistant) = %v, %v; want true, nil — "+
			"without it the shipped handled_by tuple can never be exercised", ok, err)
	}
	if ok, err := authz.InSegment(ctx, "employee:jdoe", "support-staff"); err != nil || !ok {
		t.Fatalf("InSegment(employee:jdoe, support-staff) = %v, %v; want true, nil — "+
			"a delegating employee in no segment resolves to no roles and is denied", ok, err)
	}

	// The governed door's tuples. Both are load-bearing and neither is
	// decorative: agentd is what the shipped deploy/config.yaml registers as
	// a client, and conformance-client is what garmd's conformance job
	// authenticates as — an exchange-2 case with no can_run tuple for it
	// fails as an ordinary denial with nothing in the output saying why.
	if ok, err := authz.CanRun(ctx, "runner:agentd", "agent:order-assistant"); err != nil || !ok {
		t.Fatalf("CanRun(runner:agentd, agent:order-assistant) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := authz.CanRun(ctx, "runner:conformance-client", "agent:order-assistant"); err != nil || !ok {
		t.Fatalf("CanRun(runner:conformance-client, agent:order-assistant) = %v, %v; want true, nil — "+
			"garmd's identity-conformance job authenticates as this client, and its exchange-2 case needs the tuple", ok, err)
	}
}

// TestStaticAuthorizerAnswersCanRun pins the fourth relation: may THIS
// runner execute THIS agent at all (spec §3.3, program plan §3.9). It is a
// different question from can_invoke — that one asks whether a human may
// reach an agent, this one whether a process may run it — and collapsing
// them would let any runner execute any agent a single customer happened to
// be entitled to.
func TestStaticAuthorizerAnswersCanRun(t *testing.T) {
	authz, err := sts.LoadStaticAuthorizer(writeAuthzFile(t, authzFixture))
	if err != nil {
		t.Fatalf("LoadStaticAuthorizer: %v", err)
	}
	ctx := context.Background()

	if ok, err := authz.CanRun(ctx, "runner:agentd", "agent:order-assistant"); err != nil || !ok {
		t.Fatalf("CanRun(written tuple) = %v, %v; want true, nil", ok, err)
	}

	// Argument order must matter for the same reason it does on HandledBy:
	// a swapped pair that also answered true would mean the relation is
	// really just "these two are related somehow".
	if ok, err := authz.CanRun(ctx, "agent:order-assistant", "runner:agentd"); err != nil || ok {
		t.Fatalf("CanRun(agent, runner) swapped = %v, %v; want false, nil", ok, err)
	}
}

// TestStaticAuthorizerDeniesCanRunThatIsNotWritten keeps a missing can_run
// tuple an ordinary denial rather than a 500 — the same property the other
// three relations already hold (authz.go's Authorizer doc comment).
func TestStaticAuthorizerDeniesCanRunThatIsNotWritten(t *testing.T) {
	authz, err := sts.LoadStaticAuthorizer(writeAuthzFile(t, authzFixture))
	if err != nil {
		t.Fatalf("LoadStaticAuthorizer: %v", err)
	}
	ctx := context.Background()

	cases := []struct {
		name          string
		runner, agent string
	}{
		{"unknown runner", "runner:ghost", "agent:order-assistant"},
		{"unknown agent", "runner:agentd", "agent:ghost"},
		{"both known, pairing absent", "runner:agentd", "agent:write-bot"},
		{"a can_invoke principal is not a runner", "customer:C1", "agent:order-assistant"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := authz.CanRun(ctx, c.runner, c.agent)
			if err != nil {
				t.Fatalf("got error %v; an unwritten relation must be a denial, never an error", err)
			}
			if ok {
				t.Fatalf("got true; want false for a relation that was never written")
			}
		})
	}
}
