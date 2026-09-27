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
const authzFixture = `
can_invoke:
  - principal: customer:C1
    agent: order-assistant

handled_by:
  - employee: jdoe
    customer: C1

in_segment:
  - principal: customer:C1
    segment: retail-vip
  - principal: customer:C2
    segment: sme-basic
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

	if ok, err := authz.CanInvoke(ctx, "customer:C1", "order-assistant"); err != nil || !ok {
		t.Fatalf("CanInvoke(written tuple) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := authz.HandledBy(ctx, "jdoe", "C1"); err != nil || !ok {
		t.Fatalf("HandledBy(written tuple) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := authz.InSegment(ctx, "customer:C1", "retail-vip"); err != nil || !ok {
		t.Fatalf("InSegment(written tuple) = %v, %v; want true, nil", ok, err)
	}

	// Argument order must matter: HandledBy(employee, customer) draws the
	// line between an employee helping a customer and impersonating one, so
	// swapping the two arguments must not also read as authorized.
	if ok, err := authz.HandledBy(ctx, "C1", "jdoe"); err != nil || ok {
		t.Fatalf("HandledBy(customer, employee) swapped = %v, %v; want false, nil", ok, err)
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
		{"CanInvoke: unknown principal", func() (bool, error) { return authz.CanInvoke(ctx, "ghost", "order-assistant") }},
		{"CanInvoke: unknown agent", func() (bool, error) { return authz.CanInvoke(ctx, "customer:C1", "ghost-agent") }},
		{"HandledBy: unknown employee", func() (bool, error) { return authz.HandledBy(ctx, "ghost", "C1") }},
		{"HandledBy: unknown customer", func() (bool, error) { return authz.HandledBy(ctx, "jdoe", "ghost-customer") }},
		{"InSegment: unknown principal", func() (bool, error) { return authz.InSegment(ctx, "ghost", "retail-vip") }},
		{"InSegment: unknown segment", func() (bool, error) { return authz.InSegment(ctx, "customer:C1", "ghost-segment") }},

		// Both sides of the pair are known subjects from elsewhere in the
		// file, but this exact pairing was never written.
		{"CanInvoke: principal and agent both known, pairing absent", func() (bool, error) {
			return authz.CanInvoke(ctx, "customer:C2", "order-assistant") // C2 only has a segment tuple
		}},
		{"HandledBy: employee and customer both known, pairing absent", func() (bool, error) {
			return authz.HandledBy(ctx, "jdoe", "C2") // jdoe only handles C1
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
		{"unknown top-level field", "cannot_invoke:\n  - principal: customer:C1\n    agent: order-assistant\n"},
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

	if ok, err := authz.CanInvoke(ctx, "customer:C", "order-assistant"); err != nil || !ok {
		t.Fatalf("CanInvoke(customer:C, order-assistant) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := authz.HandledBy(ctx, "jdoe", "C"); err != nil || !ok {
		t.Fatalf("HandledBy(jdoe, C) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := authz.InSegment(ctx, "customer:C", "retail-vip"); err != nil || !ok {
		t.Fatalf("InSegment(customer:C, retail-vip) = %v, %v; want true, nil", ok, err)
	}
}
