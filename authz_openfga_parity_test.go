//go:build openfga

// This file runs ONLY under -tags openfga, and never in the normal suite:
// it needs a live OpenFGA server, and a test that quietly reports ok when
// its subject is absent is worse than no test. Choosing -tags openfga is
// choosing to need the store, so TestAuthorizerBackendParity fails outright
// — never t.Skip — when -openfga-url is not given.
package sts_test

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/garm-ai/sts"
	fgaClient "github.com/openfga/go-sdk/client"
	"github.com/openfga/language/pkg/go/transformer"
	"gopkg.in/yaml.v3"
)

var openfgaURL = flag.String("openfga-url", "", "base URL of a running OpenFGA server "+
	"(required under -tags openfga; e.g. http://localhost:8080)")

// openfgaTupleRow is the on-disk shape of one entry in
// deploy/tuples.openfga.yaml.
type openfgaTupleRow struct {
	User     string `yaml:"user"`
	Relation string `yaml:"relation"`
	Object   string `yaml:"object"`
}

// provisionOpenFGAStore creates a fresh OpenFGA store, writes
// deploy/model.fga as its authorization model and deploy/tuples.openfga.yaml
// as its tuples, and returns an admin client together with the new store
// and model IDs. These are the two deployment artifacts the production
// OpenFGA-backed Authorizer is meant to run against — see their own file
// headers for the `fga` CLI commands that do the same thing outside a test.
func provisionOpenFGAStore(t *testing.T, apiURL string) (storeID, modelID string) {
	t.Helper()
	ctx := context.Background()

	admin, err := fgaClient.NewSdkClient(&fgaClient.ClientConfiguration{ApiUrl: apiURL})
	if err != nil {
		t.Fatalf("configure openfga admin client for %s: %v", apiURL, err)
	}

	storeResp, err := admin.CreateStore(ctx).
		Body(fgaClient.ClientCreateStoreRequest{Name: "sts-authz-parity-test"}).
		Execute()
	if err != nil {
		t.Fatalf("create openfga store at %s: %v — is a server actually listening there?", apiURL, err)
	}
	storeID = storeResp.Id
	t.Cleanup(func() {
		_, _ = admin.DeleteStore(ctx).Options(fgaClient.ClientDeleteStoreOptions{StoreId: &storeID}).Execute()
	})

	dsl, err := os.ReadFile("deploy/model.fga")
	if err != nil {
		t.Fatalf("read deploy/model.fga: %v", err)
	}
	modelJSON, err := transformer.TransformDSLToJSON(string(dsl))
	if err != nil {
		t.Fatalf("transform deploy/model.fga from DSL to JSON: %v", err)
	}
	var modelReq fgaClient.ClientWriteAuthorizationModelRequest
	if err := json.Unmarshal([]byte(modelJSON), &modelReq); err != nil {
		t.Fatalf("decode transformed deploy/model.fga: %v", err)
	}
	modelResp, err := admin.WriteAuthorizationModel(ctx).
		Body(modelReq).
		Options(fgaClient.ClientWriteAuthorizationModelOptions{StoreId: &storeID}).
		Execute()
	if err != nil {
		t.Fatalf("write deploy/model.fga to the openfga store: %v", err)
	}
	modelID = modelResp.AuthorizationModelId

	tuplesYAML, err := os.ReadFile("deploy/tuples.openfga.yaml")
	if err != nil {
		t.Fatalf("read deploy/tuples.openfga.yaml: %v", err)
	}
	var rows []openfgaTupleRow
	if err := yaml.Unmarshal(tuplesYAML, &rows); err != nil {
		t.Fatalf("parse deploy/tuples.openfga.yaml: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("deploy/tuples.openfga.yaml decoded to zero tuples; the parity fixtures are missing")
	}
	writes := make([]fgaClient.ClientTupleKey, len(rows))
	for i, r := range rows {
		writes[i] = fgaClient.ClientTupleKey{User: r.User, Relation: r.Relation, Object: r.Object}
	}
	_, err = admin.Write(ctx).
		Body(fgaClient.ClientWriteRequest{Writes: writes}).
		Options(fgaClient.ClientWriteOptions{StoreId: &storeID, AuthorizationModelId: &modelID}).
		Execute()
	if err != nil {
		t.Fatalf("write deploy/tuples.openfga.yaml to the openfga store: %v", err)
	}

	return storeID, modelID
}

// parityCase is one real-world scenario, expressed once and checked against
// both Authorizer implementations. method names one of Authorizer's three
// methods; subject/object are that method's two arguments in order.
type parityCase struct {
	name     string
	method   string // "CanInvoke" | "HandledBy" | "InSegment"
	subject  string
	object   string
	expected bool
}

// parityScenarios encodes real-world facts that BOTH deploy/tuples.yaml
// (the static backend) and deploy/model.fga + deploy/tuples.openfga.yaml
// (the OpenFGA backend) must agree on. It covers all three methods, an
// expected-false per method, and the derived case: customer:C can invoke
// agent:order-assistant only because it is a member of segment
// retail-vip — a flat, pre-resolved tuple on the static side, but a
// two-hop derivation (member -> invokable_by -> can_invoke) on the OpenFGA
// side. That difference in modelling the same fact is exactly what this
// test exists to keep from drifting apart.
var parityScenarios = []parityCase{
	{
		name:     "customer can invoke the agent they're entitled to only via segment membership",
		method:   "CanInvoke",
		subject:  "customer:C",
		object:   "agent:order-assistant",
		expected: true,
	},
	{
		name:     "an employee with no entitlement cannot invoke the agent",
		method:   "CanInvoke",
		subject:  "employee:jdoe",
		object:   "agent:order-assistant",
		expected: false,
	},
	{
		name:     "the assigned employee handles their customer",
		method:   "HandledBy",
		subject:  "employee:jdoe",
		object:   "customer:C",
		expected: true,
	},
	{
		name:     "an unassigned employee does not handle the customer",
		method:   "HandledBy",
		subject:  "employee:ghost",
		object:   "customer:C",
		expected: false,
	},
	{
		name:     "the customer is a member of their entitled segment",
		method:   "InSegment",
		subject:  "customer:C",
		object:   "retail-vip",
		expected: true,
	},
	{
		name:     "the customer is not a member of an unrelated segment",
		method:   "InSegment",
		subject:  "customer:C",
		object:   "sme-basic",
		expected: false,
	},
	{
		name:     "a completely unknown principal is in no segment",
		method:   "InSegment",
		subject:  "customer:ghost",
		object:   "retail-vip",
		expected: false,
	},
}

// ask dispatches one parityCase to whichever of the three Authorizer methods
// it names, so parityScenarios can be expressed as data instead of as
// hand-written calls for every case.
func ask(t *testing.T, authz sts.Authorizer, c parityCase) (bool, error) {
	t.Helper()
	ctx := context.Background()
	switch c.method {
	case "CanInvoke":
		return authz.CanInvoke(ctx, c.subject, c.object)
	case "HandledBy":
		return authz.HandledBy(ctx, c.subject, c.object)
	case "InSegment":
		return authz.InSegment(ctx, c.subject, c.object)
	default:
		t.Fatalf("parityCase %q: unrecognized method %q", c.name, c.method)
		return false, nil
	}
}

// TestAuthorizerBackendParity is the point of this file: it proves
// deploy/tuples.yaml and deploy/model.fga + deploy/tuples.openfga.yaml
// encode the same real-world facts, by running the same table of scenarios
// against both backends and asserting each answers exactly as
// parityScenarios expects. Divergence between the two files — the risk this
// test exists to catch — fails here instead of surfacing later as a
// production authorization decision that silently disagrees with dev/CI.
func TestAuthorizerBackendParity(t *testing.T) {
	// Not t.Skip. -tags openfga is opt-in specifically because it needs a
	// real store; a run with nothing to check against must not report ok.
	if *openfgaURL == "" {
		t.Fatal("-openfga-url is required under -tags openfga; " +
			"a parity run with no OpenFGA server to check must not report ok")
	}

	storeID, modelID := provisionOpenFGAStore(t, *openfgaURL)

	fgaAuthz, err := sts.NewOpenFGAAuthorizer(*openfgaURL, storeID, modelID)
	if err != nil {
		t.Fatalf("NewOpenFGAAuthorizer: %v", err)
	}

	staticAuthz, err := sts.LoadStaticAuthorizer("deploy/tuples.yaml")
	if err != nil {
		t.Fatalf("LoadStaticAuthorizer(deploy/tuples.yaml): %v", err)
	}

	for _, c := range parityScenarios {
		t.Run(c.name, func(t *testing.T) {
			staticOK, err := ask(t, staticAuthz, c)
			if err != nil {
				t.Fatalf("static: %s(%s, %s) returned an error: %v", c.method, c.subject, c.object, err)
			}
			if staticOK != c.expected {
				t.Fatalf("static: %s(%s, %s) = %v; want %v", c.method, c.subject, c.object, staticOK, c.expected)
			}

			fgaOK, err := ask(t, fgaAuthz, c)
			if err != nil {
				t.Fatalf("openfga: %s(%s, %s) returned an error: %v", c.method, c.subject, c.object, err)
			}
			if fgaOK != c.expected {
				t.Fatalf("openfga: %s(%s, %s) = %v; want %v", c.method, c.subject, c.object, fgaOK, c.expected)
			}

			if staticOK != fgaOK {
				t.Fatalf("backend parity broken: static=%v openfga=%v for %s(%s, %s)",
					staticOK, fgaOK, c.method, c.subject, c.object)
			}
		})
	}
}
