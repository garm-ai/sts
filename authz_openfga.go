//go:build openfga

// This file builds only under -tags openfga: the OpenFGA Go SDK is a real
// production dependency, and a codebase that pulls it in unconditionally
// would force every consumer of this package to vendor an authorization
// store's client just to build. The untagged build keeps using the
// file-backed StaticAuthorizer (authz_static.go); this is the production
// implementation of the same Authorizer interface (authz.go).
package sts

import (
	"context"
	"fmt"

	fgaClient "github.com/openfga/go-sdk/client"
)

// openFGAAuthorizer answers the three Authorizer questions (authz.go)
// against a live OpenFGA store, via one Check call per method. It is
// deliberately thin — no caching, no retries — and, per the Authorizer
// contract, never lets a store failure read as permission: any error from
// Check is returned as an error alongside false, never alongside true, and
// an unreachable store denies rather than approving by default.
type openFGAAuthorizer struct {
	client *fgaClient.OpenFgaClient
}

// NewOpenFGAAuthorizer builds an Authorizer backed by the OpenFGA store at
// apiURL/storeID. authorizationModelID pins every Check to one model
// version — leave it empty only for local development; production should
// always pin, since an unpinned store silently reinterprets every check the
// moment a new model version is written.
//
// This does not load deploy/model.fga or deploy/tuples.openfga.yaml — those
// are deployment artifacts, written into the store out of band with the fga
// CLI (see the comments atop each file). This constructor only opens a
// client against a store that is already provisioned.
func NewOpenFGAAuthorizer(apiURL, storeID, authorizationModelID string) (Authorizer, error) {
	c, err := fgaClient.NewSdkClient(&fgaClient.ClientConfiguration{
		ApiUrl:               apiURL,
		StoreId:              storeID,
		AuthorizationModelId: authorizationModelID,
	})
	if err != nil {
		return nil, fmt.Errorf("sts: openfga: configure client: %w", err)
	}
	return &openFGAAuthorizer{client: c}, nil
}

// check runs a single OpenFGA Check and folds every failure mode into the
// Authorizer contract's shape: (false, nil) for an ordinary denial, (false,
// non-nil) for a genuine fault. It never returns (true, non-nil) — a
// response whose Allowed came back unset behaves as false, the same as an
// explicit denial, rather than as a fault.
func (a *openFGAAuthorizer) check(ctx context.Context, user, relation, object string) (bool, error) {
	resp, err := a.client.Check(ctx).Body(fgaClient.ClientCheckRequest{
		User:     user,
		Relation: relation,
		Object:   object,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("sts: openfga check user=%s relation=%s object=%s: %w", user, relation, object, err)
	}
	return resp.GetAllowed(), nil
}

// CanInvoke checks the store's can_invoke relation on the agent. In
// deploy/model.fga, can_invoke is DERIVED — an agent is can_invoke by
// anyone who is a member of one of its invokable_by segments — so this one
// Check call resolves the same real-world fact the file-backed
// StaticAuthorizer stores as an already-flattened tuple.
func (a *openFGAAuthorizer) CanInvoke(ctx context.Context, principal, agent string) (bool, error) {
	return a.check(ctx, principal, "can_invoke", agent)
}

// HandledBy checks the store's handled_by relation on the customer.
func (a *openFGAAuthorizer) HandledBy(ctx context.Context, employee, customer string) (bool, error) {
	return a.check(ctx, employee, "handled_by", customer)
}

// InSegment checks the store's member relation on segment:<segment>.
// Segment names cross the Authorizer interface bare — they are policy
// labels, not identities (authz.go) — so this is the one place in this
// implementation that adds the "segment:" type prefix OpenFGA's object
// identifiers require. Getting this wrong produces a lookup against an
// object nothing is ever written against, which answers false exactly like
// a genuine denial — so this prefix is the load-bearing line in this
// method.
func (a *openFGAAuthorizer) InSegment(ctx context.Context, principal, segment string) (bool, error) {
	return a.check(ctx, principal, "member", "segment:"+segment)
}
