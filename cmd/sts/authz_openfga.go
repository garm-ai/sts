//go:build openfga

// This file builds the Authorizer for the -tags openfga sts binary: the
// production, OpenFGA-backed implementation. See authz_static.go for the
// untagged build's counterpart — exactly one of these two files is ever
// compiled into a given binary.
package main

import (
	"fmt"

	"github.com/garm-ai/sts"
)

// newAuthorizer builds this build's Authorizer from cfg. The -tags openfga
// build always uses the OpenFGA-backed implementation, and — unlike the
// untagged build — requires the store connection details cfg.OpenFGA
// carries: an untagged deployment never has to set these, since it cannot
// use them, but this build cannot start without them. Each missing
// required field is its own startup failure naming that field, matching
// every other config error in this service (see config.go).
func newAuthorizer(cfg *sts.Config) (sts.Authorizer, error) {
	if cfg.OpenFGA.ApiURL == "" {
		return nil, fmt.Errorf("sts: config: authz.openfga.apiUrl is required for an -tags openfga build")
	}
	if cfg.OpenFGA.StoreID == "" {
		return nil, fmt.Errorf("sts: config: authz.openfga.storeId is required for an -tags openfga build")
	}
	return sts.NewOpenFGAAuthorizer(cfg.OpenFGA.ApiURL, cfg.OpenFGA.StoreID, cfg.OpenFGA.AuthorizationModelID)
}
