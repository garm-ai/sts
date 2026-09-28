//go:build !openfga

// This file builds the Authorizer for the untagged sts binary: the flat,
// file-backed StaticAuthorizer, meant for development and CI. See
// authz_openfga.go for the -tags openfga build's counterpart — exactly one
// of these two files is ever compiled into a given binary.
package main

import "github.com/garm-ai/sts"

// newAuthorizer builds this build's Authorizer from cfg. The untagged build
// always uses the static, file-backed implementation, loaded from
// cfg.StaticAuthzPath.
func newAuthorizer(cfg *sts.Config) (sts.Authorizer, error) {
	return sts.LoadStaticAuthorizer(cfg.StaticAuthzPath)
}
