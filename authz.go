package sts

import "context"

// Authorizer answers the three relationship questions the exchange handler
// needs, per spec §3.1. Every method answers a yes/no relationship, never a
// broader query: the caller names the exact pair it wants resolved.
//
// Absence of a written relation is a denial, never an error. Every
// implementation MUST return false, nil for a principal, agent, employee,
// customer or segment it has never heard of — a missing tuple is an
// ordinary, expected state, not a fault. Errors are reserved for genuine
// faults: a malformed policy at load time, or a real backend failure in an
// implementation that talks to a remote store.
type Authorizer interface {
	// CanInvoke reports whether principal may reach agent at all.
	CanInvoke(ctx context.Context, principal, agent string) (bool, error)

	// HandledBy reports whether employee is the one assigned to customer.
	// It is asked only when an employee is acting on a customer's behalf —
	// it is the line between an employee helping a customer and an
	// employee impersonating one.
	HandledBy(ctx context.Context, employee, customer string) (bool, error)

	// InSegment reports whether principal belongs to segment. The claims
	// policy (Policy.Segments) exposes the closed, declared set of segment
	// names, so a caller asks this once per declared segment rather than
	// enumerating an open-ended list of memberships.
	InSegment(ctx context.Context, principal, segment string) (bool, error)
}
