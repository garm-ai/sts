package sts

import "context"

// Authorizer answers the four relationship questions the exchange handler
// needs, per spec §3.1. Every method answers a yes/no relationship, never a
// broader query: the caller names the exact pair it wants resolved.
//
// Absence of a written relation is a denial, never an error. Every
// implementation MUST return false, nil for a principal, agent, employee,
// customer or segment it has never heard of — a missing tuple is an
// ordinary, expected state, not a fault. Errors are reserved for genuine
// faults: a malformed policy at load time, or a real backend failure in an
// implementation that talks to a remote store.
//
// Identity convention: every principal, agent, employee and customer string
// crossing this interface is TYPE-PREFIXED — "customer:C-8123",
// "employee:jdoe", "agent:order-assistant" — matching the subject forms the
// minted tokens actually carry. This is load-bearing: every implementation
// (this package's file-backed one, and the OpenFGA-backed one that follows
// it) does exact-string comparison with no normalization step, so a caller
// that builds an unprefixed customer string for one call and a prefixed one
// for another silently never matches — and the miss reads back as an
// ordinary, correct-looking denial. Callers MUST derive these identity
// strings the same way for every Authorizer call. Segment names are the one
// exception: they are policy labels, not identities — they stay bare and
// must match the claims policy's declared Segments() names exactly.
type Authorizer interface {
	// CanInvoke reports whether principal may reach agent at all.
	CanInvoke(ctx context.Context, principal, agent string) (bool, error)

	// CanRun reports whether runner may EXECUTE agent — a different
	// question from CanInvoke, which asks whether a principal may reach an
	// agent at all. The governed door (program plan §3.9) asks both: this
	// one of the process that would run the agent, and CanInvoke of the
	// human whose authority it would exercise. Collapsing them would let
	// any runner execute any agent some customer happened to be entitled
	// to, which is the opposite of what a runner identity is for.
	//
	// runner is type-prefixed as "runner:<id>", where <id> is the client id
	// the runner AUTHENTICATED as — never a value a caller supplies.
	CanRun(ctx context.Context, runner, agent string) (bool, error)

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
