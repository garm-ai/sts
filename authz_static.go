package sts

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// canInvokeTuple, handledByTuple and inSegmentTuple are the on-disk shape of
// one written fact for each of the three relations the Authorizer interface
// asks about. Naming them after the methods they back keeps the file's
// shape obviously about the three questions being asserted.
type canInvokeTuple struct {
	Principal string `yaml:"principal"`
	Agent     string `yaml:"agent"`
}

type handledByTuple struct {
	Employee string `yaml:"employee"`
	Customer string `yaml:"customer"`
}

type inSegmentTuple struct {
	Principal string `yaml:"principal"`
	Segment   string `yaml:"segment"`
}

// staticFile is the on-disk shape of a whole static authorization file:
// exactly the three relations the Authorizer interface asks about, and
// nothing else.
type staticFile struct {
	CanInvoke []canInvokeTuple `yaml:"can_invoke"`
	HandledBy []handledByTuple `yaml:"handled_by"`
	InSegment []inSegmentTuple `yaml:"in_segment"`
}

// staticAuthorizer is a flat, file-backed Authorizer for development and
// tests. It does not resolve any graph — a segment granting an agent
// entitlement, for instance, is not followed transitively — lookups are
// plain set membership over the tuples read at load time. Any pair not
// present in the relevant set answers false, nil: this type never returns
// an error from a lookup, only from LoadStaticAuthorizer itself.
type staticAuthorizer struct {
	canInvoke map[[2]string]bool
	handledBy map[[2]string]bool
	inSegment map[[2]string]bool
}

// LoadStaticAuthorizer reads path as a static tuples YAML file (see
// deploy/tuples.yaml for the shape) and returns an Authorizer backed by its
// contents. It fails only when the file cannot be read or does not parse
// into the three-relation shape above — an empty or partially-populated
// file is perfectly valid, since every relation it omits is answered as a
// denial, not an error.
func LoadStaticAuthorizer(path string) (Authorizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sts: read static authorizer file %s: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var sf staticFile
	if err := dec.Decode(&sf); err != nil {
		return nil, fmt.Errorf("sts: parse static authorizer file %s: %w", path, err)
	}

	a := &staticAuthorizer{
		canInvoke: make(map[[2]string]bool, len(sf.CanInvoke)),
		handledBy: make(map[[2]string]bool, len(sf.HandledBy)),
		inSegment: make(map[[2]string]bool, len(sf.InSegment)),
	}
	for i, t := range sf.CanInvoke {
		if t.Principal == "" {
			return nil, fmt.Errorf("sts: static authorizer file %s: can_invoke[%d]: missing principal", path, i)
		}
		if t.Agent == "" {
			return nil, fmt.Errorf("sts: static authorizer file %s: can_invoke[%d]: missing agent", path, i)
		}
		a.canInvoke[[2]string{t.Principal, t.Agent}] = true
	}
	for i, t := range sf.HandledBy {
		if t.Employee == "" {
			return nil, fmt.Errorf("sts: static authorizer file %s: handled_by[%d]: missing employee", path, i)
		}
		if t.Customer == "" {
			return nil, fmt.Errorf("sts: static authorizer file %s: handled_by[%d]: missing customer", path, i)
		}
		a.handledBy[[2]string{t.Employee, t.Customer}] = true
	}
	for i, t := range sf.InSegment {
		if t.Principal == "" {
			return nil, fmt.Errorf("sts: static authorizer file %s: in_segment[%d]: missing principal", path, i)
		}
		if t.Segment == "" {
			return nil, fmt.Errorf("sts: static authorizer file %s: in_segment[%d]: missing segment", path, i)
		}
		a.inSegment[[2]string{t.Principal, t.Segment}] = true
	}
	return a, nil
}

func (a *staticAuthorizer) CanInvoke(_ context.Context, principal, agent string) (bool, error) {
	return a.canInvoke[[2]string{principal, agent}], nil
}

func (a *staticAuthorizer) HandledBy(_ context.Context, employee, customer string) (bool, error) {
	return a.handledBy[[2]string{employee, customer}], nil
}

func (a *staticAuthorizer) InSegment(_ context.Context, principal, segment string) (bool, error) {
	return a.inSegment[[2]string{principal, segment}], nil
}
