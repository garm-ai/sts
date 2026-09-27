package sts

import (
	"sync"
	"testing"
	"time"
)

// TestJTICacheDoesNotGrowWithoutBound is a white-box companion to
// clients_test.go's TestAuthenticateRejectsAReplayedJTI. That test proves a
// spent jti is refused on a second presentation, but an implementation that
// only ever ADDS entries to the replay cache (never removing an expired one)
// would also pass it — and would leak memory forever in a long-running
// process that anyone able to reach the token endpoint can grow without
// bound.
//
// This exercises spend directly (the same method Authenticate calls) and,
// using the injectable clock, proves an entry is actually REMOVED once its
// own recorded expiry has passed — not merely reported as "unseen" on the
// next lookup, which a lazily-overwriting-but-never-shrinking map would also
// do.
func TestJTICacheDoesNotGrowWithoutBound(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &ClientRegistry{
		now:  func() time.Time { return now },
		seen: make(map[[2]string]time.Time),
	}

	if err := r.spend("shop-bff", "jti-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("spend(jti-1) error = %v, want success recording a fresh jti", err)
	}
	if n := len(r.seen); n != 1 {
		t.Fatalf("cache size after one spend = %d, want 1", n)
	}

	// Advance the fake clock well past jti-1's own recorded expiry, then
	// spend a second, unrelated jti. If jti-1 had merely been left in
	// place, the cache would now hold two entries.
	now = now.Add(2 * time.Minute)
	if err := r.spend("shop-bff", "jti-2", now.Add(time.Minute)); err != nil {
		t.Fatalf("spend(jti-2) error = %v, want success", err)
	}

	if n := len(r.seen); n != 1 {
		t.Fatalf("cache size after jti-1 expired and jti-2 was spent = %d, want 1 — "+
			"an expired entry must be evicted, not retained forever", n)
	}
	if _, stillThere := r.seen[[2]string{"shop-bff", "jti-1"}]; stillThere {
		t.Fatal("jti-1 is still present in the cache after its own expiry passed — this is the unbounded-growth leak")
	}
}

// TestSpendIsRaceFreeUnderConcurrentPresentationOfTheSameAssertion drives
// many goroutines at the SAME (clientID, jti) pair simultaneously and
// asserts that exactly one succeeds. spend's "have I seen this" check and
// "record it" write happen inside one uninterrupted critical section, which
// is what makes this race-free by construction — but that is a claim about
// code a passing -race run does not itself exercise unless a test actually
// contends on the same key from multiple goroutines at once. A start gate
// (closed only once every goroutine is already blocked on it) forces real
// contention instead of goroutines arriving one at a time and never
// actually racing.
func TestSpendIsRaceFreeUnderConcurrentPresentationOfTheSameAssertion(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &ClientRegistry{
		now:  func() time.Time { return now },
		seen: make(map[[2]string]time.Time),
	}

	const n = 50
	exp := now.Add(time.Minute)

	var ready sync.WaitGroup
	ready.Add(n)
	start := make(chan struct{})
	results := make(chan error, n)

	for i := 0; i < n; i++ {
		go func() {
			ready.Done()
			<-start // every goroutine waits here, then all proceed together
			results <- r.spend("shop-bff", "jti-concurrent", exp)
		}()
	}

	ready.Wait() // every goroutine is blocked on <-start before any proceeds
	close(start)

	successes := 0
	for i := 0; i < n; i++ {
		if err := <-results; err == nil {
			successes++
		}
	}

	if successes != 1 {
		t.Fatalf("successes = %d out of %d concurrent spend() calls on the same (client, jti), want exactly 1", successes, n)
	}
}
