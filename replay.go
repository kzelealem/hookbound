package hookbound

import (
	"context"
	"sync"
	"time"
)

// ReplayGuard atomically claims a verified message identity. claimed=false
// means the message was already accepted.
type ReplayGuard interface {
	Claim(context.Context, string, string, time.Time) (claimed bool, err error)
}

// MemoryReplayGuard is a bounded-process replay guard for single-instance or
// test use. Durable or horizontally scaled receivers should use PostgreSQL.
type MemoryReplayGuard struct {
	mu      sync.Mutex
	entries map[string]time.Time
	clock   Clock
	max     int
}

func NewMemoryReplayGuard(maxEntries int, clock Clock) *MemoryReplayGuard {
	if maxEntries <= 0 {
		maxEntries = 10_000
	}
	return &MemoryReplayGuard{
		entries: make(map[string]time.Time),
		clock:   clockOrSystem(clock),
		max:     maxEntries,
	}
}

func (g *MemoryReplayGuard) Claim(_ context.Context, source, id string, expiresAt time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.clock.Now()
	if len(g.entries) >= g.max {
		for key, expiry := range g.entries {
			if !expiry.After(now) {
				delete(g.entries, key)
			}
		}
	}
	if len(g.entries) >= g.max {
		return false, NewError(CodeInternal, "memory replay guard capacity reached", nil)
	}

	key := source + "\x00" + id
	if expiry, exists := g.entries[key]; exists && expiry.After(now) {
		return false, nil
	}
	g.entries[key] = expiresAt
	return true, nil
}
