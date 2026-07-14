package hookbound

import (
	"context"
	"sync"
	"time"
)

// ReplayGuard atomically claims a verified message identity. claimed=false
// means the message was already accepted. Implementations must not report an
// in-progress message as accepted; they may wait for the active claim to be
// committed or released.
type ReplayGuard interface {
	Claim(context.Context, string, string, time.Time) (claimed bool, err error)
	Release(context.Context, string, string) error
}

// ReplayCommitter is an optional extension implemented by replay guards that
// distinguish in-progress claims from accepted messages. Receiver calls Commit
// only after the handler succeeds. Legacy ReplayGuard implementations may omit
// it when Claim itself records a permanently accepted identity.
type ReplayCommitter interface {
	Commit(context.Context, string, string, time.Time) error
}

type memoryReplayEntry struct {
	accepted  bool
	expiresAt time.Time
	done      chan struct{}
}

// MemoryReplayGuard is a bounded-process replay guard for single-instance or
// test use. Durable or horizontally scaled receivers should persist inbox
// identities transactionally instead.
type MemoryReplayGuard struct {
	mu      sync.Mutex
	entries map[string]*memoryReplayEntry
	clock   Clock
	max     int
}

func NewMemoryReplayGuard(maxEntries int, clock Clock) *MemoryReplayGuard {
	if maxEntries <= 0 {
		maxEntries = 10_000
	}
	return &MemoryReplayGuard{
		entries: make(map[string]*memoryReplayEntry),
		clock:   clockOrSystem(clock),
		max:     maxEntries,
	}
}

func (g *MemoryReplayGuard) Claim(ctx context.Context, source, id string, _ time.Time) (bool, error) {
	if g == nil {
		return false, NewError(CodeInvalidConfiguration, "memory replay guard is nil", nil)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	key := source + "\x00" + id

	for {
		g.mu.Lock()
		now := g.clock.Now()
		if entry, exists := g.entries[key]; exists {
			if entry.accepted {
				if entry.expiresAt.After(now) {
					g.mu.Unlock()
					return false, nil
				}
				delete(g.entries, key)
			} else {
				done := entry.done
				g.mu.Unlock()
				select {
				case <-ctx.Done():
					return false, NewError(CodeInternal, "wait for active replay claim", ctx.Err())
				case <-done:
					continue
				}
			}
		}

		if len(g.entries) >= g.max {
			for candidate, entry := range g.entries {
				if entry.accepted && !entry.expiresAt.After(now) {
					delete(g.entries, candidate)
				}
			}
		}
		if len(g.entries) >= g.max {
			g.mu.Unlock()
			return false, NewError(CodeInternal, "memory replay guard capacity reached", nil)
		}

		g.entries[key] = &memoryReplayEntry{done: make(chan struct{})}
		g.mu.Unlock()
		return true, nil
	}
}

// Commit marks an in-progress claim as accepted and wakes duplicate requests.
func (g *MemoryReplayGuard) Commit(_ context.Context, source, id string, expiresAt time.Time) error {
	if g == nil {
		return NewError(CodeInvalidConfiguration, "memory replay guard is nil", nil)
	}
	key := source + "\x00" + id
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, exists := g.entries[key]
	if !exists || entry.accepted {
		return NewError(CodeConflict, "memory replay claim is not active", nil)
	}
	entry.accepted = true
	entry.expiresAt = expiresAt
	close(entry.done)
	entry.done = nil
	return nil
}

// Release removes an uncommitted claim and wakes duplicate requests so a
// provider retry can be processed.
func (g *MemoryReplayGuard) Release(_ context.Context, source, id string) error {
	if g == nil {
		return NewError(CodeInvalidConfiguration, "memory replay guard is nil", nil)
	}
	key := source + "\x00" + id
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, exists := g.entries[key]
	if !exists {
		return nil
	}
	if entry.accepted {
		return NewError(CodeConflict, "cannot release an accepted replay claim", nil)
	}
	delete(g.entries, key)
	close(entry.done)
	return nil
}
