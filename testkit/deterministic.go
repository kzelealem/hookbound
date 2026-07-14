package testkit

import (
	"errors"
	"sync"
	"time"
)

// FixedClock is a concurrency-safe controllable clock.
type FixedClock struct {
	mu  sync.RWMutex
	now time.Time
}

func NewFixedClock(now time.Time) *FixedClock { return &FixedClock{now: now} }

func (c *FixedClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *FixedClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func (c *FixedClock) Advance(duration time.Duration) { c.Set(c.Now().Add(duration)) }

// SequenceIDs returns deterministic message IDs in order.
type SequenceIDs struct {
	mu  sync.Mutex
	IDs []string
}

func (s *SequenceIDs) NewMessageID() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.IDs) == 0 {
		return "", errors.New("testkit: no message IDs remain")
	}
	id := s.IDs[0]
	s.IDs = s.IDs[1:]
	return id, nil
}

// NoJitter makes retry schedules exact in tests.
type NoJitter struct{}

func (NoJitter) Duration(time.Duration) time.Duration { return 0 }
